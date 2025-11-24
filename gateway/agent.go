package gateway

import (
	"fmt"
	"log"
	"time"

	"github.com/zijiren233/sshgate/registry"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// SessionRequestsResult contains the results of processing session requests
type SessionRequestsResult struct {
	AgentChannel   ssh.Channel    // Agent channel to client (nil if not requested/failed)
	CachedRequests []*ssh.Request // Cached non-agent requests (max 6)
}

type sessionContext struct {
	conn     *ssh.ServerConn
	info     *registry.DevboxInfo
	realUser string
}

func (g *Gateway) handleAgentForwardingMode(
	conn *ssh.ServerConn,
	chans <-chan ssh.NewChannel,
	reqs <-chan *ssh.Request,
	info *registry.DevboxInfo,
	username string,
) {
	ctx := &sessionContext{
		conn:     conn,
		info:     info,
		realUser: username,
	}

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		g.handleChannelAgent(newChannel, ctx)
	}
}

func (g *Gateway) handleChannelAgent(
	newChannel ssh.NewChannel,
	ctx *sessionContext,
) {
	channelType := newChannel.ChannelType()
	log.Printf("[AgentForwarding] New channel: %s", channelType)

	switch channelType {
	case "session":
		g.handleSessionChannel(newChannel, ctx)

	default:
		log.Printf("[AgentForwarding] Rejecting unknown channel type: %s", channelType)
		newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
	}
}

func (g *Gateway) handleSessionChannel(
	newChannel ssh.NewChannel,
	ctx *sessionContext,
) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("[AgentForwarding] Failed to accept session channel: %v", err)
		return
	}
	defer channel.Close()

	// Process channel requests to handle auth-agent-req@openssh.com
	// This implements the OpenSSH standard where auth-agent-req is a CHANNEL request
	// Returns agent channel and cached requests
	sessionResult := g.handleSessionRequests(requests, ctx)

	// Check if agent forwarding was successful
	if sessionResult == nil || sessionResult.AgentChannel == nil {
		fmt.Fprintf(channel,
			"Failed to establish agent forwarding\r\n"+
				"Make sure your SSH agent is running and has the correct keys\r\n",
		)
		return
	}

	// Connect to backend with agent authentication if available
	backendConn, err := g.connectToBackend(ctx, sessionResult.AgentChannel)
	// close agent channel
	_ = sessionResult.AgentChannel.Close()
	if err != nil {
		log.Printf("[AgentForwarding] Failed to connect to backend: %v", err)
		fmt.Fprintf(channel,
			"Failed to connect to devbox: %v\r\n"+
				"Make sure your SSH agent has the correct key and that the key is in ~/.ssh/authorized_keys on the devbox\r\n",
			err,
		)
		return
	}
	defer backendConn.Close()

	log.Printf("[AgentForwarding] Backend connected")

	backendChannel, backendRequests, err := backendConn.OpenChannel("session", nil)
	if err != nil {
		log.Printf("[AgentForwarding] Failed to open backend channel: %v", err)
		return
	}
	defer backendChannel.Close()

	// Forward cached requests to backend
	g.forwardCachedRequests(sessionResult.CachedRequests, backendChannel)

	// Proxy all remaining requests and data
	go g.proxyRequests(requests, backendChannel)
	go g.proxyRequests(backendRequests, channel)

	g.proxyChannel(channel, backendChannel)
}

// forwardCachedRequests forwards cached SSH requests to the backend
func (g *Gateway) forwardCachedRequests(cachedRequests []*ssh.Request, backendChannel ssh.Channel) {
	for _, req := range cachedRequests {
		ok, err := backendChannel.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			log.Printf("[AgentForwarding] Failed to forward cached request %s: %v", req.Type, err)
		}

		if req.WantReply {
			req.Reply(ok, nil)
		}
	}
}

// handleSessionRequests processes channel requests for a session
// This handles auth-agent-req@openssh.com as a CHANNEL request (OpenSSH standard)
// Returns a result with agent request status and cached non-agent requests
func (g *Gateway) handleSessionRequests(
	requests <-chan *ssh.Request,
	ctx *sessionContext,
) *SessionRequestsResult {
	result := &SessionRequestsResult{
		AgentChannel:   nil,
		CachedRequests: make([]*ssh.Request, 0, 6), // Pre-allocate with max capacity 6
	}

	// Process requests until we've handled all initial setup requests
	timeout := time.NewTimer(time.Second * 3)
	defer timeout.Stop()

	for {
		select {
		case req, ok := <-requests:
			if !ok {
				return result
			}

			log.Printf(
				"[AgentForwarding] Session channel request: %s (WantReply: %v)",
				req.Type,
				req.WantReply,
			)

			// Handle auth-agent-req@openssh.com as a channel request (OpenSSH standard)
			if req.Type == "auth-agent-req@openssh.com" {
				log.Printf("[AgentForwarding] ✓ Agent forwarding requested by client")

				if req.WantReply {
					req.Reply(true, nil)
				}

				// CRITICAL: In bastion host mode, we need to actively create
				// an agent channel to the client immediately!
				result.AgentChannel = g.createAgentChannelToClient(ctx)

				result.CachedRequests = append(result.CachedRequests, req)

				// Don't forward this request to backend - we handle it
				return result
			}

			// For all other request types, cache them for forwarding (max 6)
			if len(result.CachedRequests) < 6 {
				result.CachedRequests = append(result.CachedRequests, req)
				timeout.Reset(time.Second)
				continue
			}
			return nil

		case <-timeout.C:
			// Timeout - stop processing initial requests
			return result
		}
	}
}

// createAgentChannelToClient actively creates an agent channel to the client
// This is the critical function for bastion host SSH agent forwarding
// Returns the created agent channel or nil if failed
func (g *Gateway) createAgentChannelToClient(ctx *sessionContext) ssh.Channel {
	// Use the client connection to open an agent channel
	// This tells the client "I want to access your SSH agent"
	agentChannel, agentReqs, err := ctx.conn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		log.Printf("[AgentForwarding] Failed to open agent channel to client: %v", err)
		return nil
	}

	log.Printf("[AgentForwarding] ✓ Agent channel to client established")

	// Discard requests on the agent channel
	go ssh.DiscardRequests(agentReqs)

	return agentChannel
}

func (g *Gateway) connectToBackend(
	ctx *sessionContext,
	agentChannel ssh.Channel,
) (*ssh.Client, error) {
	backendAddr := ctx.info.PodIP + ":22"

	agentClient := agent.NewClient(agentChannel)

	backendConfig := &ssh.ClientConfig{
		User:            ctx.realUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeysCallback(agentClient.Signers)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	log.Printf(
		"[AgentForwarding] Connecting to backend %s as user %s with agent authentication",
		backendAddr,
		ctx.realUser,
	)

	conn, err := ssh.Dial("tcp", backendAddr, backendConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to backend: %w", err)
	}

	return conn, nil
}
