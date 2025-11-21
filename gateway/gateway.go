package gateway

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/zijiren233/sshgate/registry"
	"golang.org/x/crypto/ssh"
)

// Gateway handles SSH connections and routes them to backend devbox pods
type Gateway struct {
	config   *ssh.ServerConfig
	registry *registry.Registry
}

// New creates a new Gateway instance
func New(hostKey ssh.Signer, reg *registry.Registry) *Gateway {
	gw := &Gateway{
		registry: reg,
	}

	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: newPublicKeyCallback(reg),
	}
	sshConfig.AddHostKey(hostKey)

	gw.config = sshConfig
	return gw
}

func newPublicKeyCallback(
	reg *registry.Registry,
) func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		// Accept any username - store it in Extensions for logging
		username := conn.User()

		// Calculate fingerprint of the connecting key
		fingerprint := ssh.FingerprintSHA256(key)

		// Look up devbox by fingerprint
		info, ok := reg.GetByFingerprint(fingerprint)
		if !ok {
			return nil, fmt.Errorf("unknown public key with fingerprint %s", fingerprint)
		}

		log.Printf(
			"Accepted key for %s/%s (user: %s, fingerprint: %s)",
			info.Namespace,
			info.DevboxName,
			username,
			fingerprint,
		)

		return &ssh.Permissions{
			Extensions: map[string]string{
				"fingerprint": fingerprint,
				"username":    username,
			},
		}, nil
	}
}

// HandleConnection handles an incoming SSH connection
func (g *Gateway) HandleConnection(nConn net.Conn) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, g.config)
	if err != nil {
		log.Printf("Failed to handshake: %v", err)
		return
	}
	defer conn.Close()

	// Get devbox info from permissions
	fingerprint := conn.Permissions.Extensions["fingerprint"]
	username := conn.Permissions.Extensions["username"]

	// Look up devbox by fingerprint
	info, ok := g.registry.GetByFingerprint(fingerprint)
	if !ok {
		log.Printf("No devbox found for fingerprint %s", fingerprint)
		return
	}

	if info.PodIP == "" {
		log.Printf("Devbox %s/%s has no pod IP", info.Namespace, info.DevboxName)
		return
	}

	log.Printf(
		"User %s logged in, routing to %s/%s at %s",
		username,
		info.Namespace,
		info.DevboxName,
		info.PodIP,
	)

	// Connect to backend pod
	backendAddr := fmt.Sprintf("%s:22", info.PodIP)

	// Use the devbox's private key to connect
	auth := []ssh.AuthMethod{
		ssh.PublicKeys(info.PrivateKey),
	}

	backendConfig := &ssh.ClientConfig{
		User:            username,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	backendConn, err := ssh.Dial("tcp", backendAddr, backendConfig)
	if err != nil {
		log.Printf("Failed to connect to backend %s: %v", backendAddr, err)
		return
	}
	defer backendConn.Close()

	// Proxy all channels and requests
	go handleGlobalRequests(reqs, backendConn)

	for newChannel := range chans {
		go handleChannel(newChannel, backendConn)
	}
}

// handleGlobalRequests handles global SSH requests
// It rejects remote port forwarding and forwards other requests to backend
func handleGlobalRequests(reqs <-chan *ssh.Request, backendConn *ssh.Client) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward", "cancel-tcpip-forward":
			// Reject remote port forwarding requests
			if req.WantReply {
				req.Reply(false, nil)
			}
			log.Printf("Rejected remote port forwarding request: %s", req.Type)
		default:
			// Forward other global requests to backend
			// This supports X11 forwarding, agent forwarding, etc.
			ok, response, err := backendConn.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				log.Printf("Error forwarding global request %s: %v", req.Type, err)
				if req.WantReply {
					req.Reply(false, nil)
				}
				return
			}
			if req.WantReply {
				req.Reply(ok, response)
			}
		}
	}
}

func handleChannel(newChannel ssh.NewChannel, backendConn *ssh.Client) {
	// Open the same type of channel on backend
	backendChannel, backendReqs, err := backendConn.OpenChannel(
		newChannel.ChannelType(),
		newChannel.ExtraData(),
	)
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		backendChannel.Close()
		return
	}

	// Bidirectional proxy for requests
	go proxyRequests(requests, backendChannel)
	go proxyRequests(backendReqs, channel)

	// Bidirectional proxy for data
	go io.Copy(channel, backendChannel)
	io.Copy(backendChannel, channel)
}

func proxyRequests(in <-chan *ssh.Request, out ssh.Channel) {
	for req := range in {
		ok, err := out.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			req.Reply(ok, nil)
		}
		if err != nil {
			return
		}
	}
}
