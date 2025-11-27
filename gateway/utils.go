package gateway

import (
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

func (g *Gateway) proxyRequests(in <-chan *ssh.Request, out ssh.Channel) {
	for req := range in {
		ok, err := out.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			_ = req.Reply(ok, nil)
		}

		if err != nil {
			return
		}
	}
}

// proxyChannelWithRequests proxies data between two SSH channels while also
// forwarding requests. It ensures that exit-status is forwarded before closing.
func (g *Gateway) proxyChannelWithRequests(
	channel, backendChannel ssh.Channel,
	clientReqs, backendReqs <-chan *ssh.Request,
) {
	backendReqsDone := sync.WaitGroup{}
	backendReqsDone.Go(func() {
		g.proxyRequests(clientReqs, backendChannel)
		_ = backendChannel.Close()
	})

	// Forward requests from backend to client (includes exit-status/exit-signal)
	// We need to wait for this to complete before closing client channel
	backendReqsDone.Go(func() {
		g.proxyRequests(backendReqs, channel)
		_ = channel.Close()
	})

	// Proxy data in both directions

	go func() {
		_, _ = io.Copy(channel, backendChannel)
		_ = channel.CloseWrite()
	}()

	go func() {
		_, _ = io.Copy(backendChannel, channel)
		_ = backendChannel.CloseWrite()
	}()

	// Wait for backend->client request forwarding to complete
	// This ensures exit-status/exit-signal is sent before closing client channel
	backendReqsDone.Wait()
}

// proxyChannelToConn proxies data between an SSH channel and a net.Conn
func (g *Gateway) proxyChannelToConn(channel ssh.Channel, conn net.Conn) {
	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = io.Copy(channel, conn)
		_ = channel.CloseWrite()
	})

	_, _ = io.Copy(conn, channel)
	_ = conn.Close()

	wg.Wait()

	_ = channel.Close()
}
