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
// forwarding requests. It ensures that request forwarding completes before
// closing channels to prevent race conditions where exit-status is lost.
func (g *Gateway) proxyChannelWithRequests(
	channel, backendChannel ssh.Channel,
	clientReqs, backendReqs <-chan *ssh.Request,
) {
	var wg sync.WaitGroup

	// Start request forwarding goroutines
	wg.Go(func() { g.proxyRequests(clientReqs, backendChannel) })
	wg.Go(func() { g.proxyRequests(backendReqs, channel) })

	// Proxy data in both directions
	var copyWg sync.WaitGroup
	copyWg.Go(func() { _, _ = io.Copy(channel, backendChannel) })
	_, _ = io.Copy(backendChannel, channel)

	// Wait for data copy to complete
	copyWg.Wait()

	// Close write sides to signal EOF, allowing request handlers to finish
	_ = channel.CloseWrite()
	_ = backendChannel.CloseWrite()

	// Wait for all request forwarding to complete before closing channels
	wg.Wait()

	// Now safe to close channels
	_ = channel.Close()
	_ = backendChannel.Close()
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
