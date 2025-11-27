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
	// Forward requests from client to backend (fire and forget)
	go g.proxyRequests(clientReqs, backendChannel)

	// Forward requests from backend to client (includes exit-status)
	// We need to wait for this to complete before closing client channel
	backendReqsDone := make(chan struct{})
	go func() {
		g.proxyRequests(backendReqs, channel)
		close(backendReqsDone)
	}()

	// Proxy data in both directions
	var once sync.Once
	done := make(chan struct{})
	closeDone := func() { once.Do(func() { close(done) }) }

	go func() {
		_, _ = io.Copy(channel, backendChannel)
		_ = channel.CloseWrite()
		closeDone()
	}()

	go func() {
		_, _ = io.Copy(backendChannel, channel)
		_ = backendChannel.CloseWrite()
		closeDone()
	}()

	// Wait for either direction's data copy to complete
	<-done

	// Close backend channel first - this closes backendReqs channel,
	// allowing the request forwarding goroutine to finish and forward exit-status
	_ = backendChannel.Close()

	// Wait for backend->client request forwarding to complete (ensures exit-status is sent)
	<-backendReqsDone

	// Now safe to close client channel
	_ = channel.Close()
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
