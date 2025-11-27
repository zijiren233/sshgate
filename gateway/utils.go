package gateway

import (
	"io"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func (g *Gateway) proxyRequests(in <-chan *ssh.Request, out ssh.Channel) {
	for req := range in {
		log.WithFields(log.Fields{
			"type":       req.Type,
			"want_reply": req.WantReply,
		}).Debug("Forwarding request")

		ok, err := out.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			_ = req.Reply(ok, nil)
		}

		if err != nil {
			log.WithError(err).WithField("type", req.Type).Warn("Failed to forward request")
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

	// Forward requests from backend to client (includes exit-status/exit-signal)
	// We need to wait for this to complete before closing client channel
	backendReqsDone := make(chan struct{})
	go func() {
		g.proxyRequests(backendReqs, channel)
		log.Debug("Backend requests forwarding completed")
		close(backendReqsDone)
	}()

	// Proxy data in both directions
	var once sync.Once

	done := make(chan struct{})
	closeDone := func() { once.Do(func() { close(done) }) }

	go func() {
		_, _ = io.Copy(channel, backendChannel)
		log.Debug("Backend -> Client data copy completed")
		closeDone()
	}()

	go func() {
		_, _ = io.Copy(backendChannel, channel)
		log.Debug("Client -> Backend data copy completed")
		closeDone()
	}()

	// Wait for either direction's data copy to complete
	<-done
	log.Debug("Data copy done, sending EOF")

	// Send EOF to both directions
	_ = channel.CloseWrite()
	_ = backendChannel.CloseWrite()

	log.Debug("Waiting for backend requests to complete")
	// Wait for backend->client request forwarding to complete
	// This ensures exit-status/exit-signal is sent before closing client channel
	<-backendReqsDone

	log.Debug("Closing channels")
	// Now safe to close channels
	_ = backendChannel.Close()
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
