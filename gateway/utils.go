package gateway

import (
	"io"
	"net"

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

func (g *Gateway) proxyChannel(channel, backendChannel ssh.Channel) {
	go func() {
		_, _ = io.Copy(channel, backendChannel)
		_ = channel.Close()
	}()

	_, _ = io.Copy(backendChannel, channel)
	_ = backendChannel.Close()
}

// proxyChannelToConn proxies data between an SSH channel and a net.Conn
func (g *Gateway) proxyChannelToConn(channel ssh.Channel, conn net.Conn) {
	go func() {
		_, _ = io.Copy(channel, conn)
		_ = channel.Close()
	}()

	_, _ = io.Copy(conn, channel)
	_ = conn.Close()
}
