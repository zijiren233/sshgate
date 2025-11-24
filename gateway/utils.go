package gateway

import (
	"io"

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
