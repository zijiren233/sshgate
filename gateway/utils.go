package gateway

import (
	"io"

	"golang.org/x/crypto/ssh"
)

func (g *Gateway) proxyRequests(in <-chan *ssh.Request, out ssh.Channel) {
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

func (g *Gateway) proxyChannel(channel, backendChannel ssh.Channel) {
	go func() {
		io.Copy(channel, backendChannel)
		channel.Close()
	}()

	io.Copy(backendChannel, channel)
	backendChannel.Close()
}
