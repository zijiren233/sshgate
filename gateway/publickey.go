package gateway

import (
	"log"
	"time"

	"github.com/zijiren233/sshgate/registry"
	"golang.org/x/crypto/ssh"
)

func (g *Gateway) handlePublicKeyMode(
	_ *ssh.ServerConn,
	chans <-chan ssh.NewChannel,
	reqs <-chan *ssh.Request,
	info *registry.DevboxInfo,
	username string,
) {
	backendAddr := info.PodIP + ":22"

	backendConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(info.PrivateKey),
		},

		//nolint:gosec
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	backendConn, err := ssh.Dial("tcp", backendAddr, backendConfig)
	if err != nil {
		log.Printf("[PublicKey] Failed to connect to backend %s: %v", backendAddr, err)
		return
	}
	defer backendConn.Close()

	log.Printf("[PublicKey] Backend connected")

	go g.handleGlobalRequestsPublicKey(reqs, backendConn)

	for newChannel := range chans {
		go g.handleChannelPublicKey(newChannel, backendConn)
	}
}

func (g *Gateway) handleGlobalRequestsPublicKey(
	reqs <-chan *ssh.Request,
	backendConn *ssh.Client,
) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward", "cancel-tcpip-forward":
			if req.WantReply {
				_ = req.Reply(false, nil)
			}

			log.Printf("[PublicKey] Rejected remote port forwarding: %s", req.Type)

		default:
			ok, response, err := backendConn.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				log.Printf("[PublicKey] Error forwarding request %s: %v", req.Type, err)

				if req.WantReply {
					_ = req.Reply(false, nil)
				}

				return
			}

			if req.WantReply {
				_ = req.Reply(ok, response)
			}
		}
	}
}

func (g *Gateway) handleChannelPublicKey(
	newChannel ssh.NewChannel,
	backendConn *ssh.Client,
) {
	backendChannel, backendReqs, err := backendConn.OpenChannel(
		newChannel.ChannelType(),
		newChannel.ExtraData(),
	)
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		backendChannel.Close()
		return
	}

	go g.proxyRequests(requests, backendChannel)
	go g.proxyRequests(backendReqs, channel)

	g.proxyChannel(channel, backendChannel)
}
