package gateway

import (
	"log"
	"time"

	"golang.org/x/crypto/ssh"
)

func (g *Gateway) handlePublicKeyMode(
	conn *ssh.ServerConn,
	chans <-chan ssh.NewChannel,
	reqs <-chan *ssh.Request,
) {
	info, err := g.getDevboxInfoFromPermissions(conn.Permissions)
	if err != nil {
		log.Printf("[PublicKey] Failed to get devbox info: %v", err)
		return
	}

	username := conn.Permissions.Extensions["username"]

	if info.PodIP == "" {
		log.Printf(
			"[PublicKey] Devbox %s/%s has no pod IP",
			info.Namespace,
			info.DevboxName,
		)
		return
	}

	log.Printf(
		"[PublicKey] Routing %s to %s/%s at %s",
		username,
		info.Namespace,
		info.DevboxName,
		info.PodIP,
	)

	backendAddr := info.PodIP + ":22"

	backendConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(info.PrivateKey),
		},
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
				req.Reply(false, nil)
			}
			log.Printf("[PublicKey] Rejected remote port forwarding: %s", req.Type)

		default:
			ok, response, err := backendConn.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				log.Printf("[PublicKey] Error forwarding request %s: %v", req.Type, err)
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

func (g *Gateway) handleChannelPublicKey(
	newChannel ssh.NewChannel,
	backendConn *ssh.Client,
) {
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

	go g.proxyRequests(requests, backendChannel)
	go g.proxyRequests(backendReqs, channel)

	g.proxyChannel(channel, backendChannel)
}
