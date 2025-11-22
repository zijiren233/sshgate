package gateway

import (
	"errors"
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
		PublicKeyCallback: NewPublicKeyCallback(reg),
	}
	sshConfig.AddHostKey(hostKey)

	gw.config = sshConfig

	return gw
}

// Config returns the SSH server configuration.
// This method is exposed for testing purposes.
func (g *Gateway) Config() *ssh.ServerConfig {
	return g.config
}

// GetDevboxInfoFromPermissions extracts DevboxInfo from SSH Permissions.
// This function is exposed for testing purposes.
func GetDevboxInfoFromPermissions(perms *ssh.Permissions) (*registry.DevboxInfo, error) {
	if perms == nil {
		return nil, errors.New("permissions is nil")
	}

	infoValue, ok := perms.ExtraData["devbox_info"]
	if !ok {
		return nil, errors.New("no devbox_info in permissions")
	}

	info, ok := infoValue.(*registry.DevboxInfo)
	if !ok || info == nil {
		return nil, errors.New("invalid devbox_info type in permissions")
	}

	return info, nil
}

// GetUsernameFromPermissions extracts username from SSH Permissions.
// This function is exposed for testing purposes.
func GetUsernameFromPermissions(perms *ssh.Permissions) (string, error) {
	if perms == nil {
		return "", errors.New("permissions is nil")
	}

	username, ok := perms.Extensions["username"]
	if !ok {
		return "", errors.New("no username in permissions")
	}

	return username, nil
}

// NewPublicKeyCallback creates a public key authentication callback for the SSH server.
// This function is exposed for testing purposes.
func NewPublicKeyCallback(
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
				"username": username,
			},
			ExtraData: map[any]any{
				"devbox_info": info,
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
	info, err := GetDevboxInfoFromPermissions(conn.Permissions)
	if err != nil {
		log.Printf("Failed to get devbox info from permissions: %v", err)
		return
	}

	username, err := GetUsernameFromPermissions(conn.Permissions)
	if err != nil {
		log.Printf("Failed to get username from permissions: %v", err)
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
	backendAddr := info.PodIP + ":22"

	// Use the devbox's private key to connect
	auth := []ssh.AuthMethod{
		ssh.PublicKeys(info.PrivateKey),
	}

	backendConfig := &ssh.ClientConfig{
		User: username,
		Auth: auth,
		// #nosec G106 -- We trust the backend pods within our cluster
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
				if err := req.Reply(false, nil); err != nil {
					log.Printf("Error replying to request: %v", err)
				}
			}

			log.Printf("Rejected remote port forwarding request: %s", req.Type)
		default:
			// Forward other global requests to backend
			// This supports X11 forwarding, agent forwarding, etc.
			ok, response, err := backendConn.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				log.Printf("Error forwarding global request %s: %v", req.Type, err)

				if req.WantReply {
					if err := req.Reply(false, nil); err != nil {
						log.Printf("Error replying to request: %v", err)
					}
				}

				return
			}

			if req.WantReply {
				if err := req.Reply(ok, response); err != nil {
					log.Printf("Error replying to request: %v", err)
				}
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
		if err := newChannel.Reject(ssh.ConnectionFailed, err.Error()); err != nil {
			log.Printf("Error rejecting channel: %v", err)
		}
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
	go func() {
		if _, err := io.Copy(channel, backendChannel); err != nil {
			log.Printf("Error copying data from backend to client: %v", err)
		}
	}()

	if _, err := io.Copy(backendChannel, channel); err != nil {
		log.Printf("Error copying data from client to backend: %v", err)
	}
}

func proxyRequests(in <-chan *ssh.Request, out ssh.Channel) {
	for req := range in {
		ok, err := out.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			if err := req.Reply(ok, nil); err != nil {
				log.Printf("Error replying to request: %v", err)
			}
		}

		if err != nil {
			return
		}
	}
}
