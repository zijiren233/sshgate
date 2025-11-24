package gateway

import (
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
	parser   *UsernameParser
}

// New creates a new Gateway instance
func New(hostKey ssh.Signer, reg *registry.Registry) *Gateway {
	gw := &Gateway{
		registry: reg,
		parser:   &UsernameParser{},
	}

	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: gw.publicKeyCallback,
	}
	sshConfig.AddHostKey(hostKey)

	gw.config = sshConfig

	return gw
}

func (g *Gateway) HandleConnection(nConn net.Conn) {
	nConn.SetDeadline(time.Now().Add(30 * time.Second))

	conn, chans, reqs, err := ssh.NewServerConn(nConn, g.config)
	if err != nil {
		log.Printf("[Connection] Handshake failed: %v", err)
		return
	}
	defer conn.Close()

	nConn.SetDeadline(time.Time{})

	info, err := g.getDevboxInfoFromPermissions(conn.Permissions)
	if err != nil {
		log.Printf("[PublicKey] Failed to get devbox info: %v", err)
		return
	}

	username := conn.Permissions.Extensions["username"]

	// Determine authentication mode
	authMode := g.determineAuthMode(conn)

	log.Printf(
		"[Connection] Established: namespace=%s devbox=%s user=%s, mode=%s, remote=%s",
		info.Namespace,
		info.DevboxName,
		conn.User(),
		authMode,
		conn.RemoteAddr(),
	)

	switch authMode {
	case AuthModePublicKey:
		g.handlePublicKeyMode(conn, chans, reqs, info, username)
	case AuthModeAgentForwarding:
		g.handleAgentForwardingMode(conn, chans, reqs, info, username)
	default:
		log.Printf("[Connection] Unknown auth mode, closing")
	}
}

func (g *Gateway) Config() *ssh.ServerConfig {
	return g.config
}
