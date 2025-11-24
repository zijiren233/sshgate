package gateway

import (
	"fmt"
	"log"

	"github.com/zijiren233/sshgate/registry"
	"golang.org/x/crypto/ssh"
)

// AuthMode represents the authentication mode
type AuthMode int

const (
	AuthModeUnknown         AuthMode = iota
	AuthModePublicKey                // Public key authentication mode
	AuthModeAgentForwarding          // Agent forwarding authentication mode
)

func (m AuthMode) String() string {
	switch m {
	case AuthModePublicKey:
		return "public-key"
	case AuthModeAgentForwarding:
		return "agent-forwarding"
	default:
		return "unknown"
	}
}

// publicKeyCallback handles public key authentication
func (g *Gateway) publicKeyCallback(
	conn ssh.ConnMetadata,
	key ssh.PublicKey,
) (*ssh.Permissions, error) {
	username := conn.User()
	fingerprint := ssh.FingerprintSHA256(key)

	log.Printf(
		"[Auth] Public key authentication: user=%s, fingerprint=%s",
		username,
		fingerprint,
	)

	// Look up devbox by public key
	info, ok := g.registry.GetByFingerprint(fingerprint)
	if !ok {
		// Parse username: username.short_user_namespace-devboxname
		username, fullNamespace, devboxName, err := g.parser.Parse(conn.User())
		if err != nil {
			log.Printf("[Auth] Invalid username format: %v", err)
			return nil, err
		}

		info, ok := g.registry.GetDevboxInfo(fullNamespace, devboxName)
		if !ok {
			log.Printf("[Auth] Unknown public key: %s", fingerprint)
			return nil, fmt.Errorf("unknown public key")
		}

		if info.PodIP == "" {
			log.Printf(
				"[PublicKey] Devbox %s/%s not running",
				info.Namespace,
				info.DevboxName,
			)
			return nil, fmt.Errorf("devbox %s/%s not running",
				info.Namespace,
				info.DevboxName,
			)
		}

		return &ssh.Permissions{
			Extensions: map[string]string{
				"username":  username,
				"auth_mode": AuthModeAgentForwarding.String(),
			},
			ExtraData: map[any]any{
				"devbox_info": info,
			},
		}, nil
	}

	log.Printf(
		"[Auth] Public key matched: %s/%s",
		info.Namespace,
		info.DevboxName,
	)

	if info.PodIP == "" {
		log.Printf(
			"[PublicKey] Devbox %s/%s not running",
			info.Namespace,
			info.DevboxName,
		)
		return nil, fmt.Errorf("devbox %s/%s not running",
			info.Namespace,
			info.DevboxName,
		)
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			"username":  username,
			"auth_mode": AuthModePublicKey.String(),
		},
		ExtraData: map[any]any{
			"devbox_info": info,
		},
	}, nil
}

// determineAuthMode determines which authentication mode is being used
func (g *Gateway) determineAuthMode(conn *ssh.ServerConn) AuthMode {
	if conn.Permissions == nil {
		return AuthModeAgentForwarding
	}

	authMode := conn.Permissions.Extensions["auth_mode"]
	if authMode == AuthModePublicKey.String() {
		return AuthModePublicKey
	}

	return AuthModeAgentForwarding
}

func (g *Gateway) getDevboxInfoFromPermissions(
	perms *ssh.Permissions,
) (*registry.DevboxInfo, error) {
	if perms == nil {
		return nil, fmt.Errorf("permissions is nil")
	}

	infoValue, ok := perms.ExtraData["devbox_info"]
	if !ok {
		return nil, fmt.Errorf("no devbox_info in permissions")
	}

	info, ok := infoValue.(*registry.DevboxInfo)
	if !ok || info == nil {
		return nil, fmt.Errorf("invalid devbox_info type")
	}

	return info, nil
}

// GetDevboxInfoFromPermissions is exported for testing
func GetDevboxInfoFromPermissions(perms *ssh.Permissions) (*registry.DevboxInfo, error) {
	gw := &Gateway{}
	return gw.getDevboxInfoFromPermissions(perms)
}

// GetUsernameFromPermissions is exported for testing
func GetUsernameFromPermissions(perms *ssh.Permissions) (string, error) {
	if perms == nil {
		return "", fmt.Errorf("permissions is nil")
	}

	username, ok := perms.Extensions["username"]
	if !ok {
		return "", fmt.Errorf("no username in permissions")
	}

	return username, nil
}

// NewPublicKeyCallback creates a public key callback for testing
func NewPublicKeyCallback(
	reg *registry.Registry,
) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	gw := &Gateway{
		registry: reg,
	}
	return gw.publicKeyCallback
}
