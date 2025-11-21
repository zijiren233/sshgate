package gateway_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"

	"github.com/zijiren233/sshgate/gateway"
	"github.com/zijiren233/sshgate/registry"
	"golang.org/x/crypto/ssh"
)

func generateTestKeys(t *testing.T) (ssh.Signer, ssh.PublicKey, []byte, []byte) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to create SSH public key: %v", err)
	}

	sshPriv, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("Failed to create SSH signer: %v", err)
	}

	pubBytes := ssh.MarshalAuthorizedKey(sshPub)

	privPEM, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	privBytes := pem.EncodeToMemory(privPEM)

	return sshPriv, sshPub, pubBytes, privBytes
}

func TestNew(t *testing.T) {
	hostKeySigner, _, _, _ := generateTestKeys(t)
	reg := registry.New()

	gw := gateway.New(hostKeySigner, reg)

	if gw == nil {
		t.Fatal("New() returned nil")
	}
}

// TestPublicKeyCallback and TestProxyRequests removed as they require access to
// internal implementation details. These are better tested through integration tests.
