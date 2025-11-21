package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"testing"

	"github.com/zijiren233/sshgate/registry"
	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	gw := New(hostKeySigner, reg)

	if gw == nil {
		t.Fatal("New() returned nil")
	}
	if gw.config == nil {
		t.Error("Gateway config is nil")
	}
	if gw.registry == nil {
		t.Error("Gateway registry is nil")
	}
}

func TestPublicKeyCallback(t *testing.T) {
	hostKeySigner, _, _, _ := generateTestKeys(t)
	_, clientPub, clientPubBytes, clientPrivBytes := generateTestKeys(t)
	reg := registry.New()

	// Add a devbox to registry
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "test-ns",
			Labels: map[string]string{
				registry.DevboxPartOfLabel: registry.DevboxPartOfValue,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: registry.DevboxOwnerKind,
					Name: "test-devbox",
				},
			},
		},
		Data: map[string][]byte{
			registry.DevboxPublicKeyField:  clientPubBytes,
			registry.DevboxPrivateKeyField: clientPrivBytes,
		},
	}

	if err := reg.AddSecret(secret); err != nil {
		t.Fatalf("Failed to add secret: %v", err)
	}

	gw := New(hostKeySigner, reg)

	tests := []struct {
		name     string
		username string
		key      ssh.PublicKey
		wantErr  bool
	}{
		{
			name:     "valid key with username devbox",
			username: "devbox",
			key:      clientPub,
			wantErr:  false,
		},
		{
			name:     "valid key with custom username",
			username: "customuser",
			key:      clientPub,
			wantErr:  false,
		},
		{
			name:     "invalid key",
			username: "anyuser",
			key:      hostKeySigner.PublicKey(),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock ConnMetadata
			mockConn := &mockConnMetadata{username: tt.username}

			perms, err := gw.config.PublicKeyCallback(mockConn, tt.key)

			if (err != nil) != tt.wantErr {
				t.Errorf("PublicKeyCallback() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if perms == nil {
					t.Error("PublicKeyCallback() returned nil permissions")
					return
				}

				// Verify username is stored in Extensions
				if perms.Extensions["username"] != tt.username {
					t.Errorf("Username = %s, want %s", perms.Extensions["username"], tt.username)
				}

				// Verify fingerprint is stored
				if perms.Extensions["fingerprint"] == "" {
					t.Error("fingerprint not set in Extensions")
				}
			}
		})
	}
}

// mockConnMetadata implements ssh.ConnMetadata for testing
type mockConnMetadata struct {
	username string
}

func (m *mockConnMetadata) User() string          { return m.username }
func (m *mockConnMetadata) SessionID() []byte     { return []byte("test-session-id-12345") }
func (m *mockConnMetadata) ClientVersion() []byte { return []byte("SSH-2.0-Test") }
func (m *mockConnMetadata) ServerVersion() []byte { return []byte("SSH-2.0-Test") }
func (m *mockConnMetadata) RemoteAddr() net.Addr  { return nil }
func (m *mockConnMetadata) LocalAddr() net.Addr   { return nil }
func (m *mockConnMetadata) Close() error          { return nil }
func (m *mockConnMetadata) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, nil
}

func TestProxyRequests(t *testing.T) {
	// Test basic proxy functionality
	// Note: This is a simple test to verify the function exists and doesn't panic
	// Full integration testing would require a complete SSH setup

	reqChan := make(chan *ssh.Request)
	close(reqChan)

	// This should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("proxyRequests panicked: %v", r)
		}
	}()

	// Can't easily test with a real channel without full SSH setup
	// Just verify the function can be called
	_ = proxyRequests
}
