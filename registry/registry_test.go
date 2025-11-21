package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func generateTestKeyPair(t *testing.T) (ssh.PublicKey, ssh.Signer, []byte, []byte) {
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

	// Marshal keys for storage in secret
	pubBytes := ssh.MarshalAuthorizedKey(sshPub)

	privPEM, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	privBytes := pem.EncodeToMemory(privPEM)

	return sshPub, sshPriv, pubBytes, privBytes
}

func TestNew(t *testing.T) {
	r := New()
	if r == nil {
		t.Fatal("New() returned nil")
	}
	if r.fingerprintToDevbox == nil {
		t.Error("fingerprintToDevbox map not initialized")
	}
	if r.devboxToInfo == nil {
		t.Error("devboxToInfo map not initialized")
	}
}

func TestAddSecret(t *testing.T) {
	r := New()
	pubKey, _, pubBytes, privBytes := generateTestKeyPair(t)

	tests := []struct {
		name    string
		secret  *corev1.Secret
		wantErr bool
	}{
		{
			name: "valid secret",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
					Labels: map[string]string{
						DevboxPartOfLabel: DevboxPartOfValue,
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind: DevboxOwnerKind,
							Name: "test-devbox",
						},
					},
				},
				Data: map[string][]byte{
					DevboxPublicKeyField:  pubBytes,
					DevboxPrivateKeyField: privBytes,
				},
			},
			wantErr: false,
		},
		{
			name: "secret without devbox label",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "other-secret",
					Namespace: "test-ns",
					Labels:    map[string]string{},
				},
			},
			wantErr: false, // Should skip without error
		},
		{
			name: "secret missing public key",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "bad-secret",
					Namespace: "test-ns",
					Labels: map[string]string{
						DevboxPartOfLabel: DevboxPartOfValue,
					},
				},
				Data: map[string][]byte{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := r.AddSecret(tt.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddSecret() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	// Verify the valid secret was added
	fingerprint := ssh.FingerprintSHA256(pubKey)
	info, ok := r.GetByFingerprint(fingerprint)
	if !ok {
		t.Fatal("Failed to get devbox by fingerprint")
	}
	if info.Namespace != "test-ns" {
		t.Errorf("Namespace = %s, want test-ns", info.Namespace)
	}
	if info.DevboxName != "test-devbox" {
		t.Errorf("DevboxName = %s, want test-devbox", info.DevboxName)
	}
}

func TestDeleteSecret(t *testing.T) {
	r := New()
	_, _, pubBytes, privBytes := generateTestKeyPair(t)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "test-ns",
			Labels: map[string]string{
				DevboxPartOfLabel: DevboxPartOfValue,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: DevboxOwnerKind,
					Name: "test-devbox",
				},
			},
		},
		Data: map[string][]byte{
			DevboxPublicKeyField:  pubBytes,
			DevboxPrivateKeyField: privBytes,
		},
	}

	// Add secret
	if err := r.AddSecret(secret); err != nil {
		t.Fatalf("Failed to add secret: %v", err)
	}

	// Delete secret
	r.DeleteSecret(secret)

	// Verify it's deleted
	pubKey, _, _, _, _ := ssh.ParseAuthorizedKey(pubBytes)
	fingerprint := ssh.FingerprintSHA256(pubKey)
	if _, ok := r.GetByFingerprint(fingerprint); ok {
		t.Error("Secret was not deleted from registry")
	}
}

func TestUpdatePod(t *testing.T) {
	r := New()

	tests := []struct {
		name    string
		pod     *corev1.Pod
		wantErr bool
		wantIP  string
	}{
		{
			name: "valid pod with IP",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "test-ns",
					Labels: map[string]string{
						DevboxPartOfLabel: DevboxPartOfValue,
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind: DevboxOwnerKind,
							Name: "test-devbox",
						},
					},
				},
				Status: corev1.PodStatus{
					PodIP: "10.0.0.1",
				},
			},
			wantErr: false,
			wantIP:  "10.0.0.1",
		},
		{
			name: "pod without IP",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pending-pod",
					Namespace: "test-ns",
					Labels: map[string]string{
						DevboxPartOfLabel: DevboxPartOfValue,
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind: DevboxOwnerKind,
							Name: "pending-devbox",
						},
					},
				},
				Status: corev1.PodStatus{
					PodIP: "",
				},
			},
			wantErr: false,
			wantIP:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := r.UpdatePod(tt.pod)
			if (err != nil) != tt.wantErr {
				t.Errorf("UpdatePod() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantIP != "" {
				key := "test-ns/test-devbox"
				r.mu.RLock()
				info, ok := r.devboxToInfo[key]
				r.mu.RUnlock()

				if !ok {
					t.Error("DevboxInfo not found after UpdatePod")
				} else if info.PodIP != tt.wantIP {
					t.Errorf("PodIP = %s, want %s", info.PodIP, tt.wantIP)
				}
			}
		})
	}
}

func TestGetByFingerprint(t *testing.T) {
	r := New()
	pubKey, _, pubBytes, privBytes := generateTestKeyPair(t)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "test-ns",
			Labels: map[string]string{
				DevboxPartOfLabel: DevboxPartOfValue,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: DevboxOwnerKind,
					Name: "test-devbox",
				},
			},
		},
		Data: map[string][]byte{
			DevboxPublicKeyField:  pubBytes,
			DevboxPrivateKeyField: privBytes,
		},
	}

	if err := r.AddSecret(secret); err != nil {
		t.Fatalf("Failed to add secret: %v", err)
	}

	fingerprint := ssh.FingerprintSHA256(pubKey)

	// Test getting existing fingerprint
	info, ok := r.GetByFingerprint(fingerprint)
	if !ok {
		t.Fatal("GetByFingerprint() returned false for existing fingerprint")
	}
	if info.DevboxName != "test-devbox" {
		t.Errorf("DevboxName = %s, want test-devbox", info.DevboxName)
	}

	// Test getting non-existent fingerprint
	_, ok = r.GetByFingerprint("SHA256:nonexistent")
	if ok {
		t.Error("GetByFingerprint() returned true for non-existent fingerprint")
	}
}

func TestConcurrentAccess(t *testing.T) {
	r := New()
	_, _, pubBytes, privBytes := generateTestKeyPair(t)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "test-ns",
			Labels: map[string]string{
				DevboxPartOfLabel: DevboxPartOfValue,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: DevboxOwnerKind,
					Name: "test-devbox",
				},
			},
		},
		Data: map[string][]byte{
			DevboxPublicKeyField:  pubBytes,
			DevboxPrivateKeyField: privBytes,
		},
	}

	// Concurrent writes
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			r.AddSecret(secret)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Concurrent reads
	pubKey, _, _, _, _ := ssh.ParseAuthorizedKey(pubBytes)
	fingerprint := ssh.FingerprintSHA256(pubKey)

	for i := 0; i < 10; i++ {
		go func() {
			r.GetByFingerprint(fingerprint)
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
