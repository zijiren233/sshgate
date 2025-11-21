package hostkey

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh"
)

// Load loads or generates a deterministic SSH host key based on SSH_HOST_KEY_SEED
func Load() (ssh.Signer, error) {
	// Generate a deterministic key based on SSH_HOST_KEY_SEED
	// This ensures multiple replicas generate the same key
	seed := os.Getenv("SSH_HOST_KEY_SEED")
	if seed == "" {
		seed = "sealos-devbox"

		log.Println("Using default SSH_HOST_KEY_SEED: sealos-devbox")
	}

	log.Println("Generating deterministic host key from SSH_HOST_KEY_SEED")

	return GenerateDeterministicKey(seed)
}

// GenerateDeterministicKey generates a deterministic ed25519 key from a seed string
func GenerateDeterministicKey(seed string) (ssh.Signer, error) {
	// Use SHA256 of seed as the ed25519 seed (32 bytes)
	hash := sha256.Sum256([]byte(seed))

	// Generate ed25519 key from seed
	privateKey := ed25519.NewKeyFromSeed(hash[:])

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	// Log the public key fingerprint for verification
	publicKey := signer.PublicKey()
	fingerprint := ssh.FingerprintSHA256(publicKey)
	log.Printf("Host key fingerprint: %s", fingerprint)

	return signer, nil
}

// GetFingerprint returns the SHA256 fingerprint of the host key
func GetFingerprint(signer ssh.Signer) string {
	return ssh.FingerprintSHA256(signer.PublicKey())
}
