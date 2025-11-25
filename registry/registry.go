package registry

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// DevboxPublicKeyField is the secret data field containing the public key
	DevboxPublicKeyField = "SEALOS_DEVBOX_PUBLIC_KEY"
	// DevboxPrivateKeyField is the secret data field containing the private key
	DevboxPrivateKeyField = "SEALOS_DEVBOX_PRIVATE_KEY"
	// DevboxPartOfLabel is the label key for identifying devbox resources
	DevboxPartOfLabel = "app.kubernetes.io/part-of"
	// DevboxPartOfValue is the expected label value for devbox resources
	DevboxPartOfValue = "devbox"
	// DevboxOwnerKind is the owner reference kind for devbox resources
	DevboxOwnerKind = "Devbox"
)

// DevboxInfo stores information about a devbox
type DevboxInfo struct {
	Namespace   string
	DevboxName  string
	PodIP       string
	PublicKey   ssh.PublicKey
	PrivateKey  ssh.Signer
	Fingerprint string
}

// Registry manages the mapping between SSH key fingerprints and devbox pods
type Registry struct {
	mu sync.RWMutex
	// fingerprint -> DevboxInfo
	fingerprintToDevbox map[string]*DevboxInfo
	// namespace/devboxName -> DevboxInfo
	devboxToInfo map[string]*DevboxInfo
	logger       *log.Entry
}

// New creates a new Registry instance
func New() *Registry {
	return &Registry{
		fingerprintToDevbox: make(map[string]*DevboxInfo),
		devboxToInfo:        make(map[string]*DevboxInfo),
		logger:              log.WithField("component", "registry"),
	}
}

// AddSecret processes a Secret and adds it to the registry
func (r *Registry) AddSecret(secret *corev1.Secret) error {
	// Check if this is a devbox secret
	if secret.Labels[DevboxPartOfLabel] != DevboxPartOfValue {
		return nil
	}

	// Get public key from secret
	publicKeyData, ok := secret.Data[DevboxPublicKeyField]
	if !ok {
		return fmt.Errorf(
			"secret %s/%s missing %s",
			secret.Namespace,
			secret.Name,
			DevboxPublicKeyField,
		)
	}

	// Parse public key
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(publicKeyData)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// Calculate fingerprint
	fingerprint := ssh.FingerprintSHA256(publicKey)

	// Get devbox name from ownerReferences
	devboxName := getDevboxNameFromOwnerReferences(secret.OwnerReferences)
	if devboxName == "" {
		return fmt.Errorf("secret %s/%s has no Devbox owner", secret.Namespace, secret.Name)
	}

	// Parse private key if available
	var privateKey ssh.Signer
	if privateKeyData, ok := secret.Data[DevboxPrivateKeyField]; ok {
		privateKey, err = ssh.ParsePrivateKey(privateKeyData)
		if err != nil {
			r.logger.WithFields(log.Fields{
				"namespace": secret.Namespace,
				"devbox":    devboxName,
			}).WithError(err).Warn("Failed to parse private key")
		}
	}

	key := fmt.Sprintf("%s/%s", secret.Namespace, devboxName)

	r.logger.WithFields(log.Fields{
		"namespace":   secret.Namespace,
		"devbox":      devboxName,
		"fingerprint": fingerprint,
	}).Info("Adding secret")

	r.mu.Lock()
	defer r.mu.Unlock()

	info, exists := r.devboxToInfo[key]
	if !exists {
		info = &DevboxInfo{
			Namespace:  secret.Namespace,
			DevboxName: devboxName,
		}
		r.devboxToInfo[key] = info
	}

	info.PublicKey = publicKey
	info.PrivateKey = privateKey
	info.Fingerprint = fingerprint
	r.fingerprintToDevbox[fingerprint] = info

	return nil
}

// DeleteSecret removes a Secret from the registry
func (r *Registry) DeleteSecret(secret *corev1.Secret) {
	devboxName := getDevboxNameFromOwnerReferences(secret.OwnerReferences)
	if devboxName == "" {
		return
	}

	key := fmt.Sprintf("%s/%s", secret.Namespace, devboxName)
	r.logger.WithFields(log.Fields{
		"namespace": secret.Namespace,
		"devbox":    devboxName,
	}).Info("Removing secret")

	r.mu.Lock()
	defer r.mu.Unlock()

	if info, ok := r.devboxToInfo[key]; ok {
		delete(r.fingerprintToDevbox, info.Fingerprint)
		delete(r.devboxToInfo, key)
	}
}

// UpdatePod updates the pod IP for a devbox
func (r *Registry) UpdatePod(pod *corev1.Pod) error {
	// Check if this is a devbox pod
	if pod.Labels[DevboxPartOfLabel] != DevboxPartOfValue {
		return nil
	}

	// Get devbox name from ownerReferences
	devboxName := getDevboxNameFromOwnerReferences(pod.OwnerReferences)
	if devboxName == "" {
		return fmt.Errorf("pod %s/%s has no Devbox owner", pod.Namespace, pod.Name)
	}

	// Get pod IP
	if pod.Status.PodIP == "" {
		return nil // Pod not ready yet
	}

	key := fmt.Sprintf("%s/%s", pod.Namespace, devboxName)
	r.logger.WithFields(log.Fields{
		"namespace": pod.Namespace,
		"devbox":    devboxName,
		"pod_ip":    pod.Status.PodIP,
	}).Info("Updating pod IP")

	r.mu.Lock()
	defer r.mu.Unlock()

	info, exists := r.devboxToInfo[key]
	if !exists {
		info = &DevboxInfo{
			Namespace:  pod.Namespace,
			DevboxName: devboxName,
		}
		r.devboxToInfo[key] = info
	}

	info.PodIP = pod.Status.PodIP

	return nil
}

// DeletePod removes a pod from the registry
func (r *Registry) DeletePod(pod *corev1.Pod) {
	devboxName := getDevboxNameFromOwnerReferences(pod.OwnerReferences)
	if devboxName == "" {
		return
	}

	key := fmt.Sprintf("%s/%s", pod.Namespace, devboxName)
	r.logger.WithFields(log.Fields{
		"namespace": pod.Namespace,
		"devbox":    devboxName,
	}).Info("Removing pod IP")

	r.mu.Lock()
	defer r.mu.Unlock()

	if info, ok := r.devboxToInfo[key]; ok {
		info.PodIP = ""
	}
}

// GetByFingerprint retrieves DevboxInfo by SSH key fingerprint
func (r *Registry) GetByFingerprint(fingerprint string) (*DevboxInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	info, ok := r.fingerprintToDevbox[fingerprint]

	return info, ok
}

// GetDevboxInfo retrieves DevboxInfo by namespace and devbox name
func (r *Registry) GetDevboxInfo(namespace, devboxName string) (*DevboxInfo, bool) {
	key := fmt.Sprintf("%s/%s", namespace, devboxName)

	r.mu.RLock()
	defer r.mu.RUnlock()

	info, ok := r.devboxToInfo[key]

	return info, ok
}

func getDevboxNameFromOwnerReferences(refs []metav1.OwnerReference) string {
	for _, ref := range refs {
		if ref.Kind == DevboxOwnerKind {
			return ref.Name
		}
	}

	return ""
}
