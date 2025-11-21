package informer

import (
	"context"
	"log"
	"time"

	"github.com/zijiren233/sshgate/registry"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Manager manages Kubernetes informers for the gateway
type Manager struct {
	clientset kubernetes.Interface
	registry  *registry.Registry
	factory   informers.SharedInformerFactory
	stopCh    chan struct{}
}

// New creates a new informer manager
func New(clientset kubernetes.Interface, reg *registry.Registry) *Manager {
	return &Manager{
		clientset: clientset,
		registry:  reg,
		stopCh:    make(chan struct{}),
	}
}

// Start initializes and starts all informers
func (m *Manager) Start(ctx context.Context) error {
	// Create informer factory
	m.factory = informers.NewSharedInformerFactory(m.clientset, 30*time.Second)

	// Setup secret informer
	secretInformer := m.factory.Core().V1().Secrets().Informer()
	secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    m.handleSecretAdd,
		UpdateFunc: m.handleSecretUpdate,
		DeleteFunc: m.handleSecretDelete,
	})

	// Setup pod informer
	podInformer := m.factory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    m.handlePodAdd,
		UpdateFunc: m.handlePodUpdate,
		DeleteFunc: m.handlePodDelete,
	})

	// Start informers
	m.factory.Start(ctx.Done())

	// Wait for cache sync
	if !cache.WaitForCacheSync(ctx.Done(), secretInformer.HasSynced, podInformer.HasSynced) {
		return ErrCacheSyncFailed
	}

	log.Println("Informers synced successfully")
	return nil
}

// Stop stops all informers
func (m *Manager) Stop() {
	close(m.stopCh)
}

// Event handlers for secrets
func (m *Manager) handleSecretAdd(obj interface{}) {
	secret := obj.(*corev1.Secret)
	if err := m.registry.AddSecret(secret); err != nil {
		log.Printf("Error adding secret: %v", err)
	}
}

func (m *Manager) handleSecretUpdate(oldObj, newObj interface{}) {
	secret := newObj.(*corev1.Secret)
	if err := m.registry.AddSecret(secret); err != nil {
		log.Printf("Error updating secret: %v", err)
	}
}

func (m *Manager) handleSecretDelete(obj interface{}) {
	secret := obj.(*corev1.Secret)
	m.registry.DeleteSecret(secret)
}

// Event handlers for pods
func (m *Manager) handlePodAdd(obj interface{}) {
	pod := obj.(*corev1.Pod)
	if err := m.registry.UpdatePod(pod); err != nil {
		log.Printf("Error adding pod: %v", err)
	}
}

func (m *Manager) handlePodUpdate(oldObj, newObj interface{}) {
	pod := newObj.(*corev1.Pod)
	if err := m.registry.UpdatePod(pod); err != nil {
		log.Printf("Error updating pod: %v", err)
	}
}

func (m *Manager) handlePodDelete(obj interface{}) {
	pod := obj.(*corev1.Pod)
	m.registry.DeletePod(pod)
}
