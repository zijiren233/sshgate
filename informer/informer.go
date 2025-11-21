package informer

import (
	"context"
	"fmt"
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

	_, err := secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    m.handleSecretAdd,
		UpdateFunc: m.handleSecretUpdate,
		DeleteFunc: m.handleSecretDelete,
	})
	if err != nil {
		return err
	}

	// Setup pod informer
	podInformer := m.factory.Core().V1().Pods().Informer()

	_, err = podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    m.handlePodAdd,
		UpdateFunc: m.handlePodUpdate,
		DeleteFunc: m.handlePodDelete,
	})
	if err != nil {
		return err
	}

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

// IsStarted returns true if the manager has been started and factory is initialized
func (m *Manager) IsStarted() bool {
	return m.factory != nil
}

// IsStopped returns true if the stop channel has been closed
func (m *Manager) IsStopped() bool {
	select {
	case <-m.stopCh:
		return true
	default:
		return false
	}
}

// ProcessSecret processes a secret (for testing)
func (m *Manager) ProcessSecret(secret *corev1.Secret, action string) error {
	switch action {
	case "add":
		m.handleSecretAdd(secret)
	case "update":
		m.handleSecretUpdate(nil, secret)
	case "delete":
		m.handleSecretDelete(secret)
	default:
		return fmt.Errorf("unknown action: %s", action)
	}

	return nil
}

// ProcessPod processes a pod (for testing)
func (m *Manager) ProcessPod(pod *corev1.Pod, action string) error {
	switch action {
	case "add":
		m.handlePodAdd(pod)
	case "update":
		m.handlePodUpdate(nil, pod)
	case "delete":
		m.handlePodDelete(pod)
	default:
		return fmt.Errorf("unknown action: %s", action)
	}

	return nil
}

// Event handlers for secrets
func (m *Manager) handleSecretAdd(obj any) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		log.Printf("Error: expected *corev1.Secret, got %T", obj)
		return
	}

	if err := m.registry.AddSecret(secret); err != nil {
		log.Printf("Error adding secret: %v", err)
	}
}

func (m *Manager) handleSecretUpdate(oldObj, newObj any) {
	secret, ok := newObj.(*corev1.Secret)
	if !ok {
		log.Printf("Error: expected *corev1.Secret, got %T", newObj)
		return
	}

	if err := m.registry.AddSecret(secret); err != nil {
		log.Printf("Error updating secret: %v", err)
	}
}

func (m *Manager) handleSecretDelete(obj any) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		log.Printf("Error: expected *corev1.Secret, got %T", obj)
		return
	}

	m.registry.DeleteSecret(secret)
}

// Event handlers for pods
func (m *Manager) handlePodAdd(obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		log.Printf("Error: expected *corev1.Pod, got %T", obj)
		return
	}

	if err := m.registry.UpdatePod(pod); err != nil {
		log.Printf("Error adding pod: %v", err)
	}
}

func (m *Manager) handlePodUpdate(oldObj, newObj any) {
	pod, ok := newObj.(*corev1.Pod)
	if !ok {
		log.Printf("Error: expected *corev1.Pod, got %T", newObj)
		return
	}

	if err := m.registry.UpdatePod(pod); err != nil {
		log.Printf("Error updating pod: %v", err)
	}
}

func (m *Manager) handlePodDelete(obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		log.Printf("Error: expected *corev1.Pod, got %T", obj)
		return
	}

	m.registry.DeletePod(pod)
}
