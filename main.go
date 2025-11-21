package main

import (
	"context"
	"log"
	"net"
	"os"

	"github.com/zijiren233/sshgate/gateway"
	"github.com/zijiren233/sshgate/hostkey"
	"github.com/zijiren233/sshgate/informer"
	"github.com/zijiren233/sshgate/registry"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	// Create Kubernetes client
	clientset, err := createKubernetesClient()
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	// Create devbox registry
	reg := registry.New()

	// Setup and start informers
	infMgr := informer.New(clientset, reg)

	ctx := context.Background()
	if err := infMgr.Start(ctx); err != nil {
		log.Fatalf("Failed to start informers: %v", err)
	}

	// Load SSH server host key
	hostKey, err := hostkey.Load()
	if err != nil {
		log.Fatalf("Failed to load host key: %v", err)
	}

	// Create gateway
	gw := gateway.New(hostKey, reg)

	// Start SSH server
	//nolint:noctx
	listener, err := net.Listen("tcp", "0.0.0.0:2222")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("SSH Gateway listening on :2222")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go gw.HandleConnection(conn)
	}
}

// createKubernetesClient creates a Kubernetes clientset
func createKubernetesClient() (*kubernetes.Clientset, error) {
	// Try in-cluster config first
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fallback to kubeconfig
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = os.Getenv("HOME") + "/.kube/config"
		}

		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}
	}

	return kubernetes.NewForConfig(config)
}
