package main

import (
	"context"
	"log"
	"net"
	"os"

	"github.com/zijiren233/sshgate/config"
	"github.com/zijiren233/sshgate/gateway"
	"github.com/zijiren233/sshgate/hostkey"
	"github.com/zijiren233/sshgate/informer"
	"github.com/zijiren233/sshgate/logger"
	"github.com/zijiren233/sshgate/pprof"
	"github.com/zijiren233/sshgate/registry"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger with configuration
	logger.InitLog(
		logger.WithDebug(cfg.Debug),
		logger.WithLevel(cfg.LogLevel),
		logger.WithFormat(cfg.LogFormat),
	)

	// Start pprof server if enabled
	if cfg.PprofEnabled {
		go func() {
			_ = pprof.RunPprofServer(cfg.PprofPort)
		}()
	}

	// Create Kubernetes client
	clientset, err := createKubernetesClient()
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	// Create devbox registry
	reg := registry.New()

	// Setup and start informers
	infMgr := informer.New(clientset, reg,
		informer.WithResyncPeriod(cfg.InformerResyncPeriod),
	)

	ctx := context.Background()
	if err := infMgr.Start(ctx); err != nil {
		log.Fatalf("Failed to start informers: %v", err)
	}

	// Load SSH server host key
	hostKey, err := hostkey.Load(cfg.SSHHostKeySeed)
	if err != nil {
		log.Fatalf("Failed to load host key: %v", err)
	}

	// Create gateway with embedded options
	gw := gateway.New(hostKey, reg, gateway.WithOptions(cfg.Gateway))

	// Start SSH server
	//nolint:noctx
	listener, err := net.Listen("tcp", cfg.SSHListenAddr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("SSH Gateway listening on %s", cfg.SSHListenAddr)

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
