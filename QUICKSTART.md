# Quick Start Guide

## Install SSH Gateway with Helm

### Prerequisites
- Kubernetes cluster
- Helm 3.x installed
- kubectl configured

### Basic Installation

```bash
# Clone the repository
git clone <repository-url>
cd sshgateway

# Install with default settings
helm install sshgate ./chart

# Wait for DaemonSet to be ready
kubectl rollout status daemonset/sshgate

# Get node IPs
kubectl get nodes -o wide
```

### Connect to SSH Gateway

```bash
# Connect to any node's IP address
ssh <username>@<NODE_IP> -p 2222 -i ~/.ssh/your_private_key

# Example
ssh devbox@192.168.1.10 -p 2222 -i ~/.ssh/id_rsa
```

The gateway will automatically route you to your devbox based on your SSH key fingerprint.

### View Generated Seed

```bash
# Check the auto-generated SSH host key seed
kubectl get configmap sshgate -o jsonpath='{.data.SSH_HOST_KEY_SEED}'
```

### Custom Configuration

```bash
# Use custom SSH port
helm install sshgate ./chart --set sshPort=22

# Set custom seed
helm install sshgate ./chart --set sshHostKeySeed="my-secure-seed"

# Deploy only on specific nodes
helm install sshgate ./chart --set nodeSelector.role=gateway

# Add custom environment variables
helm install sshgate ./chart --set env.LOG_LEVEL=debug
```

### Using Values File

```bash
# Use the example configuration
cp chart/values-example.yaml my-values.yaml

# Edit as needed
vim my-values.yaml

# Install with custom values
helm install sshgate ./chart -f my-values.yaml
```

### Uninstall

```bash
helm uninstall sshgate
```

## Next Steps

- Read the full [README.md](README.md) for detailed configuration options
- Check [chart/README.md](chart/README.md) for Helm-specific documentation
- See [chart/FEATURES.md](chart/FEATURES.md) for feature overview
- Review [chart/examples/](chart/examples/) for more examples

## Troubleshooting

### Check Pod Status
```bash
kubectl get pods -l app.kubernetes.io/name=sshgate
kubectl logs -l app.kubernetes.io/name=sshgate
```

### Check ConfigMap
```bash
kubectl get configmap sshgate -o yaml
```

### Test Connectivity
```bash
# Test SSH connection to node
telnet <NODE_IP> 2222
```

### Common Issues

1. **Port already in use**: Change `sshPort` to a different port
2. **Pods not running on desired nodes**: Check `nodeSelector` and `tolerations`
3. **Permission issues**: Verify RBAC resources are created (`rbac.create=true`)
