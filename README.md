# SSH Gateway for Sealos Devbox

A Kubernetes-native SSH gateway that routes SSH connections to Devbox pods based on client public key fingerprints.

## Features

- **Client-go Informers**: Watches Kubernetes Secrets and Pods in real-time
- **Fingerprint-based Routing**: Routes connections based on SSH public key SHA256 fingerprints
- **Multi-replica Support**: Consistent host keys across all replicas using deterministic generation
- **Zero-downtime Updates**: Informers automatically sync changes
- **Username Flexibility**: Accepts any SSH username - no restrictions
- **Modular Architecture**: Well-structured internal packages with comprehensive unit tests

## Architecture

```
User (ssh <any-username>@gateway -i ~/.ssh/key)
    ↓
SSH Gateway (fingerprint matching)
    ↓
Registry (informer cache)
    ↓
Backend Devbox Pod (via Pod IP)
```

## Host Key Management

The gateway uses deterministic key generation from a seed string. All replicas with the same seed will generate identical host keys, ensuring clients don't see "host key changed" warnings.

### Configuration

When deploying with Helm, if you don't specify `sshHostKeySeed`, a random 32-character seed will be automatically generated on first install and stored in the ConfigMap. This seed is preserved during upgrades.

```bash
# Option 1: Use auto-generated random seed (recommended)
helm install sshgate ./chart

# Option 2: Set a custom seed
helm install sshgate ./chart --set sshHostKeySeed="my-custom-seed"

# Option 3: For manual deployment
export SSH_HOST_KEY_SEED="my-custom-seed"
```

### How It Works

1. The gateway takes the seed string
2. Computes SHA256(seed) to get a 32-byte hash
3. Uses the hash as the ed25519 private key seed
4. All replicas with the same seed generate the same key pair

**⚠️ Security Note**: If you use a custom seed, keep it secure. Anyone with the seed can regenerate the private key.

## Building

```bash
# Build the gateway
go build -o sshgate .

# Build the key generator
go build -o genkey ./cmd/genkey

# Run tests
go test ./internal/... -v

# Generate coverage report
go test ./internal/... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## Test Coverage

- **hostkey**: 93.8%
- **registry**: 78.7%
- **informer**: 75.0%
- **gateway**: 17.5% (connection handling tested via integration)
- **Overall**: 66.2%

## Configuration

### Environment Variables

**Kubernetes access** (automatically available in-cluster):
- `KUBECONFIG`: Path to kubeconfig file (optional, for out-of-cluster testing)

**Host key generation**:
- `SSH_HOST_KEY_SEED`: Seed string for deterministic key generation (default: `sealos-devbox`)

### Kubernetes Resources

The gateway watches for:

**Secrets** with:
- Label: `app.kubernetes.io/part-of: devbox`
- Data fields:
  - `SEALOS_DEVBOX_PUBLIC_KEY`: User's public key (base64)
  - `SEALOS_DEVBOX_PRIVATE_KEY`: Devbox's private key (base64)
- OwnerReference: Points to Devbox CR

**Pods** with:
- Label: `app.kubernetes.io/part-of: devbox`
- OwnerReference: Points to Devbox CR
- Status: Must have PodIP assigned

## Deployment

### Helm Chart (Recommended)

The SSH Gateway is deployed as a **DaemonSet with hostNetwork**, which means:
- One pod runs on each node in the cluster
- Pods use the host's network directly (no Service needed)
- SSH is accessible on each node's IP address

Install the SSH Gateway using Helm:

```bash
# Install with default values (SSH port 2222 on all nodes)
helm install sshgate ./chart

# Or customize with your own values
helm install sshgate ./chart \
  --set sshPort=2222 \
  --set sshHostKeySeed="my-custom-seed"

# Install in a specific namespace
helm install sshgate ./chart -n devbox --create-namespace

# Install only on specific nodes (e.g., gateway nodes)
helm install sshgate ./chart \
  --set nodeSelector.role=gateway
```

After installation, connect to any node's IP address on the configured SSH port.

#### Configuration

Key configuration options in `values.yaml`:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `sshPort` | SSH port exposed on host | `2222` |
| `sshHostKeySeed` | Seed for deterministic host key generation (auto-generated if empty) | `""` (random) |
| `env` | Additional environment variables (ConfigMap) | `{}` |
| `image.repository` | Image repository | `ghcr.io/zijiren233/sshgate` |
| `image.tag` | Image tag | `latest` |
| `rbac.create` | Create RBAC resources | `true` |
| `serviceAccount.create` | Create service account | `true` |
| `nodeSelector` | Node labels for pod assignment | `{}` |
| `tolerations` | Tolerations for pod assignment | `[]` |
| `updateStrategy.type` | DaemonSet update strategy | `RollingUpdate` |
| `updateStrategy.rollingUpdate.maxUnavailable` | Max unavailable during updates | `1` |

#### Common Configurations

**Run only on specific nodes:**
```yaml
nodeSelector:
  role: gateway
```

**Run on master nodes:**
```yaml
tolerations:
- key: node-role.kubernetes.io/master
  effect: NoSchedule
```

**Use a different SSH port:**
```yaml
sshPort: 2222
```

**Add custom environment variables:**
```yaml
env:
  LOG_LEVEL: "debug"
  CUSTOM_VAR: "value"
```

#### Upgrade

```bash
# Upgrade to a new version
helm upgrade sshgate ./chart

# Upgrade with new values
helm upgrade sshgate ./chart --set sshPort=2222
```

#### Uninstall

```bash
helm uninstall sshgate
```

## Usage

### For End Users

Since the gateway uses hostNetwork, connect to any node's IP address:

```bash
# Get node IP addresses
kubectl get nodes -o wide

# Connect to your devbox with any username via a node IP
ssh myusername@<NODE_IP> -i ~/.ssh/your_private_key

# If using a custom SSH port (e.g., 2222)
ssh myusername@<NODE_IP> -p 2222 -i ~/.ssh/your_private_key

# The gateway automatically routes you based on your SSH key fingerprint
```

Example:

```bash
# Connect to node 192.168.1.10 on default port 22
ssh devbox@192.168.1.10 -i ~/.ssh/id_rsa

# Connect to node 192.168.1.10 on custom port 2222
ssh devbox@192.168.1.10 -p 2222 -i ~/.ssh/id_rsa
```

### How It Works

1. User connects with `ssh <username>@gateway` (username can be anything)
2. Gateway calculates the SHA256 fingerprint of the user's public key
3. Gateway looks up the fingerprint in the registry (populated by informers)
4. Gateway finds the corresponding Devbox and Pod IP
5. Username is logged and stored in connection metadata
6. Gateway connects to the backend pod using the devbox's private key
7. All SSH traffic is proxied bidirectionally

## Troubleshooting

### Multiple replicas show different host keys

This should not happen with the default configuration. All replicas use the same seed (`sealos-devbox` by default), so they generate the same host key. If you see different keys, ensure the `SSH_HOST_KEY_SEED` environment variable is consistent across all replicas.

## License

MIT
