# 🚀 HackAI Container & Kubernetes Deployment

A comprehensive, production-ready container orchestration and Kubernetes deployment system for the HackAI platform with advanced security, monitoring, and automation capabilities.

## 🏗️ Architecture Overview

The HackAI Container & Kubernetes Deployment system provides:

- **Multi-Stage Docker Builds**: Optimized container images with security scanning
- **Advanced Kubernetes Manifests**: Production-ready deployments with security policies
- **Container Orchestration**: Automated deployment, scaling, and management
- **Development Environment**: Docker Compose setup for local development
- **Monitoring Integration**: Prometheus, Grafana, Jaeger, and Loki
- **Security Hardening**: Pod Security Standards, Network Policies, RBAC
- **CI/CD Ready**: GitOps integration with ArgoCD and Flux support
- **Multi-Environment**: Development, staging, and production configurations

## 📁 Directory Structure

```
deployments/
├── docker/
│   ├── Dockerfile.multi-stage      # Multi-stage production Dockerfile
│   ├── docker-compose.dev.yml      # Development environment
│   ├── docker-compose.prod.yml     # Production environment
│   ├── .dockerignore               # Docker ignore patterns
│   └── init-scripts/               # Database initialization
├── kubernetes/
│   ├── enhanced/                   # Enhanced K8s manifests
│   │   ├── api-gateway-deployment.yaml
│   │   ├── threat-service-deployment.yaml
│   │   ├── security-policies.yaml
│   │   └── monitoring-stack.yaml
│   ├── base/                       # Base K8s manifests
│   ├── overlays/                   # Kustomize overlays
│   │   ├── development/
│   │   ├── staging/
│   │   └── production/
│   └── istio/                      # Service mesh configuration
├── helm/
│   └── hackai/                     # Helm chart
│       ├── Chart.yaml
│       ├── values.yaml
│       ├── values-dev.yaml
│       ├── values-staging.yaml
│       ├── values-production.yaml
│       └── templates/
└── monitoring/                     # Monitoring configurations
    ├── prometheus/
    ├── grafana/
    ├── jaeger/
    └── loki/
```

## 🚀 Quick Start

### Prerequisites

1. **Container Runtime**:
   ```bash
   # Install Docker
   curl -fsSL https://get.docker.com | sh
   sudo usermod -aG docker $USER
   ```

2. **Kubernetes Tools**:
   ```bash
   # Install kubectl
   curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
   sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
   
   # Install Helm
   curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
   ```

3. **Development Tools**:
   ```bash
   # Install Docker Compose
   sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
   sudo chmod +x /usr/local/bin/docker-compose
   ```

### Development Environment

#### Option 1: Docker Compose (Recommended for Development)

```bash
# Start development environment
cd deployments/docker
docker-compose -f docker-compose.dev.yml up -d

# View logs
docker-compose -f docker-compose.dev.yml logs -f

# Stop environment
docker-compose -f docker-compose.dev.yml down
```

#### Option 2: Container Orchestrator Script

```bash
# Build and deploy to development
./scripts/container-orchestrator.sh deploy --environment development

# Build images only
./scripts/container-orchestrator.sh build

# Scale a service
./scripts/container-orchestrator.sh scale threat-service 3

# View status
./scripts/container-orchestrator.sh status

# View logs
./scripts/container-orchestrator.sh logs api-gateway

# Port forward for debugging
./scripts/container-orchestrator.sh port-forward api-gateway 8080:8080
```

### Production Deployment

#### Option 1: Helm Deployment (Recommended)

```bash
# Deploy with Helm
./scripts/container-orchestrator.sh deploy \
  --environment production \
  --deploy-method helm \
  --enable-monitoring \
  --enable-security \
  --push-images

# Upgrade deployment
helm upgrade hackai ./deployments/helm/hackai \
  --namespace hackai \
  --values ./deployments/helm/hackai/values-production.yaml
```

#### Option 2: kubectl Deployment

```bash
# Deploy with kubectl
./scripts/container-orchestrator.sh deploy \
  --environment production \
  --deploy-method kubectl \
  --namespace hackai-prod

# Apply enhanced manifests
kubectl apply -f deployments/kubernetes/enhanced/ -n hackai-prod
```

#### Option 3: Kustomize Deployment

```bash
# Deploy with Kustomize
kubectl apply -k deployments/kubernetes/overlays/production
```

## 🐳 Container Features

### Multi-Stage Docker Builds

The `Dockerfile.multi-stage` provides multiple build targets:

- **`runtime`**: Minimal production image (scratch-based)
- **`distroless`**: Distroless base for enhanced security
- **`alpine-runtime`**: Alpine-based with debugging tools
- **`development`**: Full development environment with hot reload
- **`debug`**: Debug-enabled image with delve
- **`testing`**: Testing environment with coverage tools

```bash
# Build production image
docker build --target runtime -t hackai/api-gateway:latest .

# Build development image
docker build --target development -t hackai/api-gateway:dev .

# Build debug image
docker build --target debug -t hackai/api-gateway:debug .
```

### Security Features

- **Non-root execution**: All containers run as non-root users
- **Read-only root filesystem**: Enhanced security posture
- **Minimal attack surface**: Distroless and scratch-based images
- **Security scanning**: Integrated Trivy vulnerability scanning
- **Secrets management**: Kubernetes secrets integration

### Performance Optimization

- **Multi-architecture builds**: AMD64 and ARM64 support
- **Build caching**: Docker layer caching for faster builds
- **Parallel builds**: Concurrent image building
- **Image optimization**: Minimal image sizes (<100MB)

## ☸️ Kubernetes Features

### Advanced Deployments

- **Rolling Updates**: Zero-downtime deployments
- **Health Checks**: Comprehensive liveness, readiness, and startup probes
- **Resource Management**: CPU and memory limits/requests
- **Auto-scaling**: Horizontal Pod Autoscaler (HPA)
- **Pod Disruption Budgets**: High availability guarantees
- **Affinity Rules**: Optimal pod placement

### Security Hardening

- **Pod Security Standards**: Restricted security context
- **Network Policies**: Micro-segmentation and traffic control
- **RBAC**: Role-based access control
- **Service Accounts**: Least privilege principle
- **Secrets Management**: Encrypted secrets storage
- **Security Contexts**: Non-root, read-only filesystem

### Monitoring & Observability

- **Prometheus**: Metrics collection and alerting
- **Grafana**: Visualization and dashboards
- **Jaeger**: Distributed tracing
- **Loki**: Log aggregation
- **Service Mesh**: Istio integration for advanced networking

## 🔧 Configuration Management

### Environment-Specific Configurations

```yaml
# Development
environment: development
replicas: 1
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi

# Production
environment: production
replicas: 3
resources:
  requests:
    cpu: 200m
    memory: 256Mi
  limits:
    cpu: 1000m
    memory: 1Gi
```

### ConfigMaps and Secrets

```bash
# Create configuration
kubectl create configmap hackai-config \
  --from-file=config.yaml \
  --namespace hackai

# Create secrets
kubectl create secret generic hackai-secrets \
  --from-literal=db-password=secretpassword \
  --from-literal=jwt-secret=jwtsecretkey \
  --namespace hackai
```

## 📊 Monitoring & Alerting

### Prometheus Metrics

- **Application Metrics**: Request rates, error rates, latency
- **Infrastructure Metrics**: CPU, memory, disk, network
- **Business Metrics**: User registrations, scans performed
- **Custom Metrics**: Threat detections, vulnerability counts

### Grafana Dashboards

- **Infrastructure Overview**: Cluster health and resource usage
- **Application Performance**: Service-level metrics
- **Security Dashboard**: Threat detection and security events
- **Business Intelligence**: User activity and system usage

### Alerting Rules

```yaml
# High error rate alert
- alert: HighErrorRate
  expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "High error rate detected"

# High memory usage alert
- alert: HighMemoryUsage
  expr: container_memory_usage_bytes / container_spec_memory_limit_bytes > 0.9
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "High memory usage detected"
```

## 🧪 Testing & Validation

### Automated Testing

```bash
# Run comprehensive tests
./scripts/container-test.sh

# Test specific components
./scripts/container-test.sh --test-suite docker
./scripts/container-test.sh --test-suite kubernetes
./scripts/container-test.sh --test-suite security
```

### Test Coverage

- **Docker Build Tests**: Image building and optimization
- **Security Tests**: Vulnerability scanning and compliance
- **Kubernetes Tests**: Manifest validation and deployment
- **Integration Tests**: Service communication and health
- **Performance Tests**: Startup time and resource usage
- **Helm Tests**: Chart validation and rendering

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Container Build and Deploy
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Build and test containers
      run: ./scripts/container-orchestrator.sh build --push-images
    - name: Run tests
      run: ./scripts/container-test.sh
```

### GitOps with ArgoCD

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: hackai
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/dimajoyti/hackai
    targetRevision: HEAD
    path: deployments/kubernetes/overlays/production
  destination:
    server: https://kubernetes.default.svc
    namespace: hackai
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

## 🚀 Deployment Strategies

### Blue-Green Deployment

```bash
# Deploy to blue environment
kubectl apply -f deployments/kubernetes/overlays/blue -n hackai-blue

# Test blue environment
./scripts/container-test.sh --namespace hackai-blue

# Switch traffic to blue
kubectl patch service api-gateway -p '{"spec":{"selector":{"version":"blue"}}}'

# Cleanup green environment
kubectl delete namespace hackai-green
```

### Canary Deployment

```bash
# Deploy canary version
helm upgrade hackai ./deployments/helm/hackai \
  --set canary.enabled=true \
  --set canary.weight=10 \
  --namespace hackai

# Monitor canary metrics
kubectl get canary hackai -n hackai

# Promote canary
kubectl patch canary hackai -p '{"spec":{"analysis":{"threshold":5}}}'
```

## 🔧 Troubleshooting

### Common Issues

1. **Pod CrashLoopBackOff**:
   ```bash
   kubectl logs <pod-name> -n hackai --previous
   kubectl describe pod <pod-name> -n hackai
   ```

2. **Service Not Accessible**:
   ```bash
   kubectl get endpoints <service-name> -n hackai
   kubectl port-forward service/<service-name> 8080:80 -n hackai
   ```

3. **High Resource Usage**:
   ```bash
   kubectl top pods -n hackai
   kubectl describe hpa -n hackai
   ```

### Debug Commands

```bash
# Get cluster information
kubectl cluster-info

# Check node status
kubectl get nodes -o wide

# View events
kubectl get events -n hackai --sort-by='.lastTimestamp'

# Debug networking
kubectl run debug --image=nicolaka/netshoot -it --rm -- /bin/bash
```

## 📚 Documentation

- [Container Security Guide](./docs/security.md)
- [Kubernetes Best Practices](./docs/kubernetes.md)
- [Monitoring Setup](./docs/monitoring.md)
- [Troubleshooting Guide](./docs/troubleshooting.md)
- [Performance Tuning](./docs/performance.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

---

**🎉 Ready for Production!** The HackAI Container & Kubernetes Deployment system is now fully configured and ready for enterprise-scale deployments with comprehensive security, monitoring, and automation capabilities.
