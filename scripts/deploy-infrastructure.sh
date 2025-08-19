#!/bin/bash

# HackAI Infrastructure Deployment Script
# This script automates the deployment of the complete HackAI infrastructure

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENVIRONMENT="${ENVIRONMENT:-production}"
NAMESPACE="${NAMESPACE:-hackai-${ENVIRONMENT}}"
HELM_RELEASE="${HELM_RELEASE:-hackai-${ENVIRONMENT}}"
KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing_tools=()
    
    # Check required tools
    for tool in kubectl helm docker; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Please install the missing tools and try again."
        exit 1
    fi
    
    # Check Kubernetes connection
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster. Please check your kubeconfig."
        exit 1
    fi
    
    # Check Helm
    if ! helm version &> /dev/null; then
        log_error "Helm is not properly configured."
        exit 1
    fi
    
    log_success "All prerequisites met"
}

# Create namespace
create_namespace() {
    log_info "Creating namespace: $NAMESPACE"
    
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_warning "Namespace $NAMESPACE already exists"
    else
        kubectl create namespace "$NAMESPACE"
        log_success "Namespace $NAMESPACE created"
    fi
    
    # Label namespace for monitoring
    kubectl label namespace "$NAMESPACE" monitoring=enabled --overwrite
    kubectl label namespace "$NAMESPACE" environment="$ENVIRONMENT" --overwrite
}

# Deploy monitoring stack
deploy_monitoring() {
    log_info "Deploying monitoring stack..."
    
    # Add Prometheus Helm repository
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo add grafana https://grafana.github.io/helm-charts
    helm repo update
    
    # Deploy Prometheus
    log_info "Deploying Prometheus..."
    helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
        --namespace "$NAMESPACE" \
        --create-namespace \
        --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
        --set prometheus.prometheusSpec.podMonitorSelectorNilUsesHelmValues=false \
        --set prometheus.prometheusSpec.ruleSelectorNilUsesHelmValues=false \
        --set prometheus.prometheusSpec.retention=30d \
        --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.resources.requests.storage=50Gi \
        --set grafana.adminPassword=admin \
        --set grafana.persistence.enabled=true \
        --set grafana.persistence.size=10Gi \
        --wait --timeout=10m
    
    log_success "Monitoring stack deployed"
}

# Deploy secrets
deploy_secrets() {
    log_info "Deploying secrets..."
    
    # Create database secret
    kubectl create secret generic hackai-db-secret \
        --namespace="$NAMESPACE" \
        --from-literal=username=hackai \
        --from-literal=password="$(openssl rand -base64 32)" \
        --from-literal=database=hackai \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Create JWT secret
    kubectl create secret generic hackai-jwt-secret \
        --namespace="$NAMESPACE" \
        --from-literal=secret="$(openssl rand -base64 64)" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Create API keys secret
    kubectl create secret generic hackai-api-keys \
        --namespace="$NAMESPACE" \
        --from-literal=mitre-api-key="${MITRE_API_KEY:-}" \
        --from-literal=cve-api-key="${CVE_API_KEY:-}" \
        --from-literal=openai-api-key="${OPENAI_API_KEY:-}" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    log_success "Secrets deployed"
}

# Deploy database
deploy_database() {
    log_info "Deploying PostgreSQL database..."
    
    helm repo add bitnami https://charts.bitnami.com/bitnami
    helm repo update
    
    helm upgrade --install postgresql bitnami/postgresql \
        --namespace "$NAMESPACE" \
        --set auth.existingSecret=hackai-db-secret \
        --set auth.secretKeys.adminPasswordKey=password \
        --set auth.secretKeys.userPasswordKey=password \
        --set auth.secretKeys.replicationPasswordKey=password \
        --set primary.persistence.enabled=true \
        --set primary.persistence.size=100Gi \
        --set primary.resources.requests.memory=1Gi \
        --set primary.resources.requests.cpu=500m \
        --set primary.resources.limits.memory=2Gi \
        --set primary.resources.limits.cpu=1000m \
        --set metrics.enabled=true \
        --set metrics.serviceMonitor.enabled=true \
        --wait --timeout=10m
    
    # Deploy Redis
    log_info "Deploying Redis..."
    helm upgrade --install redis bitnami/redis \
        --namespace "$NAMESPACE" \
        --set auth.enabled=true \
        --set auth.password="$(openssl rand -base64 32)" \
        --set master.persistence.enabled=true \
        --set master.persistence.size=20Gi \
        --set replica.replicaCount=2 \
        --set replica.persistence.enabled=true \
        --set replica.persistence.size=20Gi \
        --set metrics.enabled=true \
        --set metrics.serviceMonitor.enabled=true \
        --wait --timeout=10m
    
    log_success "Database services deployed"
}

# Deploy HackAI application
deploy_application() {
    log_info "Deploying HackAI application..."
    
    # Build and push Docker images if needed
    if [ "$ENVIRONMENT" = "production" ]; then
        log_info "Building and pushing Docker images..."
        docker build -t "ghcr.io/hackai/api-gateway:${IMAGE_TAG:-latest}" -f deployments/docker/Dockerfile.gateway .
        docker build -t "ghcr.io/hackai/user-service:${IMAGE_TAG:-latest}" -f deployments/docker/Dockerfile.user .
        docker build -t "ghcr.io/hackai/scanner-service:${IMAGE_TAG:-latest}" -f deployments/docker/Dockerfile.scanner .
        docker build -t "ghcr.io/hackai/threat-service:${IMAGE_TAG:-latest}" -f deployments/docker/Dockerfile.threat .
        
        # Push images (requires authentication)
        if [ "${PUSH_IMAGES:-false}" = "true" ]; then
            docker push "ghcr.io/hackai/api-gateway:${IMAGE_TAG:-latest}"
            docker push "ghcr.io/hackai/user-service:${IMAGE_TAG:-latest}"
            docker push "ghcr.io/hackai/scanner-service:${IMAGE_TAG:-latest}"
            docker push "ghcr.io/hackai/threat-service:${IMAGE_TAG:-latest}"
        fi
    fi
    
    # Deploy using Helm
    helm upgrade --install "$HELM_RELEASE" "$PROJECT_ROOT/deployments/helm/hackai" \
        --namespace "$NAMESPACE" \
        --set app.environment="$ENVIRONMENT" \
        --set image.tag="${IMAGE_TAG:-latest}" \
        --set global.imageRegistry="ghcr.io" \
        --set ingress.enabled=true \
        --set ingress.hosts[0].host="${DOMAIN:-hackai.dev}" \
        --set autoscaling.enabled=true \
        --set monitoring.enabled=true \
        --wait --timeout=15m
    
    log_success "HackAI application deployed"
}

# Configure ingress and SSL
configure_ingress() {
    log_info "Configuring ingress and SSL..."
    
    # Install cert-manager if not present
    if ! kubectl get namespace cert-manager &> /dev/null; then
        log_info "Installing cert-manager..."
        helm repo add jetstack https://charts.jetstack.io
        helm repo update
        
        helm upgrade --install cert-manager jetstack/cert-manager \
            --namespace cert-manager \
            --create-namespace \
            --set installCRDs=true \
            --wait --timeout=10m
    fi
    
    # Create ClusterIssuer for Let's Encrypt
    cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@hackai.dev
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF
    
    log_success "Ingress and SSL configured"
}

# Run health checks
run_health_checks() {
    log_info "Running health checks..."
    
    # Wait for pods to be ready
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=hackai -n "$NAMESPACE" --timeout=300s
    
    # Check service endpoints
    local services=("api-gateway" "user-service" "scanner-service" "threat-service")
    for service in "${services[@]}"; do
        if kubectl get service "$service" -n "$NAMESPACE" &> /dev/null; then
            log_success "Service $service is running"
        else
            log_warning "Service $service not found"
        fi
    done
    
    # Test API endpoints
    local api_url="http://$(kubectl get ingress -n "$NAMESPACE" -o jsonpath='{.items[0].spec.rules[0].host}')"
    if curl -f "$api_url/health" &> /dev/null; then
        log_success "API health check passed"
    else
        log_warning "API health check failed"
    fi
    
    log_success "Health checks completed"
}

# Cleanup function
cleanup() {
    if [ "${CLEANUP_ON_FAILURE:-false}" = "true" ]; then
        log_warning "Cleaning up due to failure..."
        helm uninstall "$HELM_RELEASE" -n "$NAMESPACE" || true
        kubectl delete namespace "$NAMESPACE" || true
    fi
}

# Main deployment function
main() {
    log_info "Starting HackAI infrastructure deployment..."
    log_info "Environment: $ENVIRONMENT"
    log_info "Namespace: $NAMESPACE"
    log_info "Helm Release: $HELM_RELEASE"
    
    # Set trap for cleanup on failure
    trap cleanup ERR
    
    check_prerequisites
    create_namespace
    deploy_secrets
    deploy_monitoring
    deploy_database
    deploy_application
    configure_ingress
    run_health_checks
    
    log_success "HackAI infrastructure deployment completed successfully!"
    log_info "Access the application at: https://${DOMAIN:-hackai.dev}"
    log_info "Access Grafana at: http://$(kubectl get service prometheus-grafana -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}'):3000"
    log_info "Default Grafana credentials: admin/admin"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --environment|-e)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --namespace|-n)
            NAMESPACE="$2"
            shift 2
            ;;
        --domain|-d)
            DOMAIN="$2"
            shift 2
            ;;
        --image-tag|-t)
            IMAGE_TAG="$2"
            shift 2
            ;;
        --push-images)
            PUSH_IMAGES="true"
            shift
            ;;
        --cleanup-on-failure)
            CLEANUP_ON_FAILURE="true"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -e, --environment     Environment (default: production)"
            echo "  -n, --namespace       Kubernetes namespace (default: hackai-{environment})"
            echo "  -d, --domain          Domain name (default: hackai.dev)"
            echo "  -t, --image-tag       Docker image tag (default: latest)"
            echo "      --push-images     Push Docker images to registry"
            echo "      --cleanup-on-failure  Cleanup resources on failure"
            echo "  -h, --help            Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main function
main "$@"
