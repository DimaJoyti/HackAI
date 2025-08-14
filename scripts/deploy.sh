#!/bin/bash

# HackAI Deployment Script
# Comprehensive deployment automation for HackAI platform

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NAMESPACE="hackai"
ENVIRONMENT="${ENVIRONMENT:-production}"
VERSION="${VERSION:-latest}"
REGISTRY="${REGISTRY:-ghcr.io}"
IMAGE_PREFIX="${IMAGE_PREFIX:-hackai}"

# Default values
DRY_RUN=false
SKIP_BUILD=false
SKIP_TESTS=false
FORCE_DEPLOY=false
HELM_UPGRADE=false
MONITORING_ONLY=false

# Functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploy HackAI platform to Kubernetes

OPTIONS:
    -e, --environment ENV       Deployment environment (default: production)
    -v, --version VERSION       Application version (default: latest)
    -n, --namespace NAMESPACE   Kubernetes namespace (default: hackai)
    -r, --registry REGISTRY     Container registry (default: ghcr.io)
    --dry-run                   Show what would be deployed without executing
    --skip-build                Skip building Docker images
    --skip-tests                Skip running tests
    --force                     Force deployment even if tests fail
    --helm-upgrade              Use Helm upgrade instead of install
    --monitoring-only           Deploy only monitoring stack
    -h, --help                  Show this help message

EXAMPLES:
    $0                          # Deploy to production with latest images
    $0 -e staging -v v1.2.3     # Deploy version v1.2.3 to staging
    $0 --dry-run                # Show deployment plan without executing
    $0 --monitoring-only        # Deploy only monitoring components

EOF
}

check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check required tools
    local tools=("kubectl" "docker" "helm")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            error "$tool is required but not installed"
        fi
    done
    
    # Check Kubernetes connection
    if ! kubectl cluster-info &> /dev/null; then
        error "Cannot connect to Kubernetes cluster"
    fi
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        error "Docker daemon is not running"
    fi
    
    info "Prerequisites check passed"
}

create_namespace() {
    log "Creating namespace: $NAMESPACE"
    
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        info "Namespace $NAMESPACE already exists"
    else
        kubectl create namespace "$NAMESPACE"
        kubectl label namespace "$NAMESPACE" name="$NAMESPACE"
    fi
}

build_images() {
    if [[ "$SKIP_BUILD" == "true" ]]; then
        info "Skipping image build"
        return
    fi
    
    log "Building Docker images..."
    
    local services=("api-gateway" "user-service" "scanner-service" "network-service" "threat-service" "log-service")
    
    for service in "${services[@]}"; do
        info "Building $service..."
        
        local image_name="$REGISTRY/$IMAGE_PREFIX/$service:$VERSION"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            info "Would build: $image_name"
            continue
        fi
        
        docker build \
            -f "$PROJECT_ROOT/deployments/docker/Dockerfile.${service#*-}" \
            -t "$image_name" \
            --build-arg VERSION="$VERSION" \
            --build-arg BUILD_TIME="$(date -u '+%Y-%m-%d_%H:%M:%S')" \
            --build-arg COMMIT_HASH="$(git rev-parse HEAD)" \
            "$PROJECT_ROOT"
        
        info "Pushing $image_name..."
        docker push "$image_name"
    done
    
    # Build web frontend
    info "Building web frontend..."
    local web_image="$REGISTRY/$IMAGE_PREFIX/web:$VERSION"
    
    if [[ "$DRY_RUN" == "false" ]]; then
        docker build \
            -f "$PROJECT_ROOT/web/Dockerfile" \
            -t "$web_image" \
            "$PROJECT_ROOT/web"
        
        docker push "$web_image"
    fi
}

run_tests() {
    if [[ "$SKIP_TESTS" == "true" ]]; then
        info "Skipping tests"
        return
    fi
    
    log "Running tests..."
    
    cd "$PROJECT_ROOT"
    
    # Run unit tests
    info "Running unit tests..."
    if ! make test-unit; then
        if [[ "$FORCE_DEPLOY" == "true" ]]; then
            warn "Unit tests failed but continuing due to --force flag"
        else
            error "Unit tests failed. Use --force to deploy anyway"
        fi
    fi
    
    # Run integration tests
    info "Running integration tests..."
    if ! make test-integration; then
        if [[ "$FORCE_DEPLOY" == "true" ]]; then
            warn "Integration tests failed but continuing due to --force flag"
        else
            error "Integration tests failed. Use --force to deploy anyway"
        fi
    fi
    
    # Run security scans
    info "Running security scans..."
    if command -v trivy &> /dev/null; then
        trivy fs --exit-code 1 --severity HIGH,CRITICAL "$PROJECT_ROOT" || {
            if [[ "$FORCE_DEPLOY" == "true" ]]; then
                warn "Security scan found issues but continuing due to --force flag"
            else
                error "Security scan failed. Use --force to deploy anyway"
            fi
        }
    else
        warn "Trivy not installed, skipping security scan"
    fi
}

deploy_secrets() {
    log "Deploying secrets..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        info "Would deploy secrets to namespace: $NAMESPACE"
        return
    fi
    
    # Apply secrets
    kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/secrets.yaml" -n "$NAMESPACE"
}

deploy_configmaps() {
    log "Deploying configuration..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        info "Would deploy configmaps to namespace: $NAMESPACE"
        return
    fi
    
    # Apply configmaps
    kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/configmap.yaml" -n "$NAMESPACE"
}

deploy_rbac() {
    log "Deploying RBAC configuration..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        info "Would deploy RBAC configuration"
        return
    fi
    
    # Apply RBAC
    kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/rbac.yaml"
}

deploy_databases() {
    log "Deploying databases..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        info "Would deploy PostgreSQL and Redis"
        return
    fi
    
    # Deploy PostgreSQL
    kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/postgres.yaml" -n "$NAMESPACE"
    
    # Deploy Redis
    kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/redis.yaml" -n "$NAMESPACE"
    
    # Wait for databases to be ready
    info "Waiting for databases to be ready..."
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=postgres --timeout=300s -n "$NAMESPACE"
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=redis --timeout=300s -n "$NAMESPACE"
}

deploy_monitoring() {
    log "Deploying monitoring stack..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        info "Would deploy monitoring stack (Prometheus, Grafana, Jaeger)"
        return
    fi
    
    # Deploy monitoring
    kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/monitoring.yaml" -n "$NAMESPACE"
    
    # Wait for monitoring to be ready
    info "Waiting for monitoring stack to be ready..."
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=prometheus --timeout=300s -n "$NAMESPACE"
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=grafana --timeout=300s -n "$NAMESPACE"
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=jaeger --timeout=300s -n "$NAMESPACE"
}

deploy_services() {
    if [[ "$MONITORING_ONLY" == "true" ]]; then
        info "Skipping services deployment (monitoring-only mode)"
        return
    fi
    
    log "Deploying HackAI services..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        info "Would deploy HackAI services"
        return
    fi
    
    # Deploy API Gateway
    kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/api-gateway.yaml" -n "$NAMESPACE"
    
    # Deploy User Service
    kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/user-service.yaml" -n "$NAMESPACE"
    
    # Deploy other services (scanner, network, threat, log)
    local services=("scanner" "network" "threat" "log")
    for service in "${services[@]}"; do
        if [[ -f "$PROJECT_ROOT/deployments/kubernetes/${service}-service.yaml" ]]; then
            kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/${service}-service.yaml" -n "$NAMESPACE"
        fi
    done
    
    # Wait for services to be ready
    info "Waiting for services to be ready..."
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=api-gateway --timeout=300s -n "$NAMESPACE"
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=user-service --timeout=300s -n "$NAMESPACE"
}

deploy_ingress() {
    if [[ "$MONITORING_ONLY" == "true" ]]; then
        info "Skipping ingress deployment (monitoring-only mode)"
        return
    fi
    
    log "Deploying ingress configuration..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        info "Would deploy ingress configuration"
        return
    fi
    
    # Deploy ingress
    kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/ingress.yaml" -n "$NAMESPACE"
}

deploy_with_helm() {
    log "Deploying with Helm..."
    
    local helm_command="install"
    if [[ "$HELM_UPGRADE" == "true" ]]; then
        helm_command="upgrade"
    fi
    
    local helm_args=(
        "$helm_command"
        "hackai"
        "$PROJECT_ROOT/deployments/helm/hackai"
        "--namespace" "$NAMESPACE"
        "--create-namespace"
        "--set" "global.environment=$ENVIRONMENT"
        "--set" "image.tag=$VERSION"
        "--set" "global.imageRegistry=$REGISTRY"
    )
    
    if [[ "$DRY_RUN" == "true" ]]; then
        helm_args+=("--dry-run")
    fi
    
    if [[ "$MONITORING_ONLY" == "true" ]]; then
        helm_args+=(
            "--set" "services.apiGateway.enabled=false"
            "--set" "services.userService.enabled=false"
            "--set" "services.scannerService.enabled=false"
            "--set" "services.networkService.enabled=false"
            "--set" "services.threatService.enabled=false"
            "--set" "services.logService.enabled=false"
            "--set" "web.enabled=false"
        )
    fi
    
    helm "${helm_args[@]}"
}

verify_deployment() {
    if [[ "$DRY_RUN" == "true" ]]; then
        info "Skipping deployment verification (dry-run mode)"
        return
    fi
    
    log "Verifying deployment..."
    
    # Check pod status
    info "Checking pod status..."
    kubectl get pods -n "$NAMESPACE"
    
    # Check service status
    info "Checking service status..."
    kubectl get services -n "$NAMESPACE"
    
    # Check ingress status
    if [[ "$MONITORING_ONLY" == "false" ]]; then
        info "Checking ingress status..."
        kubectl get ingress -n "$NAMESPACE"
    fi
    
    # Run health checks
    info "Running health checks..."
    local health_checks=0
    local max_attempts=30
    
    while [[ $health_checks -lt $max_attempts ]]; do
        if kubectl get pods -n "$NAMESPACE" | grep -q "Running"; then
            info "Health check passed"
            break
        fi
        
        health_checks=$((health_checks + 1))
        info "Waiting for pods to be ready... ($health_checks/$max_attempts)"
        sleep 10
    done
    
    if [[ $health_checks -eq $max_attempts ]]; then
        error "Health checks failed after $max_attempts attempts"
    fi
}

cleanup_old_resources() {
    log "Cleaning up old resources..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        info "Would clean up old resources"
        return
    fi
    
    # Remove old ReplicaSets
    kubectl delete replicaset --all -n "$NAMESPACE" --cascade=orphan || true
    
    # Remove completed jobs
    kubectl delete job --field-selector=status.successful=1 -n "$NAMESPACE" || true
    
    # Remove old pods
    kubectl delete pod --field-selector=status.phase=Succeeded -n "$NAMESPACE" || true
}

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -v|--version)
                VERSION="$2"
                shift 2
                ;;
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -r|--registry)
                REGISTRY="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --skip-build)
                SKIP_BUILD=true
                shift
                ;;
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            --force)
                FORCE_DEPLOY=true
                shift
                ;;
            --helm-upgrade)
                HELM_UPGRADE=true
                shift
                ;;
            --monitoring-only)
                MONITORING_ONLY=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done
    
    # Display configuration
    log "HackAI Deployment Configuration:"
    info "Environment: $ENVIRONMENT"
    info "Version: $VERSION"
    info "Namespace: $NAMESPACE"
    info "Registry: $REGISTRY"
    info "Dry Run: $DRY_RUN"
    info "Skip Build: $SKIP_BUILD"
    info "Skip Tests: $SKIP_TESTS"
    info "Force Deploy: $FORCE_DEPLOY"
    info "Monitoring Only: $MONITORING_ONLY"
    
    # Confirm deployment
    if [[ "$DRY_RUN" == "false" ]]; then
        read -p "Continue with deployment? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            info "Deployment cancelled"
            exit 0
        fi
    fi
    
    # Execute deployment steps
    check_prerequisites
    create_namespace
    run_tests
    build_images
    deploy_rbac
    deploy_secrets
    deploy_configmaps
    deploy_databases
    deploy_monitoring
    deploy_services
    deploy_ingress
    verify_deployment
    cleanup_old_resources
    
    log "Deployment completed successfully!"
    
    if [[ "$DRY_RUN" == "false" ]]; then
        info "Access URLs:"
        info "  API: https://api.hackai.com"
        info "  Web: https://app.hackai.com"
        info "  Monitoring: https://monitoring.hackai.com"
        info "  Grafana: https://monitoring.hackai.com/grafana"
        info "  Prometheus: https://monitoring.hackai.com/prometheus"
        info "  Jaeger: https://monitoring.hackai.com/jaeger"
    fi
}

# Run main function
main "$@"
