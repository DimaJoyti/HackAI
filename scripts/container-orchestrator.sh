#!/bin/bash

# HackAI Container Orchestration and Kubernetes Deployment Script
# Advanced container management with multi-environment support

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEPLOYMENTS_DIR="$PROJECT_ROOT/deployments"
K8S_DIR="$DEPLOYMENTS_DIR/kubernetes"
ENHANCED_K8S_DIR="$K8S_DIR/enhanced"
HELM_DIR="$DEPLOYMENTS_DIR/helm/hackai"

# Default values
ENVIRONMENT="${ENVIRONMENT:-development}"
NAMESPACE="${NAMESPACE:-hackai}"
REGISTRY="${REGISTRY:-ghcr.io/hackai}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
BUILD_IMAGES="${BUILD_IMAGES:-true}"
PUSH_IMAGES="${PUSH_IMAGES:-false}"
DEPLOY_METHOD="${DEPLOY_METHOD:-helm}"  # helm, kubectl, kustomize
DRY_RUN="${DRY_RUN:-false}"
FORCE_RECREATE="${FORCE_RECREATE:-false}"
ENABLE_MONITORING="${ENABLE_MONITORING:-true}"
ENABLE_SECURITY="${ENABLE_SECURITY:-true}"
ENABLE_ISTIO="${ENABLE_ISTIO:-false}"
PARALLEL_BUILDS="${PARALLEL_BUILDS:-true}"
BUILD_CACHE="${BUILD_CACHE:-true}"
MULTI_ARCH="${MULTI_ARCH:-false}"

# Service definitions
declare -A SERVICES=(
    ["api-gateway"]="cmd/api-gateway"
    ["user-service"]="cmd/user-service"
    ["threat-service"]="cmd/threat-service"
    ["scanner-service"]="cmd/scanner-service"
    ["security-service"]="cmd/security-service"
    ["analytics-service"]="cmd/analytics-service"
    ["observability-server"]="cmd/observability-server"
)

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

log_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${PURPLE}[DEBUG]${NC} $1"
    fi
}

# Help function
show_help() {
    cat << EOF
HackAI Container Orchestration and Kubernetes Deployment Script

Usage: $0 [COMMAND] [OPTIONS]

COMMANDS:
    build                Build container images
    push                 Push images to registry
    deploy               Deploy to Kubernetes
    undeploy             Remove deployment from Kubernetes
    restart              Restart services
    scale                Scale services
    status               Show deployment status
    logs                 Show service logs
    exec                 Execute command in container
    port-forward         Forward ports from services
    test                 Run deployment tests
    cleanup              Clean up resources
    help                 Show this help message

OPTIONS:
    -e, --environment ENV        Set environment (development, staging, production)
    -n, --namespace NAMESPACE    Kubernetes namespace
    -r, --registry REGISTRY      Container registry
    -t, --tag TAG               Image tag
    --build-images              Build images before deployment
    --push-images               Push images to registry
    --deploy-method METHOD      Deployment method (helm, kubectl, kustomize)
    --dry-run                   Show what would be done without executing
    --force-recreate            Force recreate resources
    --enable-monitoring         Enable monitoring stack
    --enable-security           Enable security policies
    --enable-istio              Enable Istio service mesh
    --parallel-builds           Build images in parallel
    --build-cache               Use build cache
    --multi-arch                Build multi-architecture images
    --debug                     Enable debug output

EXAMPLES:
    # Build and deploy to development
    $0 deploy --environment development

    # Build multi-arch images and push to registry
    $0 build --multi-arch --push-images

    # Deploy with Helm to production
    $0 deploy --environment production --deploy-method helm --enable-monitoring

    # Scale threat-service to 5 replicas
    $0 scale threat-service 5

    # Show logs for api-gateway
    $0 logs api-gateway

    # Port forward api-gateway
    $0 port-forward api-gateway 8080:8080

EOF
}

# Parse command line arguments
parse_args() {
    COMMAND=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            build|push|deploy|undeploy|restart|scale|status|logs|exec|port-forward|test|cleanup|help)
                COMMAND="$1"
                shift
                ;;
            -e|--environment)
                ENVIRONMENT="$2"
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
            -t|--tag)
                IMAGE_TAG="$2"
                shift 2
                ;;
            --build-images)
                BUILD_IMAGES="true"
                shift
                ;;
            --push-images)
                PUSH_IMAGES="true"
                shift
                ;;
            --deploy-method)
                DEPLOY_METHOD="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            --force-recreate)
                FORCE_RECREATE="true"
                shift
                ;;
            --enable-monitoring)
                ENABLE_MONITORING="true"
                shift
                ;;
            --enable-security)
                ENABLE_SECURITY="true"
                shift
                ;;
            --enable-istio)
                ENABLE_ISTIO="true"
                shift
                ;;
            --parallel-builds)
                PARALLEL_BUILDS="true"
                shift
                ;;
            --build-cache)
                BUILD_CACHE="true"
                shift
                ;;
            --multi-arch)
                MULTI_ARCH="true"
                shift
                ;;
            --debug)
                DEBUG="true"
                shift
                ;;
            *)
                # Store additional arguments for specific commands
                EXTRA_ARGS+=("$1")
                shift
                ;;
        esac
    done
    
    if [[ -z "$COMMAND" ]]; then
        log_error "No command specified"
        show_help
        exit 1
    fi
}

# Validate prerequisites
validate_prerequisites() {
    log_info "Validating prerequisites..."
    
    # Check required tools
    local required_tools=("docker" "kubectl" "helm")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "$tool is required but not installed"
            exit 1
        fi
    done
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    # Check Kubernetes connection
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    # Check if namespace exists
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_warning "Namespace $NAMESPACE does not exist, will be created"
    fi
    
    log_success "Prerequisites validation completed"
}

# Build container images
build_images() {
    log_info "Building container images..."
    
    local build_args=(
        "--build-arg" "VERSION=$IMAGE_TAG"
        "--build-arg" "BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        "--build-arg" "COMMIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    )
    
    if [[ "$BUILD_CACHE" == "false" ]]; then
        build_args+=("--no-cache")
    fi
    
    if [[ "$MULTI_ARCH" == "true" ]]; then
        build_args+=("--platform" "linux/amd64,linux/arm64")
        if [[ "$PUSH_IMAGES" == "true" ]]; then
            build_args+=("--push")
        fi
    fi
    
    local pids=()
    
    for service in "${!SERVICES[@]}"; do
        local service_dir="${SERVICES[$service]}"
        local image_name="$REGISTRY/$service:$IMAGE_TAG"
        
        log_info "Building $service..."
        
        if [[ "$PARALLEL_BUILDS" == "true" ]]; then
            (
                if [[ "$DRY_RUN" == "true" ]]; then
                    log_info "DRY RUN: Would build $image_name"
                else
                    docker build \
                        "${build_args[@]}" \
                        --build-arg "SERVICE_NAME=$service" \
                        -t "$image_name" \
                        -f "$DEPLOYMENTS_DIR/docker/Dockerfile.multi-stage" \
                        --target "runtime" \
                        "$PROJECT_ROOT"
                fi
            ) &
            pids+=($!)
        else
            if [[ "$DRY_RUN" == "true" ]]; then
                log_info "DRY RUN: Would build $image_name"
            else
                docker build \
                    "${build_args[@]}" \
                    --build-arg "SERVICE_NAME=$service" \
                    -t "$image_name" \
                    -f "$DEPLOYMENTS_DIR/docker/Dockerfile.multi-stage" \
                    --target "runtime" \
                    "$PROJECT_ROOT"
            fi
        fi
    done
    
    # Wait for parallel builds to complete
    if [[ "$PARALLEL_BUILDS" == "true" ]]; then
        for pid in "${pids[@]}"; do
            wait "$pid"
        done
    fi
    
    log_success "Container images built successfully"
}

# Push images to registry
push_images() {
    log_info "Pushing images to registry..."
    
    for service in "${!SERVICES[@]}"; do
        local image_name="$REGISTRY/$service:$IMAGE_TAG"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "DRY RUN: Would push $image_name"
        else
            log_info "Pushing $image_name..."
            docker push "$image_name"
        fi
    done
    
    log_success "Images pushed successfully"
}

# Deploy to Kubernetes
deploy_to_kubernetes() {
    log_info "Deploying to Kubernetes using $DEPLOY_METHOD..."
    
    # Create namespace if it doesn't exist
    if [[ "$DRY_RUN" == "false" ]]; then
        kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    fi
    
    case "$DEPLOY_METHOD" in
        "helm")
            deploy_with_helm
            ;;
        "kubectl")
            deploy_with_kubectl
            ;;
        "kustomize")
            deploy_with_kustomize
            ;;
        *)
            log_error "Unknown deployment method: $DEPLOY_METHOD"
            exit 1
            ;;
    esac
    
    if [[ "$ENABLE_MONITORING" == "true" ]]; then
        deploy_monitoring_stack
    fi
    
    if [[ "$ENABLE_SECURITY" == "true" ]]; then
        deploy_security_policies
    fi
    
    if [[ "$ENABLE_ISTIO" == "true" ]]; then
        deploy_istio_config
    fi
    
    log_success "Deployment completed successfully"
}

# Deploy with Helm
deploy_with_helm() {
    log_info "Deploying with Helm..."
    
    local helm_args=(
        "upgrade" "--install" "hackai"
        "$HELM_DIR"
        "--namespace" "$NAMESPACE"
        "--create-namespace"
        "--set" "global.environment=$ENVIRONMENT"
        "--set" "global.imageRegistry=$REGISTRY"
        "--set" "image.tag=$IMAGE_TAG"
        "--set" "monitoring.enabled=$ENABLE_MONITORING"
        "--set" "security.enabled=$ENABLE_SECURITY"
        "--set" "istio.enabled=$ENABLE_ISTIO"
        "--values" "$HELM_DIR/values-$ENVIRONMENT.yaml"
        "--wait" "--timeout=10m"
    )
    
    if [[ "$DRY_RUN" == "true" ]]; then
        helm_args+=("--dry-run")
    fi
    
    if [[ "$FORCE_RECREATE" == "true" ]]; then
        helm_args+=("--force")
    fi
    
    helm "${helm_args[@]}"
}

# Deploy with kubectl
deploy_with_kubectl() {
    log_info "Deploying with kubectl..."
    
    local kubectl_args=("apply" "-f" "$ENHANCED_K8S_DIR" "--namespace" "$NAMESPACE")
    
    if [[ "$DRY_RUN" == "true" ]]; then
        kubectl_args+=("--dry-run=client")
    fi
    
    if [[ "$FORCE_RECREATE" == "true" ]]; then
        kubectl_args+=("--force")
    fi
    
    kubectl "${kubectl_args[@]}"
}

# Deploy with Kustomize
deploy_with_kustomize() {
    log_info "Deploying with Kustomize..."
    
    local kustomize_dir="$K8S_DIR/overlays/$ENVIRONMENT"
    
    if [[ ! -d "$kustomize_dir" ]]; then
        log_error "Kustomize overlay directory not found: $kustomize_dir"
        exit 1
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        kubectl kustomize "$kustomize_dir"
    else
        kubectl apply -k "$kustomize_dir" --namespace "$NAMESPACE"
    fi
}

# Deploy monitoring stack
deploy_monitoring_stack() {
    log_info "Deploying monitoring stack..."
    
    if [[ "$DRY_RUN" == "false" ]]; then
        kubectl apply -f "$DEPLOYMENTS_DIR/monitoring/" --namespace "$NAMESPACE"
    else
        log_info "DRY RUN: Would deploy monitoring stack"
    fi
}

# Deploy security policies
deploy_security_policies() {
    log_info "Deploying security policies..."
    
    if [[ "$DRY_RUN" == "false" ]]; then
        kubectl apply -f "$ENHANCED_K8S_DIR/security-policies.yaml" --namespace "$NAMESPACE"
    else
        log_info "DRY RUN: Would deploy security policies"
    fi
}

# Deploy Istio configuration
deploy_istio_config() {
    log_info "Deploying Istio configuration..."
    
    if [[ "$DRY_RUN" == "false" ]]; then
        kubectl apply -f "$K8S_DIR/istio/" --namespace "$NAMESPACE"
    else
        log_info "DRY RUN: Would deploy Istio configuration"
    fi
}

# Undeploy from Kubernetes
undeploy_from_kubernetes() {
    log_info "Undeploying from Kubernetes..."
    
    case "$DEPLOY_METHOD" in
        "helm")
            if [[ "$DRY_RUN" == "false" ]]; then
                helm uninstall hackai --namespace "$NAMESPACE"
            else
                log_info "DRY RUN: Would uninstall Helm release"
            fi
            ;;
        "kubectl"|"kustomize")
            if [[ "$DRY_RUN" == "false" ]]; then
                kubectl delete -f "$ENHANCED_K8S_DIR" --namespace "$NAMESPACE" --ignore-not-found=true
            else
                log_info "DRY RUN: Would delete Kubernetes resources"
            fi
            ;;
    esac
    
    log_success "Undeployment completed"
}

# Scale services
scale_service() {
    local service_name="${EXTRA_ARGS[0]:-}"
    local replicas="${EXTRA_ARGS[1]:-}"
    
    if [[ -z "$service_name" || -z "$replicas" ]]; then
        log_error "Usage: $0 scale <service-name> <replicas>"
        exit 1
    fi
    
    log_info "Scaling $service_name to $replicas replicas..."
    
    if [[ "$DRY_RUN" == "false" ]]; then
        kubectl scale deployment "$service_name" --replicas="$replicas" --namespace "$NAMESPACE"
    else
        log_info "DRY RUN: Would scale $service_name to $replicas replicas"
    fi
    
    log_success "Scaling completed"
}

# Show deployment status
show_status() {
    log_info "Showing deployment status..."
    
    echo -e "\n${CYAN}=== Namespace: $NAMESPACE ===${NC}"
    kubectl get namespace "$NAMESPACE" 2>/dev/null || echo "Namespace not found"
    
    echo -e "\n${CYAN}=== Deployments ===${NC}"
    kubectl get deployments -n "$NAMESPACE" -o wide
    
    echo -e "\n${CYAN}=== Pods ===${NC}"
    kubectl get pods -n "$NAMESPACE" -o wide
    
    echo -e "\n${CYAN}=== Services ===${NC}"
    kubectl get services -n "$NAMESPACE" -o wide
    
    echo -e "\n${CYAN}=== Ingress ===${NC}"
    kubectl get ingress -n "$NAMESPACE" -o wide
    
    echo -e "\n${CYAN}=== HPA ===${NC}"
    kubectl get hpa -n "$NAMESPACE" -o wide
    
    echo -e "\n${CYAN}=== PVC ===${NC}"
    kubectl get pvc -n "$NAMESPACE" -o wide
}

# Show service logs
show_logs() {
    local service_name="${EXTRA_ARGS[0]:-}"
    
    if [[ -z "$service_name" ]]; then
        log_error "Usage: $0 logs <service-name>"
        exit 1
    fi
    
    log_info "Showing logs for $service_name..."
    
    kubectl logs -f deployment/"$service_name" -n "$NAMESPACE" --tail=100
}

# Execute command in container
exec_command() {
    local service_name="${EXTRA_ARGS[0]:-}"
    local command="${EXTRA_ARGS[1]:-/bin/sh}"
    
    if [[ -z "$service_name" ]]; then
        log_error "Usage: $0 exec <service-name> [command]"
        exit 1
    fi
    
    log_info "Executing command in $service_name..."
    
    local pod_name
    pod_name=$(kubectl get pods -n "$NAMESPACE" -l app="$service_name" -o jsonpath='{.items[0].metadata.name}')
    
    if [[ -z "$pod_name" ]]; then
        log_error "No pods found for service $service_name"
        exit 1
    fi
    
    kubectl exec -it "$pod_name" -n "$NAMESPACE" -- "$command"
}

# Port forward service
port_forward() {
    local service_name="${EXTRA_ARGS[0]:-}"
    local ports="${EXTRA_ARGS[1]:-8080:8080}"
    
    if [[ -z "$service_name" ]]; then
        log_error "Usage: $0 port-forward <service-name> [local-port:remote-port]"
        exit 1
    fi
    
    log_info "Port forwarding $service_name on $ports..."
    
    kubectl port-forward service/"$service_name" "$ports" -n "$NAMESPACE"
}

# Run deployment tests
run_tests() {
    log_info "Running deployment tests..."
    
    # Health check tests
    log_info "Running health check tests..."
    for service in "${!SERVICES[@]}"; do
        log_info "Testing $service health endpoint..."
        
        local pod_name
        pod_name=$(kubectl get pods -n "$NAMESPACE" -l app="$service" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
        
        if [[ -n "$pod_name" ]]; then
            kubectl exec "$pod_name" -n "$NAMESPACE" -- curl -f http://localhost:8081/health/ready || log_warning "$service health check failed"
        else
            log_warning "No pods found for $service"
        fi
    done
    
    # Connectivity tests
    log_info "Running connectivity tests..."
    kubectl run test-pod --image=curlimages/curl:latest --rm -i --restart=Never -n "$NAMESPACE" -- \
        curl -f http://api-gateway-service/health || log_warning "API Gateway connectivity test failed"
    
    log_success "Tests completed"
}

# Cleanup resources
cleanup_resources() {
    log_info "Cleaning up resources..."
    
    if [[ "$DRY_RUN" == "false" ]]; then
        # Remove failed pods
        kubectl delete pods --field-selector=status.phase=Failed -n "$NAMESPACE" --ignore-not-found=true
        
        # Remove completed jobs
        kubectl delete jobs --field-selector=status.successful=1 -n "$NAMESPACE" --ignore-not-found=true
        
        # Prune unused images
        docker image prune -f
        
        log_success "Cleanup completed"
    else
        log_info "DRY RUN: Would clean up resources"
    fi
}

# Main function
main() {
    log_info "Starting HackAI Container Orchestration"
    log_info "Environment: $ENVIRONMENT, Namespace: $NAMESPACE"
    log_info "Registry: $REGISTRY, Tag: $IMAGE_TAG"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_warning "Running in DRY RUN mode - no changes will be made"
    fi
    
    validate_prerequisites
    
    case "$COMMAND" in
        "build")
            build_images
            if [[ "$PUSH_IMAGES" == "true" ]]; then
                push_images
            fi
            ;;
        "push")
            push_images
            ;;
        "deploy")
            if [[ "$BUILD_IMAGES" == "true" ]]; then
                build_images
            fi
            if [[ "$PUSH_IMAGES" == "true" ]]; then
                push_images
            fi
            deploy_to_kubernetes
            ;;
        "undeploy")
            undeploy_from_kubernetes
            ;;
        "restart")
            kubectl rollout restart deployment -n "$NAMESPACE"
            ;;
        "scale")
            scale_service
            ;;
        "status")
            show_status
            ;;
        "logs")
            show_logs
            ;;
        "exec")
            exec_command
            ;;
        "port-forward")
            port_forward
            ;;
        "test")
            run_tests
            ;;
        "cleanup")
            cleanup_resources
            ;;
        "help")
            show_help
            ;;
        *)
            log_error "Unknown command: $COMMAND"
            show_help
            exit 1
            ;;
    esac
    
    log_success "Container orchestration completed successfully!"
}

# Initialize extra args array
EXTRA_ARGS=()

# Parse arguments and run main function
parse_args "$@"
main
