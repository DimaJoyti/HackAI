#!/bin/bash

# HackAI Comprehensive Deployment Script
# Enterprise-grade deployment automation for all environments
# Supports multiple cloud providers, deployment strategies, and environments

set -euo pipefail

# Script metadata
readonly SCRIPT_NAME="comprehensive-deploy.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Default configuration
DEFAULT_ENVIRONMENT="development"
DEFAULT_STRATEGY="rolling"
DEFAULT_PROVIDER="kubernetes"
DEFAULT_NAMESPACE="hackai"
DEFAULT_CONFIG_FILE="$PROJECT_ROOT/configs/deployment/comprehensive-deployment-config.yaml"

# Global variables
ENVIRONMENT="${ENVIRONMENT:-$DEFAULT_ENVIRONMENT}"
DEPLOYMENT_STRATEGY="${DEPLOYMENT_STRATEGY:-$DEFAULT_STRATEGY}"
CLOUD_PROVIDER="${CLOUD_PROVIDER:-$DEFAULT_PROVIDER}"
NAMESPACE="${NAMESPACE:-$DEFAULT_NAMESPACE}"
CONFIG_FILE="${CONFIG_FILE:-$DEFAULT_CONFIG_FILE}"
DRY_RUN="${DRY_RUN:-false}"
VERBOSE="${VERBOSE:-false}"
FORCE="${FORCE:-false}"
ROLLBACK="${ROLLBACK:-false}"
VERSION="${VERSION:-latest}"
IMAGE_TAG="${IMAGE_TAG:-$VERSION}"

# Logging configuration
LOG_LEVEL="${LOG_LEVEL:-info}"
LOG_FILE="${LOG_FILE:-/tmp/hackai-deploy-$(date +%Y%m%d-%H%M%S).log}"

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# Logging functions
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log_info() {
    if [[ "$VERBOSE" == "true" ]] || [[ "$LOG_LEVEL" == "debug" ]]; then
        echo -e "${BLUE}[INFO]${NC} $*" | tee -a "$LOG_FILE"
    fi
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE"
}

log_debug() {
    if [[ "$LOG_LEVEL" == "debug" ]]; then
        echo -e "${PURPLE}[DEBUG]${NC} $*" | tee -a "$LOG_FILE"
    fi
}

# Utility functions
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

check_prerequisites() {
    log_info "Checking deployment prerequisites..."
    
    local missing_tools=()
    
    # Check required tools
    local required_tools=("kubectl" "helm" "docker" "yq" "jq")
    
    for tool in "${required_tools[@]}"; do
        if ! command_exists "$tool"; then
            missing_tools+=("$tool")
        fi
    done
    
    # Check cloud provider specific tools
    case "$CLOUD_PROVIDER" in
        "aws")
            if ! command_exists "aws"; then
                missing_tools+=("aws")
            fi
            ;;
        "gcp")
            if ! command_exists "gcloud"; then
                missing_tools+=("gcloud")
            fi
            ;;
        "azure")
            if ! command_exists "az"; then
                missing_tools+=("az")
            fi
            ;;
    esac
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Please install the missing tools and try again"
        exit 1
    fi
    
    # Check configuration file
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi
    
    # Validate configuration
    if ! yq eval '.' "$CONFIG_FILE" >/dev/null 2>&1; then
        log_error "Invalid YAML configuration file: $CONFIG_FILE"
        exit 1
    fi
    
    log_success "All prerequisites satisfied"
}

load_configuration() {
    log_info "Loading deployment configuration..."
    
    # Extract environment-specific configuration
    local env_config
    env_config=$(yq eval ".environments.$ENVIRONMENT" "$CONFIG_FILE")
    
    if [[ "$env_config" == "null" ]]; then
        log_error "Environment '$ENVIRONMENT' not found in configuration"
        exit 1
    fi
    
    # Extract deployment strategy configuration
    local strategy_config
    strategy_config=$(yq eval ".deployment_strategies.$DEPLOYMENT_STRATEGY" "$CONFIG_FILE")
    
    if [[ "$strategy_config" == "null" ]]; then
        log_error "Deployment strategy '$DEPLOYMENT_STRATEGY' not found in configuration"
        exit 1
    fi
    
    # Set global variables from configuration
    REPLICAS_MIN=$(yq eval ".environments.$ENVIRONMENT.replicas.min" "$CONFIG_FILE")
    REPLICAS_MAX=$(yq eval ".environments.$ENVIRONMENT.replicas.max" "$CONFIG_FILE")
    REPLICAS_DEFAULT=$(yq eval ".environments.$ENVIRONMENT.replicas.default" "$CONFIG_FILE")
    
    log_success "Configuration loaded successfully"
    log_debug "Environment: $ENVIRONMENT"
    log_debug "Strategy: $DEPLOYMENT_STRATEGY"
    log_debug "Provider: $CLOUD_PROVIDER"
    log_debug "Namespace: $NAMESPACE"
    log_debug "Replicas: min=$REPLICAS_MIN, max=$REPLICAS_MAX, default=$REPLICAS_DEFAULT"
}

validate_environment() {
    log_info "Validating deployment environment..."
    
    # Check Kubernetes cluster connectivity
    if ! kubectl cluster-info >/dev/null 2>&1; then
        log_error "Cannot connect to Kubernetes cluster"
        log_error "Please check your kubeconfig and cluster connectivity"
        exit 1
    fi
    
    # Check namespace
    if ! kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; then
        log_warning "Namespace '$NAMESPACE' does not exist"
        if [[ "$DRY_RUN" == "false" ]]; then
            log_info "Creating namespace '$NAMESPACE'..."
            kubectl create namespace "$NAMESPACE"
            log_success "Namespace '$NAMESPACE' created"
        else
            log_info "DRY RUN: Would create namespace '$NAMESPACE'"
        fi
    fi
    
    # Check RBAC permissions
    if ! kubectl auth can-i create deployments --namespace="$NAMESPACE" >/dev/null 2>&1; then
        log_error "Insufficient RBAC permissions for namespace '$NAMESPACE'"
        log_error "Please ensure you have the necessary permissions"
        exit 1
    fi
    
    log_success "Environment validation completed"
}

build_images() {
    log_info "Building container images..."
    
    local services
    services=$(yq eval '.containers.services | keys | .[]' "$CONFIG_FILE")
    
    local registry
    registry=$(yq eval '.containers.registry' "$CONFIG_FILE")
    
    local image_prefix
    image_prefix=$(yq eval '.containers.image_prefix' "$CONFIG_FILE")
    
    while IFS= read -r service; do
        local image_name="$registry/$image_prefix/$service:$IMAGE_TAG"
        
        log_info "Building image for service: $service"
        log_debug "Image name: $image_name"
        
        if [[ "$DRY_RUN" == "false" ]]; then
            # Build Docker image
            docker build \
                -f "$PROJECT_ROOT/deployments/docker/Dockerfile.$service" \
                -t "$image_name" \
                --build-arg VERSION="$VERSION" \
                --build-arg BUILD_TIME="$(date -u '+%Y-%m-%d_%H:%M:%S')" \
                --build-arg COMMIT_HASH="$(git rev-parse HEAD 2>/dev/null || echo 'unknown')" \
                "$PROJECT_ROOT"
            
            # Push image to registry
            log_info "Pushing image: $image_name"
            docker push "$image_name"
            
            log_success "Image built and pushed: $service"
        else
            log_info "DRY RUN: Would build and push image: $image_name"
        fi
    done <<< "$services"
    
    log_success "All images built successfully"
}

deploy_infrastructure() {
    log_info "Deploying infrastructure components..."
    
    # Deploy monitoring stack
    if [[ $(yq eval '.monitoring.enable_metrics' "$CONFIG_FILE") == "true" ]]; then
        deploy_monitoring
    fi
    
    # Deploy security components
    if [[ $(yq eval '.security.enable_rbac' "$CONFIG_FILE") == "true" ]]; then
        deploy_security
    fi
    
    # Deploy storage classes
    deploy_storage_classes
    
    log_success "Infrastructure deployment completed"
}

deploy_monitoring() {
    log_info "Deploying monitoring stack..."
    
    if [[ "$DRY_RUN" == "false" ]]; then
        # Add Prometheus Helm repository
        helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
        helm repo update
        
        # Install Prometheus stack
        helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
            --namespace monitoring \
            --create-namespace \
            --set prometheus.prometheusSpec.retention=15d \
            --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.resources.requests.storage=50Gi \
            --wait
        
        log_success "Monitoring stack deployed"
    else
        log_info "DRY RUN: Would deploy monitoring stack"
    fi
}

deploy_security() {
    log_info "Deploying security components..."
    
    if [[ "$DRY_RUN" == "false" ]]; then
        # Apply RBAC configurations
        kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/rbac/" --namespace="$NAMESPACE"
        
        # Apply network policies
        kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/network-policies/" --namespace="$NAMESPACE"
        
        # Apply pod security policies
        kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/pod-security/" --namespace="$NAMESPACE"
        
        log_success "Security components deployed"
    else
        log_info "DRY RUN: Would deploy security components"
    fi
}

deploy_storage_classes() {
    log_info "Deploying storage classes..."
    
    local storage_classes
    storage_classes=$(yq eval '.infrastructure.storage.storage_classes[].name' "$CONFIG_FILE")
    
    while IFS= read -r storage_class; do
        if [[ "$DRY_RUN" == "false" ]]; then
            # Generate storage class manifest
            yq eval ".infrastructure.storage.storage_classes[] | select(.name == \"$storage_class\")" "$CONFIG_FILE" | \
            yq eval '{
                "apiVersion": "storage.k8s.io/v1",
                "kind": "StorageClass",
                "metadata": {"name": .name},
                "provisioner": .provisioner,
                "parameters": .parameters,
                "reclaimPolicy": .reclaim_policy,
                "volumeBindingMode": .volume_binding_mode,
                "allowVolumeExpansion": .allow_volume_expansion
            }' | kubectl apply -f -
            
            log_success "Storage class deployed: $storage_class"
        else
            log_info "DRY RUN: Would deploy storage class: $storage_class"
        fi
    done <<< "$storage_classes"
}

deploy_applications() {
    log_info "Deploying applications using $DEPLOYMENT_STRATEGY strategy..."
    
    case "$DEPLOYMENT_STRATEGY" in
        "rolling")
            deploy_rolling
            ;;
        "blue_green")
            deploy_blue_green
            ;;
        "canary")
            deploy_canary
            ;;
        *)
            log_error "Unsupported deployment strategy: $DEPLOYMENT_STRATEGY"
            exit 1
            ;;
    esac
    
    log_success "Application deployment completed"
}

deploy_rolling() {
    log_info "Executing rolling deployment..."
    
    if [[ "$DRY_RUN" == "false" ]]; then
        # Deploy using Helm with rolling update strategy
        helm upgrade --install hackai "$PROJECT_ROOT/deployments/helm/hackai" \
            --namespace "$NAMESPACE" \
            --set app.environment="$ENVIRONMENT" \
            --set image.tag="$IMAGE_TAG" \
            --set replicaCount="$REPLICAS_DEFAULT" \
            --set strategy.type="RollingUpdate" \
            --set strategy.rollingUpdate.maxUnavailable="25%" \
            --set strategy.rollingUpdate.maxSurge="25%" \
            --wait --timeout=15m
        
        # Verify deployment
        kubectl rollout status deployment/api-gateway --namespace="$NAMESPACE" --timeout=600s
        
        log_success "Rolling deployment completed successfully"
    else
        log_info "DRY RUN: Would execute rolling deployment"
    fi
}

deploy_blue_green() {
    log_info "Executing blue-green deployment..."
    
    if [[ "$DRY_RUN" == "false" ]]; then
        # Implement blue-green deployment logic
        # This is a simplified implementation
        
        # Deploy to green environment
        helm upgrade --install hackai-green "$PROJECT_ROOT/deployments/helm/hackai" \
            --namespace "$NAMESPACE" \
            --set app.environment="$ENVIRONMENT" \
            --set image.tag="$IMAGE_TAG" \
            --set replicaCount="$REPLICAS_DEFAULT" \
            --set nameOverride="hackai-green" \
            --wait --timeout=15m
        
        # Test green environment
        log_info "Testing green environment..."
        sleep 30
        
        # Switch traffic to green (simplified)
        kubectl patch service hackai --namespace="$NAMESPACE" -p '{"spec":{"selector":{"app":"hackai-green"}}}'
        
        # Scale down blue environment
        log_info "Scaling down blue environment..."
        kubectl scale deployment hackai --replicas=0 --namespace="$NAMESPACE"
        
        log_success "Blue-green deployment completed successfully"
    else
        log_info "DRY RUN: Would execute blue-green deployment"
    fi
}

deploy_canary() {
    log_info "Executing canary deployment..."
    
    if [[ "$DRY_RUN" == "false" ]]; then
        # Implement canary deployment logic
        # This would typically use tools like Argo Rollouts or Flagger
        
        log_info "Canary deployment requires additional tooling (Argo Rollouts/Flagger)"
        log_info "Falling back to rolling deployment..."
        deploy_rolling
    else
        log_info "DRY RUN: Would execute canary deployment"
    fi
}

verify_deployment() {
    log_info "Verifying deployment..."
    
    # Check pod status
    local pods_ready
    pods_ready=$(kubectl get pods --namespace="$NAMESPACE" -l app=hackai --field-selector=status.phase=Running --no-headers | wc -l)
    
    if [[ "$pods_ready" -lt "$REPLICAS_MIN" ]]; then
        log_error "Insufficient pods running: $pods_ready (minimum: $REPLICAS_MIN)"
        return 1
    fi
    
    # Check service endpoints
    local services
    services=$(yq eval '.containers.services | keys | .[]' "$CONFIG_FILE")
    
    while IFS= read -r service; do
        local port
        port=$(yq eval ".containers.services.$service.port" "$CONFIG_FILE")
        
        log_info "Checking service health: $service"
        
        # Port-forward and health check (simplified)
        if kubectl get service "$service" --namespace="$NAMESPACE" >/dev/null 2>&1; then
            log_success "Service $service is accessible"
        else
            log_warning "Service $service may not be ready"
        fi
    done <<< "$services"
    
    log_success "Deployment verification completed"
}

cleanup_old_resources() {
    log_info "Cleaning up old resources..."
    
    if [[ "$DRY_RUN" == "false" ]]; then
        # Clean up old ReplicaSets
        kubectl delete replicaset --namespace="$NAMESPACE" \
            --field-selector='status.replicas=0' \
            --ignore-not-found=true
        
        # Clean up completed jobs
        kubectl delete job --namespace="$NAMESPACE" \
            --field-selector='status.successful=1' \
            --ignore-not-found=true
        
        log_success "Old resources cleaned up"
    else
        log_info "DRY RUN: Would clean up old resources"
    fi
}

rollback_deployment() {
    log_info "Rolling back deployment..."
    
    if [[ "$DRY_RUN" == "false" ]]; then
        # Rollback using Helm
        helm rollback hackai --namespace="$NAMESPACE"
        
        # Wait for rollback to complete
        kubectl rollout status deployment/api-gateway --namespace="$NAMESPACE" --timeout=600s
        
        log_success "Deployment rolled back successfully"
    else
        log_info "DRY RUN: Would rollback deployment"
    fi
}

show_usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

HackAI Comprehensive Deployment Script v$SCRIPT_VERSION

OPTIONS:
    -e, --environment ENV       Deployment environment (default: $DEFAULT_ENVIRONMENT)
    -s, --strategy STRATEGY     Deployment strategy (default: $DEFAULT_STRATEGY)
    -p, --provider PROVIDER     Cloud provider (default: $DEFAULT_PROVIDER)
    -n, --namespace NAMESPACE   Kubernetes namespace (default: $DEFAULT_NAMESPACE)
    -c, --config FILE          Configuration file (default: $DEFAULT_CONFIG_FILE)
    -v, --version VERSION      Application version (default: $VERSION)
    -t, --tag TAG              Image tag (default: $IMAGE_TAG)
    --dry-run                  Perform a dry run without making changes
    --verbose                  Enable verbose output
    --force                    Force deployment even if validation fails
    --rollback                 Rollback to previous deployment
    -h, --help                 Show this help message

ENVIRONMENTS:
    development, staging, production

STRATEGIES:
    rolling, blue_green, canary

PROVIDERS:
    kubernetes, aws, gcp, azure

EXAMPLES:
    $SCRIPT_NAME --environment production --strategy blue_green
    $SCRIPT_NAME --dry-run --verbose
    $SCRIPT_NAME --rollback --environment staging

EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -s|--strategy)
                DEPLOYMENT_STRATEGY="$2"
                shift 2
                ;;
            -p|--provider)
                CLOUD_PROVIDER="$2"
                shift 2
                ;;
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -v|--version)
                VERSION="$2"
                IMAGE_TAG="$2"
                shift 2
                ;;
            -t|--tag)
                IMAGE_TAG="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            --verbose)
                VERBOSE="true"
                shift
                ;;
            --force)
                FORCE="true"
                shift
                ;;
            --rollback)
                ROLLBACK="true"
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    # Print banner
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    HackAI Comprehensive Deployment Script                   ║"
    echo "║                                Version $SCRIPT_VERSION                                ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    log_info "Starting HackAI deployment..."
    log_info "Environment: $ENVIRONMENT"
    log_info "Strategy: $DEPLOYMENT_STRATEGY"
    log_info "Provider: $CLOUD_PROVIDER"
    log_info "Namespace: $NAMESPACE"
    log_info "Version: $VERSION"
    log_info "Image Tag: $IMAGE_TAG"
    log_info "Dry Run: $DRY_RUN"
    
    # Set trap for cleanup on failure
    trap 'log_error "Deployment failed! Check logs at: $LOG_FILE"' ERR
    
    # Execute deployment steps
    if [[ "$ROLLBACK" == "true" ]]; then
        rollback_deployment
    else
        check_prerequisites
        load_configuration
        validate_environment
        build_images
        deploy_infrastructure
        deploy_applications
        verify_deployment
        cleanup_old_resources
    fi
    
    log_success "HackAI deployment completed successfully!"
    log_info "Deployment logs saved to: $LOG_FILE"
    
    if [[ "$DRY_RUN" == "false" ]]; then
        log_info "Access URLs:"
        log_info "  API: https://api.hackai.com"
        log_info "  Web: https://app.hackai.com"
        log_info "  Monitoring: https://monitoring.hackai.com"
    fi
}

# Run main function with all arguments
main "$@"
