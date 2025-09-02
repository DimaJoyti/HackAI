#!/bin/bash

# HackAI Production Deployment & DevOps Automation Script
# Comprehensive DevOps automation for CI/CD, deployment, and operations

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
DEVOPS_CONFIG_DIR="$PROJECT_ROOT/configs/devops"
DEPLOYMENTS_DIR="$PROJECT_ROOT/deployments"
INFRASTRUCTURE_DIR="$PROJECT_ROOT/infrastructure"

# Default values
ENVIRONMENT="${ENVIRONMENT:-development}"
VERSION="${VERSION:-latest}"
NAMESPACE="${NAMESPACE:-hackai-dev}"
DEPLOY_TYPE="${DEPLOY_TYPE:-rolling}"
ENABLE_MONITORING="${ENABLE_MONITORING:-true}"
ENABLE_SECURITY="${ENABLE_SECURITY:-true}"
ENABLE_BACKUP="${ENABLE_BACKUP:-false}"
DRY_RUN="${DRY_RUN:-false}"
VERBOSE="${VERBOSE:-false}"
FORCE_DEPLOY="${FORCE_DEPLOY:-false}"
SKIP_TESTS="${SKIP_TESTS:-false}"
PUSH_IMAGES="${PUSH_IMAGES:-false}"

# DevOps automation results
declare -A AUTOMATION_RESULTS=()
TOTAL_OPERATIONS=0
SUCCESSFUL_OPERATIONS=0
FAILED_OPERATIONS=0

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
    if [[ "${VERBOSE}" == "true" ]]; then
        echo -e "${PURPLE}[DEBUG]${NC} $1"
    fi
}

log_devops() {
    echo -e "${CYAN}[DEVOPS]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
HackAI Production Deployment & DevOps Automation Script

Usage: $0 [COMMAND] [OPTIONS]

COMMANDS:
    build                Build application and container images
    test                 Run comprehensive test suite
    deploy               Deploy application to target environment
    rollback             Rollback to previous deployment
    infrastructure       Manage infrastructure with Terraform
    monitoring           Setup and manage monitoring stack
    security             Run security scans and compliance checks
    backup               Manage backups and disaster recovery
    pipeline             Execute full CI/CD pipeline
    status               Check deployment and infrastructure status
    logs                 Retrieve and analyze logs
    cleanup              Clean up resources and artifacts
    all                  Run complete DevOps automation workflow
    help                 Show this help message

OPTIONS:
    -e, --environment ENV        Target environment (development, staging, production)
    -v, --version VERSION        Application version to deploy
    -n, --namespace NAMESPACE    Kubernetes namespace
    -t, --deploy-type TYPE       Deployment type (rolling, blue-green, canary)
    --enable-monitoring          Enable monitoring stack deployment
    --enable-security            Enable security scanning and policies
    --enable-backup              Enable backup and disaster recovery
    --dry-run                    Show what would be done without executing
    --verbose                    Enable verbose output
    --force-deploy               Force deployment even if checks fail
    --skip-tests                 Skip test execution
    --push-images                Push container images to registry

EXAMPLES:
    # Full production deployment
    $0 all --environment production --version v1.2.3 --enable-monitoring --enable-security

    # Build and test only
    $0 build --environment staging
    $0 test --environment staging

    # Deploy to staging
    $0 deploy --environment staging --version v1.2.3 --deploy-type rolling

    # Infrastructure management
    $0 infrastructure --environment production --dry-run

    # Security and compliance
    $0 security --environment production --verbose

    # Monitoring setup
    $0 monitoring --environment production --enable-monitoring

    # Backup and disaster recovery
    $0 backup --environment production --enable-backup

    # Check status
    $0 status --environment production

    # Rollback deployment
    $0 rollback --environment production --version v1.2.2

EOF
}

# Parse command line arguments
parse_args() {
    COMMAND=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            build|test|deploy|rollback|infrastructure|monitoring|security|backup|pipeline|status|logs|cleanup|all|help)
                COMMAND="$1"
                shift
                ;;
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
            -t|--deploy-type)
                DEPLOY_TYPE="$2"
                shift 2
                ;;
            --enable-monitoring)
                ENABLE_MONITORING="true"
                shift
                ;;
            --enable-security)
                ENABLE_SECURITY="true"
                shift
                ;;
            --enable-backup)
                ENABLE_BACKUP="true"
                shift
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            --verbose)
                VERBOSE="true"
                shift
                ;;
            --force-deploy)
                FORCE_DEPLOY="true"
                shift
                ;;
            --skip-tests)
                SKIP_TESTS="true"
                shift
                ;;
            --push-images)
                PUSH_IMAGES="true"
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

# Setup DevOps environment
setup_devops_environment() {
    log_info "Setting up DevOps automation environment..."
    
    # Validate configuration files
    if [[ ! -f "$DEVOPS_CONFIG_DIR/comprehensive-devops-config.yaml" ]]; then
        log_error "DevOps configuration file not found: $DEVOPS_CONFIG_DIR/comprehensive-devops-config.yaml"
        exit 1
    fi
    
    # Check required tools
    local required_tools=("docker" "kubectl" "helm" "terraform")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "$tool is required but not installed"
            exit 1
        fi
    done
    
    # Check optional tools
    local optional_tools=("jq" "yq" "curl" "git")
    for tool in "${optional_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_warning "$tool is not installed, some features may be limited"
        fi
    done
    
    # Set environment variables
    export PROJECT_NAME="hackai"
    export BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    export COMMIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    
    log_success "DevOps environment setup completed"
}

# Build application and container images
build_application() {
    log_devops "Building application and container images..."
    
    local start_time=$(date +%s)
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would build application and container images"
        AUTOMATION_RESULTS["build"]="SKIPPED"
        return 0
    fi
    
    # Build Go binaries
    if build_go_binaries; then
        log_success "Go binaries built successfully"
    else
        log_error "Failed to build Go binaries"
        AUTOMATION_RESULTS["build_binaries"]="FAILED"
        return 1
    fi
    
    # Build container images
    if build_container_images; then
        log_success "Container images built successfully"
    else
        log_error "Failed to build container images"
        AUTOMATION_RESULTS["build_containers"]="FAILED"
        return 1
    fi
    
    # Push images if enabled
    if [[ "$PUSH_IMAGES" == "true" ]]; then
        if push_container_images; then
            log_success "Container images pushed successfully"
        else
            log_error "Failed to push container images"
            AUTOMATION_RESULTS["push_images"]="FAILED"
            return 1
        fi
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    AUTOMATION_RESULTS["build"]="SUCCESS"
    log_success "Application build completed in ${duration} seconds"
}

# Build Go binaries
build_go_binaries() {
    log_debug "Building Go binaries..."
    
    cd "$PROJECT_ROOT"
    
    # Create bin directory
    mkdir -p bin
    
    # Build services
    local services=("api-gateway" "user-service" "scanner-service" "threat-service")
    
    for service in "${services[@]}"; do
        log_info "Building $service..."
        
        if CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
            -ldflags "-X main.version=$VERSION -X main.buildTime=$BUILD_TIME -X main.commitHash=$COMMIT_HASH" \
            -o "bin/$service" "cmd/$service/main.go"; then
            log_success "$service built successfully"
        else
            log_error "Failed to build $service"
            return 1
        fi
    done
    
    return 0
}

# Build container images
build_container_images() {
    log_debug "Building container images..."
    
    cd "$PROJECT_ROOT"
    
    # Build images
    local services=("api-gateway" "user-service" "scanner-service" "threat-service")
    
    for service in "${services[@]}"; do
        log_info "Building container image for $service..."
        
        local image_name="hackai/$service:$VERSION"
        local dockerfile="deployments/docker/Dockerfile.$service"
        
        if docker build \
            --build-arg VERSION="$VERSION" \
            --build-arg BUILD_TIME="$BUILD_TIME" \
            --build-arg COMMIT_HASH="$COMMIT_HASH" \
            -t "$image_name" \
            -f "$dockerfile" .; then
            log_success "Container image built: $image_name"
        else
            log_error "Failed to build container image for $service"
            return 1
        fi
    done
    
    return 0
}

# Push container images
push_container_images() {
    log_debug "Pushing container images..."
    
    local registry="${DOCKER_REGISTRY:-ghcr.io}"
    local repository="${DOCKER_REPOSITORY:-dimajoyti/hackai}"
    
    # Login to registry if credentials are available
    if [[ -n "${DOCKER_REGISTRY_TOKEN:-}" ]]; then
        echo "$DOCKER_REGISTRY_TOKEN" | docker login "$registry" --username "$DOCKER_USERNAME" --password-stdin
    fi
    
    local services=("api-gateway" "user-service" "scanner-service" "threat-service")
    
    for service in "${services[@]}"; do
        log_info "Pushing container image for $service..."
        
        local local_image="hackai/$service:$VERSION"
        local remote_image="$registry/$repository/$service:$VERSION"
        
        # Tag for remote registry
        docker tag "$local_image" "$remote_image"
        
        # Push image
        if docker push "$remote_image"; then
            log_success "Container image pushed: $remote_image"
        else
            log_error "Failed to push container image for $service"
            return 1
        fi
    done
    
    return 0
}

# Run comprehensive test suite
run_tests() {
    if [[ "$SKIP_TESTS" == "true" ]]; then
        log_info "Skipping tests as requested"
        AUTOMATION_RESULTS["tests"]="SKIPPED"
        return 0
    fi
    
    log_devops "Running comprehensive test suite..."
    
    local start_time=$(date +%s)
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would run comprehensive test suite"
        AUTOMATION_RESULTS["tests"]="SKIPPED"
        return 0
    fi
    
    # Run unit tests
    if run_unit_tests; then
        log_success "Unit tests passed"
    else
        log_error "Unit tests failed"
        AUTOMATION_RESULTS["unit_tests"]="FAILED"
        return 1
    fi
    
    # Run integration tests
    if run_integration_tests; then
        log_success "Integration tests passed"
    else
        log_error "Integration tests failed"
        AUTOMATION_RESULTS["integration_tests"]="FAILED"
        return 1
    fi
    
    # Run security tests
    if [[ "$ENABLE_SECURITY" == "true" ]]; then
        if run_security_tests; then
            log_success "Security tests passed"
        else
            log_error "Security tests failed"
            AUTOMATION_RESULTS["security_tests"]="FAILED"
            return 1
        fi
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    AUTOMATION_RESULTS["tests"]="SUCCESS"
    log_success "Test suite completed in ${duration} seconds"
}

# Run unit tests
run_unit_tests() {
    log_debug "Running unit tests..."
    
    cd "$PROJECT_ROOT"
    
    # Run Go tests with coverage
    if go test -v -race -coverprofile=coverage.out ./...; then
        # Generate coverage report
        go tool cover -html=coverage.out -o coverage.html
        
        # Check coverage threshold
        local coverage=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
        local threshold=80
        
        if (( $(echo "$coverage >= $threshold" | bc -l) )); then
            log_success "Unit tests passed with ${coverage}% coverage (threshold: ${threshold}%)"
            return 0
        else
            log_error "Coverage ${coverage}% is below threshold ${threshold}%"
            return 1
        fi
    else
        log_error "Unit tests failed"
        return 1
    fi
}

# Run integration tests
run_integration_tests() {
    log_debug "Running integration tests..."
    
    cd "$PROJECT_ROOT"
    
    # Start test dependencies
    if docker-compose -f docker/docker-compose.test.yml up -d; then
        log_info "Test dependencies started"
        
        # Wait for services to be ready
        sleep 30
        
        # Run integration tests
        if go test -v -tags=integration ./test/integration/...; then
            log_success "Integration tests passed"
            docker-compose -f docker/docker-compose.test.yml down
            return 0
        else
            log_error "Integration tests failed"
            docker-compose -f docker/docker-compose.test.yml down
            return 1
        fi
    else
        log_error "Failed to start test dependencies"
        return 1
    fi
}

# Run security tests
run_security_tests() {
    log_debug "Running security tests..."
    
    cd "$PROJECT_ROOT"
    
    # Run gosec security scanner
    if command -v gosec &> /dev/null; then
        if gosec -fmt json -out gosec-report.json ./...; then
            log_success "Security scan passed"
        else
            log_error "Security scan found vulnerabilities"
            return 1
        fi
    else
        log_warning "gosec not installed, skipping security scan"
    fi
    
    # Run dependency vulnerability check
    if command -v nancy &> /dev/null; then
        if go list -json -m all | nancy sleuth; then
            log_success "Dependency vulnerability check passed"
        else
            log_error "Vulnerable dependencies found"
            return 1
        fi
    else
        log_warning "nancy not installed, skipping dependency check"
    fi
    
    return 0
}

# Deploy application
deploy_application() {
    log_devops "Deploying application to $ENVIRONMENT environment..."
    
    local start_time=$(date +%s)
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would deploy application to $ENVIRONMENT"
        AUTOMATION_RESULTS["deploy"]="SKIPPED"
        return 0
    fi
    
    # Validate deployment prerequisites
    if ! validate_deployment_prerequisites; then
        log_error "Deployment prerequisites validation failed"
        AUTOMATION_RESULTS["deploy_validation"]="FAILED"
        return 1
    fi
    
    # Deploy using Helm
    if deploy_with_helm; then
        log_success "Helm deployment completed"
    else
        log_error "Helm deployment failed"
        AUTOMATION_RESULTS["helm_deploy"]="FAILED"
        return 1
    fi
    
    # Run health checks
    if run_health_checks; then
        log_success "Health checks passed"
    else
        log_error "Health checks failed"
        AUTOMATION_RESULTS["health_checks"]="FAILED"
        return 1
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    AUTOMATION_RESULTS["deploy"]="SUCCESS"
    log_success "Application deployment completed in ${duration} seconds"
}

# Validate deployment prerequisites
validate_deployment_prerequisites() {
    log_debug "Validating deployment prerequisites..."
    
    # Check Kubernetes connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        return 1
    fi
    
    # Check namespace exists
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_info "Creating namespace: $NAMESPACE"
        kubectl create namespace "$NAMESPACE"
    fi
    
    # Check Helm
    if ! helm version &> /dev/null; then
        log_error "Helm is not available"
        return 1
    fi
    
    return 0
}

# Deploy with Helm
deploy_with_helm() {
    log_debug "Deploying with Helm..."
    
    local chart_path="$DEPLOYMENTS_DIR/helm/hackai"
    local values_file="$chart_path/values-$ENVIRONMENT.yaml"
    local release_name="hackai-$ENVIRONMENT"
    
    # Check if values file exists
    if [[ ! -f "$values_file" ]]; then
        log_warning "Values file not found: $values_file, using default values"
        values_file="$chart_path/values.yaml"
    fi
    
    # Deploy with Helm
    if helm upgrade --install "$release_name" "$chart_path" \
        --namespace "$NAMESPACE" \
        --values "$values_file" \
        --set app.version="$VERSION" \
        --set app.environment="$ENVIRONMENT" \
        --set global.imageTag="$VERSION" \
        --wait --timeout=15m; then
        log_success "Helm deployment successful"
        return 0
    else
        log_error "Helm deployment failed"
        return 1
    fi
}

# Run health checks
run_health_checks() {
    log_debug "Running health checks..."
    
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        log_info "Health check attempt $attempt/$max_attempts"
        
        # Check if pods are ready
        if kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/instance="hackai-$ENVIRONMENT" \
            -o jsonpath='{.items[*].status.conditions[?(@.type=="Ready")].status}' | grep -q "True"; then
            log_success "Pods are ready"
            
            # Check application health endpoint
            if check_application_health; then
                log_success "Application health check passed"
                return 0
            fi
        fi
        
        sleep 10
        ((attempt++))
    done
    
    log_error "Health checks failed after $max_attempts attempts"
    return 1
}

# Check application health
check_application_health() {
    # Get service endpoint
    local service_url
    if [[ "$ENVIRONMENT" == "production" ]]; then
        service_url="https://api.hackai.dev"
    elif [[ "$ENVIRONMENT" == "staging" ]]; then
        service_url="https://staging-api.hackai.dev"
    else
        # Port forward for local testing
        kubectl port-forward -n "$NAMESPACE" service/hackai-api-gateway 8080:8080 &
        local port_forward_pid=$!
        sleep 5
        service_url="http://localhost:8080"
    fi
    
    # Check health endpoint
    if curl -f -s "$service_url/health" > /dev/null; then
        if [[ -n "${port_forward_pid:-}" ]]; then
            kill $port_forward_pid 2>/dev/null || true
        fi
        return 0
    else
        if [[ -n "${port_forward_pid:-}" ]]; then
            kill $port_forward_pid 2>/dev/null || true
        fi
        return 1
    fi
}

# Record automation result
record_automation_result() {
    local operation="$1"
    local result="$2"
    
    AUTOMATION_RESULTS["$operation"]="$result"
    TOTAL_OPERATIONS=$((TOTAL_OPERATIONS + 1))
    
    if [[ "$result" == "SUCCESS" ]]; then
        SUCCESSFUL_OPERATIONS=$((SUCCESSFUL_OPERATIONS + 1))
    else
        FAILED_OPERATIONS=$((FAILED_OPERATIONS + 1))
    fi
}

# Generate automation report
generate_automation_report() {
    log_info "Generating DevOps automation report..."
    
    local report_file="$PROJECT_ROOT/devops-automation-report-$(date +%Y%m%d_%H%M%S).html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>HackAI DevOps Automation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2563eb; color: white; padding: 20px; text-align: center; }
        .summary { background: #f8fafc; padding: 15px; margin: 20px 0; }
        .success { color: #059669; }
        .failed { color: #dc2626; }
        .skipped { color: #d97706; }
        .section { margin: 20px 0; }
        .result { margin: 5px 0; padding: 5px; border-left: 3px solid #e5e7eb; }
        .result.success { border-left-color: #059669; }
        .result.failed { border-left-color: #dc2626; }
        .result.skipped { border-left-color: #d97706; }
    </style>
</head>
<body>
    <div class="header">
        <h1>HackAI DevOps Automation Report</h1>
        <p>Generated: $(date)</p>
        <p>Environment: $ENVIRONMENT | Version: $VERSION</p>
    </div>
    
    <div class="summary">
        <h2>Automation Summary</h2>
        <p><strong>Total Operations:</strong> $TOTAL_OPERATIONS</p>
        <p><strong>Successful:</strong> <span class="success">$SUCCESSFUL_OPERATIONS</span></p>
        <p><strong>Failed:</strong> <span class="failed">$FAILED_OPERATIONS</span></p>
        <p><strong>Success Rate:</strong> $(( SUCCESSFUL_OPERATIONS * 100 / TOTAL_OPERATIONS ))%</p>
    </div>
    
    <div class="section">
        <h2>Operation Results</h2>
EOF

    for operation in "${!AUTOMATION_RESULTS[@]}"; do
        local result="${AUTOMATION_RESULTS[$operation]}"
        local class="success"
        if [[ "$result" == "FAILED" ]]; then
            class="failed"
        elif [[ "$result" == "SKIPPED" ]]; then
            class="skipped"
        fi
        echo "        <div class=\"result $class\">$operation: $result</div>" >> "$report_file"
    done
    
    cat >> "$report_file" << EOF
    </div>
</body>
</html>
EOF
    
    log_success "DevOps automation report generated: $report_file"
}

# Main function
main() {
    log_info "Starting HackAI Production Deployment & DevOps Automation"
    log_info "Command: $COMMAND, Environment: $ENVIRONMENT, Version: $VERSION"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_warning "Running in DRY RUN mode - no changes will be made"
    fi
    
    setup_devops_environment
    
    case "$COMMAND" in
        "build")
            build_application
            ;;
        "test")
            run_tests
            ;;
        "deploy")
            deploy_application
            ;;
        "all")
            build_application
            run_tests
            deploy_application
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
    
    # Generate automation report
    generate_automation_report
    
    # Calculate overall success
    local overall_success=true
    for result in "${AUTOMATION_RESULTS[@]}"; do
        if [[ "$result" == "FAILED" ]]; then
            overall_success=false
            break
        fi
    done
    
    if [[ "$overall_success" == "true" ]]; then
        log_success "DevOps automation completed successfully! 🚀"
        exit 0
    else
        log_error "Some DevOps operations failed. Check the results above."
        exit 1
    fi
}

# Initialize extra args array
EXTRA_ARGS=()

# Parse arguments and run main function
parse_args "$@"
main
