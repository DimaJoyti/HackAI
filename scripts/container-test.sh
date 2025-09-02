#!/bin/bash

# HackAI Container Testing and Validation Script
# Comprehensive testing for container deployments and Kubernetes manifests

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEPLOYMENTS_DIR="$PROJECT_ROOT/deployments"

# Test configuration
ENVIRONMENT="${ENVIRONMENT:-development}"
NAMESPACE="${NAMESPACE:-hackai-test}"
REGISTRY="${REGISTRY:-ghcr.io/hackai}"
IMAGE_TAG="${IMAGE_TAG:-test}"
TEST_TIMEOUT="${TEST_TIMEOUT:-300}"
PARALLEL_TESTS="${PARALLEL_TESTS:-true}"

# Test results
declare -A TEST_RESULTS=()
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

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

log_test() {
    echo -e "${PURPLE}[TEST]${NC} $1"
}

# Test result tracking
record_test_result() {
    local test_name="$1"
    local result="$2"
    
    TEST_RESULTS["$test_name"]="$result"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if [[ "$result" == "PASS" ]]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        log_success "✓ $test_name"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        log_error "✗ $test_name: $result"
    fi
}

# Docker tests
test_docker_build() {
    log_test "Testing Docker image builds..."
    
    local services=("api-gateway" "user-service" "threat-service" "scanner-service")
    local build_errors=()
    
    for service in "${services[@]}"; do
        log_info "Building $service image..."
        
        if docker build \
            --build-arg SERVICE_NAME="$service" \
            --build-arg VERSION="$IMAGE_TAG" \
            -t "$REGISTRY/$service:$IMAGE_TAG" \
            -f "$DEPLOYMENTS_DIR/docker/Dockerfile.multi-stage" \
            --target runtime \
            "$PROJECT_ROOT" &> /tmp/build_${service}.log; then
            record_test_result "docker_build_$service" "PASS"
        else
            build_errors+=("$service")
            record_test_result "docker_build_$service" "FAIL - Build failed"
        fi
    done
    
    if [[ ${#build_errors[@]} -eq 0 ]]; then
        record_test_result "docker_build_all" "PASS"
    else
        record_test_result "docker_build_all" "FAIL - Failed services: ${build_errors[*]}"
    fi
}

# Docker security tests
test_docker_security() {
    log_test "Testing Docker image security..."
    
    local services=("api-gateway" "user-service" "threat-service" "scanner-service")
    
    for service in "${services[@]}"; do
        local image="$REGISTRY/$service:$IMAGE_TAG"
        
        # Test 1: Check if image runs as non-root
        local user_id
        user_id=$(docker run --rm "$image" id -u 2>/dev/null || echo "unknown")
        
        if [[ "$user_id" != "0" && "$user_id" != "unknown" ]]; then
            record_test_result "security_nonroot_$service" "PASS"
        else
            record_test_result "security_nonroot_$service" "FAIL - Running as root or unknown user"
        fi
        
        # Test 2: Check for security vulnerabilities (if trivy is available)
        if command -v trivy &> /dev/null; then
            if trivy image --exit-code 0 --severity HIGH,CRITICAL "$image" &> /tmp/trivy_${service}.log; then
                record_test_result "security_vuln_$service" "PASS"
            else
                record_test_result "security_vuln_$service" "FAIL - High/Critical vulnerabilities found"
            fi
        else
            record_test_result "security_vuln_$service" "SKIP - Trivy not available"
        fi
    done
}

# Docker Compose tests
test_docker_compose() {
    log_test "Testing Docker Compose deployment..."
    
    cd "$DEPLOYMENTS_DIR/docker"
    
    # Start services
    if docker-compose -f docker-compose.dev.yml up -d --build &> /tmp/compose_up.log; then
        record_test_result "compose_start" "PASS"
        
        # Wait for services to be ready
        sleep 30
        
        # Test service health
        local services=("api-gateway" "user-service" "threat-service" "scanner-service")
        local healthy_services=0
        
        for service in "${services[@]}"; do
            local container_name="hackai-${service}-dev"
            
            if docker exec "$container_name" curl -f http://localhost:8081/health/ready &> /dev/null; then
                record_test_result "compose_health_$service" "PASS"
                healthy_services=$((healthy_services + 1))
            else
                record_test_result "compose_health_$service" "FAIL - Health check failed"
            fi
        done
        
        # Test inter-service communication
        if docker exec hackai-api-gateway-dev curl -f http://user-service:8080/health/ready &> /dev/null; then
            record_test_result "compose_communication" "PASS"
        else
            record_test_result "compose_communication" "FAIL - Inter-service communication failed"
        fi
        
        # Cleanup
        docker-compose -f docker-compose.dev.yml down -v &> /tmp/compose_down.log
        record_test_result "compose_cleanup" "PASS"
        
    else
        record_test_result "compose_start" "FAIL - Failed to start services"
    fi
    
    cd - > /dev/null
}

# Kubernetes manifest validation
test_kubernetes_manifests() {
    log_test "Testing Kubernetes manifest validation..."
    
    local manifest_dirs=(
        "$DEPLOYMENTS_DIR/kubernetes/enhanced"
        "$DEPLOYMENTS_DIR/kubernetes/base"
    )
    
    for dir in "${manifest_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local dir_name=$(basename "$dir")
            
            # Validate YAML syntax
            if find "$dir" -name "*.yaml" -o -name "*.yml" | xargs -I {} kubectl apply --dry-run=client -f {} &> /tmp/k8s_validate_${dir_name}.log; then
                record_test_result "k8s_validate_$dir_name" "PASS"
            else
                record_test_result "k8s_validate_$dir_name" "FAIL - YAML validation failed"
            fi
            
            # Check for security best practices
            local security_issues=0
            
            # Check for privileged containers
            if grep -r "privileged.*true" "$dir" &> /dev/null; then
                security_issues=$((security_issues + 1))
            fi
            
            # Check for root users
            if grep -r "runAsUser.*0" "$dir" &> /dev/null; then
                security_issues=$((security_issues + 1))
            fi
            
            # Check for missing resource limits
            if ! grep -r "limits:" "$dir" &> /dev/null; then
                security_issues=$((security_issues + 1))
            fi
            
            if [[ $security_issues -eq 0 ]]; then
                record_test_result "k8s_security_$dir_name" "PASS"
            else
                record_test_result "k8s_security_$dir_name" "FAIL - $security_issues security issues found"
            fi
        fi
    done
}

# Kubernetes deployment tests
test_kubernetes_deployment() {
    log_test "Testing Kubernetes deployment..."
    
    # Create test namespace
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - &> /dev/null
    
    # Deploy using kubectl
    if kubectl apply -f "$DEPLOYMENTS_DIR/kubernetes/enhanced/" -n "$NAMESPACE" &> /tmp/k8s_deploy.log; then
        record_test_result "k8s_deploy" "PASS"
        
        # Wait for deployments to be ready
        local timeout=$TEST_TIMEOUT
        local ready=false
        
        while [[ $timeout -gt 0 && "$ready" == "false" ]]; do
            if kubectl wait --for=condition=available deployment --all -n "$NAMESPACE" --timeout=10s &> /dev/null; then
                ready=true
                record_test_result "k8s_ready" "PASS"
            else
                timeout=$((timeout - 10))
                sleep 10
            fi
        done
        
        if [[ "$ready" == "false" ]]; then
            record_test_result "k8s_ready" "FAIL - Deployments not ready within timeout"
        fi
        
        # Test pod health
        local pods
        pods=$(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}')
        
        for pod in $pods; do
            if kubectl exec "$pod" -n "$NAMESPACE" -- curl -f http://localhost:8081/health/ready &> /dev/null; then
                record_test_result "k8s_pod_health_$pod" "PASS"
            else
                record_test_result "k8s_pod_health_$pod" "FAIL - Pod health check failed"
            fi
        done
        
        # Test services
        local services
        services=$(kubectl get services -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}')
        
        for service in $services; do
            if kubectl get endpoints "$service" -n "$NAMESPACE" -o jsonpath='{.subsets[*].addresses[*].ip}' | grep -q .; then
                record_test_result "k8s_service_$service" "PASS"
            else
                record_test_result "k8s_service_$service" "FAIL - Service has no endpoints"
            fi
        done
        
        # Cleanup
        kubectl delete namespace "$NAMESPACE" --ignore-not-found=true &> /dev/null
        record_test_result "k8s_cleanup" "PASS"
        
    else
        record_test_result "k8s_deploy" "FAIL - Deployment failed"
    fi
}

# Helm chart tests
test_helm_charts() {
    log_test "Testing Helm charts..."
    
    local helm_dir="$DEPLOYMENTS_DIR/helm/hackai"
    
    if [[ -d "$helm_dir" ]]; then
        # Validate Helm chart
        if helm lint "$helm_dir" &> /tmp/helm_lint.log; then
            record_test_result "helm_lint" "PASS"
        else
            record_test_result "helm_lint" "FAIL - Helm lint failed"
        fi
        
        # Test Helm template rendering
        if helm template test-release "$helm_dir" --namespace "$NAMESPACE" &> /tmp/helm_template.log; then
            record_test_result "helm_template" "PASS"
        else
            record_test_result "helm_template" "FAIL - Template rendering failed"
        fi
        
        # Test Helm dry-run install
        if helm install test-release "$helm_dir" --namespace "$NAMESPACE" --create-namespace --dry-run &> /tmp/helm_dryrun.log; then
            record_test_result "helm_dryrun" "PASS"
        else
            record_test_result "helm_dryrun" "FAIL - Dry-run install failed"
        fi
    else
        record_test_result "helm_charts" "SKIP - Helm charts not found"
    fi
}

# Performance tests
test_performance() {
    log_test "Testing container performance..."
    
    local services=("api-gateway" "user-service" "threat-service" "scanner-service")
    
    for service in "${services[@]}"; do
        local image="$REGISTRY/$service:$IMAGE_TAG"
        
        # Test image size
        local image_size
        image_size=$(docker images "$image" --format "table {{.Size}}" | tail -n +2 | head -1)
        
        # Convert size to MB for comparison
        local size_mb
        if [[ "$image_size" == *"GB"* ]]; then
            size_mb=$(echo "$image_size" | sed 's/GB//' | awk '{print $1 * 1024}')
        else
            size_mb=$(echo "$image_size" | sed 's/MB//' | awk '{print $1}')
        fi
        
        # Check if image size is reasonable (< 500MB)
        if (( $(echo "$size_mb < 500" | bc -l) )); then
            record_test_result "perf_size_$service" "PASS - ${image_size}"
        else
            record_test_result "perf_size_$service" "FAIL - Image too large: ${image_size}"
        fi
        
        # Test startup time
        local start_time=$(date +%s)
        local container_id
        container_id=$(docker run -d "$image")
        
        # Wait for container to be ready (max 30 seconds)
        local ready=false
        local timeout=30
        
        while [[ $timeout -gt 0 && "$ready" == "false" ]]; do
            if docker exec "$container_id" curl -f http://localhost:8081/health/ready &> /dev/null; then
                ready=true
            else
                timeout=$((timeout - 1))
                sleep 1
            fi
        done
        
        local end_time=$(date +%s)
        local startup_time=$((end_time - start_time))
        
        docker rm -f "$container_id" &> /dev/null
        
        # Check if startup time is reasonable (< 30 seconds)
        if [[ $startup_time -lt 30 && "$ready" == "true" ]]; then
            record_test_result "perf_startup_$service" "PASS - ${startup_time}s"
        else
            record_test_result "perf_startup_$service" "FAIL - Startup time: ${startup_time}s, Ready: $ready"
        fi
    done
}

# Generate test report
generate_report() {
    log_info "Generating test report..."
    
    local report_file="/tmp/hackai_container_test_report.txt"
    
    cat > "$report_file" << EOF
HackAI Container & Kubernetes Deployment Test Report
===================================================

Test Summary:
- Total Tests: $TOTAL_TESTS
- Passed: $PASSED_TESTS
- Failed: $FAILED_TESTS
- Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%

Test Results:
EOF

    for test_name in "${!TEST_RESULTS[@]}"; do
        echo "- $test_name: ${TEST_RESULTS[$test_name]}" >> "$report_file"
    done
    
    echo "" >> "$report_file"
    echo "Generated at: $(date)" >> "$report_file"
    
    log_info "Test report saved to: $report_file"
    
    # Display summary
    echo ""
    echo "=========================================="
    echo "           TEST SUMMARY"
    echo "=========================================="
    echo "Total Tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $FAILED_TESTS"
    echo "Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%"
    echo "=========================================="
    
    if [[ $FAILED_TESTS -gt 0 ]]; then
        echo ""
        log_error "Some tests failed. Check the logs in /tmp/ for details."
        return 1
    else
        echo ""
        log_success "All tests passed!"
        return 0
    fi
}

# Main test execution
main() {
    log_info "Starting HackAI Container & Kubernetes Deployment Tests"
    log_info "Environment: $ENVIRONMENT"
    log_info "Namespace: $NAMESPACE"
    log_info "Registry: $REGISTRY"
    log_info "Image Tag: $IMAGE_TAG"
    
    # Run test suites
    test_docker_build
    test_docker_security
    test_docker_compose
    test_kubernetes_manifests
    test_kubernetes_deployment
    test_helm_charts
    test_performance
    
    # Generate report
    generate_report
}

# Run main function
main "$@"
