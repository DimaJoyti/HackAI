#!/bin/bash

# HackAI Test Automation and Quality Assurance Script
# Comprehensive testing automation with quality gates and CI/CD integration

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
TEST_RESULTS_DIR="$PROJECT_ROOT/test-results"
COVERAGE_DIR="$TEST_RESULTS_DIR/coverage"
REPORTS_DIR="$TEST_RESULTS_DIR/reports"

# Default values
ENVIRONMENT="${ENVIRONMENT:-development}"
TEST_SUITE="${TEST_SUITE:-all}"
COVERAGE_THRESHOLD="${COVERAGE_THRESHOLD:-80}"
QUALITY_GATE_ENABLED="${QUALITY_GATE_ENABLED:-true}"
PARALLEL_EXECUTION="${PARALLEL_EXECUTION:-true}"
GENERATE_REPORTS="${GENERATE_REPORTS:-true}"
UPLOAD_RESULTS="${UPLOAD_RESULTS:-false}"
DRY_RUN="${DRY_RUN:-false}"
VERBOSE="${VERBOSE:-false}"
FAIL_FAST="${FAIL_FAST:-false}"
ENABLE_PROFILING="${ENABLE_PROFILING:-false}"
ENABLE_RACE_DETECTION="${ENABLE_RACE_DETECTION:-true}"
ENABLE_MUTATION_TESTING="${ENABLE_MUTATION_TESTING:-false}"
ENABLE_SECURITY_TESTING="${ENABLE_SECURITY_TESTING:-true}"
ENABLE_PERFORMANCE_TESTING="${ENABLE_PERFORMANCE_TESTING:-true}"
ENABLE_AI_TESTING="${ENABLE_AI_TESTING:-true}"

# Test results
declare -A TEST_RESULTS=()
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0
COVERAGE_PERCENTAGE=0
QUALITY_SCORE=0
PERFORMANCE_SCORE=0
SECURITY_SCORE=0

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

log_test() {
    echo -e "${CYAN}[TEST]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
HackAI Test Automation and Quality Assurance Script

Usage: $0 [COMMAND] [OPTIONS]

COMMANDS:
    test                 Run test suites
    unit                 Run unit tests only
    integration          Run integration tests only
    e2e                  Run end-to-end tests only
    performance          Run performance tests only
    security             Run security tests only
    ai                   Run AI-specific tests only
    coverage             Generate coverage report
    quality              Run quality assessment
    benchmark            Run benchmark tests
    mutation             Run mutation tests
    lint                 Run code linting
    format               Check code formatting
    validate             Run validation tests
    all                  Run all test suites and quality checks
    help                 Show this help message

OPTIONS:
    -e, --environment ENV        Set environment (development, staging, production)
    -s, --suite SUITE           Test suite to run (unit, integration, e2e, performance, security, ai, all)
    -c, --coverage-threshold N   Coverage threshold percentage (default: 80)
    --quality-gate              Enable quality gates (default: true)
    --parallel                  Enable parallel test execution
    --generate-reports          Generate test reports
    --upload-results            Upload results to CI/CD system
    --dry-run                   Show what would be done without executing
    --verbose                   Enable verbose output
    --fail-fast                 Stop on first test failure
    --enable-profiling          Enable test profiling
    --enable-race               Enable race condition detection
    --enable-mutation           Enable mutation testing
    --enable-security           Enable security testing
    --enable-performance        Enable performance testing
    --enable-ai                 Enable AI testing

EXAMPLES:
    # Run all tests with coverage
    $0 test --coverage-threshold 85 --generate-reports

    # Run unit tests only
    $0 unit --parallel --verbose

    # Run performance tests
    $0 performance --environment staging

    # Run quality assessment
    $0 quality --enable-mutation --generate-reports

    # Run comprehensive test suite
    $0 all --quality-gate --upload-results

EOF
}

# Parse command line arguments
parse_args() {
    COMMAND=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            test|unit|integration|e2e|performance|security|ai|coverage|quality|benchmark|mutation|lint|format|validate|all|help)
                COMMAND="$1"
                shift
                ;;
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -s|--suite)
                TEST_SUITE="$2"
                shift 2
                ;;
            -c|--coverage-threshold)
                COVERAGE_THRESHOLD="$2"
                shift 2
                ;;
            --quality-gate)
                QUALITY_GATE_ENABLED="true"
                shift
                ;;
            --parallel)
                PARALLEL_EXECUTION="true"
                shift
                ;;
            --generate-reports)
                GENERATE_REPORTS="true"
                shift
                ;;
            --upload-results)
                UPLOAD_RESULTS="true"
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
            --fail-fast)
                FAIL_FAST="true"
                shift
                ;;
            --enable-profiling)
                ENABLE_PROFILING="true"
                shift
                ;;
            --enable-race)
                ENABLE_RACE_DETECTION="true"
                shift
                ;;
            --enable-mutation)
                ENABLE_MUTATION_TESTING="true"
                shift
                ;;
            --enable-security)
                ENABLE_SECURITY_TESTING="true"
                shift
                ;;
            --enable-performance)
                ENABLE_PERFORMANCE_TESTING="true"
                shift
                ;;
            --enable-ai)
                ENABLE_AI_TESTING="true"
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

# Setup test environment
setup_test_environment() {
    log_info "Setting up test environment..."
    
    # Create test directories
    mkdir -p "$TEST_RESULTS_DIR"
    mkdir -p "$COVERAGE_DIR"
    mkdir -p "$REPORTS_DIR"
    
    # Set environment variables
    export GO_ENV="$ENVIRONMENT"
    export TEST_ENV="$ENVIRONMENT"
    export CGO_ENABLED=1
    
    if [[ "$ENABLE_RACE_DETECTION" == "true" ]]; then
        export GORACE="halt_on_error=1"
    fi
    
    # Clean previous results
    if [[ "$DRY_RUN" == "false" ]]; then
        rm -rf "$TEST_RESULTS_DIR"/*
        mkdir -p "$TEST_RESULTS_DIR" "$COVERAGE_DIR" "$REPORTS_DIR"
    fi
    
    log_success "Test environment setup completed"
}

# Run unit tests
run_unit_tests() {
    log_test "Running unit tests..."
    
    local test_args=()
    test_args+=("-v")
    test_args+=("-timeout=10m")
    
    if [[ "$ENABLE_RACE_DETECTION" == "true" ]]; then
        test_args+=("-race")
    fi
    
    if [[ "$PARALLEL_EXECUTION" == "true" ]]; then
        test_args+=("-parallel=4")
    fi
    
    if [[ "$FAIL_FAST" == "true" ]]; then
        test_args+=("-failfast")
    fi
    
    # Coverage settings
    local coverage_file="$COVERAGE_DIR/unit-coverage.out"
    test_args+=("-coverprofile=$coverage_file")
    test_args+=("-covermode=atomic")
    
    # Test packages
    local test_packages=(
        "./pkg/..."
        "./cmd/..."
        "./internal/..."
    )
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would run unit tests with args: ${test_args[*]}"
        return 0
    fi
    
    local start_time=$(date +%s)
    
    # Run tests
    if go test "${test_args[@]}" "${test_packages[@]}" > "$TEST_RESULTS_DIR/unit-tests.log" 2>&1; then
        TEST_RESULTS["unit_tests"]="PASS"
        log_success "Unit tests passed"
    else
        TEST_RESULTS["unit_tests"]="FAIL"
        log_error "Unit tests failed"
        if [[ "$FAIL_FAST" == "true" ]]; then
            return 1
        fi
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Parse test results
    parse_test_results "$TEST_RESULTS_DIR/unit-tests.log" "unit"
    
    log_info "Unit tests completed in ${duration} seconds"
    
    # Generate coverage report
    if [[ -f "$coverage_file" ]]; then
        generate_coverage_report "$coverage_file" "unit"
    fi
}

# Run integration tests
run_integration_tests() {
    log_test "Running integration tests..."
    
    local test_args=()
    test_args+=("-v")
    test_args+=("-timeout=20m")
    test_args+=("-tags=integration")
    
    if [[ "$ENABLE_RACE_DETECTION" == "true" ]]; then
        test_args+=("-race")
    fi
    
    # Coverage settings
    local coverage_file="$COVERAGE_DIR/integration-coverage.out"
    test_args+=("-coverprofile=$coverage_file")
    test_args+=("-covermode=atomic")
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would run integration tests"
        return 0
    fi
    
    # Setup integration test environment
    setup_integration_environment
    
    local start_time=$(date +%s)
    
    # Run tests
    if go test "${test_args[@]}" ./test/integration/... > "$TEST_RESULTS_DIR/integration-tests.log" 2>&1; then
        TEST_RESULTS["integration_tests"]="PASS"
        log_success "Integration tests passed"
    else
        TEST_RESULTS["integration_tests"]="FAIL"
        log_error "Integration tests failed"
        if [[ "$FAIL_FAST" == "true" ]]; then
            cleanup_integration_environment
            return 1
        fi
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Parse test results
    parse_test_results "$TEST_RESULTS_DIR/integration-tests.log" "integration"
    
    # Cleanup
    cleanup_integration_environment
    
    log_info "Integration tests completed in ${duration} seconds"
    
    # Generate coverage report
    if [[ -f "$coverage_file" ]]; then
        generate_coverage_report "$coverage_file" "integration"
    fi
}

# Run performance tests
run_performance_tests() {
    if [[ "$ENABLE_PERFORMANCE_TESTING" != "true" ]]; then
        log_info "Performance testing disabled, skipping..."
        return 0
    fi
    
    log_test "Running performance tests..."
    
    local test_args=()
    test_args+=("-v")
    test_args+=("-timeout=30m")
    test_args+=("-tags=performance")
    test_args+=("-bench=.")
    test_args+=("-benchmem")
    test_args+=("-benchtime=10s")
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would run performance tests"
        return 0
    fi
    
    local start_time=$(date +%s)
    
    # Run performance tests
    if go test "${test_args[@]}" ./test/performance/... > "$TEST_RESULTS_DIR/performance-tests.log" 2>&1; then
        TEST_RESULTS["performance_tests"]="PASS"
        log_success "Performance tests passed"
    else
        TEST_RESULTS["performance_tests"]="FAIL"
        log_error "Performance tests failed"
        if [[ "$FAIL_FAST" == "true" ]]; then
            return 1
        fi
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Parse performance results
    parse_performance_results "$TEST_RESULTS_DIR/performance-tests.log"
    
    log_info "Performance tests completed in ${duration} seconds"
}

# Run security tests
run_security_tests() {
    if [[ "$ENABLE_SECURITY_TESTING" != "true" ]]; then
        log_info "Security testing disabled, skipping..."
        return 0
    fi
    
    log_test "Running security tests..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would run security tests"
        return 0
    fi
    
    local start_time=$(date +%s)
    
    # Run security tests
    if go test -v -timeout=15m -tags=security ./test/security/... > "$TEST_RESULTS_DIR/security-tests.log" 2>&1; then
        TEST_RESULTS["security_tests"]="PASS"
        log_success "Security tests passed"
    else
        TEST_RESULTS["security_tests"]="FAIL"
        log_error "Security tests failed"
        if [[ "$FAIL_FAST" == "true" ]]; then
            return 1
        fi
    fi
    
    # Run security scanning
    run_security_scanning
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_info "Security tests completed in ${duration} seconds"
}

# Run AI-specific tests
run_ai_tests() {
    if [[ "$ENABLE_AI_TESTING" != "true" ]]; then
        log_info "AI testing disabled, skipping..."
        return 0
    fi
    
    log_test "Running AI-specific tests..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would run AI tests"
        return 0
    fi
    
    local start_time=$(date +%s)
    
    # Run AI tests
    if go test -v -timeout=20m -tags=ai ./test/ai/... > "$TEST_RESULTS_DIR/ai-tests.log" 2>&1; then
        TEST_RESULTS["ai_tests"]="PASS"
        log_success "AI tests passed"
    else
        TEST_RESULTS["ai_tests"]="FAIL"
        log_error "AI tests failed"
        if [[ "$FAIL_FAST" == "true" ]]; then
            return 1
        fi
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_info "AI tests completed in ${duration} seconds"
}

# Generate coverage report
generate_coverage_report() {
    local coverage_file="$1"
    local test_type="$2"
    
    log_info "Generating coverage report for $test_type tests..."
    
    if [[ ! -f "$coverage_file" ]]; then
        log_warning "Coverage file not found: $coverage_file"
        return 1
    fi
    
    # Generate HTML coverage report
    local html_report="$COVERAGE_DIR/${test_type}-coverage.html"
    go tool cover -html="$coverage_file" -o "$html_report"
    
    # Calculate coverage percentage
    local coverage_percent
    coverage_percent=$(go tool cover -func="$coverage_file" | grep "total:" | awk '{print $3}' | sed 's/%//')
    
    if [[ -n "$coverage_percent" ]]; then
        COVERAGE_PERCENTAGE=$(echo "$coverage_percent" | cut -d. -f1)
        log_info "$test_type coverage: ${coverage_percent}%"
        
        # Check coverage threshold
        if (( $(echo "$coverage_percent >= $COVERAGE_THRESHOLD" | bc -l) )); then
            log_success "$test_type coverage meets threshold (${coverage_percent}% >= ${COVERAGE_THRESHOLD}%)"
        else
            log_error "$test_type coverage below threshold (${coverage_percent}% < ${COVERAGE_THRESHOLD}%)"
            TEST_RESULTS["coverage_threshold"]="FAIL"
        fi
    else
        log_warning "Could not calculate coverage percentage"
    fi
}

# Parse test results
parse_test_results() {
    local log_file="$1"
    local test_type="$2"
    
    if [[ ! -f "$log_file" ]]; then
        return 1
    fi
    
    # Extract test statistics
    local passed
    local failed
    local skipped
    
    passed=$(grep -c "PASS:" "$log_file" || echo "0")
    failed=$(grep -c "FAIL:" "$log_file" || echo "0")
    skipped=$(grep -c "SKIP:" "$log_file" || echo "0")
    
    TOTAL_TESTS=$((TOTAL_TESTS + passed + failed + skipped))
    PASSED_TESTS=$((PASSED_TESTS + passed))
    FAILED_TESTS=$((FAILED_TESTS + failed))
    SKIPPED_TESTS=$((SKIPPED_TESTS + skipped))
    
    log_debug "$test_type results: $passed passed, $failed failed, $skipped skipped"
}

# Run quality gates
run_quality_gates() {
    if [[ "$QUALITY_GATE_ENABLED" != "true" ]]; then
        log_info "Quality gates disabled, skipping..."
        return 0
    fi
    
    log_test "Running quality gates..."
    
    local quality_passed=true
    
    # Coverage gate
    if [[ "$COVERAGE_PERCENTAGE" -lt "$COVERAGE_THRESHOLD" ]]; then
        log_error "Quality gate failed: Coverage $COVERAGE_PERCENTAGE% < $COVERAGE_THRESHOLD%"
        quality_passed=false
    fi
    
    # Test failure rate gate
    if [[ "$TOTAL_TESTS" -gt 0 ]]; then
        local failure_rate=$((FAILED_TESTS * 100 / TOTAL_TESTS))
        if [[ "$failure_rate" -gt 5 ]]; then
            log_error "Quality gate failed: Test failure rate $failure_rate% > 5%"
            quality_passed=false
        fi
    fi
    
    # Security gate
    if [[ "${TEST_RESULTS[security_tests]:-}" == "FAIL" ]]; then
        log_error "Quality gate failed: Security tests failed"
        quality_passed=false
    fi
    
    if [[ "$quality_passed" == "true" ]]; then
        log_success "All quality gates passed"
        TEST_RESULTS["quality_gates"]="PASS"
    else
        log_error "Quality gates failed"
        TEST_RESULTS["quality_gates"]="FAIL"
        return 1
    fi
}

# Generate comprehensive test report
generate_test_report() {
    if [[ "$GENERATE_REPORTS" != "true" ]]; then
        return 0
    fi
    
    log_info "Generating comprehensive test report..."
    
    local report_file="$REPORTS_DIR/test-report-$(date +%Y%m%d_%H%M%S).html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>HackAI Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
        .summary { background: #ecf0f1; padding: 15px; margin: 20px 0; }
        .pass { color: #27ae60; }
        .fail { color: #e74c3c; }
        .section { margin: 20px 0; }
        .metric { display: inline-block; margin: 10px; padding: 10px; border: 1px solid #ddd; }
    </style>
</head>
<body>
    <div class="header">
        <h1>HackAI Test Report</h1>
        <p>Generated: $(date)</p>
        <p>Environment: $ENVIRONMENT</p>
    </div>
    
    <div class="summary">
        <h2>Test Summary</h2>
        <div class="metric">
            <strong>Total Tests:</strong> $TOTAL_TESTS
        </div>
        <div class="metric">
            <strong>Passed:</strong> <span class="pass">$PASSED_TESTS</span>
        </div>
        <div class="metric">
            <strong>Failed:</strong> <span class="fail">$FAILED_TESTS</span>
        </div>
        <div class="metric">
            <strong>Skipped:</strong> $SKIPPED_TESTS
        </div>
        <div class="metric">
            <strong>Coverage:</strong> ${COVERAGE_PERCENTAGE}%
        </div>
    </div>
    
    <div class="section">
        <h2>Test Results by Suite</h2>
        <ul>
EOF

    for test_suite in "${!TEST_RESULTS[@]}"; do
        local result="${TEST_RESULTS[$test_suite]}"
        local class="pass"
        if [[ "$result" == "FAIL" ]]; then
            class="fail"
        fi
        echo "            <li><span class=\"$class\">$test_suite: $result</span></li>" >> "$report_file"
    done
    
    cat >> "$report_file" << EOF
        </ul>
    </div>
</body>
</html>
EOF
    
    log_success "Test report generated: $report_file"
}

# Setup integration test environment
setup_integration_environment() {
    log_debug "Setting up integration test environment..."
    
    # Start test database
    if command -v docker &> /dev/null; then
        docker run -d --name hackai-test-db \
            -e POSTGRES_DB=hackai_test \
            -e POSTGRES_USER=test \
            -e POSTGRES_PASSWORD=test \
            -p 5433:5432 \
            postgres:15-alpine &> /dev/null || true
        
        # Wait for database to be ready
        sleep 5
    fi
}

# Cleanup integration test environment
cleanup_integration_environment() {
    log_debug "Cleaning up integration test environment..."
    
    if command -v docker &> /dev/null; then
        docker stop hackai-test-db &> /dev/null || true
        docker rm hackai-test-db &> /dev/null || true
    fi
}

# Main function
main() {
    log_info "Starting HackAI Test Automation"
    log_info "Command: $COMMAND, Environment: $ENVIRONMENT"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_warning "Running in DRY RUN mode - no tests will be executed"
    fi
    
    setup_test_environment
    
    case "$COMMAND" in
        "test"|"all")
            run_unit_tests
            run_integration_tests
            run_performance_tests
            run_security_tests
            run_ai_tests
            run_quality_gates
            ;;
        "unit")
            run_unit_tests
            ;;
        "integration")
            run_integration_tests
            ;;
        "performance")
            run_performance_tests
            ;;
        "security")
            run_security_tests
            ;;
        "ai")
            run_ai_tests
            ;;
        "quality")
            run_quality_gates
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
    
    if [[ "$GENERATE_REPORTS" == "true" ]]; then
        generate_test_report
    fi
    
    # Calculate overall success
    local overall_success=true
    for result in "${TEST_RESULTS[@]}"; do
        if [[ "$result" == "FAIL" ]]; then
            overall_success=false
            break
        fi
    done
    
    if [[ "$overall_success" == "true" ]]; then
        log_success "All tests completed successfully! 🎉"
        exit 0
    else
        log_error "Some tests failed. Check the results above."
        exit 1
    fi
}

# Initialize extra args array
EXTRA_ARGS=()

# Parse arguments and run main function
parse_args "$@"
main
