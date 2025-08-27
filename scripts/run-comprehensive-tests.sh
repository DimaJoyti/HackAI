#!/bin/bash

# HackAI Comprehensive Testing Script
# This script runs the complete testing and validation framework

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
TEST_CONFIG="${PROJECT_ROOT}/configs/testing.yaml"
TEST_REPORTS_DIR="${PROJECT_ROOT}/test-reports"
LOG_FILE="${TEST_REPORTS_DIR}/test-execution.log"

# Default values
ENVIRONMENT="development"
PARALLEL=true
VERBOSE=false
CLEAN=false
SUITES="all"
OUTPUT_FORMAT="html,json,junit"
MAX_RETRIES=3

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_header() {
    echo -e "${CYAN}"
    echo "=================================================================="
    echo "🧪 HackAI Comprehensive Testing Framework"
    echo "=================================================================="
    echo -e "${NC}"
}

print_section() {
    local title=$1
    echo -e "\n${BLUE}📋 ${title}${NC}"
    echo "----------------------------------------"
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

HackAI Comprehensive Testing Framework Runner

OPTIONS:
    -e, --environment ENV    Test environment (development|staging|production) [default: development]
    -s, --suites SUITES      Test suites to run (all|ai|multiagent|vectordb|security|performance|integration) [default: all]
    -f, --format FORMAT      Output formats (html,json,junit,xml) [default: html,json,junit]
    -p, --parallel           Enable parallel execution [default: true]
    -v, --verbose            Enable verbose output
    -c, --clean              Clean previous test results
    -r, --retries NUM        Maximum number of retries for failed tests [default: 3]
    -h, --help               Show this help message

EXAMPLES:
    # Run all tests in development environment
    $0

    # Run only AI and security tests with verbose output
    $0 --suites ai,security --verbose

    # Run tests in staging environment with clean start
    $0 --environment staging --clean

    # Run performance tests only with custom output format
    $0 --suites performance --format json,html

    # Run tests with custom retry count
    $0 --retries 5

EOF
}

# Function to parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -s|--suites)
                SUITES="$2"
                shift 2
                ;;
            -f|--format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -p|--parallel)
                PARALLEL=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -c|--clean)
                CLEAN=true
                shift
                ;;
            -r|--retries)
                MAX_RETRIES="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                print_status $RED "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Function to validate environment
validate_environment() {
    print_section "Environment Validation"
    
    # Check Go version
    if ! command -v go &> /dev/null; then
        print_status $RED "❌ Go is not installed"
        exit 1
    fi
    
    local go_version=$(go version | awk '{print $3}' | sed 's/go//')
    print_status $GREEN "✅ Go version: $go_version"
    
    # Check project structure
    if [[ ! -f "$TEST_CONFIG" ]]; then
        print_status $RED "❌ Test configuration not found: $TEST_CONFIG"
        exit 1
    fi
    print_status $GREEN "✅ Test configuration found"
    
    # Check dependencies
    print_status $YELLOW "🔍 Checking dependencies..."
    cd "$PROJECT_ROOT"
    go mod verify
    go mod tidy
    print_status $GREEN "✅ Dependencies verified"
    
    # Create test reports directory
    mkdir -p "$TEST_REPORTS_DIR"
    print_status $GREEN "✅ Test reports directory ready: $TEST_REPORTS_DIR"
}

# Function to clean previous test results
clean_test_results() {
    if [[ "$CLEAN" == "true" ]]; then
        print_section "Cleaning Previous Results"
        rm -rf "${TEST_REPORTS_DIR:?}"/*
        print_status $GREEN "✅ Previous test results cleaned"
    fi
}

# Function to run specific test suite
run_test_suite() {
    local suite=$1
    local start_time=$(date +%s)
    
    print_status $CYAN "🚀 Running $suite tests..."
    
    # Set environment variables
    export HACKAI_TEST_ENV="$ENVIRONMENT"
    export HACKAI_TEST_SUITE="$suite"
    export HACKAI_TEST_PARALLEL="$PARALLEL"
    export HACKAI_TEST_VERBOSE="$VERBOSE"
    export HACKAI_TEST_OUTPUT_FORMAT="$OUTPUT_FORMAT"
    export HACKAI_TEST_MAX_RETRIES="$MAX_RETRIES"
    
    # Run the test suite
    local exit_code=0
    case $suite in
        "ai")
            go run examples/testing/comprehensive_testing_example.go --suite=ai 2>&1 | tee -a "$LOG_FILE" || exit_code=$?
            ;;
        "multiagent")
            go run examples/testing/comprehensive_testing_example.go --suite=multiagent 2>&1 | tee -a "$LOG_FILE" || exit_code=$?
            ;;
        "vectordb")
            go run examples/testing/comprehensive_testing_example.go --suite=vectordb 2>&1 | tee -a "$LOG_FILE" || exit_code=$?
            ;;
        "security")
            go run examples/testing/comprehensive_testing_example.go --suite=security 2>&1 | tee -a "$LOG_FILE" || exit_code=$?
            ;;
        "performance")
            go run examples/testing/comprehensive_testing_example.go --suite=performance 2>&1 | tee -a "$LOG_FILE" || exit_code=$?
            ;;
        "integration")
            go run examples/testing/comprehensive_testing_example.go --suite=integration 2>&1 | tee -a "$LOG_FILE" || exit_code=$?
            ;;
        "all")
            go run examples/testing/comprehensive_testing_example.go 2>&1 | tee -a "$LOG_FILE" || exit_code=$?
            ;;
        *)
            print_status $RED "❌ Unknown test suite: $suite"
            return 1
            ;;
    esac
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    if [[ $exit_code -eq 0 ]]; then
        print_status $GREEN "✅ $suite tests completed successfully in ${duration}s"
    else
        print_status $RED "❌ $suite tests failed (exit code: $exit_code) after ${duration}s"
    fi
    
    return $exit_code
}

# Function to run all specified test suites
run_test_suites() {
    print_section "Test Execution"
    
    local overall_start_time=$(date +%s)
    local failed_suites=()
    local successful_suites=()
    
    # Parse suites to run
    IFS=',' read -ra SUITE_ARRAY <<< "$SUITES"
    
    for suite in "${SUITE_ARRAY[@]}"; do
        suite=$(echo "$suite" | xargs) # Trim whitespace
        
        if run_test_suite "$suite"; then
            successful_suites+=("$suite")
        else
            failed_suites+=("$suite")
        fi
        
        echo "" # Add spacing between suites
    done
    
    local overall_end_time=$(date +%s)
    local overall_duration=$((overall_end_time - overall_start_time))
    
    # Print summary
    print_section "Test Execution Summary"
    print_status $CYAN "⏱️  Total execution time: ${overall_duration}s"
    print_status $GREEN "✅ Successful suites (${#successful_suites[@]}): ${successful_suites[*]}"
    
    if [[ ${#failed_suites[@]} -gt 0 ]]; then
        print_status $RED "❌ Failed suites (${#failed_suites[@]}): ${failed_suites[*]}"
        return 1
    else
        print_status $GREEN "🎉 All test suites completed successfully!"
        return 0
    fi
}

# Function to generate final report
generate_final_report() {
    print_section "Report Generation"
    
    local report_file="${TEST_REPORTS_DIR}/comprehensive-test-summary.html"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>HackAI Comprehensive Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; }
        .summary { background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 6px; }
        .success { color: #27ae60; }
        .failure { color: #e74c3c; }
        .info { color: #3498db; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🧪 HackAI Comprehensive Test Report</h1>
        <p>Generated: $timestamp</p>
        <p>Environment: $ENVIRONMENT</p>
    </div>
    
    <div class="summary">
        <h2>📊 Test Execution Summary</h2>
        <p><strong>Test Suites:</strong> $SUITES</p>
        <p><strong>Parallel Execution:</strong> $PARALLEL</p>
        <p><strong>Output Formats:</strong> $OUTPUT_FORMAT</p>
        <p><strong>Max Retries:</strong> $MAX_RETRIES</p>
    </div>
    
    <div class="summary">
        <h2>📁 Generated Reports</h2>
        <ul>
EOF

    # List all generated report files
    find "$TEST_REPORTS_DIR" -name "*.json" -o -name "*.html" -o -name "*.xml" | while read -r file; do
        local filename=$(basename "$file")
        echo "            <li><a href=\"$filename\">$filename</a></li>" >> "$report_file"
    done
    
    cat >> "$report_file" << EOF
        </ul>
    </div>
    
    <div class="summary">
        <h2>📋 Next Steps</h2>
        <ul>
            <li>Review detailed test reports for any failures</li>
            <li>Check performance metrics and trends</li>
            <li>Update test configurations based on results</li>
            <li>Schedule regular test execution</li>
        </ul>
    </div>
</body>
</html>
EOF

    print_status $GREEN "✅ Final report generated: $report_file"
}

# Function to show test results
show_test_results() {
    print_section "Test Results"
    
    # Count generated reports
    local json_reports=$(find "$TEST_REPORTS_DIR" -name "*.json" | wc -l)
    local html_reports=$(find "$TEST_REPORTS_DIR" -name "*.html" | wc -l)
    local junit_reports=$(find "$TEST_REPORTS_DIR" -name "*.xml" | wc -l)
    
    print_status $CYAN "📊 Generated Reports:"
    print_status $GREEN "   JSON reports: $json_reports"
    print_status $GREEN "   HTML reports: $html_reports"
    print_status $GREEN "   JUnit reports: $junit_reports"
    
    print_status $CYAN "📁 Reports location: $TEST_REPORTS_DIR"
    
    # Show log file location
    if [[ -f "$LOG_FILE" ]]; then
        local log_size=$(du -h "$LOG_FILE" | cut -f1)
        print_status $CYAN "📝 Execution log: $LOG_FILE ($log_size)"
    fi
}

# Main execution function
main() {
    print_header
    
    # Parse command line arguments
    parse_args "$@"
    
    # Show configuration
    print_section "Configuration"
    print_status $CYAN "Environment: $ENVIRONMENT"
    print_status $CYAN "Test suites: $SUITES"
    print_status $CYAN "Output formats: $OUTPUT_FORMAT"
    print_status $CYAN "Parallel execution: $PARALLEL"
    print_status $CYAN "Verbose output: $VERBOSE"
    print_status $CYAN "Clean previous results: $CLEAN"
    print_status $CYAN "Max retries: $MAX_RETRIES"
    
    # Validate environment
    validate_environment
    
    # Clean previous results if requested
    clean_test_results
    
    # Initialize log file
    echo "HackAI Comprehensive Testing - $(date)" > "$LOG_FILE"
    
    # Run test suites
    local exit_code=0
    if ! run_test_suites; then
        exit_code=1
    fi
    
    # Generate final report
    generate_final_report
    
    # Show results
    show_test_results
    
    # Final status
    if [[ $exit_code -eq 0 ]]; then
        print_status $GREEN "🎉 Comprehensive testing completed successfully!"
    else
        print_status $RED "❌ Some tests failed. Check the reports for details."
    fi
    
    exit $exit_code
}

# Run main function with all arguments
main "$@"
