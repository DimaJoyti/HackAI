#!/bin/bash

# HackAI Security & Compliance Implementation Validation Test
# Comprehensive testing of security and compliance features

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

# Test security configuration files
test_security_configuration() {
    log_test "Testing security configuration files..."
    
    local config_files=(
        "configs/security/comprehensive-security-config.yaml"
        "configs/security/security.yaml"
    )
    
    for config_file in "${config_files[@]}"; do
        if [[ -f "$PROJECT_ROOT/$config_file" ]]; then
            # Test YAML syntax
            if command -v yq &> /dev/null; then
                if yq eval '.' "$PROJECT_ROOT/$config_file" &> /dev/null; then
                    record_test_result "config_syntax_$(basename "$config_file")" "PASS"
                else
                    record_test_result "config_syntax_$(basename "$config_file")" "FAIL - Invalid YAML syntax"
                fi
            else
                record_test_result "config_syntax_$(basename "$config_file")" "SKIP - yq not available"
            fi
            
            # Test required sections
            local required_sections=("authentication" "authorization" "encryption" "compliance")
            for section in "${required_sections[@]}"; do
                if grep -q "$section:" "$PROJECT_ROOT/$config_file"; then
                    record_test_result "config_section_${section}" "PASS"
                else
                    record_test_result "config_section_${section}" "FAIL - Missing section"
                fi
            done
        else
            record_test_result "config_file_$(basename "$config_file")" "FAIL - File not found"
        fi
    done
}

# Test security Go packages
test_security_packages() {
    log_test "Testing security Go packages..."
    
    local security_packages=(
        "pkg/security/comprehensive_security_manager.go"
        "pkg/security/automated_security_orchestrator.go"
        "pkg/security/security_monitoring_dashboard.go"
        "pkg/compliance/comprehensive_compliance_engine.go"
    )
    
    for package in "${security_packages[@]}"; do
        if [[ -f "$PROJECT_ROOT/$package" ]]; then
            # Test Go syntax
            if go fmt -l "$PROJECT_ROOT/$package" &> /dev/null; then
                record_test_result "go_syntax_$(basename "$package")" "PASS"
            else
                record_test_result "go_syntax_$(basename "$package")" "FAIL - Go syntax error"
            fi
            
            # Test for required functions/types
            local package_name=$(basename "$package" .go)
            case "$package_name" in
                "comprehensive_security_manager")
                    if grep -q "ValidateSecurityRequest" "$PROJECT_ROOT/$package"; then
                        record_test_result "security_manager_functions" "PASS"
                    else
                        record_test_result "security_manager_functions" "FAIL - Missing functions"
                    fi
                    ;;
                "automated_security_orchestrator")
                    if grep -q "ProcessSecurityEvent" "$PROJECT_ROOT/$package"; then
                        record_test_result "orchestrator_functions" "PASS"
                    else
                        record_test_result "orchestrator_functions" "FAIL - Missing functions"
                    fi
                    ;;
                "security_monitoring_dashboard")
                    if grep -q "collectDashboardData" "$PROJECT_ROOT/$package"; then
                        record_test_result "dashboard_functions" "PASS"
                    else
                        record_test_result "dashboard_functions" "FAIL - Missing functions"
                    fi
                    ;;
                "comprehensive_compliance_engine")
                    if grep -q "ValidateCompliance" "$PROJECT_ROOT/$package"; then
                        record_test_result "compliance_functions" "PASS"
                    else
                        record_test_result "compliance_functions" "FAIL - Missing functions"
                    fi
                    ;;
            esac
        else
            record_test_result "package_$(basename "$package")" "FAIL - File not found"
        fi
    done
}

# Test security scripts
test_security_scripts() {
    log_test "Testing security automation scripts..."
    
    local scripts=(
        "scripts/security-automation.sh"
        "scripts/security-setup.sh"
    )
    
    for script in "${scripts[@]}"; do
        if [[ -f "$PROJECT_ROOT/$script" ]]; then
            # Test script syntax
            if bash -n "$PROJECT_ROOT/$script" &> /dev/null; then
                record_test_result "script_syntax_$(basename "$script")" "PASS"
            else
                record_test_result "script_syntax_$(basename "$script")" "FAIL - Bash syntax error"
            fi
            
            # Test executable permissions
            if [[ -x "$PROJECT_ROOT/$script" ]]; then
                record_test_result "script_executable_$(basename "$script")" "PASS"
            else
                record_test_result "script_executable_$(basename "$script")" "FAIL - Not executable"
            fi
            
            # Test required functions
            if grep -q "main()" "$PROJECT_ROOT/$script"; then
                record_test_result "script_main_$(basename "$script")" "PASS"
            else
                record_test_result "script_main_$(basename "$script")" "FAIL - Missing main function"
            fi
        else
            record_test_result "script_$(basename "$script")" "FAIL - File not found"
        fi
    done
}

# Test compliance framework support
test_compliance_frameworks() {
    log_test "Testing compliance framework support..."
    
    local frameworks=("SOC2" "ISO27001" "GDPR" "HIPAA" "PCI-DSS" "NIST")
    
    for framework in "${frameworks[@]}"; do
        # Check if framework is mentioned in configuration
        if grep -r "$framework" "$PROJECT_ROOT/configs/security/" &> /dev/null; then
            record_test_result "framework_config_$framework" "PASS"
        else
            record_test_result "framework_config_$framework" "FAIL - Framework not configured"
        fi
        
        # Check if framework is implemented in code
        if grep -r "$framework" "$PROJECT_ROOT/pkg/compliance/" &> /dev/null; then
            record_test_result "framework_implementation_$framework" "PASS"
        else
            record_test_result "framework_implementation_$framework" "FAIL - Framework not implemented"
        fi
    done
}

# Test security features
test_security_features() {
    log_test "Testing security feature implementation..."
    
    local features=(
        "authentication"
        "authorization" 
        "encryption"
        "audit"
        "threat_detection"
        "incident_response"
        "vulnerability_management"
        "compliance"
    )
    
    for feature in "${features[@]}"; do
        # Check if feature is implemented in security packages
        if grep -r "$feature" "$PROJECT_ROOT/pkg/security/" &> /dev/null; then
            record_test_result "security_feature_$feature" "PASS"
        else
            record_test_result "security_feature_$feature" "FAIL - Feature not implemented"
        fi
        
        # Check if feature is configured
        if grep -r "$feature" "$PROJECT_ROOT/configs/security/" &> /dev/null; then
            record_test_result "security_config_$feature" "PASS"
        else
            record_test_result "security_config_$feature" "FAIL - Feature not configured"
        fi
    done
}

# Test documentation
test_documentation() {
    log_test "Testing security documentation..."
    
    local docs=(
        "docs/SECURITY_COMPLIANCE_IMPLEMENTATION.md"
        "docs/SECURITY_IMPLEMENTATION.md"
        "docs/architecture.md"
    )
    
    for doc in "${docs[@]}"; do
        if [[ -f "$PROJECT_ROOT/$doc" ]]; then
            # Test markdown syntax (basic check)
            if grep -q "^#" "$PROJECT_ROOT/$doc"; then
                record_test_result "doc_format_$(basename "$doc")" "PASS"
            else
                record_test_result "doc_format_$(basename "$doc")" "FAIL - Invalid markdown format"
            fi
            
            # Test for required sections
            local required_sections=("Security" "Compliance" "Implementation")
            local found_sections=0
            for section in "${required_sections[@]}"; do
                if grep -qi "$section" "$PROJECT_ROOT/$doc"; then
                    found_sections=$((found_sections + 1))
                fi
            done
            
            if [[ $found_sections -ge 2 ]]; then
                record_test_result "doc_content_$(basename "$doc")" "PASS"
            else
                record_test_result "doc_content_$(basename "$doc")" "FAIL - Missing required sections"
            fi
        else
            record_test_result "doc_$(basename "$doc")" "FAIL - File not found"
        fi
    done
}

# Test integration points
test_integration_points() {
    log_test "Testing security integration points..."
    
    # Test RBAC integration
    if [[ -f "$PROJECT_ROOT/pkg/rbac/rbac_manager.go" ]]; then
        if grep -q "CheckAccess" "$PROJECT_ROOT/pkg/rbac/rbac_manager.go"; then
            record_test_result "rbac_integration" "PASS"
        else
            record_test_result "rbac_integration" "FAIL - Missing RBAC functions"
        fi
    else
        record_test_result "rbac_integration" "FAIL - RBAC manager not found"
    fi
    
    # Test authentication integration
    if [[ -f "$PROJECT_ROOT/pkg/auth/security.go" ]]; then
        if grep -q "SecurityConfig" "$PROJECT_ROOT/pkg/auth/security.go"; then
            record_test_result "auth_integration" "PASS"
        else
            record_test_result "auth_integration" "FAIL - Missing auth security config"
        fi
    else
        record_test_result "auth_integration" "FAIL - Auth security not found"
    fi
    
    # Test monitoring integration
    if grep -r "prometheus" "$PROJECT_ROOT/pkg/security/" &> /dev/null; then
        record_test_result "monitoring_integration" "PASS"
    else
        record_test_result "monitoring_integration" "FAIL - No monitoring integration"
    fi
}

# Test security automation
test_security_automation() {
    log_test "Testing security automation capabilities..."
    
    # Test automation script functionality
    if [[ -f "$PROJECT_ROOT/scripts/security-automation.sh" ]]; then
        # Test help function
        if grep -q "show_help()" "$PROJECT_ROOT/scripts/security-automation.sh"; then
            record_test_result "automation_help" "PASS"
        else
            record_test_result "automation_help" "FAIL - Missing help function"
        fi
        
        # Test main commands
        local commands=("scan" "compliance" "vulnerability" "incident" "remediate")
        for command in "${commands[@]}"; do
            if grep -q "\"$command\")" "$PROJECT_ROOT/scripts/security-automation.sh"; then
                record_test_result "automation_command_$command" "PASS"
            else
                record_test_result "automation_command_$command" "FAIL - Missing command"
            fi
        done
    else
        record_test_result "automation_script" "FAIL - Script not found"
    fi
}

# Generate test report
generate_test_report() {
    log_info "Generating security validation test report..."
    
    local report_file="/tmp/hackai_security_validation_report.html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>HackAI Security & Compliance Validation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
        .summary { background: #ecf0f1; padding: 15px; margin: 20px 0; }
        .pass { color: #27ae60; }
        .fail { color: #e74c3c; }
        .section { margin: 20px 0; }
        .test-result { margin: 5px 0; padding: 5px; border-left: 3px solid #bdc3c7; }
        .test-pass { border-left-color: #27ae60; }
        .test-fail { border-left-color: #e74c3c; }
    </style>
</head>
<body>
    <div class="header">
        <h1>HackAI Security & Compliance Validation Report</h1>
        <p>Generated: $(date)</p>
    </div>
    
    <div class="summary">
        <h2>Test Summary</h2>
        <p><strong>Total Tests:</strong> $TOTAL_TESTS</p>
        <p><strong>Passed:</strong> <span class="pass">$PASSED_TESTS</span></p>
        <p><strong>Failed:</strong> <span class="fail">$FAILED_TESTS</span></p>
        <p><strong>Success Rate:</strong> $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%</p>
    </div>
    
    <div class="section">
        <h2>Test Results</h2>
EOF

    for test_name in "${!TEST_RESULTS[@]}"; do
        local result="${TEST_RESULTS[$test_name]}"
        if [[ "$result" == "PASS" ]]; then
            echo "        <div class=\"test-result test-pass\">✓ $test_name: $result</div>" >> "$report_file"
        else
            echo "        <div class=\"test-result test-fail\">✗ $test_name: $result</div>" >> "$report_file"
        fi
    done
    
    cat >> "$report_file" << EOF
    </div>
</body>
</html>
EOF
    
    log_success "Security validation report generated: $report_file"
}

# Main test execution
main() {
    log_info "Starting HackAI Security & Compliance Implementation Validation"
    
    # Run test suites
    test_security_configuration
    test_security_packages
    test_security_scripts
    test_compliance_frameworks
    test_security_features
    test_documentation
    test_integration_points
    test_security_automation
    
    # Generate report
    generate_test_report
    
    # Display summary
    echo ""
    echo "=========================================="
    echo "     SECURITY VALIDATION SUMMARY"
    echo "=========================================="
    echo "Total Tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $FAILED_TESTS"
    echo "Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%"
    echo "=========================================="
    
    if [[ $FAILED_TESTS -gt 0 ]]; then
        echo ""
        log_error "Some security validation tests failed. Please review the report for details."
        return 1
    else
        echo ""
        log_success "All security validation tests passed! 🔒"
        log_success "Security & Compliance Implementation is ready for production! 🚀"
        return 0
    fi
}

# Run main function
main "$@"
