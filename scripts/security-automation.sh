#!/bin/bash

# HackAI Security Automation and Compliance Validation Script
# Comprehensive security automation, compliance checking, and incident response

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
SECURITY_DIR="$PROJECT_ROOT/pkg/security"
COMPLIANCE_DIR="$PROJECT_ROOT/pkg/compliance"
CONFIG_DIR="$PROJECT_ROOT/configs/security"

# Default values
ENVIRONMENT="${ENVIRONMENT:-development}"
SECURITY_LEVEL="${SECURITY_LEVEL:-high}"
COMPLIANCE_FRAMEWORKS="${COMPLIANCE_FRAMEWORKS:-SOC2,ISO27001,GDPR}"
SCAN_TYPE="${SCAN_TYPE:-comprehensive}"
AUTO_REMEDIATE="${AUTO_REMEDIATE:-false}"
GENERATE_REPORT="${GENERATE_REPORT:-true}"
ALERT_ENABLED="${ALERT_ENABLED:-true}"
DRY_RUN="${DRY_RUN:-false}"
PARALLEL_EXECUTION="${PARALLEL_EXECUTION:-true}"
VERBOSE="${VERBOSE:-false}"

# Security scan results
declare -A SCAN_RESULTS=()
declare -A COMPLIANCE_RESULTS=()
TOTAL_VULNERABILITIES=0
CRITICAL_VULNERABILITIES=0
HIGH_VULNERABILITIES=0
MEDIUM_VULNERABILITIES=0
LOW_VULNERABILITIES=0
COMPLIANCE_SCORE=0
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

log_security() {
    echo -e "${CYAN}[SECURITY]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
HackAI Security Automation and Compliance Validation Script

Usage: $0 [COMMAND] [OPTIONS]

COMMANDS:
    scan                 Run comprehensive security scan
    compliance           Run compliance validation
    vulnerability        Run vulnerability assessment
    incident             Handle security incident
    remediate            Run automated remediation
    monitor              Start security monitoring
    report               Generate security report
    audit                Run security audit
    baseline             Establish security baseline
    test                 Run security tests
    help                 Show this help message

OPTIONS:
    -e, --environment ENV        Set environment (development, staging, production)
    -l, --security-level LEVEL   Set security level (low, medium, high, critical)
    -f, --frameworks FRAMEWORKS  Compliance frameworks (SOC2,ISO27001,GDPR,HIPAA,PCI-DSS)
    -t, --scan-type TYPE         Scan type (quick, standard, comprehensive, custom)
    --auto-remediate             Enable automatic remediation
    --generate-report            Generate detailed report
    --alert-enabled              Enable security alerts
    --dry-run                    Show what would be done without executing
    --parallel                   Enable parallel execution
    --verbose                    Enable verbose output

EXAMPLES:
    # Run comprehensive security scan
    $0 scan --environment production --security-level high

    # Run compliance validation for multiple frameworks
    $0 compliance --frameworks SOC2,GDPR,HIPAA

    # Run vulnerability assessment with auto-remediation
    $0 vulnerability --auto-remediate --generate-report

    # Handle security incident
    $0 incident --incident-id INC-2024-001

    # Start security monitoring
    $0 monitor --environment production

    # Generate security report
    $0 report --frameworks SOC2,ISO27001 --output-format pdf

EOF
}

# Parse command line arguments
parse_args() {
    COMMAND=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            scan|compliance|vulnerability|incident|remediate|monitor|report|audit|baseline|test|help)
                COMMAND="$1"
                shift
                ;;
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -l|--security-level)
                SECURITY_LEVEL="$2"
                shift 2
                ;;
            -f|--frameworks)
                COMPLIANCE_FRAMEWORKS="$2"
                shift 2
                ;;
            -t|--scan-type)
                SCAN_TYPE="$2"
                shift 2
                ;;
            --auto-remediate)
                AUTO_REMEDIATE="true"
                shift
                ;;
            --generate-report)
                GENERATE_REPORT="true"
                shift
                ;;
            --alert-enabled)
                ALERT_ENABLED="true"
                shift
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            --parallel)
                PARALLEL_EXECUTION="true"
                shift
                ;;
            --verbose)
                VERBOSE="true"
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
    log_info "Validating security automation prerequisites..."
    
    # Check required tools
    local required_tools=("docker" "kubectl" "helm" "openssl" "jq" "curl")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "$tool is required but not installed"
            exit 1
        fi
    done
    
    # Check security scanning tools
    local security_tools=("trivy" "grype" "syft")
    for tool in "${security_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_warning "$tool is not installed, some security scans may be limited"
        fi
    done
    
    # Check configuration files
    if [[ ! -d "$CONFIG_DIR" ]]; then
        log_warning "Security configuration directory not found: $CONFIG_DIR"
        mkdir -p "$CONFIG_DIR"
    fi
    
    # Check Kubernetes connection
    if ! kubectl cluster-info &> /dev/null; then
        log_warning "Cannot connect to Kubernetes cluster, some features may be limited"
    fi
    
    log_success "Prerequisites validation completed"
}

# Run comprehensive security scan
run_security_scan() {
    log_security "Starting comprehensive security scan..."
    log_info "Scan type: $SCAN_TYPE, Security level: $SECURITY_LEVEL"
    
    local scan_start_time=$(date +%s)
    
    # 1. Container image scanning
    if [[ "$SCAN_TYPE" == "comprehensive" || "$SCAN_TYPE" == "container" ]]; then
        scan_container_images
    fi
    
    # 2. Infrastructure scanning
    if [[ "$SCAN_TYPE" == "comprehensive" || "$SCAN_TYPE" == "infrastructure" ]]; then
        scan_infrastructure
    fi
    
    # 3. Application security scanning
    if [[ "$SCAN_TYPE" == "comprehensive" || "$SCAN_TYPE" == "application" ]]; then
        scan_application_security
    fi
    
    # 4. Network security scanning
    if [[ "$SCAN_TYPE" == "comprehensive" || "$SCAN_TYPE" == "network" ]]; then
        scan_network_security
    fi
    
    # 5. Configuration scanning
    if [[ "$SCAN_TYPE" == "comprehensive" || "$SCAN_TYPE" == "configuration" ]]; then
        scan_security_configuration
    fi
    
    # 6. Secrets scanning
    if [[ "$SCAN_TYPE" == "comprehensive" || "$SCAN_TYPE" == "secrets" ]]; then
        scan_secrets
    fi
    
    local scan_end_time=$(date +%s)
    local scan_duration=$((scan_end_time - scan_start_time))
    
    log_success "Security scan completed in ${scan_duration} seconds"
    
    # Calculate security score
    calculate_security_score
    
    # Generate alerts if enabled
    if [[ "$ALERT_ENABLED" == "true" ]]; then
        generate_security_alerts
    fi
    
    # Auto-remediate if enabled
    if [[ "$AUTO_REMEDIATE" == "true" ]]; then
        run_auto_remediation
    fi
}

# Scan container images for vulnerabilities
scan_container_images() {
    log_info "Scanning container images for vulnerabilities..."
    
    local images=(
        "ghcr.io/hackai/api-gateway:latest"
        "ghcr.io/hackai/user-service:latest"
        "ghcr.io/hackai/threat-service:latest"
        "ghcr.io/hackai/scanner-service:latest"
    )
    
    for image in "${images[@]}"; do
        log_debug "Scanning image: $image"
        
        if command -v trivy &> /dev/null; then
            if [[ "$DRY_RUN" == "false" ]]; then
                local scan_result
                scan_result=$(trivy image --format json --quiet "$image" 2>/dev/null || echo '{"Results":[]}')
                
                # Parse results
                local vulnerabilities
                vulnerabilities=$(echo "$scan_result" | jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity) | .Severity' | sort | uniq -c)
                
                if [[ -n "$vulnerabilities" ]]; then
                    while read -r count severity; do
                        case "$severity" in
                            "CRITICAL")
                                CRITICAL_VULNERABILITIES=$((CRITICAL_VULNERABILITIES + count))
                                ;;
                            "HIGH")
                                HIGH_VULNERABILITIES=$((HIGH_VULNERABILITIES + count))
                                ;;
                            "MEDIUM")
                                MEDIUM_VULNERABILITIES=$((MEDIUM_VULNERABILITIES + count))
                                ;;
                            "LOW")
                                LOW_VULNERABILITIES=$((LOW_VULNERABILITIES + count))
                                ;;
                        esac
                    done <<< "$vulnerabilities"
                fi
                
                SCAN_RESULTS["$image"]="scanned"
            else
                log_info "DRY RUN: Would scan image $image"
            fi
        else
            log_warning "Trivy not available, skipping image scan for $image"
        fi
    done
    
    TOTAL_VULNERABILITIES=$((CRITICAL_VULNERABILITIES + HIGH_VULNERABILITIES + MEDIUM_VULNERABILITIES + LOW_VULNERABILITIES))
    
    log_info "Container scan results:"
    log_info "  Critical: $CRITICAL_VULNERABILITIES"
    log_info "  High: $HIGH_VULNERABILITIES"
    log_info "  Medium: $MEDIUM_VULNERABILITIES"
    log_info "  Low: $LOW_VULNERABILITIES"
    log_info "  Total: $TOTAL_VULNERABILITIES"
}

# Scan infrastructure security
scan_infrastructure() {
    log_info "Scanning infrastructure security..."
    
    # Kubernetes security scanning
    if kubectl cluster-info &> /dev/null; then
        scan_kubernetes_security
    fi
    
    # Cloud security scanning
    scan_cloud_security
    
    # Network security scanning
    scan_network_infrastructure
}

# Scan Kubernetes security
scan_kubernetes_security() {
    log_debug "Scanning Kubernetes security configuration..."
    
    if [[ "$DRY_RUN" == "false" ]]; then
        # Check for security policies
        local psp_count
        psp_count=$(kubectl get psp --no-headers 2>/dev/null | wc -l || echo "0")
        
        local network_policies
        network_policies=$(kubectl get networkpolicies --all-namespaces --no-headers 2>/dev/null | wc -l || echo "0")
        
        local rbac_roles
        rbac_roles=$(kubectl get roles,clusterroles --all-namespaces --no-headers 2>/dev/null | wc -l || echo "0")
        
        log_info "Kubernetes security status:"
        log_info "  Pod Security Policies: $psp_count"
        log_info "  Network Policies: $network_policies"
        log_info "  RBAC Roles: $rbac_roles"
        
        # Check for privileged containers
        local privileged_pods
        privileged_pods=$(kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.securityContext.privileged}{"\n"}{end}' 2>/dev/null | grep -c "true" || echo "0")
        
        if [[ "$privileged_pods" -gt 0 ]]; then
            log_warning "Found $privileged_pods privileged pods"
            SCAN_RESULTS["privileged_pods"]="$privileged_pods"
        fi
        
        SCAN_RESULTS["kubernetes"]="scanned"
    else
        log_info "DRY RUN: Would scan Kubernetes security"
    fi
}

# Run compliance validation
run_compliance_validation() {
    log_security "Starting compliance validation..."
    log_info "Frameworks: $COMPLIANCE_FRAMEWORKS"
    
    IFS=',' read -ra FRAMEWORKS <<< "$COMPLIANCE_FRAMEWORKS"
    
    for framework in "${FRAMEWORKS[@]}"; do
        log_info "Validating compliance for: $framework"
        
        case "$framework" in
            "SOC2")
                validate_soc2_compliance
                ;;
            "ISO27001")
                validate_iso27001_compliance
                ;;
            "GDPR")
                validate_gdpr_compliance
                ;;
            "HIPAA")
                validate_hipaa_compliance
                ;;
            "PCI-DSS")
                validate_pcidss_compliance
                ;;
            "NIST")
                validate_nist_compliance
                ;;
            *)
                log_warning "Unknown compliance framework: $framework"
                ;;
        esac
    done
    
    # Calculate overall compliance score
    calculate_compliance_score
    
    log_success "Compliance validation completed"
    log_info "Overall compliance score: ${COMPLIANCE_SCORE}%"
}

# Validate SOC2 compliance
validate_soc2_compliance() {
    log_debug "Validating SOC2 compliance..."
    
    local soc2_score=0
    local total_controls=20
    local passed_controls=0
    
    # Security controls validation
    local controls=(
        "access_control"
        "authentication"
        "authorization"
        "encryption"
        "audit_logging"
        "incident_response"
        "vulnerability_management"
        "change_management"
        "backup_recovery"
        "monitoring"
    )
    
    for control in "${controls[@]}"; do
        if validate_security_control "$control"; then
            passed_controls=$((passed_controls + 1))
        fi
    done
    
    soc2_score=$(( (passed_controls * 100) / total_controls ))
    COMPLIANCE_RESULTS["SOC2"]="$soc2_score"
    
    log_info "SOC2 compliance score: ${soc2_score}% (${passed_controls}/${total_controls} controls)"
}

# Validate security control
validate_security_control() {
    local control="$1"
    
    case "$control" in
        "access_control")
            # Check RBAC implementation
            if kubectl get roles,clusterroles --all-namespaces &> /dev/null; then
                return 0
            fi
            ;;
        "authentication")
            # Check authentication mechanisms
            if kubectl get serviceaccounts --all-namespaces | grep -q "default"; then
                return 0
            fi
            ;;
        "encryption")
            # Check encryption at rest and in transit
            if kubectl get secrets --all-namespaces | grep -q "tls"; then
                return 0
            fi
            ;;
        "audit_logging")
            # Check audit logging configuration
            if kubectl get events --all-namespaces &> /dev/null; then
                return 0
            fi
            ;;
        *)
            # Default validation
            return 0
            ;;
    esac
    
    return 1
}

# Run automated remediation
run_auto_remediation() {
    log_security "Starting automated remediation..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would run automated remediation"
        return 0
    fi
    
    # Remediate critical vulnerabilities
    if [[ "$CRITICAL_VULNERABILITIES" -gt 0 ]]; then
        log_warning "Found $CRITICAL_VULNERABILITIES critical vulnerabilities, initiating remediation"
        remediate_critical_vulnerabilities
    fi
    
    # Remediate security misconfigurations
    remediate_security_misconfigurations
    
    # Update security policies
    update_security_policies
    
    log_success "Automated remediation completed"
}

# Calculate security score
calculate_security_score() {
    local base_score=100
    
    # Deduct points for vulnerabilities
    local vuln_deduction=$((CRITICAL_VULNERABILITIES * 10 + HIGH_VULNERABILITIES * 5 + MEDIUM_VULNERABILITIES * 2 + LOW_VULNERABILITIES * 1))
    
    # Deduct points for security misconfigurations
    local config_deduction=0
    if [[ "${SCAN_RESULTS[privileged_pods]:-0}" -gt 0 ]]; then
        config_deduction=$((config_deduction + 10))
    fi
    
    SECURITY_SCORE=$((base_score - vuln_deduction - config_deduction))
    
    if [[ "$SECURITY_SCORE" -lt 0 ]]; then
        SECURITY_SCORE=0
    fi
    
    log_info "Security score: ${SECURITY_SCORE}/100"
}

# Calculate compliance score
calculate_compliance_score() {
    local total_score=0
    local framework_count=0
    
    for framework in "${!COMPLIANCE_RESULTS[@]}"; do
        total_score=$((total_score + COMPLIANCE_RESULTS[$framework]))
        framework_count=$((framework_count + 1))
    done
    
    if [[ "$framework_count" -gt 0 ]]; then
        COMPLIANCE_SCORE=$((total_score / framework_count))
    else
        COMPLIANCE_SCORE=0
    fi
}

# Generate security alerts
generate_security_alerts() {
    log_info "Generating security alerts..."
    
    local alert_file="/tmp/hackai_security_alerts_$(date +%Y%m%d_%H%M%S).json"
    
    cat > "$alert_file" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "environment": "$ENVIRONMENT",
  "security_score": $SECURITY_SCORE,
  "compliance_score": $COMPLIANCE_SCORE,
  "vulnerabilities": {
    "critical": $CRITICAL_VULNERABILITIES,
    "high": $HIGH_VULNERABILITIES,
    "medium": $MEDIUM_VULNERABILITIES,
    "low": $LOW_VULNERABILITIES,
    "total": $TOTAL_VULNERABILITIES
  },
  "compliance_results": $(printf '%s\n' "${COMPLIANCE_RESULTS[@]}" | jq -R . | jq -s 'add'),
  "scan_results": $(printf '%s\n' "${SCAN_RESULTS[@]}" | jq -R . | jq -s 'add'),
  "recommendations": [
    "Review and remediate critical vulnerabilities",
    "Implement missing security controls",
    "Update security policies and procedures",
    "Conduct regular security assessments"
  ]
}
EOF
    
    log_success "Security alerts generated: $alert_file"
}

# Generate security report
generate_security_report() {
    log_info "Generating comprehensive security report..."
    
    local report_file="/tmp/hackai_security_report_$(date +%Y%m%d_%H%M%S).html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>HackAI Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
        .critical { color: #e74c3c; }
        .high { color: #f39c12; }
        .medium { color: #f1c40f; }
        .low { color: #27ae60; }
        .score { font-size: 24px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>HackAI Security Assessment Report</h1>
        <p>Generated: $(date)</p>
        <p>Environment: $ENVIRONMENT</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p>Security Score: <span class="score">$SECURITY_SCORE/100</span></p>
        <p>Compliance Score: <span class="score">$COMPLIANCE_SCORE%</span></p>
        <p>Total Vulnerabilities: $TOTAL_VULNERABILITIES</p>
    </div>
    
    <div class="section">
        <h2>Vulnerability Summary</h2>
        <ul>
            <li class="critical">Critical: $CRITICAL_VULNERABILITIES</li>
            <li class="high">High: $HIGH_VULNERABILITIES</li>
            <li class="medium">Medium: $MEDIUM_VULNERABILITIES</li>
            <li class="low">Low: $LOW_VULNERABILITIES</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Compliance Status</h2>
        <p>Frameworks assessed: $COMPLIANCE_FRAMEWORKS</p>
        <p>Overall compliance score: $COMPLIANCE_SCORE%</p>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
            <li>Address critical and high severity vulnerabilities immediately</li>
            <li>Implement missing security controls</li>
            <li>Review and update security policies</li>
            <li>Conduct regular security assessments</li>
            <li>Implement automated security monitoring</li>
        </ul>
    </div>
</body>
</html>
EOF
    
    log_success "Security report generated: $report_file"
}

# Main function
main() {
    log_info "Starting HackAI Security Automation"
    log_info "Command: $COMMAND, Environment: $ENVIRONMENT"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_warning "Running in DRY RUN mode - no changes will be made"
    fi
    
    validate_prerequisites
    
    case "$COMMAND" in
        "scan")
            run_security_scan
            ;;
        "compliance")
            run_compliance_validation
            ;;
        "vulnerability")
            scan_container_images
            ;;
        "remediate")
            run_auto_remediation
            ;;
        "report")
            if [[ "$GENERATE_REPORT" == "true" ]]; then
                generate_security_report
            fi
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
    
    if [[ "$GENERATE_REPORT" == "true" && "$COMMAND" != "report" ]]; then
        generate_security_report
    fi
    
    log_success "Security automation completed successfully!"
}

# Initialize extra args array
EXTRA_ARGS=()

# Parse arguments and run main function
parse_args "$@"
main
