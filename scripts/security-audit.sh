#!/bin/bash

# HackAI Security Audit Script
# Scans the codebase for hardcoded secrets and security vulnerabilities
# 
# 🔒 This script helps identify:
# - Hardcoded passwords, API keys, and secrets
# - Insecure configuration patterns
# - Files that should not be committed
# - Weak security practices

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
REPORT_FILE="$PROJECT_ROOT/security-audit-report.txt"

# Counters
ISSUES_FOUND=0
WARNINGS_FOUND=0

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    ((WARNINGS_FOUND++))
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    ((ISSUES_FOUND++))
}

# Function to log to report file
log_to_report() {
    echo "$1" >> "$REPORT_FILE"
}

# Function to scan for hardcoded secrets
scan_hardcoded_secrets() {
    print_info "Scanning for hardcoded secrets..."
    
    local patterns=(
        "password\s*[:=]\s*[\"'][^\"']{3,}[\"']"
        "secret\s*[:=]\s*[\"'][^\"']{3,}[\"']"
        "api[_-]?key\s*[:=]\s*[\"'][^\"']{3,}[\"']"
        "token\s*[:=]\s*[\"'][^\"']{3,}[\"']"
        "-----BEGIN.*PRIVATE.*KEY-----"
        "[\"'][A-Za-z0-9]{20,}[\"']"
        "sk-[A-Za-z0-9]{20,}"
        "xoxb-[A-Za-z0-9-]+"
        "ghp_[A-Za-z0-9]{36}"
        "AKIA[0-9A-Z]{16}"
    )
    
    local exclude_dirs=("node_modules" ".git" "vendor" "bin" ".terraform")
    local exclude_files=("*.log" "*.backup" "*.bak" "go.sum" "package-lock.json")
    
    # Build find command with exclusions
    local find_cmd="find $PROJECT_ROOT -type f"
    for dir in "${exclude_dirs[@]}"; do
        find_cmd="$find_cmd -not -path '*/$dir/*'"
    done
    for file in "${exclude_files[@]}"; do
        find_cmd="$find_cmd -not -name '$file'"
    done
    
    local files_with_secrets=()
    
    for pattern in "${patterns[@]}"; do
        while IFS= read -r -d '' file; do
            if grep -l -E "$pattern" "$file" >/dev/null 2>&1; then
                files_with_secrets+=("$file")
            fi
        done < <(eval "$find_cmd -print0")
    done
    
    # Remove duplicates and check each file
    local unique_files=($(printf '%s\n' "${files_with_secrets[@]}" | sort -u))
    
    for file in "${unique_files[@]}"; do
        # Skip example files and documentation
        if [[ "$file" == *".example"* ]] || [[ "$file" == *"README"* ]] || [[ "$file" == *"docs/"* ]]; then
            continue
        fi
        
        print_error "Potential hardcoded secret found in: $file"
        log_to_report "HARDCODED_SECRET: $file"
        
        # Show context (first few matches)
        grep -n -E "(password|secret|api[_-]?key|token)" "$file" | head -3 | while read -r line; do
            print_info "  $line"
            log_to_report "  $line"
        done
    done
}

# Function to check configuration files
check_config_files() {
    print_info "Checking configuration files..."
    
    local config_files=(
        "configs/config.yaml"
        "configs/environments/development.yaml"
        "configs/environments/production.yaml"
        "deployments/k8s/namespace.yaml"
        "deployments/kubernetes/secrets.yaml"
    )
    
    for config_file in "${config_files[@]}"; do
        local full_path="$PROJECT_ROOT/$config_file"
        if [[ -f "$full_path" ]]; then
            # Check for hardcoded values that should use environment variables
            if grep -q "password.*:" "$full_path" && ! grep -q "\${" "$full_path"; then
                print_warning "Configuration file may contain hardcoded values: $config_file"
                log_to_report "CONFIG_HARDCODED: $config_file"
            fi
            
            # Check for base64 encoded secrets with comments
            if grep -q "# [a-zA-Z0-9_-]" "$full_path" && grep -q "data:" "$full_path"; then
                print_error "Kubernetes secret file contains plaintext comments: $config_file"
                log_to_report "K8S_SECRET_EXPOSED: $config_file"
            fi
        fi
    done
}

# Function to check environment files
check_env_files() {
    print_info "Checking environment files..."
    
    # Check if .env files are properly ignored
    if [[ -f "$PROJECT_ROOT/.env" ]]; then
        if git check-ignore "$PROJECT_ROOT/.env" >/dev/null 2>&1; then
            print_success ".env file is properly ignored by git"
        else
            print_error ".env file is NOT ignored by git - this is a security risk!"
            log_to_report "ENV_NOT_IGNORED: .env"
        fi
    fi
    
    # Check for committed .env files
    local committed_env_files=$(git ls-files "$PROJECT_ROOT" | grep -E "\.env(\.|$)" | grep -v "\.example$" | grep -v "\.template$" || true)
    if [[ -n "$committed_env_files" ]]; then
        print_error "Environment files found in git history:"
        echo "$committed_env_files" | while read -r file; do
            print_error "  $file"
            log_to_report "ENV_COMMITTED: $file"
        done
    fi
}

# Function to check for weak secrets
check_weak_secrets() {
    print_info "Checking for weak secrets..."
    
    if [[ -f "$PROJECT_ROOT/.env" ]]; then
        # Source the env file safely
        while IFS= read -r line; do
            if [[ "$line" =~ ^[A-Z_]+= ]]; then
                local key=$(echo "$line" | cut -d'=' -f1)
                local value=$(echo "$line" | cut -d'=' -f2-)
                
                # Remove quotes
                value=$(echo "$value" | sed 's/^["'\'']//' | sed 's/["'\'']$//')
                
                # Check for weak patterns
                if [[ "$key" =~ (PASSWORD|SECRET|KEY|TOKEN) ]] && [[ -n "$value" ]]; then
                    if [[ ${#value} -lt 12 ]]; then
                        print_warning "Weak secret detected - too short: $key"
                        log_to_report "WEAK_SECRET_SHORT: $key"
                    fi
                    
                    # Check for common weak patterns
                    local weak_patterns=("password" "123456" "admin" "secret" "default" "changeme" "test")
                    for pattern in "${weak_patterns[@]}"; do
                        if [[ "${value,,}" == *"$pattern"* ]]; then
                            print_warning "Weak secret detected - contains '$pattern': $key"
                            log_to_report "WEAK_SECRET_PATTERN: $key contains $pattern"
                        fi
                    done
                fi
            fi
        done < "$PROJECT_ROOT/.env"
    fi
}

# Function to check file permissions
check_file_permissions() {
    print_info "Checking file permissions..."
    
    # Check for overly permissive files
    local sensitive_files=(
        ".env"
        "configs/security/"
        "scripts/"
        "deployments/"
    )
    
    for item in "${sensitive_files[@]}"; do
        local full_path="$PROJECT_ROOT/$item"
        if [[ -e "$full_path" ]]; then
            local perms=$(stat -c "%a" "$full_path" 2>/dev/null || stat -f "%A" "$full_path" 2>/dev/null || echo "unknown")
            if [[ "$perms" =~ ^[0-9]{3}$ ]] && [[ "${perms:2:1}" -gt "4" ]]; then
                print_warning "File has overly permissive permissions ($perms): $item"
                log_to_report "PERMISSIVE_PERMS: $item ($perms)"
            fi
        fi
    done
}

# Function to generate recommendations
generate_recommendations() {
    print_info "Generating security recommendations..."
    
    echo "" >> "$REPORT_FILE"
    echo "SECURITY RECOMMENDATIONS:" >> "$REPORT_FILE"
    echo "========================" >> "$REPORT_FILE"
    
    if [[ $ISSUES_FOUND -gt 0 ]]; then
        echo "1. Remove all hardcoded secrets from the codebase" >> "$REPORT_FILE"
        echo "2. Use environment variables for all sensitive configuration" >> "$REPORT_FILE"
        echo "3. Implement proper secret management (AWS Secrets Manager, Azure Key Vault, etc.)" >> "$REPORT_FILE"
        echo "4. Rotate any exposed secrets immediately" >> "$REPORT_FILE"
    fi
    
    if [[ $WARNINGS_FOUND -gt 0 ]]; then
        echo "5. Review and strengthen weak secrets" >> "$REPORT_FILE"
        echo "6. Implement secret validation in CI/CD pipeline" >> "$REPORT_FILE"
        echo "7. Regular security audits and secret rotation" >> "$REPORT_FILE"
    fi
    
    echo "8. Use the provided setup-secrets.sh script to generate secure secrets" >> "$REPORT_FILE"
    echo "9. Enable pre-commit hooks to prevent secret commits" >> "$REPORT_FILE"
    echo "10. Implement monitoring for secret exposure" >> "$REPORT_FILE"
}

# Main function
main() {
    echo "🔒 HackAI Security Audit"
    echo "======================="
    echo
    
    # Initialize report file
    echo "HackAI Security Audit Report" > "$REPORT_FILE"
    echo "Generated: $(date)" >> "$REPORT_FILE"
    echo "=================================" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Run security checks
    scan_hardcoded_secrets
    check_config_files
    check_env_files
    check_weak_secrets
    check_file_permissions
    
    # Generate recommendations
    generate_recommendations
    
    # Summary
    echo
    echo "🔒 Security Audit Summary"
    echo "========================"
    print_info "Report saved to: $REPORT_FILE"
    
    if [[ $ISSUES_FOUND -eq 0 ]] && [[ $WARNINGS_FOUND -eq 0 ]]; then
        print_success "No security issues found!"
    else
        if [[ $ISSUES_FOUND -gt 0 ]]; then
            print_error "Found $ISSUES_FOUND critical security issues"
        fi
        if [[ $WARNINGS_FOUND -gt 0 ]]; then
            print_warning "Found $WARNINGS_FOUND security warnings"
        fi
        echo
        print_info "Please review the issues above and the detailed report at: $REPORT_FILE"
        print_info "Use 'scripts/setup-secrets.sh' to help fix secret management issues"
    fi
    
    # Exit with error code if issues found
    if [[ $ISSUES_FOUND -gt 0 ]]; then
        exit 1
    fi
}

# Check if we're in a git repository
if ! git rev-parse --git-dir >/dev/null 2>&1; then
    print_warning "Not in a git repository - some checks will be skipped"
fi

# Run main function
main "$@"
