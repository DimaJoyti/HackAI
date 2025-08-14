#!/bin/bash

# Terraform validation script for HackAI infrastructure
# This script validates the Terraform configuration and checks for common issues

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Check if Terraform is installed
check_terraform() {
    if ! command -v terraform &> /dev/null; then
        error "Terraform is not installed. Please install Terraform first."
    fi
    
    local version=$(terraform version -json | jq -r '.terraform_version')
    info "Terraform version: $version"
    
    # Check if version is >= 1.5
    if [[ $(echo "$version 1.5.0" | tr " " "\n" | sort -V | head -n1) != "1.5.0" ]]; then
        warn "Terraform version $version is older than required 1.5.0"
    fi
}

# Check AWS CLI configuration
check_aws() {
    if ! command -v aws &> /dev/null; then
        error "AWS CLI is not installed. Please install AWS CLI first."
    fi
    
    if ! aws sts get-caller-identity &> /dev/null; then
        error "AWS CLI is not configured. Please run 'aws configure' first."
    fi
    
    local account_id=$(aws sts get-caller-identity --query Account --output text)
    local region=$(aws configure get region)
    info "AWS Account ID: $account_id"
    info "AWS Region: $region"
}

# Initialize Terraform
init_terraform() {
    log "Initializing Terraform..."
    
    if [[ ! -f "terraform.tfvars" ]]; then
        warn "terraform.tfvars not found. Creating from example..."
        cp terraform.tfvars.example terraform.tfvars
        warn "Please edit terraform.tfvars with your specific values before proceeding."
    fi
    
    terraform init
}

# Validate Terraform configuration
validate_terraform() {
    log "Validating Terraform configuration..."
    
    # Format check
    if ! terraform fmt -check=true -diff=true; then
        warn "Terraform files are not properly formatted. Run 'terraform fmt' to fix."
    fi
    
    # Validation
    terraform validate
    
    log "Terraform configuration is valid!"
}

# Plan Terraform deployment
plan_terraform() {
    log "Creating Terraform plan..."
    
    terraform plan -out=tfplan
    
    info "Terraform plan created successfully!"
    info "Review the plan above and run 'terraform apply tfplan' to deploy."
}

# Security checks
security_checks() {
    log "Running security checks..."
    
    # Check for hardcoded secrets
    if grep -r "password\s*=" . --include="*.tf" --include="*.tfvars" | grep -v "random_password" | grep -v "example"; then
        warn "Found potential hardcoded passwords in Terraform files"
    fi
    
    # Check for public access
    if grep -r "0.0.0.0/0" . --include="*.tf"; then
        warn "Found resources with public access (0.0.0.0/0)"
    fi
    
    # Check for unencrypted resources
    if grep -r "encrypted.*=.*false" . --include="*.tf"; then
        warn "Found resources with encryption disabled"
    fi
    
    info "Security checks completed"
}

# Cost estimation (if available)
cost_estimation() {
    if command -v infracost &> /dev/null; then
        log "Running cost estimation..."
        infracost breakdown --path .
    else
        info "Infracost not installed. Skipping cost estimation."
        info "Install infracost for cost estimation: https://www.infracost.io/docs/"
    fi
}

# Main function
main() {
    log "Starting Terraform validation for HackAI infrastructure"
    
    # Change to script directory
    cd "$(dirname "${BASH_SOURCE[0]}")"
    
    check_terraform
    check_aws
    init_terraform
    validate_terraform
    security_checks
    plan_terraform
    cost_estimation
    
    log "Terraform validation completed successfully!"
    
    echo ""
    info "Next steps:"
    info "1. Review the Terraform plan above"
    info "2. If everything looks good, run: terraform apply tfplan"
    info "3. After deployment, run: terraform output"
    echo ""
    warn "Remember to:"
    warn "- Review all resources before applying"
    warn "- Ensure you have proper AWS permissions"
    warn "- Consider running in a test environment first"
}

# Run main function
main "$@"
