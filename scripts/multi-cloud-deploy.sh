#!/bin/bash

# HackAI Multi-Cloud Infrastructure Deployment Script
# This script automates the deployment of HackAI infrastructure across multiple cloud providers

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
TERRAFORM_DIR="$PROJECT_ROOT/infrastructure/terraform/multi-cloud"
ORCHESTRATOR_DIR="$PROJECT_ROOT/infrastructure/multi-cloud-orchestrator"

# Default values
ENVIRONMENT="${ENVIRONMENT:-development}"
CONFIG_FILE="${CONFIG_FILE:-$PROJECT_ROOT/infrastructure/multi-cloud-config.yaml}"
ENABLE_AWS="${ENABLE_AWS:-true}"
ENABLE_GCP="${ENABLE_GCP:-false}"
ENABLE_AZURE="${ENABLE_AZURE:-false}"
ENABLE_MONITORING="${ENABLE_MONITORING:-true}"
DRY_RUN="${DRY_RUN:-false}"
DESTROY="${DESTROY:-false}"
SKIP_VALIDATION="${SKIP_VALIDATION:-false}"

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

# Help function
show_help() {
    cat << EOF
HackAI Multi-Cloud Infrastructure Deployment Script

Usage: $0 [OPTIONS]

OPTIONS:
    -e, --environment ENVIRONMENT    Set deployment environment (development, staging, production)
    -c, --config CONFIG_FILE         Path to configuration file
    --enable-aws                     Enable AWS deployment (default: true)
    --enable-gcp                     Enable GCP deployment (default: false)
    --enable-azure                   Enable Azure deployment (default: false)
    --enable-monitoring              Enable monitoring stack (default: true)
    --dry-run                        Show what would be deployed without making changes
    --destroy                        Destroy infrastructure instead of deploying
    --skip-validation               Skip prerequisite validation
    -h, --help                      Show this help message

EXAMPLES:
    # Deploy to development environment with AWS only
    $0 --environment development --enable-aws

    # Deploy to production with all cloud providers
    $0 --environment production --enable-aws --enable-gcp --enable-azure

    # Dry run to see what would be deployed
    $0 --dry-run --environment staging

    # Destroy infrastructure
    $0 --destroy --environment development

ENVIRONMENT VARIABLES:
    ENVIRONMENT                      Deployment environment
    CONFIG_FILE                      Configuration file path
    ENABLE_AWS                       Enable AWS (true/false)
    ENABLE_GCP                       Enable GCP (true/false)
    ENABLE_AZURE                     Enable Azure (true/false)
    ENABLE_MONITORING                Enable monitoring (true/false)
    DRY_RUN                         Dry run mode (true/false)
    DESTROY                         Destroy mode (true/false)
    SKIP_VALIDATION                 Skip validation (true/false)

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --enable-aws)
                ENABLE_AWS="true"
                shift
                ;;
            --enable-gcp)
                ENABLE_GCP="true"
                shift
                ;;
            --enable-azure)
                ENABLE_AZURE="true"
                shift
                ;;
            --enable-monitoring)
                ENABLE_MONITORING="true"
                shift
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            --destroy)
                DESTROY="true"
                shift
                ;;
            --skip-validation)
                SKIP_VALIDATION="true"
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Validate prerequisites
validate_prerequisites() {
    if [[ "$SKIP_VALIDATION" == "true" ]]; then
        log_warning "Skipping prerequisite validation"
        return 0
    fi

    log_info "Validating prerequisites..."

    # Check required tools
    local required_tools=("terraform" "kubectl" "helm" "jq" "yq")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "$tool is required but not installed"
            exit 1
        fi
    done

    # Check cloud CLI tools based on enabled providers
    if [[ "$ENABLE_AWS" == "true" ]]; then
        if ! command -v aws &> /dev/null; then
            log_error "AWS CLI is required for AWS deployment"
            exit 1
        fi
        
        # Check AWS credentials
        if ! aws sts get-caller-identity &> /dev/null; then
            log_error "AWS credentials not configured"
            exit 1
        fi
    fi

    if [[ "$ENABLE_GCP" == "true" ]]; then
        if ! command -v gcloud &> /dev/null; then
            log_error "Google Cloud CLI is required for GCP deployment"
            exit 1
        fi
        
        # Check GCP authentication
        if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -n1 &> /dev/null; then
            log_error "GCP authentication not configured"
            exit 1
        fi
    fi

    if [[ "$ENABLE_AZURE" == "true" ]]; then
        if ! command -v az &> /dev/null; then
            log_error "Azure CLI is required for Azure deployment"
            exit 1
        fi
        
        # Check Azure authentication
        if ! az account show &> /dev/null; then
            log_error "Azure authentication not configured"
            exit 1
        fi
    fi

    log_success "Prerequisites validation completed"
}

# Generate configuration file if it doesn't exist
generate_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_info "Configuration file not found. Generating default configuration..."
        
        # Build the orchestrator if it doesn't exist
        if [[ ! -f "$ORCHESTRATOR_DIR/multi-cloud-orchestrator" ]]; then
            log_info "Building multi-cloud orchestrator..."
            cd "$ORCHESTRATOR_DIR"
            go build -o multi-cloud-orchestrator main.go
            cd - > /dev/null
        fi
        
        # Generate configuration
        "$ORCHESTRATOR_DIR/multi-cloud-orchestrator" generate-config --config "$CONFIG_FILE"
        log_success "Configuration file generated at: $CONFIG_FILE"
        log_warning "Please review and customize the configuration file before proceeding"
        exit 0
    fi
}

# Initialize Terraform
init_terraform() {
    log_info "Initializing Terraform..."
    cd "$TERRAFORM_DIR"
    
    terraform init -upgrade
    
    if [[ "$DRY_RUN" == "false" ]]; then
        terraform validate
    fi
    
    cd - > /dev/null
    log_success "Terraform initialized"
}

# Plan deployment
plan_deployment() {
    log_info "Planning deployment for environment: $ENVIRONMENT"
    cd "$TERRAFORM_DIR"
    
    # Create terraform.tfvars from configuration
    create_terraform_vars
    
    # Run terraform plan
    terraform plan \
        -var-file="environments/${ENVIRONMENT}.tfvars" \
        -var="enable_aws=$ENABLE_AWS" \
        -var="enable_gcp=$ENABLE_GCP" \
        -var="enable_azure=$ENABLE_AZURE" \
        -var="enable_monitoring=$ENABLE_MONITORING" \
        -out="tfplan-${ENVIRONMENT}"
    
    cd - > /dev/null
    log_success "Deployment plan created"
}

# Apply deployment
apply_deployment() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run mode - skipping actual deployment"
        return 0
    fi

    log_info "Applying deployment..."
    cd "$TERRAFORM_DIR"
    
    terraform apply "tfplan-${ENVIRONMENT}"
    
    cd - > /dev/null
    log_success "Deployment completed"
}

# Destroy infrastructure
destroy_infrastructure() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run mode - showing what would be destroyed"
        cd "$TERRAFORM_DIR"
        terraform plan -destroy \
            -var-file="environments/${ENVIRONMENT}.tfvars" \
            -var="enable_aws=$ENABLE_AWS" \
            -var="enable_gcp=$ENABLE_GCP" \
            -var="enable_azure=$ENABLE_AZURE" \
            -var="enable_monitoring=$ENABLE_MONITORING"
        cd - > /dev/null
        return 0
    fi

    log_warning "This will destroy all infrastructure in environment: $ENVIRONMENT"
    read -p "Are you sure you want to continue? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log_info "Destruction cancelled"
        exit 0
    fi

    log_info "Destroying infrastructure..."
    cd "$TERRAFORM_DIR"
    
    terraform destroy \
        -var-file="environments/${ENVIRONMENT}.tfvars" \
        -var="enable_aws=$ENABLE_AWS" \
        -var="enable_gcp=$ENABLE_GCP" \
        -var="enable_azure=$ENABLE_AZURE" \
        -var="enable_monitoring=$ENABLE_MONITORING" \
        -auto-approve
    
    cd - > /dev/null
    log_success "Infrastructure destroyed"
}

# Create Terraform variables from configuration
create_terraform_vars() {
    log_info "Creating Terraform variables from configuration..."
    
    # This would parse the YAML config and create terraform.tfvars
    # For now, we'll use the existing environment files
    if [[ ! -f "environments/${ENVIRONMENT}.tfvars" ]]; then
        log_error "Environment file not found: environments/${ENVIRONMENT}.tfvars"
        exit 1
    fi
}

# Configure kubectl contexts
configure_kubectl() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run mode - skipping kubectl configuration"
        return 0
    fi

    log_info "Configuring kubectl contexts..."
    cd "$TERRAFORM_DIR"
    
    # Get cluster information from Terraform outputs
    if [[ "$ENABLE_AWS" == "true" ]]; then
        local aws_cluster_name
        aws_cluster_name=$(terraform output -raw aws_cluster_name 2>/dev/null || echo "")
        if [[ -n "$aws_cluster_name" ]]; then
            local aws_region
            aws_region=$(terraform output -raw aws_region 2>/dev/null || echo "us-west-2")
            aws eks update-kubeconfig --region "$aws_region" --name "$aws_cluster_name" --alias "aws-${ENVIRONMENT}"
            log_success "AWS kubectl context configured: aws-${ENVIRONMENT}"
        fi
    fi
    
    if [[ "$ENABLE_GCP" == "true" ]]; then
        local gcp_cluster_name
        gcp_cluster_name=$(terraform output -raw gcp_cluster_name 2>/dev/null || echo "")
        if [[ -n "$gcp_cluster_name" ]]; then
            local gcp_region gcp_project
            gcp_region=$(terraform output -raw gcp_region 2>/dev/null || echo "us-central1")
            gcp_project=$(terraform output -raw gcp_project_id 2>/dev/null || echo "")
            if [[ -n "$gcp_project" ]]; then
                gcloud container clusters get-credentials "$gcp_cluster_name" --region "$gcp_region" --project "$gcp_project"
                kubectl config rename-context "gke_${gcp_project}_${gcp_region}_${gcp_cluster_name}" "gcp-${ENVIRONMENT}"
                log_success "GCP kubectl context configured: gcp-${ENVIRONMENT}"
            fi
        fi
    fi
    
    if [[ "$ENABLE_AZURE" == "true" ]]; then
        local azure_cluster_name
        azure_cluster_name=$(terraform output -raw azure_cluster_name 2>/dev/null || echo "")
        if [[ -n "$azure_cluster_name" ]]; then
            local azure_resource_group
            azure_resource_group=$(terraform output -raw azure_resource_group_name 2>/dev/null || echo "")
            if [[ -n "$azure_resource_group" ]]; then
                az aks get-credentials --resource-group "$azure_resource_group" --name "$azure_cluster_name" --context "azure-${ENVIRONMENT}"
                log_success "Azure kubectl context configured: azure-${ENVIRONMENT}"
            fi
        fi
    fi
    
    cd - > /dev/null
}

# Main function
main() {
    log_info "Starting HackAI Multi-Cloud Infrastructure Deployment"
    log_info "Environment: $ENVIRONMENT"
    log_info "AWS: $ENABLE_AWS, GCP: $ENABLE_GCP, Azure: $ENABLE_AZURE"
    log_info "Monitoring: $ENABLE_MONITORING"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_warning "Running in DRY RUN mode - no changes will be made"
    fi
    
    validate_prerequisites
    generate_config
    init_terraform
    
    if [[ "$DESTROY" == "true" ]]; then
        destroy_infrastructure
    else
        plan_deployment
        apply_deployment
        configure_kubectl
        
        log_success "Multi-cloud infrastructure deployment completed!"
        log_info "Next steps:"
        log_info "1. Verify cluster connectivity: kubectl get nodes --context=aws-${ENVIRONMENT}"
        log_info "2. Deploy applications: helm install hackai ./deployments/helm/hackai"
        log_info "3. Access monitoring: kubectl port-forward svc/grafana 3000:3000"
    fi
}

# Parse arguments and run main function
parse_args "$@"
main
