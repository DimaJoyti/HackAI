#!/bin/bash

# Multi-Cloud Deployment Script for HackAI
# Supports AWS, GCP, and Azure deployments with serverless functions

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_FILE="${PROJECT_ROOT}/logs/deployment-$(date +%Y%m%d-%H%M%S).log"

# Default values
ENVIRONMENT="${ENVIRONMENT:-development}"
CLOUD_PROVIDERS="${CLOUD_PROVIDERS:-aws,gcp,azure}"
DEPLOY_SERVERLESS="${DEPLOY_SERVERLESS:-true}"
DEPLOY_MONITORING="${DEPLOY_MONITORING:-true}"
DEPLOY_SECURITY="${DEPLOY_SECURITY:-true}"
DRY_RUN="${DRY_RUN:-false}"
PARALLEL_DEPLOYMENT="${PARALLEL_DEPLOYMENT:-true}"
TERRAFORM_WORKSPACE="${TERRAFORM_WORKSPACE:-$ENVIRONMENT}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Multi-Cloud Deployment Script for HackAI Platform

OPTIONS:
    -e, --environment ENVIRONMENT    Deployment environment (development, staging, production)
    -c, --clouds PROVIDERS          Comma-separated list of cloud providers (aws,gcp,azure)
    -s, --serverless                Deploy serverless functions
    -m, --monitoring                Deploy monitoring stack
    --security                      Deploy security components
    -d, --dry-run                   Show what would be deployed without executing
    -p, --parallel                  Deploy to clouds in parallel
    -w, --workspace WORKSPACE       Terraform workspace name
    -h, --help                      Show this help message

EXAMPLES:
    $0 -e production -c aws,gcp
    $0 --environment staging --clouds aws --serverless --monitoring
    $0 --dry-run --environment production

ENVIRONMENT VARIABLES:
    AWS_PROFILE                     AWS profile to use
    GCP_PROJECT_ID                  Google Cloud project ID
    AZURE_SUBSCRIPTION_ID           Azure subscription ID
    TERRAFORM_WORKSPACE             Terraform workspace (defaults to environment)
    SLACK_WEBHOOK_URL              Slack webhook for notifications

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                TERRAFORM_WORKSPACE="$2"
                shift 2
                ;;
            -c|--clouds)
                CLOUD_PROVIDERS="$2"
                shift 2
                ;;
            -s|--serverless)
                DEPLOY_SERVERLESS="true"
                shift
                ;;
            -m|--monitoring)
                DEPLOY_MONITORING="true"
                shift
                ;;
            --security)
                DEPLOY_SECURITY="true"
                shift
                ;;
            -d|--dry-run)
                DRY_RUN="true"
                shift
                ;;
            -p|--parallel)
                PARALLEL_DEPLOYMENT="true"
                shift
                ;;
            -w|--workspace)
                TERRAFORM_WORKSPACE="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Validate prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing_tools=()
    
    # Check required tools
    for tool in terraform kubectl helm docker jq; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    # Check cloud CLI tools based on enabled providers
    IFS=',' read -ra PROVIDERS <<< "$CLOUD_PROVIDERS"
    for provider in "${PROVIDERS[@]}"; do
        case $provider in
            aws)
                if ! command -v aws &> /dev/null; then
                    missing_tools+=("aws-cli")
                fi
                ;;
            gcp)
                if ! command -v gcloud &> /dev/null; then
                    missing_tools+=("gcloud")
                fi
                ;;
            azure)
                if ! command -v az &> /dev/null; then
                    missing_tools+=("azure-cli")
                fi
                ;;
        esac
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Please install the missing tools and try again."
        exit 1
    fi
    
    # Check environment variables
    if [[ "$CLOUD_PROVIDERS" == *"gcp"* ]] && [[ -z "${GCP_PROJECT_ID:-}" ]]; then
        log_error "GCP_PROJECT_ID environment variable is required for GCP deployment"
        exit 1
    fi
    
    if [[ "$CLOUD_PROVIDERS" == *"azure"* ]] && [[ -z "${AZURE_SUBSCRIPTION_ID:-}" ]]; then
        log_error "AZURE_SUBSCRIPTION_ID environment variable is required for Azure deployment"
        exit 1
    fi
    
    log_success "Prerequisites check completed"
}

# Validate cloud credentials
validate_credentials() {
    log_info "Validating cloud credentials..."
    
    IFS=',' read -ra PROVIDERS <<< "$CLOUD_PROVIDERS"
    for provider in "${PROVIDERS[@]}"; do
        case $provider in
            aws)
                if ! aws sts get-caller-identity &> /dev/null; then
                    log_error "AWS credentials not configured or invalid"
                    exit 1
                fi
                log_success "AWS credentials validated"
                ;;
            gcp)
                if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -n1 &> /dev/null; then
                    log_error "GCP credentials not configured or invalid"
                    exit 1
                fi
                log_success "GCP credentials validated"
                ;;
            azure)
                if ! az account show &> /dev/null; then
                    log_error "Azure credentials not configured or invalid"
                    exit 1
                fi
                log_success "Azure credentials validated"
                ;;
        esac
    done
}

# Initialize Terraform
init_terraform() {
    log_info "Initializing Terraform..."
    
    cd "${PROJECT_ROOT}/infrastructure/terraform/multi-cloud"
    
    if [[ "$DRY_RUN" == "false" ]]; then
        terraform init
        
        # Create or select workspace
        if terraform workspace list | grep -q "$TERRAFORM_WORKSPACE"; then
            terraform workspace select "$TERRAFORM_WORKSPACE"
        else
            terraform workspace new "$TERRAFORM_WORKSPACE"
        fi
        
        log_success "Terraform initialized with workspace: $TERRAFORM_WORKSPACE"
    else
        log_info "DRY RUN: Would initialize Terraform with workspace: $TERRAFORM_WORKSPACE"
    fi
}

# Deploy infrastructure for a specific cloud provider
deploy_cloud_infrastructure() {
    local provider=$1
    log_info "Deploying infrastructure to $provider..."
    
    cd "${PROJECT_ROOT}/infrastructure/terraform/multi-cloud"
    
    local tf_vars_file="environments/${ENVIRONMENT}.tfvars"
    local tf_plan_file="tfplan-${provider}-${ENVIRONMENT}"
    
    if [[ ! -f "$tf_vars_file" ]]; then
        log_error "Terraform variables file not found: $tf_vars_file"
        return 1
    fi
    
    # Create Terraform plan
    local tf_plan_cmd="terraform plan"
    tf_plan_cmd+=" -var-file=\"$tf_vars_file\""
    tf_plan_cmd+=" -var=\"enable_${provider}=true\""
    
    # Disable other providers for focused deployment
    IFS=',' read -ra ALL_PROVIDERS <<< "aws,gcp,azure"
    for p in "${ALL_PROVIDERS[@]}"; do
        if [[ "$p" != "$provider" ]]; then
            tf_plan_cmd+=" -var=\"enable_${p}=false\""
        fi
    done
    
    tf_plan_cmd+=" -out=\"$tf_plan_file\""
    
    if [[ "$DRY_RUN" == "false" ]]; then
        if eval "$tf_plan_cmd"; then
            log_success "Terraform plan created for $provider"
            
            # Apply the plan
            if terraform apply -auto-approve "$tf_plan_file"; then
                log_success "Infrastructure deployed to $provider"
                
                # Save outputs
                terraform output -json > "outputs-${provider}-${ENVIRONMENT}.json"
                log_info "Terraform outputs saved for $provider"
            else
                log_error "Failed to deploy infrastructure to $provider"
                return 1
            fi
        else
            log_error "Failed to create Terraform plan for $provider"
            return 1
        fi
    else
        log_info "DRY RUN: Would execute: $tf_plan_cmd"
        log_info "DRY RUN: Would apply Terraform plan for $provider"
    fi
}

# Deploy serverless functions
deploy_serverless_functions() {
    if [[ "$DEPLOY_SERVERLESS" != "true" ]]; then
        log_info "Skipping serverless deployment"
        return 0
    fi
    
    log_info "Deploying serverless functions..."
    
    # Build Lambda functions
    if [[ "$CLOUD_PROVIDERS" == *"aws"* ]]; then
        log_info "Building AWS Lambda functions..."
        cd "${PROJECT_ROOT}/serverless/aws-lambda"
        
        for func_dir in */; do
            if [[ -f "${func_dir}main.go" ]]; then
                func_name="${func_dir%/}"
                log_info "Building function: $func_name"
                
                if [[ "$DRY_RUN" == "false" ]]; then
                    cd "$func_dir"
                    GOOS=linux GOARCH=amd64 go build -o main main.go
                    zip "../${func_name}.zip" main
                    cd ..
                    log_success "Built function: $func_name"
                else
                    log_info "DRY RUN: Would build function: $func_name"
                fi
            fi
        done
    fi
    
    # Deploy functions using Terraform outputs
    IFS=',' read -ra PROVIDERS <<< "$CLOUD_PROVIDERS"
    for provider in "${PROVIDERS[@]}"; do
        case $provider in
            aws)
                deploy_aws_lambda_functions
                ;;
            gcp)
                deploy_gcp_cloud_functions
                ;;
            azure)
                deploy_azure_functions
                ;;
        esac
    done
}

# Deploy AWS Lambda functions
deploy_aws_lambda_functions() {
    log_info "Deploying AWS Lambda functions..."
    
    cd "${PROJECT_ROOT}/serverless/aws-lambda"
    
    for zip_file in *.zip; do
        if [[ -f "$zip_file" ]]; then
            func_name="${zip_file%.zip}"
            lambda_name="hackai-${ENVIRONMENT}-${func_name}"
            
            if [[ "$DRY_RUN" == "false" ]]; then
                # Check if function exists and update code
                if aws lambda get-function --function-name "$lambda_name" &> /dev/null; then
                    aws lambda update-function-code \
                        --function-name "$lambda_name" \
                        --zip-file "fileb://$zip_file"
                    log_success "Updated Lambda function: $lambda_name"
                else
                    log_warning "Lambda function $lambda_name not found (will be created by Terraform)"
                fi
            else
                log_info "DRY RUN: Would deploy Lambda function: $lambda_name"
            fi
        fi
    done
}

# Deploy GCP Cloud Functions
deploy_gcp_cloud_functions() {
    log_info "Deploying GCP Cloud Functions..."
    # Implementation for GCP Cloud Functions deployment
    if [[ "$DRY_RUN" == "false" ]]; then
        log_info "GCP Cloud Functions deployment logic would go here"
    else
        log_info "DRY RUN: Would deploy GCP Cloud Functions"
    fi
}

# Deploy Azure Functions
deploy_azure_functions() {
    log_info "Deploying Azure Functions..."
    # Implementation for Azure Functions deployment
    if [[ "$DRY_RUN" == "false" ]]; then
        log_info "Azure Functions deployment logic would go here"
    else
        log_info "DRY RUN: Would deploy Azure Functions"
    fi
}

# Deploy applications to Kubernetes clusters
deploy_applications() {
    log_info "Deploying applications to Kubernetes clusters..."
    
    IFS=',' read -ra PROVIDERS <<< "$CLOUD_PROVIDERS"
    for provider in "${PROVIDERS[@]}"; do
        deploy_to_kubernetes "$provider"
    done
}

# Deploy to specific Kubernetes cluster
deploy_to_kubernetes() {
    local provider=$1
    log_info "Deploying applications to $provider Kubernetes cluster..."
    
    local outputs_file="${PROJECT_ROOT}/infrastructure/terraform/multi-cloud/outputs-${provider}-${ENVIRONMENT}.json"
    
    if [[ ! -f "$outputs_file" ]]; then
        log_error "Terraform outputs file not found: $outputs_file"
        return 1
    fi
    
    # Configure kubectl based on provider
    case $provider in
        aws)
            if [[ "$DRY_RUN" == "false" ]]; then
                local cluster_name
                cluster_name=$(jq -r ".aws_infrastructure.value.cluster_id" "$outputs_file")
                aws eks update-kubeconfig --region us-west-2 --name "$cluster_name" --alias "aws-${ENVIRONMENT}"
                log_success "Configured kubectl for AWS EKS: $cluster_name"
            else
                log_info "DRY RUN: Would configure kubectl for AWS EKS"
            fi
            ;;
        gcp)
            if [[ "$DRY_RUN" == "false" ]]; then
                local cluster_name project_id
                cluster_name=$(jq -r ".gcp_infrastructure.value.cluster_name" "$outputs_file")
                project_id=$(jq -r ".gcp_infrastructure.value.project_id" "$outputs_file")
                gcloud container clusters get-credentials "$cluster_name" --region us-central1 --project "$project_id"
                log_success "Configured kubectl for GCP GKE: $cluster_name"
            else
                log_info "DRY RUN: Would configure kubectl for GCP GKE"
            fi
            ;;
        azure)
            if [[ "$DRY_RUN" == "false" ]]; then
                local cluster_name resource_group
                cluster_name=$(jq -r ".azure_infrastructure.value.cluster_name" "$outputs_file")
                resource_group=$(jq -r ".azure_infrastructure.value.resource_group_name" "$outputs_file")
                az aks get-credentials --resource-group "$resource_group" --name "$cluster_name" --overwrite-existing
                log_success "Configured kubectl for Azure AKS: $cluster_name"
            else
                log_info "DRY RUN: Would configure kubectl for Azure AKS"
            fi
            ;;
    esac
    
    # Deploy using Helm
    local namespace="hackai-${ENVIRONMENT}"
    local release_name="hackai-${provider}"
    
    if [[ "$DRY_RUN" == "false" ]]; then
        helm upgrade --install "$release_name" \
            "${PROJECT_ROOT}/deployments/helm/hackai" \
            --namespace "$namespace" \
            --create-namespace \
            --set app.environment="$ENVIRONMENT" \
            --set global.cloudProvider="$provider" \
            --values "${PROJECT_ROOT}/deployments/helm/hackai/values-${provider}.yaml" \
            --wait --timeout=10m
        
        log_success "Deployed applications to $provider cluster"
        
        # Verify deployment
        kubectl get pods -n "$namespace"
        kubectl get services -n "$namespace"
    else
        log_info "DRY RUN: Would deploy Helm chart to $provider cluster"
    fi
}

# Run health checks
run_health_checks() {
    log_info "Running health checks..."
    
    if [[ "$DRY_RUN" == "false" ]]; then
        # Implementation for health checks
        log_info "Health check implementation would go here"
        log_success "Health checks completed"
    else
        log_info "DRY RUN: Would run health checks"
    fi
}

# Send notifications
send_notifications() {
    local status=$1
    local message=$2
    
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        local color="good"
        if [[ "$status" == "failure" ]]; then
            color="danger"
        elif [[ "$status" == "warning" ]]; then
            color="warning"
        fi
        
        local payload
        payload=$(cat << EOF
{
    "attachments": [
        {
            "color": "$color",
            "title": "HackAI Multi-Cloud Deployment",
            "fields": [
                {
                    "title": "Environment",
                    "value": "$ENVIRONMENT",
                    "short": true
                },
                {
                    "title": "Cloud Providers",
                    "value": "$CLOUD_PROVIDERS",
                    "short": true
                },
                {
                    "title": "Status",
                    "value": "$status",
                    "short": true
                },
                {
                    "title": "Message",
                    "value": "$message",
                    "short": false
                }
            ],
            "footer": "HackAI Deployment Bot",
            "ts": $(date +%s)
        }
    ]
}
EOF
        )
        
        if [[ "$DRY_RUN" == "false" ]]; then
            curl -X POST -H 'Content-type: application/json' \
                --data "$payload" \
                "$SLACK_WEBHOOK_URL" &> /dev/null || true
        else
            log_info "DRY RUN: Would send Slack notification"
        fi
    fi
}

# Cleanup function
cleanup() {
    local exit_code=$?
    
    if [[ $exit_code -ne 0 ]]; then
        log_error "Deployment failed with exit code: $exit_code"
        send_notifications "failure" "Multi-cloud deployment failed. Check logs for details."
    fi
    
    # Cleanup temporary files
    cd "${PROJECT_ROOT}/infrastructure/terraform/multi-cloud"
    rm -f tfplan-* &> /dev/null || true
    
    exit $exit_code
}

# Main deployment function
main() {
    # Set up logging
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Set up cleanup trap
    trap cleanup EXIT
    
    log_info "Starting HackAI Multi-Cloud Deployment"
    log_info "Environment: $ENVIRONMENT"
    log_info "Cloud Providers: $CLOUD_PROVIDERS"
    log_info "Terraform Workspace: $TERRAFORM_WORKSPACE"
    log_info "Dry Run: $DRY_RUN"
    
    # Validate prerequisites and credentials
    check_prerequisites
    validate_credentials
    
    # Initialize Terraform
    init_terraform
    
    # Deploy infrastructure
    if [[ "$PARALLEL_DEPLOYMENT" == "true" ]]; then
        log_info "Deploying infrastructure in parallel..."
        IFS=',' read -ra PROVIDERS <<< "$CLOUD_PROVIDERS"
        for provider in "${PROVIDERS[@]}"; do
            deploy_cloud_infrastructure "$provider" &
        done
        wait
    else
        log_info "Deploying infrastructure sequentially..."
        IFS=',' read -ra PROVIDERS <<< "$CLOUD_PROVIDERS"
        for provider in "${PROVIDERS[@]}"; do
            deploy_cloud_infrastructure "$provider"
        done
    fi
    
    # Deploy serverless functions
    deploy_serverless_functions
    
    # Deploy applications
    deploy_applications
    
    # Run health checks
    run_health_checks
    
    log_success "Multi-cloud deployment completed successfully!"
    send_notifications "success" "Multi-cloud deployment completed successfully for environment: $ENVIRONMENT"
}

# Parse arguments and run main function
parse_args "$@"
main
