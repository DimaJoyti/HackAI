#!/bin/bash

# HackAI Secure Secrets Setup Script
# This script helps set up secure secrets for the HackAI platform
# 
# 🔒 SECURITY BEST PRACTICES:
# - Never store secrets in version control
# - Use strong, randomly generated secrets
# - Rotate secrets regularly
# - Use external secret management in production

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
ENV_FILE="$PROJECT_ROOT/.env"
ENV_EXAMPLE_FILE="$PROJECT_ROOT/.env.example"

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to generate a secure random string
generate_secret() {
    local length=${1:-32}
    openssl rand -base64 $length | tr -d "=+/" | cut -c1-$length
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to validate secret strength
validate_secret_strength() {
    local secret="$1"
    local min_length=${2:-16}
    
    if [[ ${#secret} -lt $min_length ]]; then
        return 1
    fi
    
    # Check for weak patterns
    local weak_patterns=("password" "123456" "admin" "secret" "default" "changeme" "test")
    for pattern in "${weak_patterns[@]}"; do
        if [[ "${secret,,}" == *"${pattern}"* ]]; then
            return 1
        fi
    done
    
    return 0
}

# Function to setup environment file
setup_env_file() {
    print_info "Setting up environment file..."
    
    if [[ -f "$ENV_FILE" ]]; then
        print_warning "Environment file already exists at $ENV_FILE"
        read -p "Do you want to backup and recreate it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            cp "$ENV_FILE" "$ENV_FILE.backup.$(date +%Y%m%d_%H%M%S)"
            print_info "Backed up existing .env file"
        else
            print_info "Keeping existing .env file"
            return 0
        fi
    fi
    
    if [[ ! -f "$ENV_EXAMPLE_FILE" ]]; then
        print_error "Environment example file not found at $ENV_EXAMPLE_FILE"
        exit 1
    fi
    
    # Copy example file
    cp "$ENV_EXAMPLE_FILE" "$ENV_FILE"
    
    # Generate secure secrets
    print_info "Generating secure secrets..."
    
    local db_password=$(generate_secret 24)
    local redis_password=$(generate_secret 24)
    local jwt_secret=$(generate_secret 32)
    local encryption_key=$(generate_secret 32)
    
    # Update .env file with generated secrets
    sed -i "s/^DB_PASSWORD=.*/DB_PASSWORD=$db_password/" "$ENV_FILE"
    sed -i "s/^REDIS_PASSWORD=.*/REDIS_PASSWORD=$redis_password/" "$ENV_FILE"
    sed -i "s/^JWT_SECRET=.*/JWT_SECRET=$jwt_secret/" "$ENV_FILE"
    sed -i "s/^ENCRYPTION_KEY=.*/ENCRYPTION_KEY=$encryption_key/" "$ENV_FILE"
    
    print_success "Environment file created with secure secrets"
    print_warning "Please review $ENV_FILE and set the remaining required variables"
}

# Function to setup Kubernetes secrets
setup_k8s_secrets() {
    print_info "Setting up Kubernetes secrets..."
    
    if ! command_exists kubectl; then
        print_error "kubectl is not installed or not in PATH"
        return 1
    fi
    
    # Check if we have access to the cluster
    if ! kubectl cluster-info >/dev/null 2>&1; then
        print_error "Cannot connect to Kubernetes cluster"
        return 1
    fi
    
    local namespace="hackai"
    
    # Create namespace if it doesn't exist
    if ! kubectl get namespace "$namespace" >/dev/null 2>&1; then
        kubectl create namespace "$namespace"
        print_success "Created namespace: $namespace"
    fi
    
    # Generate secrets
    local db_password=$(generate_secret 24)
    local redis_password=$(generate_secret 24)
    local jwt_secret=$(generate_secret 32)
    local encryption_key=$(generate_secret 32)
    
    # Prompt for API keys
    echo
    print_info "Please provide API keys (press Enter to skip):"
    read -p "OpenAI API Key: " -s openai_api_key
    echo
    read -p "Anthropic API Key: " -s anthropic_api_key
    echo
    
    # Create or update the secret
    kubectl create secret generic hackai-secrets \
        --from-literal=db-password="$db_password" \
        --from-literal=redis-password="$redis_password" \
        --from-literal=jwt-secret="$jwt_secret" \
        --from-literal=encryption-key="$encryption_key" \
        --from-literal=openai-api-key="${openai_api_key:-}" \
        --from-literal=anthropic-api-key="${anthropic_api_key:-}" \
        --namespace="$namespace" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    print_success "Kubernetes secrets created/updated in namespace: $namespace"
}

# Function to validate existing secrets
validate_secrets() {
    print_info "Validating existing secrets..."
    
    local validation_failed=false
    
    if [[ -f "$ENV_FILE" ]]; then
        # Source the env file
        set -a
        source "$ENV_FILE"
        set +a
        
        # Validate critical secrets
        if [[ -n "${DB_PASSWORD:-}" ]]; then
            if validate_secret_strength "$DB_PASSWORD" 12; then
                print_success "DB_PASSWORD: Strong"
            else
                print_error "DB_PASSWORD: Weak or too short (minimum 12 characters)"
                validation_failed=true
            fi
        else
            print_error "DB_PASSWORD: Not set"
            validation_failed=true
        fi
        
        if [[ -n "${JWT_SECRET:-}" ]]; then
            if validate_secret_strength "$JWT_SECRET" 32; then
                print_success "JWT_SECRET: Strong"
            else
                print_error "JWT_SECRET: Weak or too short (minimum 32 characters)"
                validation_failed=true
            fi
        else
            print_error "JWT_SECRET: Not set"
            validation_failed=true
        fi
        
        if [[ -n "${ENCRYPTION_KEY:-}" ]]; then
            if validate_secret_strength "$ENCRYPTION_KEY" 32; then
                print_success "ENCRYPTION_KEY: Strong"
            else
                print_error "ENCRYPTION_KEY: Weak or too short (minimum 32 characters)"
                validation_failed=true
            fi
        else
            print_error "ENCRYPTION_KEY: Not set"
            validation_failed=true
        fi
    else
        print_error "Environment file not found at $ENV_FILE"
        validation_failed=true
    fi
    
    if [[ "$validation_failed" == "true" ]]; then
        print_error "Secret validation failed. Please fix the issues above."
        return 1
    else
        print_success "All secrets validated successfully"
        return 0
    fi
}

# Function to rotate secrets
rotate_secrets() {
    print_warning "This will generate new secrets and update your .env file"
    read -p "Are you sure you want to rotate secrets? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Secret rotation cancelled"
        return 0
    fi
    
    # Backup current env file
    if [[ -f "$ENV_FILE" ]]; then
        cp "$ENV_FILE" "$ENV_FILE.backup.$(date +%Y%m%d_%H%M%S)"
        print_info "Backed up current .env file"
    fi
    
    setup_env_file
    print_success "Secrets rotated successfully"
    print_warning "Remember to restart all services and update any external references"
}

# Main function
main() {
    echo "🔒 HackAI Secure Secrets Setup"
    echo "=============================="
    echo
    
    case "${1:-}" in
        "setup")
            setup_env_file
            ;;
        "k8s")
            setup_k8s_secrets
            ;;
        "validate")
            validate_secrets
            ;;
        "rotate")
            rotate_secrets
            ;;
        *)
            echo "Usage: $0 {setup|k8s|validate|rotate}"
            echo
            echo "Commands:"
            echo "  setup    - Create .env file with secure secrets"
            echo "  k8s      - Setup Kubernetes secrets"
            echo "  validate - Validate existing secrets"
            echo "  rotate   - Rotate all secrets"
            echo
            exit 1
            ;;
    esac
}

# Check dependencies
if ! command_exists openssl; then
    print_error "openssl is required but not installed"
    exit 1
fi

# Run main function
main "$@"
