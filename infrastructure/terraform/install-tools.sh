#!/bin/bash

# Install required tools for HackAI Terraform infrastructure
# This script installs Terraform, AWS CLI, kubectl, and other useful tools

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

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root"
    fi
}

# Check OS
check_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        ARCH=$(uname -m)
        if [[ "$ARCH" == "x86_64" ]]; then
            ARCH="amd64"
        elif [[ "$ARCH" == "aarch64" ]]; then
            ARCH="arm64"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="darwin"
        ARCH=$(uname -m)
        if [[ "$ARCH" == "x86_64" ]]; then
            ARCH="amd64"
        elif [[ "$ARCH" == "arm64" ]]; then
            ARCH="arm64"
        fi
    else
        error "Unsupported operating system: $OSTYPE"
    fi
    
    info "Detected OS: $OS, Architecture: $ARCH"
}

# Install Terraform
install_terraform() {
    if command -v terraform &> /dev/null; then
        local version=$(terraform version -json | jq -r '.terraform_version' 2>/dev/null || terraform version | head -n1 | cut -d' ' -f2 | tr -d 'v')
        info "Terraform already installed: $version"
        return
    fi
    
    log "Installing Terraform..."
    
    local terraform_version="1.6.6"
    local download_url="https://releases.hashicorp.com/terraform/${terraform_version}/terraform_${terraform_version}_${OS}_${ARCH}.zip"
    
    # Create temporary directory
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Download and install
    curl -LO "$download_url"
    unzip "terraform_${terraform_version}_${OS}_${ARCH}.zip"
    
    # Install to user's local bin
    mkdir -p "$HOME/.local/bin"
    mv terraform "$HOME/.local/bin/"
    
    # Add to PATH if not already there
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc" 2>/dev/null || true
        export PATH="$HOME/.local/bin:$PATH"
    fi
    
    # Cleanup
    cd - > /dev/null
    rm -rf "$temp_dir"
    
    info "Terraform installed successfully"
}

# Install AWS CLI
install_aws_cli() {
    if command -v aws &> /dev/null; then
        local version=$(aws --version 2>&1 | cut -d' ' -f1 | cut -d'/' -f2)
        info "AWS CLI already installed: $version"
        return
    fi
    
    log "Installing AWS CLI..."
    
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    if [[ "$OS" == "linux" ]]; then
        curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
        unzip awscliv2.zip
        ./aws/install --bin-dir "$HOME/.local/bin" --install-dir "$HOME/.local/aws-cli"
    elif [[ "$OS" == "darwin" ]]; then
        curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
        sudo installer -pkg AWSCLIV2.pkg -target /
    fi
    
    # Cleanup
    cd - > /dev/null
    rm -rf "$temp_dir"
    
    info "AWS CLI installed successfully"
}

# Install kubectl
install_kubectl() {
    if command -v kubectl &> /dev/null; then
        local version=$(kubectl version --client --short 2>/dev/null | cut -d' ' -f3 || kubectl version --client -o json | jq -r '.clientVersion.gitVersion')
        info "kubectl already installed: $version"
        return
    fi
    
    log "Installing kubectl..."
    
    local kubectl_version=$(curl -L -s https://dl.k8s.io/release/stable.txt)
    local download_url="https://dl.k8s.io/release/${kubectl_version}/bin/${OS}/${ARCH}/kubectl"
    
    curl -LO "$download_url"
    chmod +x kubectl
    mkdir -p "$HOME/.local/bin"
    mv kubectl "$HOME/.local/bin/"
    
    info "kubectl installed successfully"
}

# Install Helm
install_helm() {
    if command -v helm &> /dev/null; then
        local version=$(helm version --short 2>/dev/null | cut -d' ' -f1 || helm version --template='{{.Version}}')
        info "Helm already installed: $version"
        return
    fi
    
    log "Installing Helm..."
    
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    
    info "Helm installed successfully"
}

# Install jq (JSON processor)
install_jq() {
    if command -v jq &> /dev/null; then
        local version=$(jq --version)
        info "jq already installed: $version"
        return
    fi
    
    log "Installing jq..."
    
    if [[ "$OS" == "linux" ]]; then
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y jq
        elif command -v yum &> /dev/null; then
            sudo yum install -y jq
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y jq
        else
            # Manual installation
            curl -L "https://github.com/stedolan/jq/releases/latest/download/jq-${OS}64" -o jq
            chmod +x jq
            mkdir -p "$HOME/.local/bin"
            mv jq "$HOME/.local/bin/"
        fi
    elif [[ "$OS" == "darwin" ]]; then
        if command -v brew &> /dev/null; then
            brew install jq
        else
            curl -L "https://github.com/stedolan/jq/releases/latest/download/jq-osx-amd64" -o jq
            chmod +x jq
            mkdir -p "$HOME/.local/bin"
            mv jq "$HOME/.local/bin/"
        fi
    fi
    
    info "jq installed successfully"
}

# Install optional tools
install_optional_tools() {
    log "Installing optional tools..."
    
    # tfsec (Terraform security scanner)
    if ! command -v tfsec &> /dev/null; then
        info "Installing tfsec..."
        if command -v go &> /dev/null; then
            go install github.com/aquasecurity/tfsec/cmd/tfsec@latest
        else
            warn "Go not installed, skipping tfsec installation"
        fi
    fi
    
    # terraform-docs
    if ! command -v terraform-docs &> /dev/null; then
        info "Installing terraform-docs..."
        if command -v go &> /dev/null; then
            go install github.com/terraform-docs/terraform-docs@latest
        else
            warn "Go not installed, skipping terraform-docs installation"
        fi
    fi
    
    # checkov (Infrastructure security scanner)
    if ! command -v checkov &> /dev/null; then
        info "Installing checkov..."
        if command -v pip3 &> /dev/null; then
            pip3 install --user checkov
        elif command -v pip &> /dev/null; then
            pip install --user checkov
        else
            warn "pip not installed, skipping checkov installation"
        fi
    fi
}

# Verify installations
verify_installations() {
    log "Verifying installations..."
    
    local tools=("terraform" "aws" "kubectl" "jq")
    local failed=0
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            info "✓ $tool is installed"
        else
            error "✗ $tool is not installed"
            failed=1
        fi
    done
    
    if [[ $failed -eq 0 ]]; then
        log "All required tools are installed successfully!"
    else
        error "Some tools failed to install"
    fi
}

# Configure AWS (optional)
configure_aws() {
    if [[ -f "$HOME/.aws/credentials" ]] || [[ -n "${AWS_ACCESS_KEY_ID:-}" ]]; then
        info "AWS credentials already configured"
        return
    fi
    
    echo ""
    read -p "Do you want to configure AWS credentials now? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        aws configure
    else
        warn "AWS credentials not configured. Run 'aws configure' later."
    fi
}

# Main function
main() {
    log "Starting HackAI infrastructure tools installation"
    
    check_root
    check_os
    
    install_terraform
    install_aws_cli
    install_kubectl
    install_helm
    install_jq
    install_optional_tools
    
    verify_installations
    configure_aws
    
    log "Installation completed successfully!"
    
    echo ""
    info "Next steps:"
    info "1. Configure AWS credentials: aws configure"
    info "2. Initialize Terraform: make init"
    info "3. Plan deployment: make plan ENV=development"
    info "4. Apply deployment: make apply ENV=development"
    echo ""
    warn "Note: You may need to restart your shell or run 'source ~/.bashrc' to update PATH"
}

# Run main function
main "$@"
