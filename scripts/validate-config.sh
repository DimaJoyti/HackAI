#!/bin/bash

# LLM Security Proxy - Configuration Validation Script
# Validates environment-specific configurations

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration directory
CONFIG_DIR="configs"
ENV_DIR="$CONFIG_DIR/environments"

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_success() {
    print_status "$GREEN" "✓ $1"
}

print_error() {
    print_status "$RED" "✗ $1"
}

print_warning() {
    print_status "$YELLOW" "⚠ $1"
}

print_info() {
    print_status "$BLUE" "ℹ $1"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to validate YAML syntax
validate_yaml() {
    local file=$1
    
    if command_exists yq; then
        if yq eval '.' "$file" >/dev/null 2>&1; then
            return 0
        else
            return 1
        fi
    elif command_exists python3; then
        if python3 -c "import yaml; yaml.safe_load(open('$file'))" >/dev/null 2>&1; then
            return 0
        else
            return 1
        fi
    else
        print_warning "No YAML validator found (yq or python3). Skipping syntax validation."
        return 0
    fi
}

# Function to validate environment file
validate_env_file() {
    local env_file=$1
    local env_name=$(basename "$env_file" .yaml)
    
    print_info "Validating $env_name environment configuration..."
    
    # Check if file exists
    if [[ ! -f "$env_file" ]]; then
        print_error "Configuration file not found: $env_file"
        return 1
    fi
    
    # Validate YAML syntax
    if ! validate_yaml "$env_file"; then
        print_error "Invalid YAML syntax in $env_file"
        return 1
    fi
    
    # Check required sections
    local required_sections=("server" "database" "security" "audit" "observability")
    local missing_sections=()
    
    for section in "${required_sections[@]}"; do
        if command_exists yq; then
            if ! yq eval "has(\"$section\")" "$env_file" | grep -q "true"; then
                missing_sections+=("$section")
            fi
        fi
    done
    
    if [[ ${#missing_sections[@]} -gt 0 ]]; then
        print_error "Missing required sections in $env_file: ${missing_sections[*]}"
        return 1
    fi
    
    # Environment-specific validations
    case "$env_name" in
        "development")
            validate_development_config "$env_file"
            ;;
        "staging")
            validate_staging_config "$env_file"
            ;;
        "production")
            validate_production_config "$env_file"
            ;;
    esac
    
    print_success "$env_name configuration is valid"
    return 0
}

# Function to validate development configuration
validate_development_config() {
    local file=$1
    
    # Check that debug is enabled
    if command_exists yq; then
        local debug_enabled=$(yq eval '.debug.enabled // false' "$file")
        if [[ "$debug_enabled" != "true" ]]; then
            print_warning "Debug should be enabled in development environment"
        fi
        
        # Check that security is relaxed
        local strict_mode=$(yq eval '.security.strict_mode // false' "$file")
        if [[ "$strict_mode" == "true" ]]; then
            print_warning "Strict mode should be disabled in development for easier testing"
        fi
        
        # Check database name
        local db_name=$(yq eval '.database.name // ""' "$file")
        if [[ "$db_name" != *"dev"* ]]; then
            print_warning "Database name should contain 'dev' for development environment"
        fi
    fi
}

# Function to validate staging configuration
validate_staging_config() {
    local file=$1
    
    if command_exists yq; then
        # Check that TLS is enabled
        local tls_enabled=$(yq eval '.server.tls_enabled // false' "$file")
        if [[ "$tls_enabled" != "true" ]]; then
            print_warning "TLS should be enabled in staging environment"
        fi
        
        # Check that SSL is required for database
        local ssl_mode=$(yq eval '.database.ssl_mode // ""' "$file")
        if [[ "$ssl_mode" != "require" ]]; then
            print_warning "Database SSL should be required in staging environment"
        fi
        
        # Check that audit is enabled
        local audit_enabled=$(yq eval '.audit.enabled // false' "$file")
        if [[ "$audit_enabled" != "true" ]]; then
            print_error "Audit must be enabled in staging environment"
        fi
    fi
}

# Function to validate production configuration
validate_production_config() {
    local file=$1
    
    if command_exists yq; then
        # Check that debug is disabled
        local debug_enabled=$(yq eval '.debug.enabled // false' "$file")
        if [[ "$debug_enabled" == "true" ]]; then
            print_error "Debug must be disabled in production environment"
        fi
        
        # Check that strict mode is enabled
        local strict_mode=$(yq eval '.security.strict_mode // false' "$file")
        if [[ "$strict_mode" != "true" ]]; then
            print_error "Strict mode must be enabled in production environment"
        fi
        
        # Check that TLS is enabled
        local tls_enabled=$(yq eval '.server.tls_enabled // false' "$file")
        if [[ "$tls_enabled" != "true" ]]; then
            print_error "TLS must be enabled in production environment"
        fi
        
        # Check that SSL is required for database
        local ssl_mode=$(yq eval '.database.ssl_mode // ""' "$file")
        if [[ "$ssl_mode" != "require" ]]; then
            print_error "Database SSL must be required in production environment"
        fi
        
        # Check that audit is enabled
        local audit_enabled=$(yq eval '.audit.enabled // false' "$file")
        if [[ "$audit_enabled" != "true" ]]; then
            print_error "Audit must be enabled in production environment"
        fi
        
        # Check that sensitive data masking is enabled
        local mask_sensitive=$(yq eval '.audit.logger.mask_sensitive_data // false' "$file")
        if [[ "$mask_sensitive" != "true" ]]; then
            print_error "Sensitive data masking must be enabled in production environment"
        fi
        
        # Check logging level
        local log_level=$(yq eval '.observability.logging.level // ""' "$file")
        if [[ "$log_level" == "debug" ]]; then
            print_error "Debug logging should not be used in production environment"
        fi
    fi
}

# Function to validate environment variables
validate_env_vars() {
    local env_file=$1
    
    print_info "Validating environment variables for $(basename "$env_file" .env)..."
    
    if [[ ! -f "$env_file" ]]; then
        print_error "Environment file not found: $env_file"
        return 1
    fi
    
    # Check for required environment variables
    local required_vars=("ENVIRONMENT" "DB_HOST" "DB_USER" "JWT_SECRET")
    local missing_vars=()
    
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue
        
        # Extract variable name
        local var_name=$(echo "$line" | cut -d'=' -f1)
        local var_value=$(echo "$line" | cut -d'=' -f2-)
        
        # Check if required variable is set
        for required_var in "${required_vars[@]}"; do
            if [[ "$var_name" == "$required_var" ]]; then
                if [[ -z "$var_value" || "$var_value" == "\${*}" ]]; then
                    missing_vars+=("$required_var")
                fi
            fi
        done
        
        # Validate JWT secret length
        if [[ "$var_name" == "JWT_SECRET" && ${#var_value} -lt 32 ]]; then
            print_error "JWT_SECRET must be at least 32 characters long"
        fi
        
    done < "$env_file"
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        print_error "Missing or empty required environment variables: ${missing_vars[*]}"
        return 1
    fi
    
    print_success "Environment variables are valid"
    return 0
}

# Function to validate Docker Compose files
validate_docker_compose() {
    local compose_file=$1
    
    print_info "Validating Docker Compose file: $(basename "$compose_file")..."
    
    if [[ ! -f "$compose_file" ]]; then
        print_error "Docker Compose file not found: $compose_file"
        return 1
    fi
    
    # Validate YAML syntax
    if ! validate_yaml "$compose_file"; then
        print_error "Invalid YAML syntax in $compose_file"
        return 1
    fi
    
    # Check if docker-compose can parse the file
    if command_exists docker-compose; then
        if docker-compose -f "$compose_file" config >/dev/null 2>&1; then
            print_success "Docker Compose file is valid"
        else
            print_error "Docker Compose file has configuration errors"
            return 1
        fi
    else
        print_warning "docker-compose not found. Skipping compose validation."
    fi
    
    return 0
}

# Main validation function
main() {
    print_info "Starting configuration validation..."
    
    local errors=0
    
    # Validate base configuration
    if [[ -f "$CONFIG_DIR/config.yaml" ]]; then
        print_info "Validating base configuration..."
        if ! validate_yaml "$CONFIG_DIR/config.yaml"; then
            print_error "Invalid YAML syntax in base configuration"
            ((errors++))
        else
            print_success "Base configuration is valid"
        fi
    else
        print_error "Base configuration file not found: $CONFIG_DIR/config.yaml"
        ((errors++))
    fi
    
    # Validate environment-specific configurations
    for env_file in "$ENV_DIR"/*.yaml; do
        if [[ -f "$env_file" ]]; then
            if ! validate_env_file "$env_file"; then
                ((errors++))
            fi
        fi
    done
    
    # Validate environment variable files
    for env_file in .env.*; do
        if [[ -f "$env_file" && "$env_file" != ".env.example" ]]; then
            if ! validate_env_vars "$env_file"; then
                ((errors++))
            fi
        fi
    done
    
    # Validate Docker Compose files
    for compose_file in docker-compose*.yml; do
        if [[ -f "$compose_file" ]]; then
            if ! validate_docker_compose "$compose_file"; then
                ((errors++))
            fi
        fi
    done
    
    # Summary
    echo
    if [[ $errors -eq 0 ]]; then
        print_success "All configurations are valid!"
        exit 0
    else
        print_error "Found $errors configuration error(s)"
        exit 1
    fi
}

# Check if script is being run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
