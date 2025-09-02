#!/bin/bash

# HackAI API Documentation & Integration Automation Script
# Comprehensive API management, documentation generation, and client creation

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
API_CONFIG_DIR="$PROJECT_ROOT/configs/api"
DOCS_OUTPUT_DIR="$PROJECT_ROOT/docs/api"
CLIENTS_OUTPUT_DIR="$PROJECT_ROOT/clients"
OPENAPI_OUTPUT_DIR="$PROJECT_ROOT/docs/openapi"

# Default values
ENVIRONMENT="${ENVIRONMENT:-development}"
API_VERSION="${API_VERSION:-v1}"
GENERATE_DOCS="${GENERATE_DOCS:-true}"
GENERATE_OPENAPI="${GENERATE_OPENAPI:-true}"
GENERATE_CLIENTS="${GENERATE_CLIENTS:-true}"
CLIENT_LANGUAGES="${CLIENT_LANGUAGES:-go,javascript,python}"
VALIDATE_SPEC="${VALIDATE_SPEC:-true}"
PUBLISH_DOCS="${PUBLISH_DOCS:-false}"
DEPLOY_CLIENTS="${DEPLOY_CLIENTS:-false}"
DRY_RUN="${DRY_RUN:-false}"
VERBOSE="${VERBOSE:-false}"
FORCE_REGENERATE="${FORCE_REGENERATE:-false}"

# API automation results
declare -A AUTOMATION_RESULTS=()
TOTAL_OPERATIONS=0
SUCCESSFUL_OPERATIONS=0
FAILED_OPERATIONS=0

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

log_api() {
    echo -e "${CYAN}[API]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
HackAI API Documentation & Integration Automation Script

Usage: $0 [COMMAND] [OPTIONS]

COMMANDS:
    docs                 Generate API documentation
    openapi              Generate OpenAPI specification
    clients              Generate API clients
    validate             Validate API specification
    test                 Test API endpoints
    deploy               Deploy API documentation
    publish              Publish API clients
    serve                Serve API documentation locally
    all                  Run all API automation tasks
    help                 Show this help message

OPTIONS:
    -e, --environment ENV        Set environment (development, staging, production)
    -v, --api-version VERSION    API version to process (default: v1)
    --generate-docs              Generate API documentation
    --generate-openapi           Generate OpenAPI specification
    --generate-clients           Generate API clients
    --client-languages LANGS     Comma-separated list of client languages
    --validate-spec              Validate OpenAPI specification
    --publish-docs               Publish documentation to hosting
    --deploy-clients             Deploy clients to package repositories
    --dry-run                    Show what would be done without executing
    --verbose                    Enable verbose output
    --force-regenerate           Force regeneration of all artifacts

EXAMPLES:
    # Generate all API artifacts
    $0 all --environment production --api-version v1

    # Generate documentation only
    $0 docs --generate-docs --publish-docs

    # Generate clients for specific languages
    $0 clients --client-languages "go,python,javascript"

    # Validate OpenAPI specification
    $0 validate --validate-spec --verbose

    # Serve documentation locally
    $0 serve --environment development

    # Deploy everything to production
    $0 all --environment production --publish-docs --deploy-clients

EOF
}

# Parse command line arguments
parse_args() {
    COMMAND=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            docs|openapi|clients|validate|test|deploy|publish|serve|all|help)
                COMMAND="$1"
                shift
                ;;
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -v|--api-version)
                API_VERSION="$2"
                shift 2
                ;;
            --generate-docs)
                GENERATE_DOCS="true"
                shift
                ;;
            --generate-openapi)
                GENERATE_OPENAPI="true"
                shift
                ;;
            --generate-clients)
                GENERATE_CLIENTS="true"
                shift
                ;;
            --client-languages)
                CLIENT_LANGUAGES="$2"
                shift 2
                ;;
            --validate-spec)
                VALIDATE_SPEC="true"
                shift
                ;;
            --publish-docs)
                PUBLISH_DOCS="true"
                shift
                ;;
            --deploy-clients)
                DEPLOY_CLIENTS="true"
                shift
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            --verbose)
                VERBOSE="true"
                shift
                ;;
            --force-regenerate)
                FORCE_REGENERATE="true"
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

# Setup API automation environment
setup_api_environment() {
    log_info "Setting up API automation environment..."
    
    # Create output directories
    mkdir -p "$DOCS_OUTPUT_DIR"
    mkdir -p "$CLIENTS_OUTPUT_DIR"
    mkdir -p "$OPENAPI_OUTPUT_DIR"
    
    # Validate configuration files
    if [[ ! -f "$API_CONFIG_DIR/comprehensive-api-config.yaml" ]]; then
        log_error "API configuration file not found: $API_CONFIG_DIR/comprehensive-api-config.yaml"
        exit 1
    fi
    
    # Check required tools
    local required_tools=("curl" "jq" "yq")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_warning "$tool is not installed, some features may be limited"
        fi
    done
    
    # Check optional tools for enhanced functionality
    local optional_tools=("swagger-codegen" "openapi-generator" "redoc-cli" "swagger-ui-dist")
    for tool in "${optional_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_debug "$tool is not available, will use built-in alternatives"
        fi
    done
    
    log_success "API automation environment setup completed"
}

# Generate API documentation
generate_api_documentation() {
    if [[ "$GENERATE_DOCS" != "true" ]]; then
        log_info "API documentation generation disabled, skipping..."
        return 0
    fi
    
    log_api "Generating comprehensive API documentation..."
    
    local start_time=$(date +%s)
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would generate API documentation"
        AUTOMATION_RESULTS["documentation"]="SKIPPED"
        return 0
    fi
    
    # Generate HTML documentation
    if generate_html_documentation; then
        log_success "HTML documentation generated successfully"
    else
        log_error "Failed to generate HTML documentation"
        AUTOMATION_RESULTS["html_docs"]="FAILED"
        return 1
    fi
    
    # Generate Markdown documentation
    if generate_markdown_documentation; then
        log_success "Markdown documentation generated successfully"
    else
        log_error "Failed to generate Markdown documentation"
        AUTOMATION_RESULTS["markdown_docs"]="FAILED"
        return 1
    fi
    
    # Generate Swagger UI
    if generate_swagger_ui; then
        log_success "Swagger UI generated successfully"
    else
        log_error "Failed to generate Swagger UI"
        AUTOMATION_RESULTS["swagger_ui"]="FAILED"
        return 1
    fi
    
    # Generate Redoc documentation
    if generate_redoc_documentation; then
        log_success "Redoc documentation generated successfully"
    else
        log_error "Failed to generate Redoc documentation"
        AUTOMATION_RESULTS["redoc_docs"]="FAILED"
        return 1
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    AUTOMATION_RESULTS["documentation"]="SUCCESS"
    log_success "API documentation generated in ${duration} seconds"
}

# Generate HTML documentation
generate_html_documentation() {
    log_debug "Generating HTML documentation..."
    
    local output_file="$DOCS_OUTPUT_DIR/index.html"
    
    # Use Go API manager to generate documentation
    if command -v go &> /dev/null; then
        cd "$PROJECT_ROOT"
        go run cmd/api-docs/main.go \
            --config "$API_CONFIG_DIR/comprehensive-api-config.yaml" \
            --format html \
            --output "$output_file" \
            --version "$API_VERSION" \
            --environment "$ENVIRONMENT"
    else
        log_warning "Go not available, using template-based generation"
        generate_html_from_template "$output_file"
    fi
    
    return 0
}

# Generate Markdown documentation
generate_markdown_documentation() {
    log_debug "Generating Markdown documentation..."
    
    local output_file="$DOCS_OUTPUT_DIR/README.md"
    
    # Use Go API manager to generate documentation
    if command -v go &> /dev/null; then
        cd "$PROJECT_ROOT"
        go run cmd/api-docs/main.go \
            --config "$API_CONFIG_DIR/comprehensive-api-config.yaml" \
            --format markdown \
            --output "$output_file" \
            --version "$API_VERSION" \
            --environment "$ENVIRONMENT"
    else
        log_warning "Go not available, using template-based generation"
        generate_markdown_from_template "$output_file"
    fi
    
    return 0
}

# Generate OpenAPI specification
generate_openapi_specification() {
    if [[ "$GENERATE_OPENAPI" != "true" ]]; then
        log_info "OpenAPI specification generation disabled, skipping..."
        return 0
    fi
    
    log_api "Generating OpenAPI specification..."
    
    local start_time=$(date +%s)
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would generate OpenAPI specification"
        AUTOMATION_RESULTS["openapi"]="SKIPPED"
        return 0
    fi
    
    # Generate JSON specification
    local json_output="$OPENAPI_OUTPUT_DIR/openapi.json"
    if generate_openapi_json "$json_output"; then
        log_success "OpenAPI JSON specification generated"
    else
        log_error "Failed to generate OpenAPI JSON specification"
        AUTOMATION_RESULTS["openapi_json"]="FAILED"
        return 1
    fi
    
    # Generate YAML specification
    local yaml_output="$OPENAPI_OUTPUT_DIR/openapi.yaml"
    if generate_openapi_yaml "$yaml_output"; then
        log_success "OpenAPI YAML specification generated"
    else
        log_error "Failed to generate OpenAPI YAML specification"
        AUTOMATION_RESULTS["openapi_yaml"]="FAILED"
        return 1
    fi
    
    # Validate specification if enabled
    if [[ "$VALIDATE_SPEC" == "true" ]]; then
        if validate_openapi_specification "$json_output"; then
            log_success "OpenAPI specification validation passed"
        else
            log_error "OpenAPI specification validation failed"
            AUTOMATION_RESULTS["openapi_validation"]="FAILED"
            return 1
        fi
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    AUTOMATION_RESULTS["openapi"]="SUCCESS"
    log_success "OpenAPI specification generated in ${duration} seconds"
}

# Generate OpenAPI JSON specification
generate_openapi_json() {
    local output_file="$1"
    
    log_debug "Generating OpenAPI JSON specification..."
    
    if command -v go &> /dev/null; then
        cd "$PROJECT_ROOT"
        go run cmd/openapi-gen/main.go \
            --config "$API_CONFIG_DIR/comprehensive-api-config.yaml" \
            --format json \
            --output "$output_file" \
            --version "$API_VERSION" \
            --environment "$ENVIRONMENT"
    else
        log_warning "Go not available, using template-based generation"
        generate_openapi_from_template "$output_file" "json"
    fi
    
    return 0
}

# Generate OpenAPI YAML specification
generate_openapi_yaml() {
    local output_file="$1"
    
    log_debug "Generating OpenAPI YAML specification..."
    
    if command -v go &> /dev/null; then
        cd "$PROJECT_ROOT"
        go run cmd/openapi-gen/main.go \
            --config "$API_CONFIG_DIR/comprehensive-api-config.yaml" \
            --format yaml \
            --output "$output_file" \
            --version "$API_VERSION" \
            --environment "$ENVIRONMENT"
    else
        log_warning "Go not available, using template-based generation"
        generate_openapi_from_template "$output_file" "yaml"
    fi
    
    return 0
}

# Generate API clients
generate_api_clients() {
    if [[ "$GENERATE_CLIENTS" != "true" ]]; then
        log_info "API client generation disabled, skipping..."
        return 0
    fi
    
    log_api "Generating API clients..."
    
    local start_time=$(date +%s)
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would generate API clients for languages: $CLIENT_LANGUAGES"
        AUTOMATION_RESULTS["clients"]="SKIPPED"
        return 0
    fi
    
    # Parse client languages
    IFS=',' read -ra LANGUAGES <<< "$CLIENT_LANGUAGES"
    
    for language in "${LANGUAGES[@]}"; do
        log_info "Generating $language client..."
        
        if generate_client_for_language "$language"; then
            log_success "$language client generated successfully"
            AUTOMATION_RESULTS["client_$language"]="SUCCESS"
        else
            log_error "Failed to generate $language client"
            AUTOMATION_RESULTS["client_$language"]="FAILED"
        fi
    done
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    AUTOMATION_RESULTS["clients"]="SUCCESS"
    log_success "API clients generated in ${duration} seconds"
}

# Generate client for specific language
generate_client_for_language() {
    local language="$1"
    local output_dir="$CLIENTS_OUTPUT_DIR/$language"
    
    mkdir -p "$output_dir"
    
    if command -v go &> /dev/null; then
        cd "$PROJECT_ROOT"
        go run cmd/client-gen/main.go \
            --config "$API_CONFIG_DIR/comprehensive-api-config.yaml" \
            --language "$language" \
            --output "$output_dir" \
            --version "$API_VERSION" \
            --environment "$ENVIRONMENT"
    else
        log_warning "Go not available, using openapi-generator if available"
        if command -v openapi-generator &> /dev/null; then
            openapi-generator generate \
                -i "$OPENAPI_OUTPUT_DIR/openapi.json" \
                -g "$language" \
                -o "$output_dir" \
                --package-name "hackai-$language-client"
        else
            log_error "No client generation tools available"
            return 1
        fi
    fi
    
    return 0
}

# Validate OpenAPI specification
validate_openapi_specification() {
    local spec_file="$1"
    
    log_debug "Validating OpenAPI specification..."
    
    # Use swagger-codegen validate if available
    if command -v swagger-codegen &> /dev/null; then
        swagger-codegen validate -i "$spec_file"
        return $?
    fi
    
    # Use openapi-generator validate if available
    if command -v openapi-generator &> /dev/null; then
        openapi-generator validate -i "$spec_file"
        return $?
    fi
    
    # Basic JSON validation
    if command -v jq &> /dev/null; then
        jq empty "$spec_file" &> /dev/null
        return $?
    fi
    
    log_warning "No OpenAPI validation tools available"
    return 0
}

# Serve API documentation locally
serve_api_documentation() {
    log_api "Starting local API documentation server..."
    
    local port="${API_DOCS_PORT:-8080}"
    local docs_dir="$DOCS_OUTPUT_DIR"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would serve documentation on port $port"
        return 0
    fi
    
    # Use Python's built-in HTTP server
    if command -v python3 &> /dev/null; then
        cd "$docs_dir"
        log_info "Serving API documentation at http://localhost:$port"
        python3 -m http.server "$port"
    elif command -v python &> /dev/null; then
        cd "$docs_dir"
        log_info "Serving API documentation at http://localhost:$port"
        python -m SimpleHTTPServer "$port"
    else
        log_error "Python not available for serving documentation"
        return 1
    fi
}

# Record automation result
record_automation_result() {
    local operation="$1"
    local result="$2"
    
    AUTOMATION_RESULTS["$operation"]="$result"
    TOTAL_OPERATIONS=$((TOTAL_OPERATIONS + 1))
    
    if [[ "$result" == "SUCCESS" ]]; then
        SUCCESSFUL_OPERATIONS=$((SUCCESSFUL_OPERATIONS + 1))
    else
        FAILED_OPERATIONS=$((FAILED_OPERATIONS + 1))
    fi
}

# Generate automation report
generate_automation_report() {
    log_info "Generating API automation report..."
    
    local report_file="$PROJECT_ROOT/api-automation-report-$(date +%Y%m%d_%H%M%S).html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>HackAI API Automation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2563eb; color: white; padding: 20px; text-align: center; }
        .summary { background: #f8fafc; padding: 15px; margin: 20px 0; }
        .success { color: #059669; }
        .failed { color: #dc2626; }
        .skipped { color: #d97706; }
        .section { margin: 20px 0; }
        .result { margin: 5px 0; padding: 5px; border-left: 3px solid #e5e7eb; }
        .result.success { border-left-color: #059669; }
        .result.failed { border-left-color: #dc2626; }
        .result.skipped { border-left-color: #d97706; }
    </style>
</head>
<body>
    <div class="header">
        <h1>HackAI API Automation Report</h1>
        <p>Generated: $(date)</p>
        <p>Environment: $ENVIRONMENT | API Version: $API_VERSION</p>
    </div>
    
    <div class="summary">
        <h2>Automation Summary</h2>
        <p><strong>Total Operations:</strong> $TOTAL_OPERATIONS</p>
        <p><strong>Successful:</strong> <span class="success">$SUCCESSFUL_OPERATIONS</span></p>
        <p><strong>Failed:</strong> <span class="failed">$FAILED_OPERATIONS</span></p>
        <p><strong>Success Rate:</strong> $(( SUCCESSFUL_OPERATIONS * 100 / TOTAL_OPERATIONS ))%</p>
    </div>
    
    <div class="section">
        <h2>Operation Results</h2>
EOF

    for operation in "${!AUTOMATION_RESULTS[@]}"; do
        local result="${AUTOMATION_RESULTS[$operation]}"
        local class="success"
        if [[ "$result" == "FAILED" ]]; then
            class="failed"
        elif [[ "$result" == "SKIPPED" ]]; then
            class="skipped"
        fi
        echo "        <div class=\"result $class\">$operation: $result</div>" >> "$report_file"
    done
    
    cat >> "$report_file" << EOF
    </div>
</body>
</html>
EOF
    
    log_success "API automation report generated: $report_file"
}

# Main function
main() {
    log_info "Starting HackAI API Documentation & Integration Automation"
    log_info "Command: $COMMAND, Environment: $ENVIRONMENT, API Version: $API_VERSION"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_warning "Running in DRY RUN mode - no changes will be made"
    fi
    
    setup_api_environment
    
    case "$COMMAND" in
        "docs")
            generate_api_documentation
            ;;
        "openapi")
            generate_openapi_specification
            ;;
        "clients")
            generate_openapi_specification
            generate_api_clients
            ;;
        "validate")
            generate_openapi_specification
            ;;
        "serve")
            serve_api_documentation
            ;;
        "all")
            generate_api_documentation
            generate_openapi_specification
            generate_api_clients
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
    
    # Generate automation report
    generate_automation_report
    
    # Calculate overall success
    local overall_success=true
    for result in "${AUTOMATION_RESULTS[@]}"; do
        if [[ "$result" == "FAILED" ]]; then
            overall_success=false
            break
        fi
    done
    
    if [[ "$overall_success" == "true" ]]; then
        log_success "API automation completed successfully! 🚀"
        exit 0
    else
        log_error "Some API automation operations failed. Check the results above."
        exit 1
    fi
}

# Initialize extra args array
EXTRA_ARGS=()

# Parse arguments and run main function
parse_args "$@"
main
