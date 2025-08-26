#!/bin/bash

# AI-First Company Deployment Script
# This script sets up and deploys the complete AI-First Company platform

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="ai-first-company"
DOCKER_COMPOSE_FILE="docker-compose.ai-company.yml"
ENV_FILE=".env.ai-company"

# Functions
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

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed. Please install Go 1.22 or later."
        exit 1
    fi
    
    # Check Go version
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    REQUIRED_VERSION="1.22"
    if ! printf '%s\n%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V -C; then
        log_error "Go version $GO_VERSION is too old. Please install Go $REQUIRED_VERSION or later."
        exit 1
    fi
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        log_warning "Docker is not installed. Some features may not work."
    fi
    
    # Check if PostgreSQL is available
    if ! command -v psql &> /dev/null; then
        log_warning "PostgreSQL client is not installed. Database setup may require manual configuration."
    fi
    
    log_success "Prerequisites check completed"
}

setup_environment() {
    log_info "Setting up environment..."
    
    # Create .env file if it doesn't exist
    if [ ! -f "$ENV_FILE" ]; then
        log_info "Creating environment file: $ENV_FILE"
        cat > "$ENV_FILE" << EOF
# AI-First Company Environment Configuration

# Binance API Configuration (REQUIRED)
BINANCE_API_KEY=your_binance_api_key_here
BINANCE_SECRET_KEY=your_binance_secret_key_here
BINANCE_TESTNET=true

# Database Configuration
DATABASE_URL=postgres://postgres:password@localhost:5432/hackai?sslmode=disable
DATABASE_PASSWORD=password

# Redis Configuration
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=

# External APIs (Optional)
NEWS_API_KEY=your_news_api_key_here
ECONOMIC_DATA_API_KEY=your_economic_data_api_key_here

# Security
ENCRYPTION_KEY=your_32_character_encryption_key_here
JWT_SECRET=your_jwt_secret_here

# Monitoring
ENABLE_METRICS=true
ENABLE_TRACING=true
LOG_LEVEL=info

# Development
ENVIRONMENT=development
DEBUG_MODE=false
MOCK_TRADING=true
EOF
        log_warning "Please update $ENV_FILE with your actual API keys and configuration"
    else
        log_info "Environment file already exists: $ENV_FILE"
    fi
    
    # Source the environment file
    if [ -f "$ENV_FILE" ]; then
        export $(cat "$ENV_FILE" | grep -v '^#' | xargs)
    fi
    
    log_success "Environment setup completed"
}

build_application() {
    log_info "Building AI-First Company application..."
    
    # Clean and build
    go clean -cache
    go mod tidy
    go mod download
    
    # Build the main demo application
    log_info "Building demo application..."
    go build -o bin/ai-company-demo cmd/ai-company-demo/main.go
    
    # Build additional tools if they exist
    if [ -d "cmd/ai-company-server" ]; then
        log_info "Building server application..."
        go build -o bin/ai-company-server cmd/ai-company-server/main.go
    fi
    
    if [ -d "cmd/ai-company-cli" ]; then
        log_info "Building CLI application..."
        go build -o bin/ai-company-cli cmd/ai-company-cli/main.go
    fi
    
    log_success "Application build completed"
}

setup_database() {
    log_info "Setting up database..."
    
    # Check if PostgreSQL is running
    if ! pg_isready -h localhost -p 5432 &> /dev/null; then
        log_warning "PostgreSQL is not running on localhost:5432"
        log_info "Please ensure PostgreSQL is running and accessible"
        return 1
    fi
    
    # Create database if it doesn't exist
    createdb hackai 2>/dev/null || log_info "Database 'hackai' already exists"
    
    # Run migrations if they exist
    if [ -d "migrations" ]; then
        log_info "Running database migrations..."
        # Add migration logic here
    fi
    
    log_success "Database setup completed"
}

setup_redis() {
    log_info "Setting up Redis..."
    
    # Check if Redis is running
    if ! redis-cli ping &> /dev/null; then
        log_warning "Redis is not running on localhost:6379"
        log_info "Please ensure Redis is running and accessible"
        return 1
    fi
    
    log_success "Redis setup completed"
}

run_tests() {
    log_info "Running tests..."
    
    # Run unit tests
    log_info "Running unit tests..."
    go test -v ./pkg/agents/... -timeout 30s
    
    # Run integration tests if they exist
    if [ -d "tests/integration" ]; then
        log_info "Running integration tests..."
        go test -v ./tests/integration/... -timeout 60s
    fi
    
    log_success "Tests completed"
}

deploy_with_docker() {
    log_info "Deploying with Docker..."
    
    # Create Docker Compose file
    cat > "$DOCKER_COMPOSE_FILE" << EOF
version: '3.8'

services:
  ai-company-app:
    build:
      context: .
      dockerfile: Dockerfile.ai-company
    environment:
      - BINANCE_API_KEY=\${BINANCE_API_KEY}
      - BINANCE_SECRET_KEY=\${BINANCE_SECRET_KEY}
      - DATABASE_URL=postgres://postgres:password@postgres:5432/hackai?sslmode=disable
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
    ports:
      - "8080:8080"
    volumes:
      - ./configs:/app/configs
      - ./logs:/app/logs

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=hackai
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./configs/prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana

volumes:
  postgres_data:
  redis_data:
  grafana_data:
EOF

    # Create Dockerfile
    cat > "Dockerfile.ai-company" << EOF
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o ai-company-demo cmd/ai-company-demo/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/ai-company-demo .
COPY --from=builder /app/configs ./configs

CMD ["./ai-company-demo"]
EOF

    # Deploy with Docker Compose
    docker-compose -f "$DOCKER_COMPOSE_FILE" up -d
    
    log_success "Docker deployment completed"
}

deploy_local() {
    log_info "Deploying locally..."
    
    # Ensure services are running
    setup_database
    setup_redis
    
    # Start the application
    log_info "Starting AI-First Company demo..."
    ./bin/ai-company-demo &
    APP_PID=$!
    
    log_success "Application started with PID: $APP_PID"
    log_info "Application logs will be displayed below..."
    
    # Wait for the application to finish
    wait $APP_PID
}

cleanup() {
    log_info "Cleaning up..."
    
    # Stop Docker containers if running
    if [ -f "$DOCKER_COMPOSE_FILE" ]; then
        docker-compose -f "$DOCKER_COMPOSE_FILE" down
    fi
    
    # Clean build artifacts
    rm -rf bin/
    
    log_success "Cleanup completed"
}

show_usage() {
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  setup     - Setup environment and dependencies"
    echo "  build     - Build the application"
    echo "  test      - Run tests"
    echo "  deploy    - Deploy locally"
    echo "  docker    - Deploy with Docker"
    echo "  cleanup   - Clean up deployment"
    echo "  help      - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 setup     # Setup environment"
    echo "  $0 build     # Build application"
    echo "  $0 deploy    # Deploy locally"
    echo "  $0 docker    # Deploy with Docker"
}

# Main execution
main() {
    case "${1:-help}" in
        setup)
            check_prerequisites
            setup_environment
            ;;
        build)
            build_application
            ;;
        test)
            run_tests
            ;;
        deploy)
            check_prerequisites
            setup_environment
            build_application
            deploy_local
            ;;
        docker)
            check_prerequisites
            setup_environment
            build_application
            deploy_with_docker
            ;;
        cleanup)
            cleanup
            ;;
        help|*)
            show_usage
            ;;
    esac
}

# Trap to cleanup on exit
trap cleanup EXIT

# Run main function
main "$@"
