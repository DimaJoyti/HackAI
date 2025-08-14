# HackAI Makefile
.PHONY: help build test clean run-services stop-services docker-build docker-up docker-down

# Default target
help: ## Show this help message
	@echo "HackAI - Educational Cybersecurity AI Platform"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Build targets
build: ## Build all services
	@echo "Building all services..."
	go build -o bin/api-gateway ./cmd/api-gateway
	go build -o bin/user-service ./cmd/user-service
	go build -o bin/scanner-service ./cmd/scanner-service
	go build -o bin/network-service ./cmd/network-service
	go build -o bin/threat-service ./cmd/threat-service
	go build -o bin/log-service ./cmd/log-service

build-gateway: ## Build API Gateway
	go build -o bin/api-gateway ./cmd/api-gateway

build-user: ## Build User Service
	go build -o bin/user-service ./cmd/user-service

build-scanner: ## Build Scanner Service
	go build -o bin/scanner-service ./cmd/scanner-service

build-network: ## Build Network Service
	go build -o bin/network-service ./cmd/network-service

build-threat: ## Build Threat Service
	go build -o bin/threat-service ./cmd/threat-service

build-log: ## Build Log Service
	go build -o bin/log-service ./cmd/log-service

build-demos: ## Build demo applications
	@echo "Building demo applications..."
	@mkdir -p bin
	go build -o bin/auth-demo ./cmd/auth-demo-simple
	go build -o bin/observability-demo ./cmd/observability-demo
	@echo "Demo applications built successfully"

# Test targets
test: ## Run all tests
	go test -v ./...

test-coverage: ## Run tests with coverage
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-integration: ## Run integration tests
	go test -v ./test/integration/...

test-unit: ## Run unit tests only
	go test -v ./test/unit/...

test-benchmark: ## Run benchmark tests
	@echo "Running benchmark tests..."
	go test -v -bench=. -benchmem ./test/benchmark/...

test-race: ## Run tests with race detection
	@echo "Running tests with race detection..."
	go test -race -v ./...

# Development targets
run-gateway: build-gateway ## Run API Gateway
	./bin/api-gateway

run-user: build-user ## Run User Service
	./bin/user-service

run-scanner: build-scanner ## Run Scanner Service
	./bin/scanner-service

run-network: build-network ## Run Network Service
	./bin/network-service

run-threat: build-threat ## Run Threat Service
	./bin/threat-service

run-log: build-log ## Run Log Service
	./bin/log-service

run-services: build ## Run all services in background
	@echo "Starting all services..."
	./bin/user-service &
	./bin/scanner-service &
	./bin/network-service &
	./bin/threat-service &
	./bin/log-service &
	./bin/api-gateway &
	@echo "All services started. Use 'make stop-services' to stop them."

stop-services: ## Stop all running services
	@echo "Stopping all services..."
	pkill -f "bin/api-gateway" || true
	pkill -f "bin/user-service" || true
	pkill -f "bin/scanner-service" || true
	pkill -f "bin/network-service" || true
	pkill -f "bin/threat-service" || true
	pkill -f "bin/log-service" || true
	@echo "All services stopped."

# Demo targets
demo-auth: ## Run authentication demo
	@echo "Running authentication demo..."
	@if [ -f bin/auth-demo ]; then \
		bin/auth-demo; \
	else \
		echo "Building auth demo first..."; \
		$(MAKE) build-demos; \
		bin/auth-demo; \
	fi

demo-observability: ## Run observability demo
	@echo "Running observability demo..."
	@if [ -f bin/observability-demo ]; then \
		bin/observability-demo; \
	else \
		echo "Building observability demo first..."; \
		$(MAKE) build-demos; \
		bin/observability-demo; \
	fi

demo-all: ## Run all demos
	@echo "Running all demos..."
	$(MAKE) demo-auth
	@echo ""
	$(MAKE) demo-observability

# Deployment targets
deploy-dev: ## Deploy to development environment
	@echo "Deploying to development environment..."
	./scripts/deploy.sh --environment development --skip-tests

deploy-staging: ## Deploy to staging environment
	@echo "Deploying to staging environment..."
	./scripts/deploy.sh --environment staging

deploy-prod: ## Deploy to production environment
	@echo "Deploying to production environment..."
	./scripts/deploy.sh --environment production

deploy-monitoring: ## Deploy monitoring stack only
	@echo "Deploying monitoring stack..."
	./scripts/deploy.sh --monitoring-only

deploy-dry-run: ## Show deployment plan without executing
	@echo "Showing deployment plan..."
	./scripts/deploy.sh --dry-run

# Infrastructure targets
infra-init: ## Initialize Terraform infrastructure
	@echo "Initializing Terraform..."
	cd infrastructure/terraform && terraform init

infra-plan: ## Plan infrastructure changes
	@echo "Planning infrastructure changes..."
	cd infrastructure/terraform && terraform plan

infra-apply: ## Apply infrastructure changes
	@echo "Applying infrastructure changes..."
	cd infrastructure/terraform && terraform apply

infra-destroy: ## Destroy infrastructure
	@echo "Destroying infrastructure..."
	cd infrastructure/terraform && terraform destroy

# Docker targets
docker-build-all: ## Build all Docker images
	@echo "Building all Docker images..."
	docker build -f deployments/docker/Dockerfile.user -t hackai/user-service .
	docker build -f deployments/docker/Dockerfile.scanner -t hackai/scanner-service .
	docker build -f deployments/docker/Dockerfile.network -t hackai/network-service .
	docker build -f deployments/docker/Dockerfile.threat -t hackai/threat-service .
	docker build -f deployments/docker/Dockerfile.log -t hackai/log-service .

docker-push-all: ## Push all Docker images
	@echo "Pushing all Docker images..."
	docker push hackai/user-service
	docker push hackai/scanner-service
	docker push hackai/network-service
	docker push hackai/threat-service
	docker push hackai/log-service

# Kubernetes targets
k8s-apply: ## Apply Kubernetes manifests
	@echo "Applying Kubernetes manifests..."
	kubectl apply -f deployments/kubernetes/

k8s-delete: ## Delete Kubernetes resources
	@echo "Deleting Kubernetes resources..."
	kubectl delete -f deployments/kubernetes/

k8s-status: ## Show Kubernetes cluster status
	@echo "Kubernetes cluster status:"
	kubectl get nodes
	kubectl get pods -A
	kubectl get services -A

# Helm targets
helm-install: ## Install with Helm
	@echo "Installing with Helm..."
	helm install hackai deployments/helm/hackai --namespace hackai --create-namespace

helm-upgrade: ## Upgrade with Helm
	@echo "Upgrading with Helm..."
	helm upgrade hackai deployments/helm/hackai --namespace hackai

helm-uninstall: ## Uninstall Helm release
	@echo "Uninstalling Helm release..."
	helm uninstall hackai --namespace hackai

# Infrastructure targets (Terraform)
infra-tools: ## Install infrastructure tools
	@echo "Installing infrastructure tools..."
	cd infrastructure/terraform && ./install-tools.sh

infra-init: ## Initialize Terraform infrastructure
	@echo "Initializing Terraform..."
	cd infrastructure/terraform && make init

infra-plan: ## Plan infrastructure changes
	@echo "Planning infrastructure changes..."
	cd infrastructure/terraform && make plan ENV=$(ENV)

infra-apply: ## Apply infrastructure changes
	@echo "Applying infrastructure changes..."
	cd infrastructure/terraform && make apply ENV=$(ENV)

infra-destroy: ## Destroy infrastructure
	@echo "Destroying infrastructure..."
	cd infrastructure/terraform && make destroy ENV=$(ENV)

infra-status: ## Show infrastructure status
	@echo "Infrastructure status:"
	cd infrastructure/terraform && make status ENV=$(ENV)

infra-output: ## Show infrastructure outputs
	@echo "Infrastructure outputs:"
	cd infrastructure/terraform && make output ENV=$(ENV)

# Quick deployment targets
deploy-dev-infra: ## Deploy development infrastructure
	@echo "Deploying development infrastructure..."
	cd infrastructure/terraform && make quick-dev

deploy-staging-infra: ## Deploy staging infrastructure
	@echo "Deploying staging infrastructure..."
	cd infrastructure/terraform && make quick-staging

deploy-prod-infra: ## Deploy production infrastructure
	@echo "Deploying production infrastructure..."
	cd infrastructure/terraform && make prod

# Complete deployment (infrastructure + applications)
deploy-complete-dev: ## Complete development deployment
	@echo "Complete development deployment..."
	$(MAKE) deploy-dev-infra
	$(MAKE) helm-install

deploy-complete-staging: ## Complete staging deployment
	@echo "Complete staging deployment..."
	$(MAKE) deploy-staging-infra
	$(MAKE) helm-install

deploy-complete-prod: ## Complete production deployment
	@echo "Complete production deployment..."
	$(MAKE) deploy-prod-infra
	$(MAKE) helm-install

# Docker targets
docker-build: ## Build Docker images
	docker-compose build

docker-up: ## Start all services with Docker Compose
	docker-compose up -d

docker-down: ## Stop all Docker services
	docker-compose down

docker-logs: ## Show Docker logs
	docker-compose logs -f

# Database targets
db-migrate: ## Run database migrations
	@echo "Running database migrations..."
	go run ./cmd/migrate

db-seed: ## Seed database with test data
	@echo "Seeding database..."
	go run ./cmd/seed

db-reset: ## Reset database (drop and recreate)
	@echo "Resetting database..."
	go run ./cmd/migrate -reset

# Frontend targets
web-install: ## Install frontend dependencies
	cd web && npm install

web-dev: ## Start frontend development server
	cd web && npm run dev

web-build: ## Build frontend for production
	cd web && npm run build

web-test: ## Run frontend tests
	cd web && npm test

web-lint: ## Lint frontend code
	cd web && npm run lint

# Linting and formatting
lint: ## Run Go linters
	golangci-lint run

fmt: ## Format Go code
	go fmt ./...
	goimports -w .

# Security
security-scan: ## Run security vulnerability scan
	gosec ./...

# Clean targets
clean: ## Clean build artifacts
	rm -rf bin/
	rm -rf coverage.out coverage.html
	rm -rf web/dist/
	rm -rf web/.next/

clean-docker: ## Clean Docker images and volumes
	docker-compose down -v
	docker system prune -f

# Documentation
docs-serve: ## Serve documentation locally
	@echo "Starting documentation server..."
	cd docs && python3 -m http.server 8000

# Development setup
setup: ## Setup development environment
	@echo "Setting up development environment..."
	go mod download
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	cd web && npm install
	@echo "Development environment setup complete!"

# Production targets
deploy-staging: ## Deploy to staging environment
	@echo "Deploying to staging..."
	# Add staging deployment commands here

deploy-prod: ## Deploy to production environment
	@echo "Deploying to production..."
	# Add production deployment commands here

# Monitoring
logs: ## Show application logs
	tail -f logs/*.log

metrics: ## Show application metrics
	curl http://localhost:8080/metrics

health: ## Check service health
	@echo "Checking service health..."
	curl -f http://localhost:8080/health || echo "API Gateway: DOWN"
	curl -f http://localhost:8081/health || echo "User Service: DOWN"
	curl -f http://localhost:8082/health || echo "Scanner Service: DOWN"
	curl -f http://localhost:8083/health || echo "Network Service: DOWN"
	curl -f http://localhost:8084/health || echo "Threat Service: DOWN"
	curl -f http://localhost:8085/health || echo "Log Service: DOWN"
