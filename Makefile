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

build-multicloud-cli: ## Build Multi-Cloud DevOps CLI
	@echo "Building Multi-Cloud DevOps CLI..."
	@mkdir -p bin
	go build -o bin/multicloud-devops-cli ./cmd/multicloud-devops-cli
	@echo "Multi-Cloud DevOps CLI built successfully"

install-multicloud-cli: build-multicloud-cli ## Install Multi-Cloud DevOps CLI to system PATH
	@echo "Installing Multi-Cloud DevOps CLI to /usr/local/bin..."
	sudo cp bin/multicloud-devops-cli /usr/local/bin/
	@echo "CLI installed successfully! Run 'multicloud-devops-cli -help' to get started"

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

# Kubernetes Deployment Commands
.PHONY: deploy-k8s undeploy-k8s k8s-status k8s-logs

deploy-k8s: ## Deploy to Kubernetes
	@echo "Deploying to Kubernetes..."
	kubectl apply -f deployments/k8s/namespace.yaml
	kubectl apply -f deployments/k8s/postgres.yaml
	kubectl apply -f deployments/k8s/redis.yaml
	kubectl apply -f deployments/k8s/api-gateway.yaml
	kubectl apply -f deployments/k8s/ingress.yaml
	@echo "Kubernetes deployment completed!"

undeploy-k8s: ## Remove Kubernetes deployment
	@echo "Removing Kubernetes deployment..."
	kubectl delete namespace hackai --ignore-not-found=true

k8s-status: ## Check Kubernetes deployment status
	@echo "Checking Kubernetes status..."
	kubectl get pods -n hackai
	kubectl get services -n hackai
	kubectl get ingress -n hackai

k8s-logs: ## View Kubernetes logs
	@echo "Viewing Kubernetes logs..."
	kubectl logs -f -l app=api-gateway -n hackai

# Database Management Commands
.PHONY: db-migrate db-rollback db-seed db-reset db-backup db-restore

db-migrate: ## Run database migrations
	@echo "Running database migrations..."
	docker-compose exec postgres psql -U hackai -d hackai -f /docker-entrypoint-initdb.d/init.sql

db-rollback: ## Rollback database migrations
	@echo "Rolling back database migrations..."
	@echo "Manual rollback required - check migration files"

db-seed: ## Seed database with sample data
	@echo "Seeding database with sample data..."
	docker-compose exec postgres psql -U hackai -d hackai -c "INSERT INTO auth.users (email, password_hash, name, role) VALUES ('demo@hackai.com', crypt('demo123', gen_salt('bf', 12)), 'Demo User', 'student') ON CONFLICT (email) DO NOTHING;"

db-reset: ## Reset database (drop and recreate)
	@echo "Resetting database..."
	docker-compose exec postgres psql -U hackai -d postgres -c "DROP DATABASE IF EXISTS hackai;"
	docker-compose exec postgres psql -U hackai -d postgres -c "CREATE DATABASE hackai;"
	make db-migrate
	make db-seed

db-backup: ## Backup database
	@echo "Creating database backup..."
	docker-compose exec postgres pg_dump -U hackai hackai > backup_$(shell date +%Y%m%d_%H%M%S).sql

db-restore: ## Restore database from backup (requires BACKUP_FILE variable)
	@echo "Restoring database from backup..."
	@if [ -z "$(BACKUP_FILE)" ]; then echo "Please specify BACKUP_FILE=filename.sql"; exit 1; fi
	docker-compose exec -T postgres psql -U hackai hackai < $(BACKUP_FILE)

# Security and Quality Commands
.PHONY: security-scan vulnerability-check lint format audit security-audit setup-secrets validate-secrets

security-scan: ## Run comprehensive security scan
	@echo "Running security vulnerability scan..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not installed. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi

vulnerability-check: ## Check for known vulnerabilities
	@echo "Checking for known vulnerabilities..."
	go list -json -m all | nancy sleuth

lint: ## Run code linting
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Install from: https://golangci-lint.run/usage/install/"; \
	fi
	@if [ -d "web" ]; then cd web && npm run lint; fi

format: ## Format code
	@echo "Formatting code..."
	go fmt ./...
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	else \
		echo "goimports not installed. Install with: go install golang.org/x/tools/cmd/goimports@latest"; \
	fi
	@if [ -d "web" ]; then cd web && npm run format; fi

audit: ## Run comprehensive security audit
	@echo "Running comprehensive security audit..."
	@$(MAKE) security-scan
	@$(MAKE) vulnerability-check
	@$(MAKE) security-audit
	go mod verify
	@if [ -d "web" ]; then cd web && npm audit; fi

security-audit: ## Run security audit for hardcoded secrets
	@echo "Running security audit for hardcoded secrets..."
	@./scripts/security-audit.sh

setup-secrets: ## Setup secure environment variables
	@echo "Setting up secure secrets..."
	@./scripts/setup-secrets.sh setup

validate-secrets: ## Validate existing secrets
	@echo "Validating existing secrets..."
	@./scripts/setup-secrets.sh validate

rotate-secrets: ## Rotate all secrets (use with caution)
	@echo "Rotating secrets..."
	@./scripts/setup-secrets.sh rotate

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

# Duplicate k8s-status target removed - see line 168

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

# Duplicate infra-* targets removed - see lines 253-266

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

# Duplicate db-* targets removed - see lines 181-198

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

# Duplicate lint target removed - see line 224

fmt: ## Format Go code
	go fmt ./...
	goimports -w .

# Duplicate security-scan target removed - see line 212

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

# Duplicate deploy-* targets removed - see lines 140-148

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
