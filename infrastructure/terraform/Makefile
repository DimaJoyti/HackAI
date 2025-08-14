# Makefile for HackAI Terraform Infrastructure

# Default environment
ENV ?= development

# Terraform variables
TF_VAR_FILE = environments/$(ENV).tfvars
TF_PLAN_FILE = tfplan-$(ENV)

# Colors for output
GREEN = \033[0;32m
YELLOW = \033[1;33m
RED = \033[0;31m
NC = \033[0m # No Color

.PHONY: help init plan apply destroy validate format check clean

# Default target
help: ## Show this help message
	@echo "HackAI Terraform Infrastructure Management"
	@echo ""
	@echo "Usage: make [target] [ENV=environment]"
	@echo ""
	@echo "Environments:"
	@echo "  development  - Development environment (default)"
	@echo "  staging      - Staging environment"
	@echo "  production   - Production environment"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

init: ## Initialize Terraform
	@echo -e "$(GREEN)Initializing Terraform for $(ENV) environment...$(NC)"
	@if [ ! -f "terraform.tfvars" ]; then \
		echo -e "$(YELLOW)Creating terraform.tfvars from example...$(NC)"; \
		cp terraform.tfvars.example terraform.tfvars; \
		echo -e "$(YELLOW)Please edit terraform.tfvars with your values$(NC)"; \
	fi
	terraform init

validate: init ## Validate Terraform configuration
	@echo -e "$(GREEN)Validating Terraform configuration...$(NC)"
	terraform fmt -check=true -diff=true || (echo -e "$(YELLOW)Running terraform fmt...$(NC)" && terraform fmt)
	terraform validate
	@echo -e "$(GREEN)Validation completed successfully!$(NC)"

plan: validate ## Create Terraform plan
	@echo -e "$(GREEN)Creating Terraform plan for $(ENV) environment...$(NC)"
	@if [ ! -f "$(TF_VAR_FILE)" ]; then \
		echo -e "$(RED)Error: $(TF_VAR_FILE) not found$(NC)"; \
		exit 1; \
	fi
	terraform plan -var-file="$(TF_VAR_FILE)" -out="$(TF_PLAN_FILE)"
	@echo -e "$(GREEN)Plan created: $(TF_PLAN_FILE)$(NC)"

apply: ## Apply Terraform plan
	@echo -e "$(GREEN)Applying Terraform plan for $(ENV) environment...$(NC)"
	@if [ ! -f "$(TF_PLAN_FILE)" ]; then \
		echo -e "$(RED)Error: $(TF_PLAN_FILE) not found. Run 'make plan ENV=$(ENV)' first$(NC)"; \
		exit 1; \
	fi
	terraform apply "$(TF_PLAN_FILE)"
	@echo -e "$(GREEN)Infrastructure deployed successfully!$(NC)"
	@echo ""
	@echo -e "$(YELLOW)Next steps:$(NC)"
	@echo "1. Configure kubectl: make kubeconfig ENV=$(ENV)"
	@echo "2. View outputs: make output ENV=$(ENV)"

destroy: ## Destroy infrastructure (use with caution)
	@echo -e "$(RED)WARNING: This will destroy all infrastructure for $(ENV) environment!$(NC)"
	@echo -e "$(RED)This action cannot be undone!$(NC)"
	@echo ""
	@read -p "Are you sure you want to continue? Type 'yes' to confirm: " confirm; \
	if [ "$$confirm" = "yes" ]; then \
		echo -e "$(RED)Destroying infrastructure...$(NC)"; \
		terraform destroy -var-file="$(TF_VAR_FILE)" -auto-approve; \
	else \
		echo -e "$(GREEN)Destruction cancelled$(NC)"; \
	fi

output: ## Show Terraform outputs
	@echo -e "$(GREEN)Terraform outputs for $(ENV) environment:$(NC)"
	terraform output

format: ## Format Terraform files
	@echo -e "$(GREEN)Formatting Terraform files...$(NC)"
	terraform fmt -recursive

check: ## Run security and best practice checks
	@echo -e "$(GREEN)Running security checks...$(NC)"
	@if command -v tfsec >/dev/null 2>&1; then \
		tfsec .; \
	else \
		echo -e "$(YELLOW)tfsec not installed. Install with: go install github.com/aquasecurity/tfsec/cmd/tfsec@latest$(NC)"; \
	fi
	@if command -v checkov >/dev/null 2>&1; then \
		checkov -d .; \
	else \
		echo -e "$(YELLOW)checkov not installed. Install with: pip install checkov$(NC)"; \
	fi

cost: ## Estimate infrastructure costs
	@echo -e "$(GREEN)Estimating infrastructure costs...$(NC)"
	@if command -v infracost >/dev/null 2>&1; then \
		infracost breakdown --path .; \
	else \
		echo -e "$(YELLOW)infracost not installed. Install from: https://www.infracost.io/docs/$(NC)"; \
	fi

kubeconfig: ## Configure kubectl for EKS cluster
	@echo -e "$(GREEN)Configuring kubectl for $(ENV) environment...$(NC)"
	$(eval CLUSTER_NAME := $(shell terraform output -raw cluster_name 2>/dev/null || echo "hackai-$(ENV)"))
	$(eval AWS_REGION := $(shell terraform output -raw aws_region 2>/dev/null || echo "us-west-2"))
	aws eks update-kubeconfig --region $(AWS_REGION) --name $(CLUSTER_NAME)
	@echo -e "$(GREEN)kubectl configured successfully!$(NC)"
	kubectl get nodes

clean: ## Clean up temporary files
	@echo -e "$(GREEN)Cleaning up temporary files...$(NC)"
	rm -f tfplan-*
	rm -f terraform.tfstate.backup
	rm -f .terraform.lock.hcl
	@echo -e "$(GREEN)Cleanup completed$(NC)"

# Environment-specific targets
dev: ## Deploy to development environment
	$(MAKE) plan apply ENV=development

staging: ## Deploy to staging environment
	$(MAKE) plan apply ENV=staging

prod: ## Deploy to production environment
	@echo -e "$(RED)WARNING: Deploying to PRODUCTION environment!$(NC)"
	@read -p "Are you sure? Type 'production' to confirm: " confirm; \
	if [ "$$confirm" = "production" ]; then \
		$(MAKE) plan apply ENV=production; \
	else \
		echo -e "$(GREEN)Production deployment cancelled$(NC)"; \
	fi

# Quick commands
quick-dev: ## Quick development deployment (plan + apply)
	$(MAKE) init validate plan apply ENV=development

quick-staging: ## Quick staging deployment (plan + apply)
	$(MAKE) init validate plan apply ENV=staging

# Status check
status: ## Show current infrastructure status
	@echo -e "$(GREEN)Infrastructure status for $(ENV) environment:$(NC)"
	@echo ""
	@echo "Terraform State:"
	terraform show -json | jq -r '.values.root_module.resources[] | select(.type == "aws_eks_cluster") | .values.name' 2>/dev/null || echo "No EKS cluster found"
	@echo ""
	@echo "AWS Resources:"
	@if command -v aws >/dev/null 2>&1; then \
		echo "EKS Clusters:"; \
		aws eks list-clusters --query 'clusters' --output table 2>/dev/null || echo "Unable to list EKS clusters"; \
		echo ""; \
		echo "RDS Instances:"; \
		aws rds describe-db-instances --query 'DBInstances[].DBInstanceIdentifier' --output table 2>/dev/null || echo "Unable to list RDS instances"; \
	else \
		echo "AWS CLI not available"; \
	fi

# Documentation
docs: ## Generate documentation
	@echo -e "$(GREEN)Generating Terraform documentation...$(NC)"
	@if command -v terraform-docs >/dev/null 2>&1; then \
		terraform-docs markdown table . > TERRAFORM_DOCS.md; \
		echo -e "$(GREEN)Documentation generated: TERRAFORM_DOCS.md$(NC)"; \
	else \
		echo -e "$(YELLOW)terraform-docs not installed. Install from: https://terraform-docs.io/$(NC)"; \
	fi

# Backup state
backup: ## Backup Terraform state
	@echo -e "$(GREEN)Backing up Terraform state...$(NC)"
	cp terraform.tfstate terraform.tfstate.backup.$(shell date +%Y%m%d_%H%M%S) 2>/dev/null || echo "No local state file found"
	@echo -e "$(GREEN)State backup completed$(NC)"

# Show current environment
env: ## Show current environment configuration
	@echo -e "$(GREEN)Current environment: $(ENV)$(NC)"
	@echo "Variable file: $(TF_VAR_FILE)"
	@echo "Plan file: $(TF_PLAN_FILE)"
	@if [ -f "$(TF_VAR_FILE)" ]; then \
		echo ""; \
		echo "Environment configuration:"; \
		grep -E "^[^#].*=" $(TF_VAR_FILE) | head -10; \
	else \
		echo -e "$(RED)Variable file not found: $(TF_VAR_FILE)$(NC)"; \
	fi
