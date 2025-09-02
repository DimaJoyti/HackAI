# HackAI Multi-Cloud Deployment Guide

## Prerequisites

### Required Tools
```bash
# Install required tools
curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
wget https://releases.hashicorp.com/terraform/1.6.0/terraform_1.6.0_linux_amd64.zip
```

### Cloud Provider Setup

#### AWS Setup
```bash
# Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && sudo ./aws/install

# Configure AWS credentials
aws configure
# Enter: Access Key ID, Secret Access Key, Region (us-west-2), Output format (json)

# Verify access
aws sts get-caller-identity
```

#### GCP Setup
```bash
# Install gcloud CLI
curl https://sdk.cloud.google.com | bash
exec -l $SHELL

# Authenticate and set project
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
gcloud auth application-default login

# Enable required APIs
gcloud services enable container.googleapis.com
gcloud services enable compute.googleapis.com
gcloud services enable iam.googleapis.com
```

#### Azure Setup
```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Login to Azure
az login
az account set --subscription YOUR_SUBSCRIPTION_ID

# Verify access
az account show
```

## Environment Configuration

### 1. Set Environment Variables
```bash
# Create environment configuration
cat > .env << EOF
# Global Configuration
PROJECT_NAME=hackai
ENVIRONMENT=production
OWNER=HackAI-Team

# AWS Configuration
AWS_REGION=us-west-2
AWS_PROFILE=default

# GCP Configuration
GCP_PROJECT_ID=hackai-production
GCP_REGION=us-central1

# Azure Configuration
AZURE_SUBSCRIPTION_ID=your-subscription-id
AZURE_LOCATION="East US"

# Multi-Cloud Settings
CLOUD_PROVIDERS=aws,gcp,azure
PRIMARY_CLOUD=aws
DEPLOY_SERVERLESS=true
DEPLOY_MONITORING=true

# Notification Settings
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
EOF

# Load environment variables
source .env
```

### 2. Terraform Backend Setup
```bash
# Create S3 bucket for Terraform state
aws s3 mb s3://hackai-terraform-state-multi-cloud --region us-west-2
aws s3api put-bucket-versioning \
  --bucket hackai-terraform-state-multi-cloud \
  --versioning-configuration Status=Enabled

# Create DynamoDB table for state locking
aws dynamodb create-table \
  --table-name hackai-terraform-locks-multi-cloud \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5
```

## Deployment Steps

### Step 1: Infrastructure Deployment

#### Option A: Automated Deployment (Recommended)
```bash
# Make deployment script executable
chmod +x scripts/deploy-multi-cloud.sh

# Deploy to production
./scripts/deploy-multi-cloud.sh \
  --environment production \
  --clouds aws,gcp,azure \
  --serverless \
  --monitoring \
  --security

# Deploy to staging (single cloud)
./scripts/deploy-multi-cloud.sh \
  --environment staging \
  --clouds aws \
  --dry-run
```

#### Option B: Manual Deployment
```bash
# Navigate to Terraform directory
cd infrastructure/terraform/multi-cloud

# Initialize Terraform
terraform init

# Create or select workspace
terraform workspace new production
terraform workspace select production

# Plan deployment
terraform plan -var-file="environments/production.tfvars" -out=tfplan

# Apply infrastructure
terraform apply tfplan

# Save outputs
terraform output -json > outputs.json
```

### Step 2: Serverless Functions Deployment

#### Build and Deploy Lambda Functions
```bash
# Navigate to serverless directory
cd serverless/aws-lambda

# Build all functions
for func in */; do
  echo "Building $func"
  cd "$func"
  GOOS=linux GOARCH=amd64 go build -o main main.go
  zip "../${func%/}.zip" main
  cd ..
done

# Deploy functions (if not using Terraform)
for zip_file in *.zip; do
  func_name="${zip_file%.zip}"
  aws lambda update-function-code \
    --function-name "hackai-production-${func_name}" \
    --zip-file "fileb://$zip_file"
done
```

### Step 3: Application Deployment

#### Configure Kubernetes Access
```bash
# AWS EKS
aws eks update-kubeconfig --region us-west-2 --name hackai-production-aws

# GCP GKE
gcloud container clusters get-credentials hackai-production-gcp \
  --region us-central1 --project hackai-production

# Azure AKS
az aks get-credentials --resource-group hackai-production-rg \
  --name hackai-production-azure
```

#### Deploy Applications with Helm
```bash
# Add Helm repositories
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Deploy to AWS cluster
kubectl config use-context aws-production
helm upgrade --install hackai-aws ./deployments/helm/hackai \
  --namespace hackai --create-namespace \
  --set global.cloudProvider=aws \
  --set app.environment=production \
  --values ./deployments/helm/hackai/values-aws.yaml

# Deploy to GCP cluster
kubectl config use-context gcp-production
helm upgrade --install hackai-gcp ./deployments/helm/hackai \
  --namespace hackai --create-namespace \
  --set global.cloudProvider=gcp \
  --set app.environment=production \
  --values ./deployments/helm/hackai/values-gcp.yaml

# Deploy to Azure cluster
kubectl config use-context azure-production
helm upgrade --install hackai-azure ./deployments/helm/hackai \
  --namespace hackai --create-namespace \
  --set global.cloudProvider=azure \
  --set app.environment=production \
  --values ./deployments/helm/hackai/values-azure.yaml
```

### Step 4: Monitoring and Observability

#### Deploy Monitoring Stack
```bash
# Deploy Prometheus and Grafana
helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace \
  --values ./deployments/monitoring/prometheus/values-multi-cloud.yaml

# Deploy OpenTelemetry Collector
kubectl apply -f ./deployments/monitoring/opentelemetry/

# Deploy Jaeger
helm upgrade --install jaeger jaegertracing/jaeger \
  --namespace monitoring \
  --values ./deployments/monitoring/jaeger/values.yaml
```

#### Configure Dashboards
```bash
# Import Grafana dashboards
kubectl create configmap grafana-dashboards \
  --from-file=./deployments/monitoring/grafana/dashboards/ \
  --namespace monitoring

# Apply dashboard configuration
kubectl apply -f ./deployments/monitoring/grafana/dashboard-config.yaml
```

### Step 5: GitOps Setup

#### ArgoCD Installation
```bash
# Install ArgoCD
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Get admin password
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

# Port forward to access UI
kubectl port-forward svc/argocd-server -n argocd 8080:443

# Apply ArgoCD applications
kubectl apply -f ./gitops/argocd/applications/
```

#### Flux Installation (Alternative)
```bash
# Install Flux CLI
curl -s https://fluxcd.io/install.sh | sudo bash

# Bootstrap Flux
flux bootstrap github \
  --owner=DimaJoyti \
  --repository=HackAI \
  --branch=main \
  --path=./gitops/flux/clusters/production

# Apply Flux configurations
kubectl apply -f ./gitops/flux/clusters/production/
```

## Verification and Testing

### Health Checks
```bash
# Check cluster status
kubectl get nodes --all-namespaces
kubectl get pods --all-namespaces

# Check application health
kubectl get pods -n hackai
kubectl get services -n hackai
kubectl get ingress -n hackai

# Check monitoring stack
kubectl get pods -n monitoring
kubectl get services -n monitoring
```

### Functional Testing
```bash
# Test API endpoints
curl -k https://api.hackai.com/health
curl -k https://api.hackai.com/api/v1/status

# Test database connectivity
kubectl exec -it deployment/api-gateway -n hackai -- \
  psql -h postgres-service -U hackai -d hackai -c "SELECT 1;"

# Test Redis connectivity
kubectl exec -it deployment/api-gateway -n hackai -- \
  redis-cli -h redis-service ping
```

### Performance Testing
```bash
# Install k6 for load testing
sudo apt-get install k6

# Run performance tests
k6 run tests/performance/load-test.js

# Monitor during testing
kubectl top nodes
kubectl top pods -n hackai
```

## Troubleshooting

### Common Issues

#### 1. Terraform State Lock
```bash
# Force unlock if needed (use with caution)
terraform force-unlock LOCK_ID
```

#### 2. Kubernetes Context Issues
```bash
# List available contexts
kubectl config get-contexts

# Switch context
kubectl config use-context CONTEXT_NAME

# Verify current context
kubectl config current-context
```

#### 3. Helm Deployment Issues
```bash
# Check Helm releases
helm list --all-namespaces

# Get release history
helm history RELEASE_NAME -n NAMESPACE

# Rollback if needed
helm rollback RELEASE_NAME REVISION -n NAMESPACE
```

#### 4. Pod Issues
```bash
# Describe pod for events
kubectl describe pod POD_NAME -n NAMESPACE

# Check logs
kubectl logs POD_NAME -n NAMESPACE --previous

# Debug with shell access
kubectl exec -it POD_NAME -n NAMESPACE -- /bin/bash
```

## Support and Documentation

### Additional Resources
- [Multi-Cloud Architecture Documentation](./MULTI_CLOUD_ARCHITECTURE.md)
- [Operational Runbooks](./runbooks/)
- [Security Guidelines](./SECURITY.md)
- [Cost Optimization Guide](./COST_OPTIMIZATION.md)

### Getting Help
- **Internal Documentation**: Check the `docs/` directory
- **Monitoring Dashboards**: Grafana dashboards for real-time insights
- **Logs**: Centralized logging in the monitoring namespace
- **Alerts**: Slack notifications for critical issues

### Emergency Contacts
- **Platform Team**: platform-team@hackai.com
- **Security Team**: security-team@hackai.com
- **On-Call Engineer**: +1-XXX-XXX-XXXX
