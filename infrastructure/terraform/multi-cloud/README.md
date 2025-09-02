# HackAI Multi-Cloud Infrastructure

This Terraform configuration deploys HackAI infrastructure across multiple cloud providers (AWS, GCP, and Azure) with Kubernetes clusters, databases, caching, storage, and monitoring.

## Architecture Overview

The multi-cloud deployment includes:

- **AWS**: EKS cluster, RDS PostgreSQL, ElastiCache Redis, S3 storage
- **GCP**: GKE cluster, Cloud SQL PostgreSQL, Cloud Storage
- **Azure**: AKS cluster, PostgreSQL Flexible Server, Redis Cache, Storage Account

## Prerequisites

1. **Terraform**: Version 1.5 or later
2. **Cloud Provider CLIs**:
   - AWS CLI configured with appropriate credentials
   - Google Cloud SDK with authentication
   - Azure CLI logged in
3. **kubectl**: For Kubernetes cluster management
4. **Helm**: For application deployments

## Quick Start

### 1. Initialize Terraform

```bash
cd infrastructure/terraform/multi-cloud
terraform init
```

### 2. Configure Variables

Copy and customize the environment configuration:

```bash
cp environments/development.tfvars environments/my-environment.tfvars
# Edit the file with your specific values
```

Required variables to set:
- `gcp_project_id`: Your GCP project ID
- `azure_subscription_id`: Your Azure subscription ID

### 3. Plan and Apply

```bash
# Plan the deployment
terraform plan -var-file="environments/my-environment.tfvars"

# Apply the configuration
terraform apply -var-file="environments/my-environment.tfvars"
```

## Environment Configurations

### Development Environment

- **Clouds**: AWS only (GCP and Azure disabled for cost savings)
- **Resources**: Minimal instance sizes
- **Features**: Basic monitoring, no backup, spot instances enabled

```bash
terraform apply -var-file="environments/development.tfvars"
```

### Production Environment

- **Clouds**: All three clouds enabled
- **Resources**: Production-grade instance sizes
- **Features**: Full monitoring, backup, security scanning, compliance

```bash
terraform apply -var-file="environments/production.tfvars"
```

## Module Structure

```
modules/
├── aws/           # AWS infrastructure (EKS, RDS, ElastiCache, S3)
├── gcp/           # GCP infrastructure (GKE, Cloud SQL, Storage)
├── azure/         # Azure infrastructure (AKS, PostgreSQL, Redis, Storage)
├── monitoring/    # Cross-cloud monitoring and dashboards
├── security/      # Security policies and encryption
└── serverless/    # Serverless functions across clouds
```

## Key Features

### Multi-Cloud Strategy
- **Primary Cloud**: Configurable (default: AWS)
- **Selective Deployment**: Enable/disable individual clouds
- **Consistent Naming**: Unified naming convention across clouds

### Kubernetes Clusters
- **AWS EKS**: Managed Kubernetes with auto-scaling node groups
- **GCP GKE**: VPC-native cluster with Workload Identity
- **Azure AKS**: Managed cluster with Azure CNI

### Databases
- **AWS**: RDS PostgreSQL with automated backups
- **GCP**: Cloud SQL PostgreSQL with private networking
- **Azure**: PostgreSQL Flexible Server with geo-redundant backup

### Monitoring
- **AWS**: CloudWatch logs and dashboards
- **GCP**: Cloud Monitoring with custom dashboards
- **Azure**: Log Analytics and Azure Monitor

### Security
- **Encryption**: At-rest and in-transit encryption
- **Network Security**: Security groups, firewall rules, NSGs
- **Identity Management**: IAM roles, service accounts, managed identities

## Configuration Examples

### Enable Only AWS and GCP

```hcl
enable_aws   = true
enable_gcp   = true
enable_azure = false
```

### Cost Optimization Settings

```hcl
enable_spot_instances    = true
aws_single_nat_gateway   = true
enable_backup           = false
enable_monitoring       = false
```

### Production Security Settings

```hcl
enable_encryption_at_rest    = true
enable_encryption_in_transit = true
enable_network_policies      = true
enable_security_scanning     = true
```

## Outputs

After deployment, Terraform provides:

- **Cluster Information**: Names, endpoints, and connection commands
- **Database Details**: Connection strings and credentials
- **Storage Resources**: Bucket/container names and URLs
- **Monitoring URLs**: Dashboard links for each cloud
- **Cost Estimates**: Monthly cost projections

## Connecting to Clusters

Use the provided kubectl configuration commands:

```bash
# AWS EKS
aws eks update-kubeconfig --region us-west-2 --name hackai-production-eks

# GCP GKE
gcloud container clusters get-credentials hackai-production-gke --region us-central1

# Azure AKS
az aks get-credentials --resource-group hackai-production-rg --name hackai-production-aks
```

## Deployment Commands

Deploy applications using Helm:

```bash
# Install HackAI application
helm install hackai ./deployments/helm/hackai --namespace hackai --create-namespace

# Deploy to specific cloud context
kubectl apply -f ./deployments/multi-cloud/aws/ --context=aws
```

## Troubleshooting

### Common Issues

1. **Provider Authentication**: Ensure all cloud CLIs are properly authenticated
2. **Resource Limits**: Check cloud provider quotas and limits
3. **Network Connectivity**: Verify VPC/subnet configurations
4. **Permissions**: Ensure service accounts have required permissions

### Validation

```bash
# Validate configuration
terraform validate

# Check formatting
terraform fmt -check

# Plan without applying
terraform plan -var-file="environments/development.tfvars"
```

## Cost Management

### Development Environment
- Estimated monthly cost: ~$200 USD
- Single cloud (AWS only)
- Minimal instance sizes
- Spot instances enabled

### Production Environment
- Estimated monthly cost: ~$1,500 USD
- All three clouds enabled
- Production-grade instances
- High availability and backup

## Security Considerations

1. **Secrets Management**: Use cloud-native secret stores
2. **Network Security**: Private subnets and security groups
3. **Encryption**: Enable encryption for all data stores
4. **Access Control**: Implement least-privilege access
5. **Monitoring**: Enable audit logging and monitoring

## Contributing

1. Follow Terraform best practices
2. Update documentation for new features
3. Test changes in development environment
4. Use consistent naming conventions
5. Add appropriate tags and labels

## Support

For issues and questions:
- Check the troubleshooting section
- Review Terraform and cloud provider documentation
- Open an issue in the project repository
