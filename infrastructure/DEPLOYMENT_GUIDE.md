# HackAI Infrastructure Deployment Guide

This comprehensive guide walks you through deploying the HackAI platform infrastructure on AWS using Terraform.

## 🚀 Quick Start

### 1. Install Required Tools
```bash
cd infrastructure/terraform
./install-tools.sh
```

### 2. Configure AWS
```bash
aws configure
```

### 3. Deploy Development Environment
```bash
make quick-dev
```

### 4. Configure Kubernetes Access
```bash
make kubeconfig ENV=development
```

### 5. Deploy Applications
```bash
cd ../../
make helm-install
```

## 📋 Prerequisites

### System Requirements
- **Operating System**: Linux (Ubuntu/Debian/CentOS) or macOS
- **Memory**: Minimum 4GB RAM
- **Storage**: At least 10GB free space
- **Network**: Internet connection for downloading tools and AWS access

### Required Tools
- **Terraform** (>= 1.5.0)
- **AWS CLI** (>= 2.0)
- **kubectl** (>= 1.25)
- **Helm** (>= 3.0)
- **jq** (JSON processor)

### AWS Requirements
- **AWS Account** with appropriate permissions
- **IAM User** with programmatic access
- **Required IAM Permissions**:
  - EC2 (VPC, Security Groups, Load Balancers)
  - EKS (Cluster management)
  - RDS (Database management)
  - ElastiCache (Redis management)
  - S3 (Storage)
  - IAM (Role management)
  - CloudWatch (Monitoring)

## 🏗️ Infrastructure Architecture

### Core Components
```
┌─────────────────────────────────────────────────────────────┐
│                    AWS Cloud Infrastructure                 │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Route53   │  │     ACM     │  │     WAF     │         │
│  │     DNS     │  │    Certs    │  │  Firewall   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Application Load Balancer                  │ │
│  └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                 EKS Cluster                             │ │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐       │ │
│  │  │ API Gateway │ │ User Service│ │   Scanner   │       │ │
│  │  └─────────────┘ └─────────────┘ └─────────────┘       │ │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐       │ │
│  │  │  Network    │ │   Threat    │ │     Log     │       │ │
│  │  │   Service   │ │   Service   │ │   Service   │       │ │
│  │  └─────────────┘ └─────────────┘ └─────────────┘       │ │
│  └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ PostgreSQL  │  │    Redis    │  │     S3      │         │
│  │     RDS     │  │ ElastiCache │  │   Storage   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

### Network Architecture
- **VPC**: Multi-AZ setup with public and private subnets
- **Public Subnets**: Load balancers and NAT gateways
- **Private Subnets**: EKS nodes, RDS, and ElastiCache
- **Security Groups**: Least privilege access control

## 🔧 Step-by-Step Deployment

### Step 1: Environment Setup

#### 1.1 Install Tools
```bash
# Navigate to Terraform directory
cd infrastructure/terraform

# Install all required tools
./install-tools.sh

# Verify installations
terraform version
aws --version
kubectl version --client
helm version
```

#### 1.2 Configure AWS Credentials
```bash
# Configure AWS CLI
aws configure

# Verify access
aws sts get-caller-identity
```

### Step 2: Infrastructure Configuration

#### 2.1 Choose Environment
```bash
# Development (recommended for first deployment)
export ENV=development

# Staging
export ENV=staging

# Production
export ENV=production
```

#### 2.2 Review Configuration
```bash
# View environment configuration
make env ENV=$ENV

# Edit configuration if needed
nano environments/$ENV.tfvars
```

### Step 3: Infrastructure Deployment

#### 3.1 Initialize Terraform
```bash
make init
```

#### 3.2 Validate Configuration
```bash
make validate
```

#### 3.3 Plan Deployment
```bash
make plan ENV=$ENV
```

#### 3.4 Apply Infrastructure
```bash
make apply ENV=$ENV
```

#### 3.5 Configure Kubernetes Access
```bash
make kubeconfig ENV=$ENV
```

### Step 4: Application Deployment

#### 4.1 Deploy with Helm
```bash
# Navigate back to project root
cd ../../

# Install HackAI application
make helm-install

# Check deployment status
kubectl get pods -n hackai
```

#### 4.2 Deploy with Kubernetes Manifests (Alternative)
```bash
# Apply Kubernetes manifests
make k8s-apply

# Check status
make k8s-status
```

### Step 5: Verification

#### 5.1 Check Infrastructure
```bash
cd infrastructure/terraform

# View outputs
make output ENV=$ENV

# Check status
make status ENV=$ENV
```

#### 5.2 Check Applications
```bash
# Check pods
kubectl get pods -n hackai

# Check services
kubectl get services -n hackai

# Check ingress
kubectl get ingress -n hackai
```

#### 5.3 Access Applications
```bash
# Get load balancer URL
kubectl get ingress -n hackai -o jsonpath='{.items[0].status.loadBalancer.ingress[0].hostname}'

# Or use port forwarding for testing
kubectl port-forward -n hackai svc/api-gateway-service 8080:8080
```

## 🌍 Environment-Specific Deployments

### Development Environment
```bash
# Quick development deployment
make quick-dev

# Features:
# - Smaller instance types
# - Single AZ deployment
# - Minimal monitoring
# - Cost optimized
```

### Staging Environment
```bash
# Staging deployment
make plan apply ENV=staging

# Features:
# - Production-like configuration
# - Full monitoring
# - Security enabled
# - Multi-AZ for testing
```

### Production Environment
```bash
# Production deployment (requires confirmation)
make prod

# Features:
# - High availability
# - Full security
# - Comprehensive monitoring
# - Auto-scaling enabled
# - Backup and disaster recovery
```

## 📊 Monitoring and Observability

### Access Monitoring Tools
```bash
# Get monitoring URLs
terraform output monitoring_urls

# Port forward to access locally
kubectl port-forward -n hackai svc/grafana-service 3000:3000
kubectl port-forward -n hackai svc/prometheus-service 9090:9090
kubectl port-forward -n hackai svc/jaeger-service 16686:16686
```

### Key Metrics to Monitor
- **Application**: Request rate, latency, error rate
- **Infrastructure**: CPU, memory, network, storage
- **Security**: Authentication failures, suspicious activity
- **Business**: User activity, scan performance

## 🔒 Security Considerations

### Network Security
- VPC with private subnets
- Security groups with minimal access
- Network ACLs for additional protection
- VPC Flow Logs enabled

### Data Security
- Encryption at rest for all data stores
- Encryption in transit with TLS
- Secrets managed with AWS Secrets Manager
- Regular security scanning

### Access Control
- IAM roles with least privilege
- Kubernetes RBAC
- Pod security policies
- Network policies

## 💰 Cost Management

### Cost Optimization
```bash
# Estimate costs
make cost ENV=$ENV

# Monitor costs
aws ce get-cost-and-usage --time-period Start=2024-01-01,End=2024-01-31 --granularity MONTHLY --metrics BlendedCost
```

### Cost-Saving Tips
- Use spot instances for non-critical workloads
- Right-size instances based on usage
- Enable auto-scaling
- Use Reserved Instances for predictable workloads
- Monitor and optimize storage usage

## 🔧 Troubleshooting

### Common Issues

#### 1. Terraform Errors
```bash
# Check Terraform state
terraform state list

# Refresh state
terraform refresh

# Import existing resources
terraform import aws_instance.example i-1234567890abcdef0
```

#### 2. AWS Permission Issues
```bash
# Check current user
aws sts get-caller-identity

# List attached policies
aws iam list-attached-user-policies --user-name your-username
```

#### 3. Kubernetes Connection Issues
```bash
# Update kubeconfig
aws eks update-kubeconfig --region us-west-2 --name hackai-development

# Check cluster status
kubectl cluster-info

# Check node status
kubectl get nodes
```

#### 4. Application Deployment Issues
```bash
# Check pod logs
kubectl logs -n hackai deployment/api-gateway

# Check events
kubectl get events -n hackai --sort-by='.lastTimestamp'

# Describe problematic resources
kubectl describe pod -n hackai <pod-name>
```

### Getting Help
1. Check the troubleshooting section in README.md
2. Review AWS CloudTrail logs
3. Check Kubernetes events and logs
4. Contact the DevOps team

## 🧹 Cleanup

### Destroy Infrastructure
```bash
# Development environment
make destroy ENV=development

# Staging environment
make destroy ENV=staging

# Production environment (be very careful!)
make destroy ENV=production
```

### Manual Cleanup
Some resources may require manual cleanup:
- S3 buckets with objects
- EBS snapshots
- CloudWatch log groups
- Route53 records (if managing DNS)

## 📚 Additional Resources

### Documentation
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [EKS Best Practices](https://aws.github.io/aws-eks-best-practices/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Helm Documentation](https://helm.sh/docs/)

### Tools
- [AWS CLI Reference](https://docs.aws.amazon.com/cli/latest/reference/)
- [kubectl Cheat Sheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)
- [Terraform CLI](https://www.terraform.io/docs/cli/index.html)

### Monitoring
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [Jaeger Documentation](https://www.jaegertracing.io/docs/)

## 🎯 Next Steps

After successful deployment:

1. **Configure DNS**: Point your domain to the load balancer
2. **Set up CI/CD**: Integrate with GitHub Actions
3. **Configure Monitoring**: Set up alerts and dashboards
4. **Security Hardening**: Review and implement additional security measures
5. **Backup Strategy**: Implement regular backup procedures
6. **Documentation**: Update team documentation and runbooks

The HackAI platform is now ready for production use with enterprise-grade infrastructure! 🚀
