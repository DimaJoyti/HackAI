# HackAI Infrastructure - Terraform Configuration

This directory contains the Terraform configuration for deploying the HackAI platform infrastructure on AWS.

## Prerequisites

### Required Tools

1. **Terraform** (>= 1.5.0)
   ```bash
   # Install Terraform
   curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
   sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
   sudo apt-get update && sudo apt-get install terraform
   ```

2. **AWS CLI** (>= 2.0)
   ```bash
   # Install AWS CLI
   curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
   unzip awscliv2.zip
   sudo ./aws/install
   ```

3. **kubectl** (for EKS management)
   ```bash
   # Install kubectl
   curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
   sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
   ```

### AWS Configuration

1. **Configure AWS credentials:**
   ```bash
   aws configure
   ```
   
2. **Verify AWS access:**
   ```bash
   aws sts get-caller-identity
   ```

## Quick Start

### 1. Initialize Configuration

```bash
# Copy example variables
cp terraform.tfvars.example terraform.tfvars

# Edit with your specific values
nano terraform.tfvars
```

### 2. Validate and Deploy

```bash
# Run validation script (recommended)
./validate.sh

# Or manually:
terraform init
terraform plan
terraform apply
```

### 3. Configure kubectl

```bash
# Update kubeconfig
aws eks update-kubeconfig --region us-west-2 --name hackai-production

# Verify connection
kubectl get nodes
```

## Environment-Specific Deployment

### Development Environment
```bash
terraform plan -var-file="environments/development.tfvars"
terraform apply -var-file="environments/development.tfvars"
```

### Staging Environment
```bash
terraform plan -var-file="environments/staging.tfvars"
terraform apply -var-file="environments/staging.tfvars"
```

### Production Environment
```bash
terraform plan -var-file="environments/production.tfvars"
terraform apply -var-file="environments/production.tfvars"
```

## Infrastructure Components

### Core Infrastructure
- **VPC**: Multi-AZ setup with public/private subnets
- **EKS Cluster**: Managed Kubernetes with auto-scaling
- **RDS**: PostgreSQL with Multi-AZ and encryption
- **ElastiCache**: Redis cluster with replication
- **ALB**: Application Load Balancer with SSL termination

### Security Features
- **Encryption**: All data encrypted at rest and in transit
- **Network Security**: Security groups, NACLs, VPC Flow Logs
- **IAM**: Least privilege access policies
- **Monitoring**: CloudWatch, GuardDuty, Config

### Storage
- **S3**: Object storage for application data and logs
- **EBS**: Persistent volumes for Kubernetes

## Configuration Variables

### Required Variables
```hcl
aws_region  = "us-west-2"
environment = "production"
domain_name = "hackai.com"
```

### Optional Variables
```hcl
# Database
db_instance_class = "db.t3.small"
redis_node_type   = "cache.t3.micro"

# EKS Node Groups
node_group_min_size     = 2
node_group_max_size     = 10
node_group_desired_size = 3

# Security
enable_encryption = true
manage_dns       = false
```

## Outputs

After deployment, Terraform provides important outputs:

```bash
# View all outputs
terraform output

# Specific outputs
terraform output cluster_endpoint
terraform output database_endpoint
terraform output load_balancer_dns_name
```

## State Management

### Remote State (Recommended)
The configuration uses S3 backend for state storage:

```hcl
backend "s3" {
  bucket         = "hackai-terraform-state"
  key            = "infrastructure/terraform.tfstate"
  region         = "us-west-2"
  encrypt        = true
  dynamodb_table = "hackai-terraform-locks"
}
```

### Setup Remote State
```bash
# Create S3 bucket for state
aws s3 mb s3://hackai-terraform-state

# Create DynamoDB table for locking
aws dynamodb create-table \
  --table-name hackai-terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5
```

## Security Best Practices

### 1. Secrets Management
- Never commit secrets to version control
- Use AWS Secrets Manager or Parameter Store
- Rotate credentials regularly

### 2. Access Control
- Use IAM roles instead of access keys
- Implement least privilege principle
- Enable MFA for sensitive operations

### 3. Network Security
- Use private subnets for databases
- Implement security groups with minimal access
- Enable VPC Flow Logs

## Monitoring and Alerting

### CloudWatch Dashboards
- Infrastructure metrics
- Application performance
- Cost monitoring

### Alerts
- High CPU/Memory usage
- Database connection issues
- Security events

## Cost Optimization

### Development Environment
- Use smaller instance types
- Enable spot instances
- Disable expensive features

### Production Environment
- Use Reserved Instances for predictable workloads
- Implement auto-scaling
- Monitor costs with AWS Cost Explorer

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   # Check AWS credentials
   aws sts get-caller-identity
   
   # Verify IAM permissions
   aws iam get-user
   ```

2. **State Lock Issues**
   ```bash
   # Force unlock (use carefully)
   terraform force-unlock <LOCK_ID>
   ```

3. **Resource Conflicts**
   ```bash
   # Import existing resources
   terraform import aws_instance.example i-1234567890abcdef0
   ```

### Validation Script
Use the provided validation script to check configuration:

```bash
./validate.sh
```

## Cleanup

### Destroy Infrastructure
```bash
# Development
terraform destroy -var-file="environments/development.tfvars"

# Staging
terraform destroy -var-file="environments/staging.tfvars"

# Production (be very careful!)
terraform destroy -var-file="environments/production.tfvars"
```

### Manual Cleanup
Some resources may need manual cleanup:
- S3 buckets with objects
- EBS snapshots
- CloudWatch logs

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review AWS CloudTrail logs
3. Contact the DevOps team

## References

- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [EKS Module Documentation](https://registry.terraform.io/modules/terraform-aws-modules/eks/aws/latest)
- [VPC Module Documentation](https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/latest)
- [AWS EKS Best Practices](https://aws.github.io/aws-eks-best-practices/)
