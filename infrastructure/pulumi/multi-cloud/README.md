# HackAI Multi-Cloud Infrastructure

This directory contains Pulumi infrastructure code for deploying HackAI across multiple cloud providers (AWS, GCP, and Azure).

## Current Status

The infrastructure code is currently in a simplified state due to missing cloud provider dependencies. The core Pulumi SDK is available and working, but the cloud-specific providers need to be added when network connectivity allows.

## Prerequisites

- [Pulumi CLI](https://www.pulumi.com/docs/get-started/install/)
- [Go](https://golang.org/dl/) (version 1.23+)
- Cloud provider CLI tools (when dependencies are available):
  - AWS CLI
  - GCP CLI (gcloud)
  - Azure CLI (az)

## Configuration

The infrastructure is configured through the `Pulumi.yaml` file and supports the following configuration options:

- `projectName`: Name of the project (default: "hackai")
- `environment`: Environment name (default: "production")
- `enableAWS`: Enable AWS deployment (default: false)
- `enableGCP`: Enable GCP deployment (default: false)
- `enableAzure`: Enable Azure deployment (default: false)
- `primaryCloud`: Primary cloud provider (default: "aws")
- `awsRegion`: AWS region (default: "us-west-2")
- `gcpRegion`: GCP region (default: "us-central1")
- `azureLocation`: Azure location (default: "East US")
- `kubernetesVersion`: Kubernetes version (default: "1.28")

## Usage

### 1. Initialize Pulumi Project

```bash
cd infrastructure/pulumi/multi-cloud
pulumi stack init dev
```

### 2. Set Configuration

```bash
pulumi config set projectName hackai
pulumi config set environment development
pulumi config set enableAWS true
pulumi config set awsRegion us-east-1
```

### 3. Deploy Infrastructure

```bash
pulumi up
```

### 4. View Outputs

```bash
pulumi stack output
```

## TODO: Missing Dependencies

The following cloud provider dependencies need to be added when network connectivity is available:

```bash
go get github.com/pulumi/pulumi-aws/sdk/v6@latest
go get github.com/pulumi/pulumi-gcp/sdk/v7@latest
go get github.com/pulumi/pulumi-azure-native-sdk@latest
```

Once dependencies are added, uncomment the cloud-specific infrastructure code in `main.go`.

## Architecture

When fully implemented, this infrastructure will provision:


### AWS Components
- VPC with public/private subnets
- EKS cluster with managed node groups
- RDS database instance
- Security groups and IAM roles


### GCP Components
- VPC network with subnets
- GKE cluster with node pools
- Cloud SQL instance
- Service accounts and IAM policies


### Azure Components
- Resource group and VNet
- AKS cluster with node pools  
- Azure Database for PostgreSQL
- Network security groups and managed identities


## Security

All infrastructure follows security best practices:
- Private subnets for databases
- Least privilege IAM policies
- Network security groups/firewalls
- Encrypted storage and transit
- Regular security updates


## Monitoring

The infrastructure includes:
- CloudWatch/Stackdriver/Azure Monitor integration
- Centralized logging
- Performance metrics
- Health checks
- Alerting and notifications
