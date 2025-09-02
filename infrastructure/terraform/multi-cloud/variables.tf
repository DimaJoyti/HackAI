# Multi-Cloud Variables for HackAI Infrastructure

# Global Configuration
variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "hackai"
}

variable "environment" {
  description = "Environment name (development, staging, production)"
  type        = string
  default     = "production"

  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be one of: development, staging, production."
  }
}

variable "owner" {
  description = "Owner of the infrastructure"
  type        = string
  default     = "HackAI-Team"
}

# AWS Configuration
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-west-2"
}

variable "aws_availability_zones" {
  description = "AWS availability zones"
  type        = list(string)
  default     = ["us-west-2a", "us-west-2b", "us-west-2c"]
}

variable "aws_vpc_cidr" {
  description = "CIDR block for AWS VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "aws_enable_nat_gateway" {
  description = "Enable NAT Gateway for AWS VPC"
  type        = bool
  default     = true
}

variable "aws_single_nat_gateway" {
  description = "Use single NAT Gateway for cost optimization"
  type        = bool
  default     = false
}

# AWS EKS Configuration
variable "aws_cluster_version" {
  description = "Kubernetes version for AWS EKS"
  type        = string
  default     = "1.28"
}

variable "aws_node_group_instance_types" {
  description = "Instance types for AWS EKS node group"
  type        = list(string)
  default     = ["m5.large", "m5a.large", "m5d.large"]
}

variable "aws_node_group_min_size" {
  description = "Minimum size of AWS EKS node group"
  type        = number
  default     = 2
}

variable "aws_node_group_max_size" {
  description = "Maximum size of AWS EKS node group"
  type        = number
  default     = 10
}

variable "aws_node_group_desired_size" {
  description = "Desired size of AWS EKS node group"
  type        = number
  default     = 3
}

# AWS Database Configuration
variable "aws_db_instance_class" {
  description = "RDS instance class for AWS"
  type        = string
  default     = "db.t3.medium"
}

variable "aws_redis_node_type" {
  description = "ElastiCache node type for AWS"
  type        = string
  default     = "cache.t3.medium"
}

# Google Cloud Configuration
variable "gcp_project_id" {
  description = "Google Cloud project ID"
  type        = string
}

variable "gcp_region" {
  description = "Google Cloud region"
  type        = string
  default     = "us-central1"
}

variable "gcp_zone" {
  description = "Google Cloud zone"
  type        = string
  default     = "us-central1-a"
}

variable "gcp_vpc_cidr" {
  description = "CIDR block for GCP VPC"
  type        = string
  default     = "10.1.0.0/16"
}

# GKE Configuration
variable "gcp_cluster_version" {
  description = "Kubernetes version for GKE"
  type        = string
  default     = "1.28"
}

variable "gcp_node_pool_machine_type" {
  description = "Machine type for GKE node pool"
  type        = string
  default     = "e2-standard-4"
}

variable "gcp_node_pool_min_count" {
  description = "Minimum node count for GKE"
  type        = number
  default     = 1
}

variable "gcp_node_pool_max_count" {
  description = "Maximum node count for GKE"
  type        = number
  default     = 5
}

variable "gcp_node_pool_initial_count" {
  description = "Initial node count for GKE"
  type        = number
  default     = 2
}

# Azure Configuration
variable "azure_subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "azure_location" {
  description = "Azure location"
  type        = string
  default     = "East US"
}

variable "azure_vnet_cidr" {
  description = "CIDR block for Azure VNet"
  type        = string
  default     = "10.2.0.0/16"
}

# AKS Configuration
variable "azure_cluster_version" {
  description = "Kubernetes version for AKS"
  type        = string
  default     = "1.28"
}

variable "azure_node_pool_vm_size" {
  description = "VM size for AKS node pool"
  type        = string
  default     = "Standard_D2s_v3"
}

variable "azure_node_pool_min_count" {
  description = "Minimum node count for AKS"
  type        = number
  default     = 1
}

variable "azure_node_pool_max_count" {
  description = "Maximum node count for AKS"
  type        = number
  default     = 5
}

variable "azure_node_pool_node_count" {
  description = "Initial node count for AKS"
  type        = number
  default     = 2
}

# Multi-Cloud Strategy Configuration
variable "primary_cloud" {
  description = "Primary cloud provider (aws, gcp, azure)"
  type        = string
  default     = "aws"

  validation {
    condition     = contains(["aws", "gcp", "azure"], var.primary_cloud)
    error_message = "Primary cloud must be one of: aws, gcp, azure."
  }
}

variable "enable_aws" {
  description = "Enable AWS resources"
  type        = bool
  default     = true
}

variable "enable_gcp" {
  description = "Enable GCP resources"
  type        = bool
  default     = true
}

variable "enable_azure" {
  description = "Enable Azure resources"
  type        = bool
  default     = true
}

# Kubernetes Cluster Configuration
variable "enable_aws_eks" {
  description = "Enable AWS EKS cluster"
  type        = bool
  default     = true
}

variable "enable_gcp_gke" {
  description = "Enable GCP GKE cluster"
  type        = bool
  default     = true
}

variable "enable_azure_aks" {
  description = "Enable Azure AKS cluster"
  type        = bool
  default     = true
}

# Serverless Configuration
variable "enable_serverless" {
  description = "Enable serverless functions"
  type        = bool
  default     = true
}

variable "serverless_runtime" {
  description = "Runtime for serverless functions"
  type        = string
  default     = "go1.x"
}

# Monitoring Configuration
variable "enable_monitoring" {
  description = "Enable monitoring stack"
  type        = bool
  default     = true
}

variable "enable_logging" {
  description = "Enable centralized logging"
  type        = bool
  default     = true
}

# Security Configuration
variable "enable_security_scanning" {
  description = "Enable security scanning"
  type        = bool
  default     = true
}

variable "enable_network_policies" {
  description = "Enable Kubernetes network policies"
  type        = bool
  default     = true
}

# Cost Optimization
variable "enable_spot_instances" {
  description = "Enable spot instances for cost optimization"
  type        = bool
  default     = true
}

variable "enable_auto_scaling" {
  description = "Enable auto-scaling"
  type        = bool
  default     = true
}

# Domain Configuration
variable "domain_name" {
  description = "Domain name for the application"
  type        = string
  default     = "hackai.dev"
}

variable "enable_ssl" {
  description = "Enable SSL/TLS certificates"
  type        = bool
  default     = true
}

# Backup and Disaster Recovery
variable "enable_backup" {
  description = "Enable automated backups"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Backup retention period in days"
  type        = number
  default     = 30
}

variable "enable_cross_region_backup" {
  description = "Enable cross-region backup"
  type        = bool
  default     = true
}
