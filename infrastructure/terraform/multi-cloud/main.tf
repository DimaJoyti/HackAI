# Multi-Cloud Infrastructure Main Configuration for HackAI

# AWS Infrastructure Module
module "aws_infrastructure" {
  count  = var.enable_aws ? 1 : 0
  source = "./modules/aws"

  # Required arguments
  cluster_name        = "${var.project_name}-${var.environment}-eks"
  vpc_id             = "" # Will be set internally by the VPC module
  subnet_ids         = [] # Will be set internally by the VPC module
  private_subnet_ids = [] # Will be set internally by the VPC module

  # Global Configuration
  project_name = var.project_name
  environment  = var.environment

  # AWS Configuration
  kubernetes_version = var.aws_cluster_version

  # Node group configuration
  node_groups = {
    main = {
      instance_types               = var.aws_node_group_instance_types
      ami_type                    = "AL2_x86_64"
      capacity_type               = var.enable_spot_instances ? "SPOT" : "ON_DEMAND"
      disk_size                   = 50
      desired_size                = var.aws_node_group_desired_size
      max_size                    = var.aws_node_group_max_size
      min_size                    = var.aws_node_group_min_size
      max_unavailable_percentage  = 25
      enable_remote_access        = false
      ssh_key_name               = ""
      labels                     = {}
      taints                     = []
      tags                       = {}
      launch_template            = null
    }
  }

  # Database configuration
  db_password = random_password.shared_secret.result

  # Feature flags
  enable_backup     = var.enable_backup
  enable_monitoring = var.enable_monitoring

  # Tags
  tags = local.aws_tags
}

# GCP Infrastructure Module
module "gcp_infrastructure" {
  count  = var.enable_gcp ? 1 : 0
  source = "./modules/gcp"

  # Global Configuration
  project_name = var.project_name
  environment  = var.environment
  owner        = var.owner

  # GCP Configuration
  gcp_project_id = var.gcp_project_id
  gcp_region     = var.gcp_region
  gcp_zone       = var.gcp_zone
  gcp_vpc_cidr   = var.gcp_vpc_cidr

  # GKE Configuration
  cluster_version         = var.gcp_cluster_version
  node_pool_machine_type  = var.gcp_node_pool_machine_type
  node_pool_min_count     = var.gcp_node_pool_min_count
  node_pool_max_count     = var.gcp_node_pool_max_count
  node_pool_initial_count = var.gcp_node_pool_initial_count

  # Feature flags
  enable_spot_instances   = var.enable_spot_instances
  enable_network_policies = var.enable_network_policies
  enable_backup           = var.enable_backup
  backup_retention_days   = var.backup_retention_days
}

# Azure Infrastructure Module
module "azure_infrastructure" {
  count  = var.enable_azure ? 1 : 0
  source = "./modules/azure"

  # Global Configuration
  project_name = var.project_name
  environment  = var.environment
  owner        = var.owner

  # Azure Configuration
  azure_subscription_id = var.azure_subscription_id
  azure_location        = var.azure_location
  azure_vnet_cidr       = var.azure_vnet_cidr

  # AKS Configuration
  cluster_version      = var.azure_cluster_version
  node_pool_vm_size    = var.azure_node_pool_vm_size
  node_pool_min_count  = var.azure_node_pool_min_count
  node_pool_max_count  = var.azure_node_pool_max_count
  node_pool_node_count = var.azure_node_pool_node_count

  # Feature flags
  enable_spot_instances   = var.enable_spot_instances
  enable_network_policies = var.enable_network_policies
  enable_backup           = var.enable_backup
  backup_retention_days   = var.backup_retention_days
}

# Serverless Functions Module
module "serverless_functions" {
  count  = var.enable_serverless ? 1 : 0
  source = "./modules/serverless"

  # Global Configuration
  project_name = var.project_name
  environment  = var.environment
  owner        = var.owner

  # Cloud Provider Configuration
  enable_aws   = var.enable_aws
  enable_gcp   = var.enable_gcp
  enable_azure = var.enable_azure

  # Serverless Configuration
  runtime = var.serverless_runtime
}

# Cross-Cloud Monitoring Module
module "cross_cloud_monitoring" {
  count  = var.enable_monitoring ? 1 : 0
  source = "./modules/monitoring"

  # Global Configuration
  project_name = var.project_name
  environment  = var.environment
  owner        = var.owner

  # Cloud Provider Configuration
  enable_aws   = var.enable_aws
  enable_gcp   = var.enable_gcp
  enable_azure = var.enable_azure

  # AWS Configuration
  aws_region = var.aws_region

  # GCP Configuration
  gcp_project_id = var.gcp_project_id
  gcp_region     = var.gcp_region

  # Azure Configuration
  azure_location            = var.azure_location
  azure_resource_group_name = var.enable_azure ? module.azure_infrastructure[0].resource_group_name : ""

  # Monitoring Configuration
  log_retention_days = var.enable_logging ? 30 : 7
  alert_email        = var.owner
}

# Cross-Cloud Security Module
module "cross_cloud_security" {
  count  = var.enable_security_scanning ? 1 : 0
  source = "./modules/security"

  # Global Configuration
  project_name = var.project_name
  environment  = var.environment
  owner        = var.owner

  # Cloud Provider Configuration
  enable_aws   = var.enable_aws
  enable_gcp   = var.enable_gcp
  enable_azure = var.enable_azure

  # AWS Configuration
  aws_vpc_id = var.enable_aws ? module.aws_infrastructure[0].vpc_id : ""
  aws_region = var.aws_region

  # GCP Configuration
  gcp_project_id   = var.gcp_project_id
  gcp_region       = var.gcp_region
  gcp_network_name = var.enable_gcp ? module.gcp_infrastructure[0].vpc_name : ""
  gcp_vpc_cidr     = var.gcp_vpc_cidr

  # Azure Configuration
  azure_location            = var.azure_location
  azure_resource_group_name = var.enable_azure ? module.azure_infrastructure[0].resource_group_name : ""
  create_key_vault          = false # Key vault is created by the main Azure module

  # Security Configuration
  enable_encryption             = var.enable_ssl
  enable_network_policies       = var.enable_network_policies
  enable_vulnerability_scanning = var.enable_security_scanning
}

# Random password for shared secrets
resource "random_password" "shared_secret" {
  length  = 32
  special = true
}

# Store shared secrets in each cloud's secret management service
resource "aws_secretsmanager_secret" "shared_secret" {
  count = var.enable_aws ? 1 : 0
  name  = "${local.name_prefix}-shared-secret"

  tags = local.aws_tags
}

resource "aws_secretsmanager_secret_version" "shared_secret" {
  count     = var.enable_aws ? 1 : 0
  secret_id = aws_secretsmanager_secret.shared_secret[0].id
  secret_string = jsonencode({
    shared_secret = random_password.shared_secret.result
  })
}
