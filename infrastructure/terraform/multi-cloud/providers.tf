# Multi-Cloud Provider Configuration for HackAI
# Supports AWS, GCP, and Azure deployments

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.9.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.10"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # Use local backend for development
  # For production, uncomment and configure S3 backend
  # backend "s3" {
  #   bucket         = "hackai-terraform-state-multi-cloud"
  #   key            = "multi-cloud/terraform.tfstate"
  #   region         = "us-west-2"
  #   encrypt        = true
  #   use_lockfile   = true
  # }
}

# AWS Provider Configuration
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project       = "HackAI"
      Environment   = var.environment
      ManagedBy     = "Terraform"
      Owner         = "HackAI-Team"
      CloudProvider = "AWS"
    }
  }
}

# Google Cloud Provider Configuration
provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
  zone    = var.gcp_zone
}

# Azure Provider Configuration
provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
  }

  subscription_id = var.azure_subscription_id
}

# Kubernetes Provider for AWS EKS
provider "kubernetes" {
  alias = "aws"

  # Use data sources to avoid circular dependencies
  host                   = try(data.aws_eks_cluster.cluster[0].endpoint, "")
  cluster_ca_certificate = try(base64decode(data.aws_eks_cluster.cluster[0].certificate_authority[0].data), "")

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", try(data.aws_eks_cluster.cluster[0].name, "")]
  }
}

# Kubernetes Provider for GKE
provider "kubernetes" {
  alias = "gcp"

  # Use data sources to avoid circular dependencies
  host                   = try("https://${data.google_container_cluster.primary[0].endpoint}", "")
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = try(base64decode(data.google_container_cluster.primary[0].master_auth[0].cluster_ca_certificate), "")
}

# Kubernetes Provider for AKS
provider "kubernetes" {
  alias = "azure"

  # Use data sources to avoid circular dependencies
  host                   = try(data.azurerm_kubernetes_cluster.main[0].kube_config[0].host, "")
  client_certificate     = try(base64decode(data.azurerm_kubernetes_cluster.main[0].kube_config[0].client_certificate), "")
  client_key             = try(base64decode(data.azurerm_kubernetes_cluster.main[0].kube_config[0].client_key), "")
  cluster_ca_certificate = try(base64decode(data.azurerm_kubernetes_cluster.main[0].kube_config[0].cluster_ca_certificate), "")
}

# Helm Provider for AWS
provider "helm" {
  alias = "aws"
  kubernetes {
    host                   = try(data.aws_eks_cluster.cluster[0].endpoint, "")
    cluster_ca_certificate = try(base64decode(data.aws_eks_cluster.cluster[0].certificate_authority[0].data), "")
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", try(data.aws_eks_cluster.cluster[0].name, "")]
    }
  }
}

# Helm Provider for GCP
provider "helm" {
  alias = "gcp"
  kubernetes {
    host                   = try("https://${data.google_container_cluster.primary[0].endpoint}", "")
    token                  = data.google_client_config.default.access_token
    cluster_ca_certificate = try(base64decode(data.google_container_cluster.primary[0].master_auth[0].cluster_ca_certificate), "")
  }
}

# Helm Provider for Azure
provider "helm" {
  alias = "azure"

  kubernetes {
    host                   = try(data.azurerm_kubernetes_cluster.main[0].kube_config[0].host, "")
    client_certificate     = try(base64decode(data.azurerm_kubernetes_cluster.main[0].kube_config[0].client_certificate), "")
    client_key             = try(base64decode(data.azurerm_kubernetes_cluster.main[0].kube_config[0].client_key), "")
    cluster_ca_certificate = try(base64decode(data.azurerm_kubernetes_cluster.main[0].kube_config[0].cluster_ca_certificate), "")
  }
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {}
data "google_client_config" "default" {}
data "azurerm_client_config" "current" {}

# Conditional data sources for Kubernetes clusters
data "aws_eks_cluster" "cluster" {
  count = var.enable_aws_eks ? 1 : 0
  name  = "${local.name_prefix}-eks"
}

data "google_container_cluster" "primary" {
  count    = var.enable_gcp_gke ? 1 : 0
  name     = "${local.name_prefix}-gke"
  location = var.gcp_region
  project  = var.gcp_project_id
}

data "azurerm_kubernetes_cluster" "main" {
  count               = var.enable_azure_aks ? 1 : 0
  name                = "${local.name_prefix}-aks"
  resource_group_name = "${local.name_prefix}-rg"
}

# Local values for consistent naming
locals {
  name_prefix = "${var.project_name}-${var.environment}"

  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Owner       = var.owner
  }

  aws_tags = merge(local.common_tags, {
    CloudProvider = "AWS"
  })

  gcp_labels = {
    project        = lower(var.project_name)
    environment    = var.environment
    managed-by     = "terraform"
    owner          = lower(var.owner)
    cloud-provider = "gcp"
  }

  azure_tags = merge(local.common_tags, {
    CloudProvider = "Azure"
  })
}
