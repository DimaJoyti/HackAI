# Cross-Cloud Security Module
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.9.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

# AWS Security Hub
resource "aws_securityhub_account" "main" {
  count                    = var.enable_aws ? 1 : 0
  enable_default_standards = true
}

# AWS GuardDuty
resource "aws_guardduty_detector" "main" {
  count  = var.enable_aws ? 1 : 0
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = var.common_tags
}

# AWS Inspector V2
resource "aws_inspector2_enabler" "main" {
  count           = var.enable_aws ? 1 : 0
  account_ids     = [data.aws_caller_identity.current[0].account_id]
  resource_types  = ["ECR", "EC2"]
}

data "aws_caller_identity" "current" {
  count = var.enable_aws ? 1 : 0
}

# AWS Config
resource "aws_config_configuration_recorder" "main" {
  count    = var.enable_aws ? 1 : 0
  name     = "${var.project_name}-${var.environment}-config"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

  depends_on = [aws_config_delivery_channel.main]
}

resource "aws_config_delivery_channel" "main" {
  count          = var.enable_aws ? 1 : 0
  name           = "${var.project_name}-${var.environment}-config"
  s3_bucket_name = aws_s3_bucket.config[0].bucket
}

resource "aws_s3_bucket" "config" {
  count         = var.enable_aws ? 1 : 0
  bucket        = "${var.project_name}-${var.environment}-config-${random_id.bucket_suffix[0].hex}"
  force_destroy = true

  tags = var.common_tags
}

resource "random_id" "bucket_suffix" {
  count       = var.enable_aws ? 1 : 0
  byte_length = 8
}

resource "aws_iam_role" "config" {
  count = var.enable_aws ? 1 : 0
  name  = "${var.project_name}-${var.environment}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  tags = var.common_tags
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_aws ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

# GCP Security Command Center
resource "google_security_center_notification_config" "main" {
  count           = var.enable_gcp ? 1 : 0
  config_id       = "${var.project_name}-${var.environment}-scc"
  organization    = var.gcp_organization_id
  description     = "Security Command Center notifications"
  pubsub_topic    = google_pubsub_topic.security[0].id
  streaming_config {
    filter = "state=\"ACTIVE\""
  }
}

resource "google_pubsub_topic" "security" {
  count   = var.enable_gcp ? 1 : 0
  name    = "${var.project_name}-${var.environment}-security"
  project = var.gcp_project_id
}

# GCP Binary Authorization
resource "google_binary_authorization_policy" "main" {
  count   = var.enable_gcp ? 1 : 0
  project = var.gcp_project_id

  default_admission_rule {
    evaluation_mode  = "REQUIRE_ATTESTATION"
    enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"
    require_attestations_by = [
      google_binary_authorization_attestor.main[0].name
    ]
  }

  cluster_admission_rules {
    cluster                = "${var.gcp_region}.${var.gke_cluster_name}"
    evaluation_mode        = "REQUIRE_ATTESTATION"
    enforcement_mode       = "ENFORCED_BLOCK_AND_AUDIT_LOG"
    require_attestations_by = [
      google_binary_authorization_attestor.main[0].name
    ]
  }
}

resource "google_binary_authorization_attestor" "main" {
  count   = var.enable_gcp ? 1 : 0
  name    = "${var.project_name}-${var.environment}-attestor"
  project = var.gcp_project_id

  attestation_authority_note {
    note_reference = google_container_analysis_note.main[0].name
  }
}

resource "google_container_analysis_note" "main" {
  count   = var.enable_gcp ? 1 : 0
  name    = "${var.project_name}-${var.environment}-note"
  project = var.gcp_project_id

  attestation_authority {
    hint {
      human_readable_name = "HackAI Security Attestor"
    }
  }
}

# Azure Security Center
resource "azurerm_security_center_subscription_pricing" "main" {
  count         = var.enable_azure ? 1 : 0
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "containers" {
  count         = var.enable_azure ? 1 : 0
  tier          = "Standard"
  resource_type = "Containers"
}

# Azure Key Vault
resource "azurerm_key_vault" "main" {
  count                      = var.enable_azure ? 1 : 0
  name                       = "${var.project_name}-${var.environment}-kv"
  location                   = var.azure_location
  resource_group_name        = var.azure_resource_group_name
  tenant_id                  = data.azurerm_client_config.current[0].tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7

  access_policy {
    tenant_id = data.azurerm_client_config.current[0].tenant_id
    object_id = data.azurerm_client_config.current[0].object_id

    key_permissions = [
      "Create",
      "Get",
      "List",
      "Delete",
      "Update",
    ]

    secret_permissions = [
      "Set",
      "Get",
      "Delete",
      "List",
    ]
  }

  tags = var.common_tags
}

data "azurerm_client_config" "current" {
  count = var.enable_azure ? 1 : 0
}

# Variables
variable "enable_aws" {
  description = "Enable AWS security services"
  type        = bool
  default     = false
}

variable "enable_gcp" {
  description = "Enable GCP security services"
  type        = bool
  default     = false
}

variable "enable_azure" {
  description = "Enable Azure security services"
  type        = bool
  default     = false
}

variable "project_name" {
  description = "Project name"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "gcp_project_id" {
  description = "GCP project ID"
  type        = string
  default     = ""
}

variable "gcp_organization_id" {
  description = "GCP organization ID"
  type        = string
  default     = ""
}

variable "gcp_region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "gke_cluster_name" {
  description = "GKE cluster name"
  type        = string
  default     = ""
}

variable "azure_location" {
  description = "Azure location"
  type        = string
  default     = "East US"
}

variable "azure_resource_group_name" {
  description = "Azure resource group name"
  type        = string
  default     = ""
}

variable "common_tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}

# Outputs
output "aws_guardduty_detector_id" {
  description = "AWS GuardDuty detector ID"
  value       = var.enable_aws ? aws_guardduty_detector.main[0].id : null
}

output "aws_config_bucket" {
  description = "AWS Config S3 bucket name"
  value       = var.enable_aws ? aws_s3_bucket.config[0].bucket : null
}

output "gcp_security_topic" {
  description = "GCP Security Pub/Sub topic"
  value       = var.enable_gcp ? google_pubsub_topic.security[0].name : null
}

output "azure_key_vault_uri" {
  description = "Azure Key Vault URI"
  value       = var.enable_azure ? azurerm_key_vault.main[0].vault_uri : null
}
