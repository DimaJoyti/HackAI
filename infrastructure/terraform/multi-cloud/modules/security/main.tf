# Cross-Cloud Security Module for HackAI Multi-Cloud

terraform {
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
  }
}

# Local values
locals {
  name = "${var.project_name}-${var.environment}"
  
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Owner       = var.owner
    Module      = "security"
  }
}

# AWS Security Group for additional security rules
resource "aws_security_group" "additional" {
  count       = var.enable_aws ? 1 : 0
  name_prefix = "${local.name}-additional-"
  description = "Additional security group for ${local.name}"
  vpc_id      = var.aws_vpc_id

  # Allow HTTPS outbound
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow HTTP outbound
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name}-additional-sg"
  })
}

# AWS KMS Key for encryption
resource "aws_kms_key" "main" {
  count       = var.enable_aws ? 1 : 0
  description = "KMS key for ${local.name}"

  tags = local.common_tags
}

resource "aws_kms_alias" "main" {
  count         = var.enable_aws ? 1 : 0
  name          = "alias/${local.name}-key"
  target_key_id = aws_kms_key.main[0].key_id
}

# AWS IAM Role for security scanning
resource "aws_iam_role" "security_scanner" {
  count = var.enable_aws ? 1 : 0
  name  = "${local.name}-security-scanner"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# GCP Firewall Rules
resource "google_compute_firewall" "deny_all" {
  count   = var.enable_gcp ? 1 : 0
  name    = "${local.name}-deny-all"
  network = var.gcp_network_name

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
  priority      = 65534

  description = "Deny all traffic by default"
}

resource "google_compute_firewall" "allow_internal" {
  count   = var.enable_gcp ? 1 : 0
  name    = "${local.name}-allow-internal"
  network = var.gcp_network_name

  allow {
    protocol = "tcp"
    ports    = ["22", "80", "443"]
  }

  source_ranges = [var.gcp_vpc_cidr]
  priority      = 1000

  description = "Allow internal traffic"
}

# GCP Service Account for security
resource "google_service_account" "security" {
  count        = var.enable_gcp ? 1 : 0
  account_id   = "${local.name}-security"
  display_name = "Security Service Account for ${local.name}"
  description  = "Service account for security operations"
}

# GCP KMS Key Ring and Key
resource "google_kms_key_ring" "security" {
  count    = var.enable_gcp ? 1 : 0
  name     = "${local.name}-security"
  location = var.gcp_region
}

resource "google_kms_crypto_key" "security" {
  count    = var.enable_gcp ? 1 : 0
  name     = "${local.name}-security-key"
  key_ring = google_kms_key_ring.security[0].id

  lifecycle {
    prevent_destroy = true
  }
}

# Azure Network Security Group
resource "azurerm_network_security_group" "main" {
  count               = var.enable_azure ? 1 : 0
  name                = "${local.name}-security-nsg"
  location            = var.azure_location
  resource_group_name = var.azure_resource_group_name

  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "DenyAll"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = local.common_tags
}

# Azure Managed Identity
resource "azurerm_user_assigned_identity" "main" {
  count               = var.enable_azure ? 1 : 0
  name                = "${local.name}-identity"
  location            = var.azure_location
  resource_group_name = var.azure_resource_group_name

  tags = local.common_tags
}

# Azure Key Vault (if not already created by main module)
resource "azurerm_key_vault" "security" {
  count               = var.enable_azure && var.create_key_vault ? 1 : 0
  name                = "${local.name}-sec-kv-${random_id.kv_suffix[0].hex}"
  location            = var.azure_location
  resource_group_name = var.azure_resource_group_name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    key_permissions = [
      "Get", "List", "Create", "Delete", "Update", "Recover", "Purge"
    ]

    secret_permissions = [
      "Get", "List", "Set", "Delete", "Recover", "Purge"
    ]
  }

  tags = local.common_tags
}

resource "random_id" "kv_suffix" {
  count       = var.enable_azure && var.create_key_vault ? 1 : 0
  byte_length = 4
}

# Data sources
data "azurerm_client_config" "current" {}
