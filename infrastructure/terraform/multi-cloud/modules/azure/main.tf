# Azure Infrastructure Module for HackAI Multi-Cloud

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

# Local values
locals {
  name = "${var.project_name}-${var.environment}"

  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Owner       = var.owner
  }
}

# Resource Group
resource "azurerm_resource_group" "main" {
  name     = "${local.name}-rg"
  location = var.azure_location

  tags = local.tags
}

# Virtual Network
resource "azurerm_virtual_network" "main" {
  name                = "${local.name}-vnet"
  address_space       = [var.azure_vnet_cidr]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = local.tags
}

# Subnet for AKS
resource "azurerm_subnet" "aks" {
  name                 = "${local.name}-aks-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(var.azure_vnet_cidr, 8, 1)]
}

# Network Security Group
resource "azurerm_network_security_group" "aks" {
  name                = "${local.name}-aks-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

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
    name                       = "AllowHTTP"
    priority                   = 1002
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = local.tags
}

# Associate Network Security Group to Subnet
resource "azurerm_subnet_network_security_group_association" "aks" {
  subnet_id                 = azurerm_subnet.aks.id
  network_security_group_id = azurerm_network_security_group.aks.id
}

# AKS Cluster
resource "azurerm_kubernetes_cluster" "main" {
  name                = "${local.name}-aks"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = "${local.name}-aks"
  kubernetes_version  = var.cluster_version

  default_node_pool {
    name           = "default"
    node_count     = var.node_pool_node_count
    vm_size        = var.node_pool_vm_size
    vnet_subnet_id = azurerm_subnet.aks.id

    enable_auto_scaling = true
    min_count           = var.node_pool_min_count
    max_count           = var.node_pool_max_count

    upgrade_settings {
      max_surge = "10%"
    }
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin    = "azure"
    load_balancer_sku = "standard"
  }

  # Enable monitoring
  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  }

  tags = local.tags
}

# Log Analytics Workspace for monitoring
resource "azurerm_log_analytics_workspace" "main" {
  name                = "${local.name}-logs"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = local.tags
}

# PostgreSQL Flexible Server
resource "random_password" "db_password" {
  length  = 16
  special = true
}

resource "azurerm_postgresql_flexible_server" "main" {
  name                   = "${local.name}-postgres"
  resource_group_name    = azurerm_resource_group.main.name
  location               = azurerm_resource_group.main.location
  version                = "15"
  administrator_login    = "hackai"
  administrator_password = random_password.db_password.result
  zone                   = "1"

  storage_mb = 32768

  sku_name = var.db_sku_name

  backup_retention_days        = var.enable_backup ? var.backup_retention_days : 7
  geo_redundant_backup_enabled = var.enable_backup

  tags = local.tags
}

# PostgreSQL Database
resource "azurerm_postgresql_flexible_server_database" "main" {
  name      = "hackai"
  server_id = azurerm_postgresql_flexible_server.main.id
  collation = "en_US.utf8"
  charset   = "utf8"
}

# Redis Cache
resource "azurerm_redis_cache" "main" {
  name                 = "${local.name}-redis"
  location             = azurerm_resource_group.main.location
  resource_group_name  = azurerm_resource_group.main.name
  capacity             = 0
  family               = "C"
  sku_name             = var.redis_sku_name
  non_ssl_port_enabled = false
  minimum_tls_version  = "1.2"

  redis_configuration {
    authentication_enabled = true
  }

  tags = local.tags
}

# Storage Account
resource "random_id" "storage_suffix" {
  byte_length = 4
}

resource "azurerm_storage_account" "main" {
  name                     = "${replace(local.name, "-", "")}${random_id.storage_suffix.hex}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  blob_properties {
    versioning_enabled = true
  }

  tags = local.tags
}

# Storage Container
resource "azurerm_storage_container" "app_data" {
  name                  = "app-data"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "private"
}

# Key Vault for secrets
resource "azurerm_key_vault" "main" {
  name                = "${local.name}-kv-${random_id.storage_suffix.hex}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
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

  tags = local.tags
}

# Store database password in Key Vault
resource "azurerm_key_vault_secret" "db_password" {
  name         = "database-password"
  value        = random_password.db_password.result
  key_vault_id = azurerm_key_vault.main.id
}

# Data sources
data "azurerm_client_config" "current" {}

# Public IP for Load Balancer
resource "azurerm_public_ip" "main" {
  name                = "${local.name}-lb-ip"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = local.tags
}
