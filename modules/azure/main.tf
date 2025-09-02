# Azure Infrastructure Module
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

# Resource Group
resource "azurerm_resource_group" "main" {
  count    = var.enable_azure ? 1 : 0
  name     = "${var.project_name}-${var.environment}-rg"
  location = var.azure_location

  tags = var.common_tags
}

# Virtual Network
resource "azurerm_virtual_network" "main" {
  count               = var.enable_azure ? 1 : 0
  name                = "${var.project_name}-${var.environment}-vnet"
  address_space       = ["10.1.0.0/16"]
  location            = azurerm_resource_group.main[0].location
  resource_group_name = azurerm_resource_group.main[0].name

  tags = var.common_tags
}

# Subnet for AKS
resource "azurerm_subnet" "aks" {
  count                = var.enable_azure ? 1 : 0
  name                 = "${var.project_name}-${var.environment}-aks-subnet"
  resource_group_name  = azurerm_resource_group.main[0].name
  virtual_network_name = azurerm_virtual_network.main[0].name
  address_prefixes     = ["10.1.1.0/24"]
}

# AKS Cluster
resource "azurerm_kubernetes_cluster" "main" {
  count               = var.enable_azure ? 1 : 0
  name                = "${var.project_name}-${var.environment}-aks"
  location            = azurerm_resource_group.main[0].location
  resource_group_name = azurerm_resource_group.main[0].name
  dns_prefix          = "${var.project_name}-${var.environment}"

  default_node_pool {
    name       = "default"
    node_count = var.azure_node_pool_node_count
    vm_size    = var.azure_node_pool_vm_size
    vnet_subnet_id = azurerm_subnet.aks[0].id
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin = "azure"
    service_cidr   = "10.1.2.0/24"
    dns_service_ip = "10.1.2.10"
  }

  tags = var.common_tags
}

# PostgreSQL Database
resource "azurerm_postgresql_flexible_server" "main" {
  count               = var.enable_azure ? 1 : 0
  name                = "${var.project_name}-${var.environment}-postgres"
  resource_group_name = azurerm_resource_group.main[0].name
  location            = azurerm_resource_group.main[0].location
  version             = "13"
  
  administrator_login    = var.azure_db_admin_username
  administrator_password = var.azure_db_admin_password
  
  sku_name = var.azure_db_sku_name
  storage_mb = 32768

  tags = var.common_tags
}

# Redis Cache
resource "azurerm_redis_cache" "main" {
  count               = var.enable_azure ? 1 : 0
  name                = "${var.project_name}-${var.environment}-redis"
  location            = azurerm_resource_group.main[0].location
  resource_group_name = azurerm_resource_group.main[0].name
  capacity            = 0
  family              = "C"
  sku_name            = "Basic"
  non_ssl_port_enabled = false
  minimum_tls_version = "1.2"

  tags = var.common_tags
}

# Variables
variable "enable_azure" {
  description = "Enable Azure infrastructure"
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

variable "azure_location" {
  description = "Azure location"
  type        = string
  default     = "East US"
}

variable "azure_node_pool_node_count" {
  description = "Number of nodes in the AKS node pool"
  type        = number
  default     = 2
}

variable "azure_node_pool_vm_size" {
  description = "VM size for AKS nodes"
  type        = string
  default     = "Standard_D2s_v3"
}

variable "azure_db_admin_username" {
  description = "PostgreSQL admin username"
  type        = string
  default     = "hackai_admin"
}

variable "azure_db_admin_password" {
  description = "PostgreSQL admin password"
  type        = string
  sensitive   = true
}

variable "azure_db_sku_name" {
  description = "PostgreSQL SKU name"
  type        = string
  default     = "B_Standard_B1ms"
}

variable "common_tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}

# Outputs
output "resource_group_name" {
  description = "Name of the resource group"
  value       = var.enable_azure ? azurerm_resource_group.main[0].name : null
}

output "cluster_name" {
  description = "Name of the AKS cluster"
  value       = var.enable_azure ? azurerm_kubernetes_cluster.main[0].name : null
}

output "cluster_endpoint" {
  description = "Endpoint for the AKS cluster"
  value       = var.enable_azure ? azurerm_kubernetes_cluster.main[0].kube_config[0].host : null
}

output "database_endpoint" {
  description = "PostgreSQL database endpoint"
  value       = var.enable_azure ? azurerm_postgresql_flexible_server.main[0].fqdn : null
}

output "redis_endpoint" {
  description = "Redis cache endpoint"
  value       = var.enable_azure ? azurerm_redis_cache.main[0].hostname : null
}
