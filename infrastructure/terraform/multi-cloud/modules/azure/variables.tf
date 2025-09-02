# Azure Module Variables

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "hackai"
}

variable "environment" {
  description = "Environment name (development, staging, production)"
  type        = string
  default     = "development"
}

variable "owner" {
  description = "Owner of the infrastructure"
  type        = string
  default     = "HackAI-Team"
}

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
variable "cluster_version" {
  description = "Kubernetes version for AKS"
  type        = string
  default     = "1.28"
}

variable "node_pool_vm_size" {
  description = "VM size for AKS node pool"
  type        = string
  default     = "Standard_D2s_v3"
}

variable "node_pool_min_count" {
  description = "Minimum node count for AKS"
  type        = number
  default     = 1
}

variable "node_pool_max_count" {
  description = "Maximum node count for AKS"
  type        = number
  default     = 5
}

variable "node_pool_node_count" {
  description = "Initial node count for AKS"
  type        = number
  default     = 2
}

variable "enable_spot_instances" {
  description = "Enable spot instances for cost optimization"
  type        = bool
  default     = false
}

variable "enable_network_policies" {
  description = "Enable Kubernetes network policies"
  type        = bool
  default     = true
}

# Database Configuration
variable "db_sku_name" {
  description = "PostgreSQL Flexible Server SKU name"
  type        = string
  default     = "B_Standard_B1ms"
}

variable "enable_backup" {
  description = "Enable backup for PostgreSQL"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Backup retention period in days"
  type        = number
  default     = 7
}

# Redis Configuration
variable "redis_sku_name" {
  description = "Redis Cache SKU name"
  type        = string
  default     = "Basic"
}

# Storage Configuration
variable "storage_account_tier" {
  description = "Storage account tier"
  type        = string
  default     = "Standard"
}

variable "storage_replication_type" {
  description = "Storage account replication type"
  type        = string
  default     = "LRS"
}

# Monitoring Configuration
variable "enable_monitoring" {
  description = "Enable monitoring and logging"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Log Analytics workspace retention in days"
  type        = number
  default     = 30
}

# Common tags
variable "tags" {
  description = "Tags for Azure resources"
  type        = map(string)
  default     = {}
}
