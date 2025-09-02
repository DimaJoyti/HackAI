# Azure Functions Module
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

# Storage Account for Azure Functions
resource "azurerm_storage_account" "functions" {
  count                    = var.enable_azure_functions ? 1 : 0
  name                     = "${var.project_name}${var.environment}funcsa"
  resource_group_name      = var.resource_group_name
  location                 = var.azure_location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = var.common_tags
}

# App Service Plan for Azure Functions
resource "azurerm_service_plan" "functions" {
  count               = var.enable_azure_functions ? 1 : 0
  name                = "${var.project_name}-${var.environment}-functions-plan"
  resource_group_name = var.resource_group_name
  location            = var.azure_location
  os_type             = "Linux"
  sku_name            = "Y1"

  tags = var.common_tags
}

# Application Insights for Functions
resource "azurerm_application_insights" "functions" {
  count               = var.enable_azure_functions ? 1 : 0
  name                = "${var.project_name}-${var.environment}-functions-insights"
  location            = var.azure_location
  resource_group_name = var.resource_group_name
  application_type    = "web"

  tags = var.common_tags
}

# Auto Scaler Function App
resource "azurerm_linux_function_app" "auto_scaler" {
  count               = var.enable_azure_functions ? 1 : 0
  name                = "${var.project_name}-${var.environment}-auto-scaler"
  resource_group_name = var.resource_group_name
  location            = var.azure_location

  storage_account_name       = azurerm_storage_account.functions[0].name
  storage_account_access_key = azurerm_storage_account.functions[0].primary_access_key
  service_plan_id            = azurerm_service_plan.functions[0].id

  site_config {
    application_stack {
      node_version = "18"
    }
  }

  app_settings = {
    "FUNCTIONS_WORKER_RUNTIME"       = "custom"
    "APPINSIGHTS_INSTRUMENTATIONKEY" = azurerm_application_insights.functions[0].instrumentation_key
    "ENVIRONMENT"                    = var.environment
    "PROJECT"                        = var.project_name
  }

  tags = var.common_tags
}

# Security Scanner Function App
resource "azurerm_linux_function_app" "security_scanner" {
  count               = var.enable_azure_functions ? 1 : 0
  name                = "${var.project_name}-${var.environment}-security-scanner"
  resource_group_name = var.resource_group_name
  location            = var.azure_location

  storage_account_name       = azurerm_storage_account.functions[0].name
  storage_account_access_key = azurerm_storage_account.functions[0].primary_access_key
  service_plan_id            = azurerm_service_plan.functions[0].id

  site_config {
    application_stack {
      node_version = "18"
    }
  }

  app_settings = {
    "FUNCTIONS_WORKER_RUNTIME"       = "custom"
    "APPINSIGHTS_INSTRUMENTATIONKEY" = azurerm_application_insights.functions[0].instrumentation_key
    "ENVIRONMENT"                    = var.environment
    "PROJECT"                        = var.project_name
  }

  tags = var.common_tags
}

# Logic App for Auto Scaler Scheduling
resource "azurerm_logic_app_workflow" "auto_scaler_schedule" {
  count               = var.enable_azure_functions ? 1 : 0
  name                = "${var.project_name}-${var.environment}-auto-scaler-schedule"
  location            = var.azure_location
  resource_group_name = var.resource_group_name

  workflow_schema     = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#"
  workflow_version    = "1.0.0.0"
  workflow_parameters = {}

  tags = var.common_tags
}

# Logic App for Security Scanner Scheduling
resource "azurerm_logic_app_workflow" "security_scanner_schedule" {
  count               = var.enable_azure_functions ? 1 : 0
  name                = "${var.project_name}-${var.environment}-security-scanner-schedule"
  location            = var.azure_location
  resource_group_name = var.resource_group_name

  workflow_schema     = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#"
  workflow_version    = "1.0.0.0"
  workflow_parameters = {}

  tags = var.common_tags
}

# Variables
variable "enable_azure_functions" {
  description = "Enable Azure Functions"
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

variable "resource_group_name" {
  description = "Azure resource group name"
  type        = string
}

variable "common_tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}

# Outputs
output "auto_scaler_function_app_name" {
  description = "Auto scaler function app name"
  value       = var.enable_azure_functions ? azurerm_linux_function_app.auto_scaler[0].name : null
}

output "auto_scaler_function_app_url" {
  description = "Auto scaler function app URL"
  value       = var.enable_azure_functions ? azurerm_linux_function_app.auto_scaler[0].default_hostname : null
}

output "security_scanner_function_app_name" {
  description = "Security scanner function app name"
  value       = var.enable_azure_functions ? azurerm_linux_function_app.security_scanner[0].name : null
}

output "security_scanner_function_app_url" {
  description = "Security scanner function app URL"
  value       = var.enable_azure_functions ? azurerm_linux_function_app.security_scanner[0].default_hostname : null
}

output "storage_account_name" {
  description = "Storage account name for functions"
  value       = var.enable_azure_functions ? azurerm_storage_account.functions[0].name : null
}
