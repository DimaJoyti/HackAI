# Cross-Cloud Monitoring Module
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

# AWS CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "app_logs" {
  count             = var.enable_aws ? 1 : 0
  name              = "/aws/eks/${var.project_name}-${var.environment}"
  retention_in_days = var.log_retention_days

  tags = var.common_tags
}

resource "aws_cloudwatch_log_group" "security_logs" {
  count             = var.enable_aws ? 1 : 0
  name              = "/aws/security/${var.project_name}-${var.environment}"
  retention_in_days = var.log_retention_days

  tags = var.common_tags
}

# AWS CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  count               = var.enable_aws ? 1 : 0
  alarm_name          = "${var.project_name}-${var.environment}-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EKS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors EKS CPU utilization"
  alarm_actions       = var.sns_topic_arn != null ? [var.sns_topic_arn] : []

  tags = var.common_tags
}

# GCP Monitoring - Log Sinks
resource "google_logging_project_sink" "app_logs" {
  count       = var.enable_gcp ? 1 : 0
  name        = "${var.project_name}-${var.environment}-app-logs"
  destination = "storage.googleapis.com/${google_storage_bucket.logs[0].name}"
  filter      = "resource.type=\"gke_container\" AND resource.labels.cluster_name=\"${var.gke_cluster_name}\""
  project     = var.gcp_project_id

  unique_writer_identity = true
}

resource "google_storage_bucket" "logs" {
  count    = var.enable_gcp ? 1 : 0
  name     = "${var.project_name}-${var.environment}-logs-${random_id.bucket_suffix[0].hex}"
  location = var.gcp_region
  project  = var.gcp_project_id

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "Delete"
    }
  }
}

resource "random_id" "bucket_suffix" {
  count       = var.enable_gcp ? 1 : 0
  byte_length = 8
}

# GCP Monitoring Alerts
resource "google_monitoring_alert_policy" "high_cpu" {
  count        = var.enable_gcp ? 1 : 0
  display_name = "${var.project_name}-${var.environment}-high-cpu"
  project      = var.gcp_project_id

  conditions {
    display_name = "GKE CPU usage"
    condition_threshold {
      filter          = "resource.type=\"gke_container\""
      duration        = "300s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 0.8

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  combiner = "OR"
  enabled  = true
}

# Azure Monitor - Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "main" {
  count               = var.enable_azure ? 1 : 0
  name                = "${var.project_name}-${var.environment}-logs"
  location            = var.azure_location
  resource_group_name = var.azure_resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days

  tags = var.common_tags
}

# Azure Monitor - Application Insights
resource "azurerm_application_insights" "main" {
  count               = var.enable_azure ? 1 : 0
  name                = "${var.project_name}-${var.environment}-insights"
  location            = var.azure_location
  resource_group_name = var.azure_resource_group_name
  workspace_id        = azurerm_log_analytics_workspace.main[0].id
  application_type    = "web"

  tags = var.common_tags
}

# Azure Monitor - Metric Alerts
resource "azurerm_monitor_metric_alert" "high_cpu" {
  count               = var.enable_azure ? 1 : 0
  name                = "${var.project_name}-${var.environment}-high-cpu"
  resource_group_name = var.azure_resource_group_name
  scopes              = [var.aks_cluster_id]
  description         = "Alert when CPU usage is high"

  criteria {
    metric_namespace = "Microsoft.ContainerService/managedClusters"
    metric_name      = "node_cpu_usage_percentage"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 80
  }

  frequency   = "PT5M"
  window_size = "PT5M"
  severity    = 2

  tags = var.common_tags
}

# Variables
variable "enable_aws" {
  description = "Enable AWS monitoring"
  type        = bool
  default     = false
}

variable "enable_gcp" {
  description = "Enable GCP monitoring"
  type        = bool
  default     = false
}

variable "enable_azure" {
  description = "Enable Azure monitoring"
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

variable "log_retention_days" {
  description = "Log retention period in days"
  type        = number
  default     = 30
}

variable "gcp_project_id" {
  description = "GCP project ID"
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

variable "aks_cluster_id" {
  description = "AKS cluster resource ID"
  type        = string
  default     = ""
}

variable "sns_topic_arn" {
  description = "SNS topic ARN for AWS alerts"
  type        = string
  default     = null
}

variable "common_tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}

# Outputs
output "aws_log_group_names" {
  description = "AWS CloudWatch log group names"
  value = var.enable_aws ? {
    app_logs      = aws_cloudwatch_log_group.app_logs[0].name
    security_logs = aws_cloudwatch_log_group.security_logs[0].name
  } : {}
}

output "gcp_log_sink_name" {
  description = "GCP log sink name"
  value       = var.enable_gcp ? google_logging_project_sink.app_logs[0].name : null
}

output "azure_workspace_id" {
  description = "Azure Log Analytics workspace ID"
  value       = var.enable_azure ? azurerm_log_analytics_workspace.main[0].workspace_id : null
}

output "azure_insights_instrumentation_key" {
  description = "Application Insights instrumentation key"
  value       = var.enable_azure ? azurerm_application_insights.main[0].instrumentation_key : null
  sensitive   = true
}
