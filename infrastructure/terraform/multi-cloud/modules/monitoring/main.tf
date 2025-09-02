# Cross-Cloud Monitoring Module for HackAI Multi-Cloud

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
    Module      = "monitoring"
  }
}

# AWS CloudWatch Log Group
resource "aws_cloudwatch_log_group" "main" {
  count             = var.enable_aws ? 1 : 0
  name              = "/aws/hackai/${local.name}"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

# AWS CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "main" {
  count          = var.enable_aws ? 1 : 0
  dashboard_name = "${local.name}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/EKS", "cluster_failed_request_count", "ClusterName", "${local.name}-eks"],
            [".", "cluster_request_total", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "EKS Cluster Metrics"
          period  = 300
        }
      }
    ]
  })
}

# GCP Monitoring Workspace (using existing default workspace)
data "google_monitoring_notification_channel" "email" {
  count        = var.enable_gcp ? 1 : 0
  display_name = "Email Notification Channel"
  type         = "email"
}

# GCP Monitoring Dashboard
resource "google_monitoring_dashboard" "main" {
  count = var.enable_gcp ? 1 : 0

  dashboard_json = jsonencode({
    displayName = "${local.name} Dashboard"
    mosaicLayout = {
      tiles = [
        {
          width  = 6
          height = 4
          widget = {
            title = "GKE Cluster CPU Usage"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "resource.type=\"k8s_cluster\""
                      aggregation = {
                        alignmentPeriod  = "60s"
                        perSeriesAligner = "ALIGN_RATE"
                      }
                    }
                  }
                }
              ]
            }
          }
        }
      ]
    }
  })
}

# Azure Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "main" {
  count               = var.enable_azure ? 1 : 0
  name                = "${local.name}-logs"
  location            = var.azure_location
  resource_group_name = var.azure_resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days

  tags = local.common_tags
}

# Azure Monitor Dashboard
resource "azurerm_portal_dashboard" "main" {
  count               = var.enable_azure ? 1 : 0
  name                = "${local.name}-dashboard"
  resource_group_name = var.azure_resource_group_name
  location            = var.azure_location

  dashboard_properties = jsonencode({
    lenses = {
      "0" = {
        order = 0
        parts = {
          "0" = {
            position = {
              x = 0
              y = 0
              rowSpan = 4
              colSpan = 6
            }
            metadata = {
              inputs = []
              type   = "Extension/Microsoft_Azure_Monitoring/PartType/MetricsChartPart"
            }
          }
        }
      }
    }
    metadata = {
      model = {
        timeRange = {
          value = {
            relative = {
              duration = 24
              timeUnit = 1
            }
          }
          type = "MsPortalFx.Composition.Configuration.ValueTypes.TimeRange"
        }
      }
    }
  })

  tags = local.common_tags
}

# Data sources
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
