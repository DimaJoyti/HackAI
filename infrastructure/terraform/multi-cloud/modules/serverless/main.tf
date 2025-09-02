# Serverless Functions Module for Multi-Cloud HackAI

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
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

# Local values
locals {
  name = "${var.project_name}-${var.environment}"

  function_names = [
    "auto-scaler",
    "security-scanner",
    "cost-optimizer",
    "health-monitor",
    "event-processor",
    "data-pipeline"
  ]
}

# AWS Lambda Functions
module "aws_lambda_functions" {
  count  = var.enable_aws ? 1 : 0
  source = "./aws-lambda"

  project_name = var.project_name
  environment  = var.environment
  owner        = var.owner

  vpc_id     = var.aws_vpc_id
  subnet_ids = var.aws_subnet_ids

  function_names = local.function_names
  runtime        = var.runtime

  tags = {
    Project       = var.project_name
    Environment   = var.environment
    ManagedBy     = "Terraform"
    Owner         = var.owner
    CloudProvider = "AWS"
  }
}

# Google Cloud Functions
module "gcp_cloud_functions" {
  count  = var.enable_gcp ? 1 : 0
  source = "./gcp-functions"

  enable_gcp_functions = var.enable_gcp
  project_name         = var.project_name
  environment          = var.environment
  project_id           = "default-project"
  gcp_region           = "us-central1"
}

# Azure Functions
module "azure_functions" {
  count  = var.enable_azure ? 1 : 0
  source = "./azure-functions"

  enable_azure_functions = var.enable_azure
  project_name           = var.project_name
  environment            = var.environment
  resource_group_name    = "${var.project_name}-${var.environment}-rg"
}

# Cross-Cloud Event Bridge for serverless orchestration
resource "aws_cloudwatch_event_rule" "cross_cloud_events" {
  count = var.enable_aws ? 1 : 0
  name  = "${local.name}-cross-cloud-events"

  description = "Cross-cloud event orchestration for HackAI"

  event_pattern = jsonencode({
    source      = ["hackai.multi-cloud"]
    detail-type = ["Auto Scaling Event", "Security Alert", "Cost Alert", "Health Check"]
  })

  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# EventBridge targets for Lambda functions
resource "aws_cloudwatch_event_target" "lambda_targets" {
  count = var.enable_aws ? length(local.function_names) : 0

  rule      = aws_cloudwatch_event_rule.cross_cloud_events[0].name
  target_id = "Lambda-${local.function_names[count.index]}"
  arn       = module.aws_lambda_functions[0].auto_scaler_function_arn

  input_transformer {
    input_paths = {
      source      = "$.source"
      detail-type = "$.detail-type"
      detail      = "$.detail"
    }
    input_template = jsonencode({
      source      = "<source>"
      detail-type = "<detail-type>"
      detail      = "<detail>"
      function    = local.function_names[count.index]
    })
  }
}

# Lambda permissions for EventBridge
resource "aws_lambda_permission" "allow_eventbridge" {
  count = var.enable_aws ? length(local.function_names) : 0

  statement_id  = "AllowExecutionFromEventBridge-${local.function_names[count.index]}"
  action        = "lambda:InvokeFunction"
  function_name = module.aws_lambda_functions[0].auto_scaler_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cross_cloud_events[0].arn
}

# Google Cloud Pub/Sub for cross-cloud messaging
resource "google_pubsub_topic" "cross_cloud_events" {
  count = var.enable_gcp ? 1 : 0
  name  = "${local.name}-cross-cloud-events"

  labels = {
    project     = lower(var.project_name)
    environment = var.environment
    managed-by  = "terraform"
  }
}

# Pub/Sub subscriptions for Cloud Functions
resource "google_pubsub_subscription" "function_subscriptions" {
  count = var.enable_gcp ? length(local.function_names) : 0

  name  = "${local.name}-${local.function_names[count.index]}-subscription"
  topic = google_pubsub_topic.cross_cloud_events[0].name

  ack_deadline_seconds = 20

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dead_letter[0].id
    max_delivery_attempts = 5
  }

  labels = {
    project     = lower(var.project_name)
    environment = var.environment
    managed-by  = "terraform"
    function    = local.function_names[count.index]
  }
}

# Dead letter topic for failed messages
resource "google_pubsub_topic" "dead_letter" {
  count = var.enable_gcp ? 1 : 0
  name  = "${local.name}-dead-letter"

  labels = {
    project     = lower(var.project_name)
    environment = var.environment
    managed-by  = "terraform"
  }
}

# Azure Service Bus for cross-cloud messaging
resource "azurerm_servicebus_namespace" "cross_cloud" {
  count = var.enable_azure ? 1 : 0

  name                = "${local.name}-servicebus"
  location            = var.azure_location
  resource_group_name = var.azure_resource_group_name
  sku                 = "Standard"

  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Service Bus topics for each function type
resource "azurerm_servicebus_topic" "function_topics" {
  count = var.enable_azure ? length(local.function_names) : 0

  name         = local.function_names[count.index]
  namespace_id = azurerm_servicebus_namespace.cross_cloud[0].id

  partitioning_enabled = true
}

# Service Bus subscriptions
resource "azurerm_servicebus_subscription" "function_subscriptions" {
  count = var.enable_azure ? length(local.function_names) : 0

  name     = "${local.function_names[count.index]}-subscription"
  topic_id = azurerm_servicebus_topic.function_topics[count.index].id

  max_delivery_count = 5

  dead_lettering_on_message_expiration      = true
  dead_lettering_on_filter_evaluation_error = true
}

# Cross-cloud monitoring for serverless functions
resource "aws_cloudwatch_log_group" "serverless_logs" {
  count = var.enable_aws ? 1 : 0

  name              = "/aws/lambda/${local.name}-serverless"
  retention_in_days = 14

  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# CloudWatch alarms for serverless functions
resource "aws_cloudwatch_metric_alarm" "function_errors" {
  count = var.enable_aws ? length(local.function_names) : 0

  alarm_name          = "${local.name}-${local.function_names[count.index]}-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "60"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "This metric monitors lambda errors for ${local.function_names[count.index]}"

  dimensions = {
    FunctionName = module.aws_lambda_functions[0].auto_scaler_function_name
  }

  alarm_actions = [aws_sns_topic.alerts[0].arn]

  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  count = var.enable_aws ? 1 : 0
  name  = "${local.name}-serverless-alerts"

  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# API Gateway for serverless HTTP endpoints
resource "aws_api_gateway_rest_api" "serverless_api" {
  count = var.enable_aws ? 1 : 0
  name  = "${local.name}-serverless-api"

  description = "API Gateway for HackAI serverless functions"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# API Gateway deployment
resource "aws_api_gateway_deployment" "serverless_api" {
  count = var.enable_aws ? 1 : 0

  depends_on = [
    aws_api_gateway_rest_api.serverless_api
  ]

  rest_api_id = aws_api_gateway_rest_api.serverless_api[0].id

  lifecycle {
    create_before_destroy = true
  }
}

# Variables
variable "project_name" {
  description = "Project name"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "owner" {
  description = "Owner of the resources"
  type        = string
  default     = "HackAI Team"
}

variable "enable_aws" {
  description = "Enable AWS serverless functions"
  type        = bool
  default     = false
}

variable "enable_gcp" {
  description = "Enable GCP serverless functions"
  type        = bool
  default     = false
}

variable "enable_azure" {
  description = "Enable Azure serverless functions"
  type        = bool
  default     = false
}

variable "aws_vpc_id" {
  description = "AWS VPC ID for Lambda functions"
  type        = string
  default     = ""
}

variable "aws_subnet_ids" {
  description = "AWS subnet IDs for Lambda functions"
  type        = list(string)
  default     = []
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

variable "azure_resource_group_name" {
  description = "Azure resource group name"
  type        = string
  default     = ""
}

variable "azure_location" {
  description = "Azure location"
  type        = string
  default     = "East US"
}

variable "runtime" {
  description = "Runtime for serverless functions"
  type        = string
  default     = "go1.x"
}

variable "function_names" {
  description = "List of function names to deploy"
  type        = list(string)
  default     = ["auto-scaler", "security-scanner"]
}
