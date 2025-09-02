# Monitoring Module Variables

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

# Cloud Provider Flags
variable "enable_aws" {
  description = "Enable AWS monitoring resources"
  type        = bool
  default     = true
}

variable "enable_gcp" {
  description = "Enable GCP monitoring resources"
  type        = bool
  default     = true
}

variable "enable_azure" {
  description = "Enable Azure monitoring resources"
  type        = bool
  default     = true
}

# AWS Configuration
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

# GCP Configuration
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

# Azure Configuration
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

# Monitoring Configuration
variable "log_retention_days" {
  description = "Log retention period in days"
  type        = number
  default     = 30
}

variable "enable_detailed_monitoring" {
  description = "Enable detailed monitoring"
  type        = bool
  default     = true
}

variable "enable_alerting" {
  description = "Enable alerting"
  type        = bool
  default     = true
}

variable "alert_email" {
  description = "Email for alerts"
  type        = string
  default     = ""
}

# Common tags
variable "tags" {
  description = "Tags for monitoring resources"
  type        = map(string)
  default     = {}
}
