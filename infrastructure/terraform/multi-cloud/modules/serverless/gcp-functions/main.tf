# GCP Cloud Functions Module
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
}

# Storage Bucket for Cloud Functions Source Code
resource "google_storage_bucket" "functions_source" {
  count    = var.enable_gcp_functions ? 1 : 0
  name     = "${var.project_name}-${var.environment}-functions-source-${random_id.bucket_suffix[0].hex}"
  location = var.gcp_region
  project  = var.project_id

  uniform_bucket_level_access = true

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
  count       = var.enable_gcp_functions ? 1 : 0
  byte_length = 8
}

# Variables
variable "enable_gcp_functions" {
  description = "Enable GCP Cloud Functions"
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

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "gcp_region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "auto_scaler_source_path" {
  description = "Path to auto scaler source zip file"
  type        = string
  default     = "auto-scaler-source.zip"
}

variable "security_scanner_source_path" {
  description = "Path to security scanner source zip file"
  type        = string
  default     = "security-scanner-source.zip"
}

# Outputs
output "auto_scaler_function_name" {
  description = "Auto scaler Cloud Function name"
  value       = null
}

output "auto_scaler_function_uri" {
  description = "Auto scaler Cloud Function URI"
  value       = null
}

output "security_scanner_function_name" {
  description = "Security scanner Cloud Function name"
  value       = null
}

output "security_scanner_function_uri" {
  description = "Security scanner Cloud Function URI"
  value       = null
}

output "functions_source_bucket" {
  description = "Cloud Functions source bucket name"
  value       = var.enable_gcp_functions ? google_storage_bucket.functions_source[0].name : null
}
