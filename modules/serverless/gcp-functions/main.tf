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
  project  = var.gcp_project_id

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

# Auto Scaler Cloud Function Source Archive
resource "google_storage_bucket_object" "auto_scaler_source" {
  count  = var.enable_gcp_functions ? 1 : 0
  name   = "auto-scaler-source.zip"
  bucket = google_storage_bucket.functions_source[0].name
  source = var.auto_scaler_source_path
}

# Auto Scaler Cloud Function
resource "google_cloudfunctions2_function" "auto_scaler" {
  count    = var.enable_gcp_functions ? 1 : 0
  name     = "${var.project_name}-${var.environment}-auto-scaler"
  location = var.gcp_region
  project  = var.gcp_project_id

  build_config {
    runtime     = "go121"
    entry_point = "AutoScaler"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source[0].name
        object = google_storage_bucket_object.auto_scaler_source[0].name
      }
    }
  }

  service_config {
    max_instance_count = 10
    available_memory   = "256M"
    timeout_seconds    = 300
    environment_variables = {
      ENVIRONMENT = var.environment
      PROJECT     = var.project_name
    }
  }
}

# Security Scanner Cloud Function Source Archive
resource "google_storage_bucket_object" "security_scanner_source" {
  count  = var.enable_gcp_functions ? 1 : 0
  name   = "security-scanner-source.zip"
  bucket = google_storage_bucket.functions_source[0].name
  source = var.security_scanner_source_path
}

# Security Scanner Cloud Function
resource "google_cloudfunctions2_function" "security_scanner" {
  count    = var.enable_gcp_functions ? 1 : 0
  name     = "${var.project_name}-${var.environment}-security-scanner"
  location = var.gcp_region
  project  = var.gcp_project_id

  build_config {
    runtime     = "go121"
    entry_point = "SecurityScanner"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source[0].name
        object = google_storage_bucket_object.security_scanner_source[0].name
      }
    }
  }

  service_config {
    max_instance_count = 5
    available_memory   = "512M"
    timeout_seconds    = 900
    environment_variables = {
      ENVIRONMENT = var.environment
      PROJECT     = var.project_name
    }
  }
}

# Cloud Scheduler Job for Auto Scaler
resource "google_cloud_scheduler_job" "auto_scaler_schedule" {
  count    = var.enable_gcp_functions ? 1 : 0
  name     = "${var.project_name}-${var.environment}-auto-scaler-schedule"
  region   = var.gcp_region
  project  = var.gcp_project_id
  schedule = "*/5 * * * *" # Every 5 minutes

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.auto_scaler[0].service_config[0].uri

    oidc_token {
      service_account_email = google_service_account.scheduler[0].email
    }
  }
}

# Cloud Scheduler Job for Security Scanner
resource "google_cloud_scheduler_job" "security_scanner_schedule" {
  count    = var.enable_gcp_functions ? 1 : 0
  name     = "${var.project_name}-${var.environment}-security-scanner-schedule"
  region   = var.gcp_region
  project  = var.gcp_project_id
  schedule = "0 2 * * *" # Daily at 2 AM

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.security_scanner[0].service_config[0].uri

    oidc_token {
      service_account_email = google_service_account.scheduler[0].email
    }
  }
}

# Service Account for Cloud Scheduler
resource "google_service_account" "scheduler" {
  count        = var.enable_gcp_functions ? 1 : 0
  account_id   = "${var.project_name}-${var.environment}-scheduler"
  display_name = "Cloud Scheduler Service Account"
  project      = var.gcp_project_id
}

# IAM Binding for Cloud Functions Invoker
resource "google_cloudfunctions2_function_iam_binding" "auto_scaler_invoker" {
  count        = var.enable_gcp_functions ? 1 : 0
  project      = var.gcp_project_id
  location     = var.gcp_region
  cloud_function = google_cloudfunctions2_function.auto_scaler[0].name
  role         = "roles/cloudfunctions.invoker"
  members = [
    "serviceAccount:${google_service_account.scheduler[0].email}"
  ]
}

resource "google_cloudfunctions2_function_iam_binding" "security_scanner_invoker" {
  count        = var.enable_gcp_functions ? 1 : 0
  project      = var.gcp_project_id
  location     = var.gcp_region
  cloud_function = google_cloudfunctions2_function.security_scanner[0].name
  role         = "roles/cloudfunctions.invoker"
  members = [
    "serviceAccount:${google_service_account.scheduler[0].email}"
  ]
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

variable "gcp_project_id" {
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
  value       = var.enable_gcp_functions ? google_cloudfunctions2_function.auto_scaler[0].name : null
}

output "auto_scaler_function_uri" {
  description = "Auto scaler Cloud Function URI"
  value       = var.enable_gcp_functions ? google_cloudfunctions2_function.auto_scaler[0].service_config[0].uri : null
}

output "security_scanner_function_name" {
  description = "Security scanner Cloud Function name"
  value       = var.enable_gcp_functions ? google_cloudfunctions2_function.security_scanner[0].name : null
}

output "security_scanner_function_uri" {
  description = "Security scanner Cloud Function URI"
  value       = var.enable_gcp_functions ? google_cloudfunctions2_function.security_scanner[0].service_config[0].uri : null
}

output "functions_source_bucket" {
  description = "Cloud Functions source bucket name"
  value       = var.enable_gcp_functions ? google_storage_bucket.functions_source[0].name : null
}
