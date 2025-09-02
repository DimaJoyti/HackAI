# GCP Infrastructure Module
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
}

# VPC Network
resource "google_compute_network" "main" {
  count                   = var.enable_gcp ? 1 : 0
  name                    = "${var.project_name}-${var.environment}-vpc"
  auto_create_subnetworks = false
  project                 = var.project_id
}

# Subnet for GKE
resource "google_compute_subnetwork" "gke" {
  count         = var.enable_gcp ? 1 : 0
  name          = "${var.project_name}-${var.environment}-gke-subnet"
  ip_cidr_range = "10.2.0.0/24"
  region        = var.region
  network       = google_compute_network.main[0].id
  project       = var.project_id

  secondary_ip_range {
    range_name    = "gke-pods"
    ip_cidr_range = "10.2.1.0/24"
  }

  secondary_ip_range {
    range_name    = "gke-services"
    ip_cidr_range = "10.2.2.0/24"
  }
}

# GKE Cluster
resource "google_container_cluster" "main" {
  count    = var.enable_gcp ? 1 : 0
  name     = "${var.project_name}-${var.environment}-gke"
  location = var.region
  project  = var.project_id

  # We can't create a cluster with no node pool defined, but we want to only use
  # separately managed node pools. So we create the smallest possible default
  # node pool and immediately delete it.
  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.main[0].name
  subnetwork = google_compute_subnetwork.gke[0].name

  ip_allocation_policy {
    cluster_secondary_range_name  = "gke-pods"
    services_secondary_range_name = "gke-services"
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }
}

# GKE Node Pool
resource "google_container_node_pool" "main" {
  count      = var.enable_gcp ? 1 : 0
  name       = "${var.project_name}-${var.environment}-node-pool"
  location   = var.region
  cluster    = google_container_cluster.main[0].name
  node_count = var.node_pool_initial_count
  project    = var.project_id

  node_config {
    preemptible  = false
    machine_type = var.node_pool_machine_type

    service_account = google_service_account.gke[0].email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }

  autoscaling {
    min_node_count = var.node_pool_min_count
    max_node_count = var.node_pool_max_count
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }
}

# Service Account for GKE
resource "google_service_account" "gke" {
  count        = var.enable_gcp ? 1 : 0
  account_id   = "${var.project_name}-${var.environment}-gke-sa"
  display_name = "GKE Service Account"
  project      = var.project_id
}

# Cloud SQL Instance
resource "google_sql_database_instance" "main" {
  count            = var.enable_gcp ? 1 : 0
  name             = "${var.project_name}-${var.environment}-postgres"
  database_version = "POSTGRES_13"
  region           = var.region
  project          = var.project_id

  settings {
    tier = "db-f1-micro"

    backup_configuration {
      enabled = true
    }

    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        value = "0.0.0.0/0"
        name  = "all"
      }
    }
  }

  deletion_protection = false
}

# Cloud SQL Database
resource "google_sql_database" "main" {
  count    = var.enable_gcp ? 1 : 0
  name     = "hackai_db"
  instance = google_sql_database_instance.main[0].name
  project  = var.project_id
}

# Cloud SQL User
resource "google_sql_user" "main" {
  count    = var.enable_gcp ? 1 : 0
  name     = "hackai_admin"
  instance = google_sql_database_instance.main[0].name
  password = "changeme123!"
  project  = var.project_id
}

# Memorystore Redis Instance
resource "google_redis_instance" "main" {
  count          = var.enable_gcp ? 1 : 0
  name           = "${var.project_name}-${var.environment}-redis"
  tier           = "BASIC"
  memory_size_gb = 1
  region         = var.region
  project        = var.project_id

  authorized_network = google_compute_network.main[0].id

  redis_version     = "REDIS_6_X"
  display_name      = "HackAI Redis Cache"
}

# Variables (cleaned up - no duplicates)
variable "enable_gcp" {
  description = "Enable GCP infrastructure"
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

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "node_pool_initial_count" {
  description = "Initial number of nodes in the node pool"
  type        = number
  default     = 1
}

variable "node_pool_min_count" {
  description = "Minimum number of nodes in the node pool"
  type        = number
  default     = 1
}

variable "node_pool_max_count" {
  description = "Maximum number of nodes in the node pool"
  type        = number
  default     = 3
}

variable "node_pool_machine_type" {
  description = "Machine type for the node pool"
  type        = string
  default     = "e2-medium"
}

# Outputs
output "project_id" {
  description = "GCP project ID"
  value       = var.project_id
}

output "cluster_name" {
  description = "Name of the GKE cluster"
  value       = var.enable_gcp ? google_container_cluster.main[0].name : null
}

output "cluster_endpoint" {
  description = "Endpoint for the GKE cluster"
  value       = var.enable_gcp ? google_container_cluster.main[0].endpoint : null
}

output "database_connection_name" {
  description = "Cloud SQL connection name"
  value       = var.enable_gcp ? google_sql_database_instance.main[0].connection_name : null
}

output "redis_host" {
  description = "Redis instance host"
  value       = var.enable_gcp ? google_redis_instance.main[0].host : null
}




