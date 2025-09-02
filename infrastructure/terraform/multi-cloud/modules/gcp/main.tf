# GCP Infrastructure Module for HackAI Multi-Cloud

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

# Local values
locals {
  name = "${var.project_name}-${var.environment}"

  labels = {
    project     = lower(var.project_name)
    environment = var.environment
    managed-by  = "terraform"
    owner       = lower(var.owner)
  }
}

# Data sources
data "google_client_config" "default" {}
data "google_compute_zones" "available" {
  region = var.gcp_region
}

# VPC Network
resource "google_compute_network" "main" {
  name                    = "${local.name}-vpc"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

# Subnet for GKE
resource "google_compute_subnetwork" "gke" {
  name          = "${local.name}-gke-subnet"
  ip_cidr_range = var.gcp_vpc_cidr
  region        = var.gcp_region
  network       = google_compute_network.main.id

  secondary_ip_range {
    range_name    = "gke-pods"
    ip_cidr_range = "10.1.0.0/16"
  }

  secondary_ip_range {
    range_name    = "gke-services"
    ip_cidr_range = "10.2.0.0/16"
  }
}

# Firewall rules
resource "google_compute_firewall" "allow_internal" {
  name    = "${local.name}-allow-internal"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = [var.gcp_vpc_cidr, "10.1.0.0/16", "10.2.0.0/16"]
}

# GKE Cluster
resource "google_container_cluster" "primary" {
  name     = "${local.name}-gke"
  location = var.gcp_region

  # We can't create a cluster with no node pool defined, but we want to only use
  # separately managed node pools. So we create the smallest possible default
  # node pool and immediately delete it.
  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.main.name
  subnetwork = google_compute_subnetwork.gke.name

  # IP allocation policy for VPC-native cluster
  ip_allocation_policy {
    cluster_secondary_range_name  = "gke-pods"
    services_secondary_range_name = "gke-services"
  }

  # Network policy
  network_policy {
    enabled = var.enable_network_policies
  }

  # Workload Identity
  workload_identity_config {
    workload_pool = "${var.gcp_project_id}.svc.id.goog"
  }

  # Private cluster configuration
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  # Master authorized networks
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "0.0.0.0/0"
      display_name = "All networks"
    }
  }

  # Addons
  addons_config {
    http_load_balancing {
      disabled = false
    }

    horizontal_pod_autoscaling {
      disabled = false
    }

    network_policy_config {
      disabled = !var.enable_network_policies
    }
  }

  # Maintenance policy
  maintenance_policy {
    recurring_window {
      start_time = "2023-01-01T09:00:00Z"
      end_time   = "2023-01-01T17:00:00Z"
      recurrence = "FREQ=WEEKLY;BYDAY=SA,SU"
    }
  }

  # Logging and monitoring
  logging_service    = "logging.googleapis.com/kubernetes"
  monitoring_service = "monitoring.googleapis.com/kubernetes"

  # Resource labels
  resource_labels = local.labels
}

# GKE Node Pool
resource "google_container_node_pool" "primary_nodes" {
  name     = "${local.name}-node-pool"
  location = var.gcp_region
  cluster  = google_container_cluster.primary.name

  # Autoscaling configuration
  autoscaling {
    min_node_count = var.node_pool_min_count
    max_node_count = var.node_pool_max_count
  }

  # Node configuration
  node_config {
    preemptible  = var.enable_spot_instances
    machine_type = var.node_pool_machine_type

    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    service_account = google_service_account.gke_nodes.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]

    labels = local.labels

    tags = ["gke-node", "${local.name}-gke"]

    metadata = {
      disable-legacy-endpoints = "true"
    }

    # Workload Identity
    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }

  # Upgrade settings
  upgrade_settings {
    max_surge       = 1
    max_unavailable = 0
  }

  # Management
  management {
    auto_repair  = true
    auto_upgrade = true
  }
}

# Service Account for GKE nodes
resource "google_service_account" "gke_nodes" {
  account_id   = "${local.name}-gke-nodes"
  display_name = "GKE Nodes Service Account"
}

# IAM bindings for GKE nodes
resource "google_project_iam_member" "gke_nodes" {
  for_each = toset([
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/monitoring.viewer",
    "roles/stackdriver.resourceMetadata.writer"
  ])

  project = var.gcp_project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

# Cloud SQL PostgreSQL instance
resource "random_password" "db_password" {
  length  = 16
  special = true
}

resource "google_sql_database_instance" "main" {
  name             = "${local.name}-postgres"
  database_version = "POSTGRES_15"
  region           = var.gcp_region

  settings {
    tier = var.db_instance_class

    backup_configuration {
      enabled                        = var.enable_backup
      start_time                     = "03:00"
      point_in_time_recovery_enabled = true
      backup_retention_settings {
        retained_backups = var.backup_retention_days
      }
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.main.id
    }

    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }

    database_flags {
      name  = "log_connections"
      value = "on"
    }

    database_flags {
      name  = "log_disconnections"
      value = "on"
    }

    database_flags {
      name  = "log_lock_waits"
      value = "on"
    }

    user_labels = local.labels
  }

  deletion_protection = var.environment == "production"
}

# Database
resource "google_sql_database" "main" {
  name     = "hackai"
  instance = google_sql_database_instance.main.name
}

# Database user
resource "google_sql_user" "main" {
  name     = "hackai"
  instance = google_sql_database_instance.main.name
  password = random_password.db_password.result
}

# Private service connection for Cloud SQL
resource "google_compute_global_address" "private_ip_address" {
  name          = "${local.name}-private-ip-address"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.main.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.main.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_address.name]
}

# Cloud Storage bucket
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "google_storage_bucket" "app_data" {
  name     = "${local.name}-app-data-${random_id.bucket_suffix.hex}"
  location = var.gcp_region

  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.bucket_key.id
  }

  labels = local.labels
}

# KMS for bucket encryption
resource "google_kms_key_ring" "main" {
  name     = "${local.name}-keyring"
  location = var.gcp_region
}

resource "google_kms_crypto_key" "bucket_key" {
  name     = "${local.name}-bucket-key"
  key_ring = google_kms_key_ring.main.id

  lifecycle {
    prevent_destroy = true
  }
}
