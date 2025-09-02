# GCP Module Outputs

# Network outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = google_compute_network.main.id
}

output "vpc_name" {
  description = "Name of the VPC"
  value       = google_compute_network.main.name
}

output "subnet_id" {
  description = "ID of the GKE subnet"
  value       = google_compute_subnetwork.gke.id
}

output "subnet_name" {
  description = "Name of the GKE subnet"
  value       = google_compute_subnetwork.gke.name
}

# GKE outputs
output "cluster_id" {
  description = "ID of the GKE cluster"
  value       = google_container_cluster.primary.id
}

output "cluster_name" {
  description = "Name of the GKE cluster"
  value       = google_container_cluster.primary.name
}

output "cluster_endpoint" {
  description = "Endpoint of the GKE cluster"
  value       = google_container_cluster.primary.endpoint
  sensitive   = true
}

output "cluster_ca_certificate" {
  description = "CA certificate of the GKE cluster"
  value       = google_container_cluster.primary.master_auth[0].cluster_ca_certificate
  sensitive   = true
}

output "cluster_location" {
  description = "Location of the GKE cluster"
  value       = google_container_cluster.primary.location
}

output "node_pool_name" {
  description = "Name of the primary node pool"
  value       = google_container_node_pool.primary_nodes.name
}

# Database outputs
output "database_instance_name" {
  description = "Name of the Cloud SQL instance"
  value       = google_sql_database_instance.main.name
}

output "database_connection_name" {
  description = "Connection name of the Cloud SQL instance"
  value       = google_sql_database_instance.main.connection_name
}

output "database_private_ip" {
  description = "Private IP address of the Cloud SQL instance"
  value       = google_sql_database_instance.main.private_ip_address
  sensitive   = true
}

output "database_name" {
  description = "Name of the database"
  value       = google_sql_database.main.name
}

output "database_username" {
  description = "Username for the database"
  value       = google_sql_user.main.name
}

output "database_password" {
  description = "Password for the database"
  value       = random_password.db_password.result
  sensitive   = true
}

# Storage outputs
output "storage_bucket_name" {
  description = "Name of the storage bucket"
  value       = google_storage_bucket.app_data.name
}

output "storage_bucket_url" {
  description = "URL of the storage bucket"
  value       = google_storage_bucket.app_data.url
}

# Service Account outputs
output "gke_service_account_email" {
  description = "Email of the GKE service account"
  value       = google_service_account.gke_nodes.email
}

# KMS outputs
output "kms_key_ring_name" {
  description = "Name of the KMS key ring"
  value       = google_kms_key_ring.main.name
}

output "kms_crypto_key_name" {
  description = "Name of the KMS crypto key"
  value       = google_kms_crypto_key.bucket_key.name
}

# Project information
output "project_id" {
  description = "GCP project ID"
  value       = var.gcp_project_id
}

output "region" {
  description = "GCP region"
  value       = var.gcp_region
}

output "zone" {
  description = "GCP zone"
  value       = var.gcp_zone
}
