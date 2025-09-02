# GCP Module Variables

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

variable "gcp_project_id" {
  description = "Google Cloud project ID"
  type        = string
}

# Alias for compatibility with enhanced module
variable "project_id" {
  description = "Google Cloud project ID (alias)"
  type        = string
  default     = ""
}

variable "cluster_name" {
  description = "Name of the GKE cluster"
  type        = string
  default     = ""
}

variable "gcp_region" {
  description = "Google Cloud region"
  type        = string
  default     = "us-central1"
}

# Alias for compatibility with enhanced module
variable "region" {
  description = "Google Cloud region (alias)"
  type        = string
  default     = ""
}

variable "gcp_zone" {
  description = "Google Cloud zone"
  type        = string
  default     = "us-central1-a"
}

# Alias for compatibility with enhanced module
variable "zone" {
  description = "Google Cloud zone (alias)"
  type        = string
  default     = ""
}

variable "gcp_vpc_cidr" {
  description = "CIDR block for GCP VPC"
  type        = string
  default     = "10.1.0.0/16"
}

# GKE Configuration
variable "cluster_version" {
  description = "Kubernetes version for GKE"
  type        = string
  default     = "1.28"
}

variable "node_pool_machine_type" {
  description = "Machine type for GKE node pool"
  type        = string
  default     = "e2-standard-4"
}

variable "node_pool_min_count" {
  description = "Minimum node count for GKE"
  type        = number
  default     = 1
}

variable "node_pool_max_count" {
  description = "Maximum node count for GKE"
  type        = number
  default     = 5
}

variable "node_pool_initial_count" {
  description = "Initial node count for GKE"
  type        = number
  default     = 2
}

variable "enable_spot_instances" {
  description = "Enable preemptible instances for cost optimization"
  type        = bool
  default     = false
}

variable "enable_network_policies" {
  description = "Enable Kubernetes network policies"
  type        = bool
  default     = true
}

# Database Configuration
variable "db_instance_class" {
  description = "Cloud SQL instance class"
  type        = string
  default     = "db-f1-micro"
}

variable "enable_backup" {
  description = "Enable backup for Cloud SQL"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Backup retention period in days"
  type        = number
  default     = 7
}

# Storage Configuration
variable "enable_encryption" {
  description = "Enable encryption for storage"
  type        = bool
  default     = true
}

# Common tags/labels
variable "labels" {
  description = "Labels for GCP resources"
  type        = map(string)
  default     = {}
}

# Enhanced GKE Variables
variable "kubernetes_version" {
  description = "Kubernetes version prefix for the GKE cluster"
  type        = string
  default     = "1.28."
}

variable "regional_cluster" {
  description = "Create a regional cluster instead of zonal"
  type        = bool
  default     = true
}

variable "release_channel" {
  description = "Release channel for GKE cluster"
  type        = string
  default     = "STABLE"
}

variable "network" {
  description = "The VPC network to host the cluster in"
  type        = string
  default     = "default"
}

variable "subnetwork" {
  description = "The subnetwork to host the cluster in"
  type        = string
  default     = "default"
}

variable "pods_range_name" {
  description = "The name of the secondary subnet ip range to use for pods"
  type        = string
  default     = "pods"
}

variable "services_range_name" {
  description = "The name of the secondary subnet range to use for services"
  type        = string
  default     = "services"
}

variable "enable_private_cluster" {
  description = "Enable private cluster"
  type        = bool
  default     = true
}

variable "enable_private_endpoint" {
  description = "Enable private endpoint for the cluster"
  type        = bool
  default     = false
}

variable "master_ipv4_cidr_block" {
  description = "The IP range in CIDR notation to use for the hosted master network"
  type        = string
  default     = "172.16.0.0/28"
}

variable "enable_master_global_access" {
  description = "Enable global access to the master endpoint"
  type        = bool
  default     = false
}

variable "master_authorized_networks" {
  description = "List of master authorized networks"
  type = object({
    cidr_blocks = list(object({
      cidr_block   = string
      display_name = string
    }))
  })
  default = null
}

variable "enable_workload_identity" {
  description = "Enable Workload Identity"
  type        = bool
  default     = true
}

variable "enable_http_load_balancing" {
  description = "Enable HTTP load balancing addon"
  type        = bool
  default     = true
}

variable "enable_horizontal_pod_autoscaling" {
  description = "Enable horizontal pod autoscaling addon"
  type        = bool
  default     = true
}

variable "enable_network_policy" {
  description = "Enable network policy addon"
  type        = bool
  default     = true
}

variable "enable_cloudrun" {
  description = "Enable Cloud Run addon"
  type        = bool
  default     = false
}

variable "enable_dns_cache" {
  description = "Enable DNS cache addon"
  type        = bool
  default     = true
}

variable "enable_gce_persistent_disk_csi_driver" {
  description = "Enable GCE Persistent Disk CSI driver"
  type        = bool
  default     = true
}

variable "enable_gcp_filestore_csi_driver" {
  description = "Enable GCP Filestore CSI driver"
  type        = bool
  default     = false
}

variable "enable_gke_backup_agent" {
  description = "Enable GKE Backup agent"
  type        = bool
  default     = false
}

variable "enable_config_connector" {
  description = "Enable Config Connector"
  type        = bool
  default     = false
}

variable "enable_pod_security_policy" {
  description = "Enable Pod Security Policy"
  type        = bool
  default     = false
}

variable "enable_binary_authorization" {
  description = "Enable Binary Authorization"
  type        = bool
  default     = false
}

variable "enable_cluster_autoscaling" {
  description = "Enable cluster autoscaling"
  type        = bool
  default     = true
}

variable "cluster_autoscaling_cpu_min" {
  description = "Minimum CPU cores for cluster autoscaling"
  type        = number
  default     = 1
}

variable "cluster_autoscaling_cpu_max" {
  description = "Maximum CPU cores for cluster autoscaling"
  type        = number
  default     = 100
}

variable "cluster_autoscaling_memory_min" {
  description = "Minimum memory in GB for cluster autoscaling"
  type        = number
  default     = 1
}

variable "cluster_autoscaling_memory_max" {
  description = "Maximum memory in GB for cluster autoscaling"
  type        = number
  default     = 1000
}

variable "enable_shielded_nodes" {
  description = "Enable Shielded GKE Nodes features on all nodes in this cluster"
  type        = bool
  default     = true
}

# Additional essential variables for enhanced module
variable "maintenance_start_time" {
  description = "Start time for maintenance window"
  type        = string
  default     = "2023-01-01T09:00:00Z"
}

variable "maintenance_end_time" {
  description = "End time for maintenance window"
  type        = string
  default     = "2023-01-01T17:00:00Z"
}

variable "maintenance_recurrence" {
  description = "Recurrence rule for maintenance window"
  type        = string
  default     = "FREQ=WEEKLY;BYDAY=SA"
}

variable "logging_service" {
  description = "The logging service that the cluster should write logs to"
  type        = string
  default     = "logging.googleapis.com/kubernetes"
}

variable "monitoring_service" {
  description = "The monitoring service that the cluster should write metrics to"
  type        = string
  default     = "monitoring.googleapis.com/kubernetes"
}

variable "logging_enabled_components" {
  description = "List of GKE components exposing logs"
  type        = list(string)
  default     = ["SYSTEM_COMPONENTS", "WORKLOADS"]
}

variable "monitoring_enabled_components" {
  description = "List of GKE components exposing metrics"
  type        = list(string)
  default     = ["SYSTEM_COMPONENTS"]
}

variable "enable_managed_prometheus" {
  description = "Enable managed Prometheus"
  type        = bool
  default     = true
}

variable "cluster_resource_labels" {
  description = "The GCE resource labels (a map of key/value pairs) to be applied to the cluster"
  type        = map(string)
  default     = {}
}

variable "node_pools" {
  description = "Map of node pool configurations"
  type        = map(any)
  default     = {}
}

variable "node_pools_oauth_scopes" {
  description = "Map of lists containing node oauth scopes by node-pool name"
  type        = list(string)
  default = [
    "https://www.googleapis.com/auth/logging.write",
    "https://www.googleapis.com/auth/monitoring",
  ]
}

variable "node_pools_labels" {
  description = "Map of maps containing node labels by node-pool name"
  type        = map(string)
  default     = {}
}

variable "node_pools_metadata" {
  description = "Map of maps containing node metadata by node-pool name"
  type        = map(string)
  default     = {}
}

variable "node_pools_tags" {
  description = "List of network tags applied to all nodes"
  type        = list(string)
  default     = []
}

# Cloud SQL variables
variable "enable_cloud_sql" {
  description = "Enable Cloud SQL instance"
  type        = bool
  default     = false
}

variable "cloud_sql_database_version" {
  description = "Database version for Cloud SQL"
  type        = string
  default     = "POSTGRES_15"
}

variable "cloud_sql_tier" {
  description = "Machine type for Cloud SQL instance"
  type        = string
  default     = "db-f1-micro"
}

variable "cloud_sql_deletion_protection" {
  description = "Enable deletion protection for Cloud SQL"
  type        = bool
  default     = true
}

# Service account variables
variable "enable_cloud_sql_proxy" {
  description = "Enable Cloud SQL Proxy service account"
  type        = bool
  default     = false
}

variable "cloud_sql_proxy_namespace" {
  description = "Kubernetes namespace for Cloud SQL Proxy"
  type        = string
  default     = "default"
}

variable "cloud_sql_proxy_service_account" {
  description = "Kubernetes service account for Cloud SQL Proxy"
  type        = string
  default     = "cloud-sql-proxy"
}

variable "enable_external_dns" {
  description = "Enable External DNS service account"
  type        = bool
  default     = false
}

variable "external_dns_namespace" {
  description = "Kubernetes namespace for External DNS"
  type        = string
  default     = "kube-system"
}

variable "external_dns_service_account" {
  description = "Kubernetes service account for External DNS"
  type        = string
  default     = "external-dns"
}

variable "enable_cert_manager" {
  description = "Enable Cert Manager service account"
  type        = bool
  default     = false
}

variable "cert_manager_namespace" {
  description = "Kubernetes namespace for Cert Manager"
  type        = string
  default     = "cert-manager"
}

variable "cert_manager_service_account" {
  description = "Kubernetes service account for Cert Manager"
  type        = string
  default     = "cert-manager"
}
