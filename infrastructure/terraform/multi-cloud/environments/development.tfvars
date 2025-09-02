# Development Multi-Cloud Environment Configuration for HackAI

# Global Configuration
project_name = "hackai"
environment  = "development"
owner        = "HackAI-Team"

# Multi-Cloud Strategy
primary_cloud = "aws"
enable_aws    = true
enable_gcp    = false # Disabled for development to save costs
enable_azure  = false # Disabled for development to save costs

# AWS Configuration
aws_region             = "us-west-2"
aws_availability_zones = ["us-west-2a", "us-west-2b"]
aws_vpc_cidr           = "10.0.0.0/16"
aws_enable_nat_gateway = true
aws_single_nat_gateway = true # Single NAT for cost savings

# AWS EKS Configuration
aws_cluster_version           = "1.28"
aws_node_group_instance_types = ["t3.medium"]
aws_node_group_min_size       = 1
aws_node_group_max_size       = 3
aws_node_group_desired_size   = 2

# AWS Database Configuration
aws_db_instance_class = "db.t3.micro"
aws_redis_node_type   = "cache.t3.micro"

# GCP Configuration (disabled for development)
gcp_project_id = "hackai-development"
gcp_region     = "us-central1"
gcp_zone       = "us-central1-a"
gcp_vpc_cidr   = "10.1.0.0/16"

# GCP GKE Configuration
gcp_cluster_version         = "1.28"
gcp_node_pool_machine_type  = "e2-standard-2"
gcp_node_pool_min_count     = 1
gcp_node_pool_max_count     = 3
gcp_node_pool_initial_count = 1

# Azure Configuration (disabled for development)
azure_subscription_id = "your-azure-subscription-id"
azure_location        = "East US"
azure_vnet_cidr       = "10.2.0.0/16"

# Azure AKS Configuration
azure_cluster_version      = "1.28"
azure_node_pool_vm_size    = "Standard_B2s"
azure_node_pool_min_count  = 1
azure_node_pool_max_count  = 3
azure_node_pool_node_count = 1

# Feature Flags
enable_serverless        = true
enable_monitoring        = true
enable_logging           = true
enable_security_scanning = false # Disabled for development
enable_network_policies  = false # Disabled for development
enable_spot_instances    = true  # Enable for cost savings
enable_auto_scaling      = true
enable_backup            = false # Disabled for development
enable_ssl               = false # Disabled for development

# Serverless Configuration
serverless_runtime = "go1.x"

# Domain Configuration
domain_name = "dev.hackai.local"

# Backup and Disaster Recovery
backup_retention_days      = 7
enable_cross_region_backup = false

# Development-specific settings
enable_deletion_protection  = false
enable_enhanced_monitoring  = false
enable_performance_insights = false

# Security Settings (relaxed for development)
enable_encryption_at_rest    = false
enable_encryption_in_transit = false
enable_vpc_flow_logs         = false
enable_cloudtrail            = false
enable_config_rules          = false

# Monitoring and Alerting (minimal for development)
enable_detailed_monitoring = false
enable_custom_metrics      = false
enable_alerting            = false
alert_email                = "dev-alerts@hackai.com"

# Performance Settings (minimal for development)
enable_performance_monitoring = false
enable_apm                    = false
enable_distributed_tracing    = false

# Scaling Configuration (conservative for development)
auto_scaling_target_cpu          = 80
auto_scaling_target_memory       = 85
auto_scaling_scale_up_cooldown   = "3m"
auto_scaling_scale_down_cooldown = "5m"

# Network Configuration (simplified for development)
enable_private_endpoints = false
enable_service_mesh      = false

# Storage Configuration (minimal for development)
enable_backup_encryption        = false
backup_schedule                 = "0 6 * * 0" # Weekly on Sunday at 6 AM
backup_cross_region_replication = false

# Disaster Recovery (disabled for development)
enable_disaster_recovery = false

# Load Balancing (basic for development)
enable_global_load_balancer      = false
enable_health_checks             = true
health_check_interval            = "60s"
health_check_timeout             = "10s"
health_check_healthy_threshold   = 2
health_check_unhealthy_threshold = 3

# CDN Configuration (disabled for development)
enable_cdn = false

# API Gateway Configuration (basic for development)
enable_api_gateway         = false
api_gateway_throttle_rate  = 100
api_gateway_throttle_burst = 200

# Database Configuration (minimal for development)
enable_read_replicas     = false
read_replica_count       = 0
enable_automated_backups = false
backup_window            = "06:00-07:00"
maintenance_window       = "sun:07:00-sun:08:00"

# Cache Configuration (minimal for development)
enable_cache_clustering = false
cache_node_count        = 1
enable_cache_backup     = false

# Logging Configuration (basic for development)
log_retention_days     = 7
enable_log_aggregation = false
enable_log_analysis    = false

# Security Scanning (disabled for development)
enable_vulnerability_scanning = false
enable_container_scanning     = false
enable_secrets_scanning       = false

# Cost Management (basic for development)
enable_cost_monitoring = true
enable_budget_alerts   = true
monthly_budget_limit   = 200 # USD
budget_alert_threshold = 90  # Percentage

# Resource Tagging
additional_tags = {
  CostCenter  = "Engineering"
  Project     = "HackAI"
  Environment = "Development"
  Owner       = "Dev-Team"
  Backup      = "NotRequired"
  Monitoring  = "Basic"
  Compliance  = "NotRequired"
}
