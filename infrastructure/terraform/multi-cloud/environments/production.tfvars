# Production Multi-Cloud Environment Configuration for HackAI

# Global Configuration
project_name = "hackai"
environment  = "production"
owner        = "HackAI-Team"

# Multi-Cloud Strategy
primary_cloud = "aws"
enable_aws    = true
enable_gcp    = true
enable_azure  = true

# AWS Configuration
aws_region             = "us-west-2"
aws_availability_zones = ["us-west-2a", "us-west-2b", "us-west-2c"]
aws_vpc_cidr           = "10.0.0.0/16"
aws_enable_nat_gateway = true
aws_single_nat_gateway = false

# AWS EKS Configuration
aws_cluster_version           = "1.28"
aws_node_group_instance_types = ["m5.xlarge", "m5a.xlarge", "m5d.xlarge"]
aws_node_group_min_size       = 3
aws_node_group_max_size       = 20
aws_node_group_desired_size   = 5

# AWS Database Configuration
aws_db_instance_class = "db.r6g.large"
aws_redis_node_type   = "cache.r6g.large"

# GCP Configuration
gcp_project_id = "hackai-production"
gcp_region     = "us-central1"
gcp_zone       = "us-central1-a"
gcp_vpc_cidr   = "10.1.0.0/16"

# GCP GKE Configuration
gcp_cluster_version         = "1.28"
gcp_node_pool_machine_type  = "e2-standard-8"
gcp_node_pool_min_count     = 2
gcp_node_pool_max_count     = 10
gcp_node_pool_initial_count = 3

# Azure Configuration
azure_subscription_id = "your-azure-subscription-id"
azure_location        = "East US"
azure_vnet_cidr       = "10.2.0.0/16"

# Azure AKS Configuration
azure_cluster_version      = "1.28"
azure_node_pool_vm_size    = "Standard_D4s_v3"
azure_node_pool_min_count  = 2
azure_node_pool_max_count  = 10
azure_node_pool_node_count = 3

# Feature Flags
enable_serverless        = true
enable_monitoring        = true
enable_logging           = true
enable_security_scanning = true
enable_network_policies  = true
enable_spot_instances    = true
enable_auto_scaling      = true
enable_backup            = true
enable_ssl               = true

# Serverless Configuration
serverless_runtime = "go1.x"

# Domain Configuration
domain_name = "hackai.com"

# Backup and Disaster Recovery
backup_retention_days      = 30
enable_cross_region_backup = true

# Cost Optimization Settings
# AWS Spot Instance Configuration
aws_spot_instance_types = [
  "m5.xlarge",
  "m5a.xlarge",
  "m5d.xlarge",
  "m5n.xlarge",
  "c5.xlarge",
  "c5a.xlarge"
]

# Production-specific settings
enable_deletion_protection  = true
enable_enhanced_monitoring  = true
enable_performance_insights = true

# Security Settings
enable_encryption_at_rest    = true
enable_encryption_in_transit = true
enable_vpc_flow_logs         = true
enable_cloudtrail            = true
enable_config_rules          = true

# Compliance Settings
enable_compliance_scanning = true
compliance_frameworks = [
  "SOC2",
  "ISO27001",
  "GDPR",
  "HIPAA"
]

# Monitoring and Alerting
enable_detailed_monitoring = true
enable_custom_metrics      = true
enable_alerting            = true
alert_email                = "alerts@hackai.com"
slack_webhook_url          = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

# Performance Settings
enable_performance_monitoring = true
enable_apm                    = true
enable_distributed_tracing    = true

# Scaling Configuration
auto_scaling_target_cpu          = 70
auto_scaling_target_memory       = 80
auto_scaling_scale_up_cooldown   = "5m"
auto_scaling_scale_down_cooldown = "10m"

# Network Configuration
enable_private_endpoints = true
enable_service_mesh      = true
service_mesh_type        = "istio"

# Storage Configuration
enable_backup_encryption        = true
backup_schedule                 = "0 2 * * *" # Daily at 2 AM
backup_cross_region_replication = true

# Disaster Recovery
enable_disaster_recovery = true
dr_region_aws            = "us-east-1"
dr_region_gcp            = "us-east1"
dr_region_azure          = "West US"
rto_minutes              = 60 # Recovery Time Objective
rpo_minutes              = 15 # Recovery Point Objective

# Load Balancing
enable_global_load_balancer      = true
enable_health_checks             = true
health_check_interval            = "30s"
health_check_timeout             = "5s"
health_check_healthy_threshold   = 2
health_check_unhealthy_threshold = 3

# CDN Configuration
enable_cdn           = true
cdn_cache_ttl        = 3600
cdn_compress_content = true

# API Gateway Configuration
enable_api_gateway         = true
api_gateway_throttle_rate  = 1000
api_gateway_throttle_burst = 2000

# Database Configuration
enable_read_replicas     = true
read_replica_count       = 2
enable_automated_backups = true
backup_window            = "03:00-04:00"
maintenance_window       = "sun:04:00-sun:05:00"

# Cache Configuration
enable_cache_clustering = true
cache_node_count        = 3
enable_cache_backup     = true

# Logging Configuration
log_retention_days     = 90
enable_log_aggregation = true
enable_log_analysis    = true

# Security Scanning
enable_vulnerability_scanning = true
enable_container_scanning     = true
enable_secrets_scanning       = true
security_scan_schedule        = "0 1 * * *" # Daily at 1 AM

# Cost Management
enable_cost_monitoring = true
enable_budget_alerts   = true
monthly_budget_limit   = 5000 # USD
budget_alert_threshold = 80   # Percentage

# Resource Tagging
additional_tags = {
  CostCenter  = "Engineering"
  Project     = "HackAI"
  Environment = "Production"
  Owner       = "Platform-Team"
  Backup      = "Required"
  Monitoring  = "Critical"
  Compliance  = "Required"
}
