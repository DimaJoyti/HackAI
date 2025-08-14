# Staging environment configuration for HackAI

# Basic Configuration
environment = "staging"
aws_region  = "us-west-2"

# Domain Configuration
domain_name = "staging.hackai.com"
manage_dns  = false

# Database Configuration (medium instances for staging)
db_instance_class = "db.t3.small"
redis_node_type   = "cache.t3.small"

# Node Group Configuration (medium for staging)
node_group_instance_types = ["m5.large", "m5a.large"]
node_group_min_size       = 2
node_group_max_size       = 6
node_group_desired_size   = 2

# Cost optimization for staging
enable_spot_instances = true
spot_instance_types   = ["m5.large", "m5a.large", "m5d.large"]

# Monitoring (full monitoring for staging)
enable_monitoring = true
enable_logging    = true

# Security (production-like for staging)
enable_network_policies      = true
enable_pod_security_policies = true
enable_encryption           = true

# Backup and Retention (moderate for staging)
backup_retention_days              = 3
cloudwatch_log_retention_days      = 14
performance_insights_retention_period = 7

# Moderate protection for staging
enable_multi_az                = false  # Single AZ for cost savings
enable_deletion_protection     = false
enable_enhanced_monitoring     = true
enable_performance_insights    = true

# Cost Management
enable_cost_anomaly_detection = true
cost_anomaly_threshold       = 75

# Notifications
notification_email = "staging-team@hackai.com"

# Staging-specific tags
tags = {
  Project     = "HackAI"
  Owner       = "QA Team"
  Environment = "staging"
  CostCenter  = "Engineering"
  Purpose     = "testing"
}
