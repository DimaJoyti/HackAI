# Development environment configuration for HackAI

# Basic Configuration
environment = "development"
aws_region  = "us-west-2"

# Domain Configuration
domain_name = "dev.hackai.com"
manage_dns  = false

# Database Configuration (smaller instances for dev)
db_instance_class = "db.t3.micro"
redis_node_type   = "cache.t3.micro"

# Node Group Configuration (smaller for dev)
node_group_instance_types = ["t3.medium", "t3a.medium"]
node_group_min_size       = 1
node_group_max_size       = 3
node_group_desired_size   = 1

# Cost optimization for development
enable_spot_instances = true
spot_instance_types   = ["t3.medium", "t3a.medium", "t3.large"]

# Monitoring (basic for dev)
enable_monitoring = true
enable_logging    = false  # Disable expensive logging in dev

# Security (relaxed for dev)
enable_network_policies      = false
enable_pod_security_policies = false
enable_encryption           = true

# Backup and Retention (minimal for dev)
backup_retention_days              = 1
cloudwatch_log_retention_days      = 7
performance_insights_retention_period = 7

# Disable expensive features for dev
enable_multi_az                = false
enable_deletion_protection     = false
enable_enhanced_monitoring     = false
enable_performance_insights    = false

# Cost Management
enable_cost_anomaly_detection = false
cost_anomaly_threshold       = 50

# Notifications
notification_email = "dev-team@hackai.com"

# Development-specific tags
tags = {
  Project     = "HackAI"
  Owner       = "Development Team"
  Environment = "development"
  CostCenter  = "Engineering"
  AutoShutdown = "true"  # Can be used by automation to shut down dev resources
}
