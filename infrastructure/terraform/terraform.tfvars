# Example Terraform variables file for HackAI infrastructure
# Copy this file to terraform.tfvars and customize the values

# Basic Configuration
aws_region  = "us-west-2"
environment = "production"

# Domain Configuration
domain_name = "hackai.com"
manage_dns  = false  # Set to true if you want Terraform to manage Route53

# Database Configuration
db_instance_class = "db.t3.small"  # Use larger instance for production
redis_node_type   = "cache.t3.micro"

# Node Group Configuration
node_group_instance_types = ["m5.large", "m5a.large", "m5d.large"]
node_group_min_size       = 2
node_group_max_size       = 10
node_group_desired_size   = 3

# Enable spot instances for cost optimization
enable_spot_instances = true
spot_instance_types   = ["m5.large", "m5a.large", "m5d.large", "m4.large"]

# Monitoring and Observability
enable_monitoring = true
enable_logging    = true

# Security Features
enable_network_policies      = true
enable_pod_security_policies = true
enable_encryption           = true

# Backup and Retention
backup_retention_days              = 7
cloudwatch_log_retention_days      = 30
performance_insights_retention_period = 7

# Cost Management
enable_cost_anomaly_detection = true
cost_anomaly_threshold       = 100

# Notifications
notification_email = "admin@hackai.com"
# slack_webhook_url = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

# Additional tags
tags = {
  Project     = "HackAI"
  Owner       = "DevOps Team"
  Environment = "production"
  CostCenter  = "Engineering"
}
