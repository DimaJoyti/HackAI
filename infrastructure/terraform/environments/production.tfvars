# Production environment configuration for HackAI

# Basic Configuration
environment = "production"
aws_region  = "us-west-2"

# Domain Configuration
domain_name = "hackai.com"
manage_dns  = true  # Manage DNS in production

# Database Configuration (production-grade instances)
db_instance_class = "db.r6g.large"
redis_node_type   = "cache.r6g.large"

# Node Group Configuration (production-grade)
node_group_instance_types = ["m5.xlarge", "m5a.xlarge", "m5d.xlarge"]
node_group_min_size       = 3
node_group_max_size       = 20
node_group_desired_size   = 5

# Mixed instance strategy for production
enable_spot_instances = true
spot_instance_types   = ["m5.xlarge", "m5a.xlarge", "m5d.xlarge", "m5n.xlarge"]

# Full monitoring and observability for production
enable_monitoring = true
enable_logging    = true

# Maximum security for production
enable_network_policies      = true
enable_pod_security_policies = true
enable_encryption           = true
enable_guardduty            = true
enable_config               = true
enable_cloudtrail           = true
enable_security_hub         = true
enable_inspector            = true
enable_waf                  = true

# Production backup and retention
backup_retention_days              = 30
cloudwatch_log_retention_days      = 90
performance_insights_retention_period = 731  # 2 years

# Maximum protection for production
enable_multi_az                = true
enable_deletion_protection     = true
enable_enhanced_monitoring     = true
enable_performance_insights    = true

# Advanced features for production
enable_cluster_autoscaler           = true
enable_metrics_server              = true
enable_aws_load_balancer_controller = true
enable_external_dns                = true
enable_cert_manager                = true
enable_ingress_nginx               = true
enable_velero                      = true
enable_opa_gatekeeper              = true

# Cost Management
enable_cost_anomaly_detection = true
cost_anomaly_threshold       = 500

# Production notifications
notification_email = "ops-team@hackai.com"
# slack_webhook_url = "https://hooks.slack.com/services/YOUR/PRODUCTION/WEBHOOK"

# Production-specific tags
tags = {
  Project     = "HackAI"
  Owner       = "Operations Team"
  Environment = "production"
  CostCenter  = "Engineering"
  Criticality = "high"
  Compliance  = "required"
}
