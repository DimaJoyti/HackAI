# Variables for HackAI Infrastructure

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-west-2"
}

variable "environment" {
  description = "Environment name (development, staging, production)"
  type        = string
  default     = "production"
  
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be one of: development, staging, production."
  }
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.micro"
  
  validation {
    condition = can(regex("^db\\.", var.db_instance_class))
    error_message = "DB instance class must start with 'db.'."
  }
}

variable "redis_node_type" {
  description = "ElastiCache Redis node type"
  type        = string
  default     = "cache.t3.micro"
  
  validation {
    condition = can(regex("^cache\\.", var.redis_node_type))
    error_message = "Redis node type must start with 'cache.'."
  }
}

variable "domain_name" {
  description = "Domain name for the application"
  type        = string
  default     = "hackai.com"
}

variable "manage_dns" {
  description = "Whether to manage DNS with Route53"
  type        = bool
  default     = false
}

variable "enable_monitoring" {
  description = "Enable monitoring stack (Prometheus, Grafana, Jaeger)"
  type        = bool
  default     = true
}

variable "enable_logging" {
  description = "Enable centralized logging (ELK stack)"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Number of days to retain backups"
  type        = number
  default     = 7
  
  validation {
    condition     = var.backup_retention_days >= 1 && var.backup_retention_days <= 35
    error_message = "Backup retention days must be between 1 and 35."
  }
}

variable "node_group_instance_types" {
  description = "Instance types for EKS node groups"
  type        = list(string)
  default     = ["m5.large", "m5a.large", "m5d.large"]
}

variable "node_group_min_size" {
  description = "Minimum size of the node group"
  type        = number
  default     = 2
}

variable "node_group_max_size" {
  description = "Maximum size of the node group"
  type        = number
  default     = 10
}

variable "node_group_desired_size" {
  description = "Desired size of the node group"
  type        = number
  default     = 3
}

variable "enable_spot_instances" {
  description = "Enable spot instances for cost optimization"
  type        = bool
  default     = true
}

variable "spot_instance_types" {
  description = "Instance types for spot instances"
  type        = list(string)
  default     = ["m5.large", "m5a.large", "m5d.large", "m4.large"]
}

variable "enable_cluster_autoscaler" {
  description = "Enable cluster autoscaler"
  type        = bool
  default     = true
}

variable "enable_metrics_server" {
  description = "Enable metrics server"
  type        = bool
  default     = true
}

variable "enable_aws_load_balancer_controller" {
  description = "Enable AWS Load Balancer Controller"
  type        = bool
  default     = true
}

variable "enable_external_dns" {
  description = "Enable External DNS"
  type        = bool
  default     = false
}

variable "enable_cert_manager" {
  description = "Enable cert-manager for automatic TLS certificates"
  type        = bool
  default     = true
}

variable "enable_ingress_nginx" {
  description = "Enable NGINX Ingress Controller"
  type        = bool
  default     = true
}

variable "enable_velero" {
  description = "Enable Velero for backup and disaster recovery"
  type        = bool
  default     = false
}

variable "velero_backup_schedule" {
  description = "Velero backup schedule (cron format)"
  type        = string
  default     = "0 2 * * *"
}

variable "enable_network_policies" {
  description = "Enable Kubernetes network policies"
  type        = bool
  default     = true
}

variable "enable_pod_security_policies" {
  description = "Enable Pod Security Policies"
  type        = bool
  default     = true
}

variable "enable_falco" {
  description = "Enable Falco for runtime security monitoring"
  type        = bool
  default     = false
}

variable "enable_kube_bench" {
  description = "Enable kube-bench for CIS Kubernetes Benchmark"
  type        = bool
  default     = false
}

variable "enable_opa_gatekeeper" {
  description = "Enable OPA Gatekeeper for policy enforcement"
  type        = bool
  default     = false
}

variable "database_backup_window" {
  description = "Database backup window"
  type        = string
  default     = "03:00-04:00"
}

variable "database_maintenance_window" {
  description = "Database maintenance window"
  type        = string
  default     = "sun:04:00-sun:05:00"
}

variable "redis_backup_retention_limit" {
  description = "Redis backup retention limit"
  type        = number
  default     = 5
}

variable "cloudwatch_log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
  
  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653
    ], var.cloudwatch_log_retention_days)
    error_message = "CloudWatch log retention days must be a valid value."
  }
}

variable "enable_enhanced_monitoring" {
  description = "Enable enhanced monitoring for RDS"
  type        = bool
  default     = true
}

variable "monitoring_interval" {
  description = "Monitoring interval for RDS enhanced monitoring"
  type        = number
  default     = 60
  
  validation {
    condition     = contains([0, 1, 5, 10, 15, 30, 60], var.monitoring_interval)
    error_message = "Monitoring interval must be one of: 0, 1, 5, 10, 15, 30, 60."
  }
}

variable "enable_performance_insights" {
  description = "Enable Performance Insights for RDS"
  type        = bool
  default     = true
}

variable "performance_insights_retention_period" {
  description = "Performance Insights retention period"
  type        = number
  default     = 7
  
  validation {
    condition     = contains([7, 731], var.performance_insights_retention_period)
    error_message = "Performance Insights retention period must be 7 or 731 days."
  }
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection for critical resources"
  type        = bool
  default     = true
}

variable "enable_multi_az" {
  description = "Enable Multi-AZ deployment for RDS"
  type        = bool
  default     = true
}

variable "enable_encryption" {
  description = "Enable encryption for all supported resources"
  type        = bool
  default     = true
}

variable "kms_key_deletion_window" {
  description = "KMS key deletion window in days"
  type        = number
  default     = 7
  
  validation {
    condition     = var.kms_key_deletion_window >= 7 && var.kms_key_deletion_window <= 30
    error_message = "KMS key deletion window must be between 7 and 30 days."
  }
}

variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs"
  type        = bool
  default     = true
}

variable "vpc_flow_logs_retention" {
  description = "VPC Flow Logs retention in days"
  type        = number
  default     = 14
}

variable "enable_guardduty" {
  description = "Enable AWS GuardDuty"
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Enable AWS Config"
  type        = bool
  default     = true
}

variable "enable_cloudtrail" {
  description = "Enable AWS CloudTrail"
  type        = bool
  default     = true
}

variable "cloudtrail_retention_days" {
  description = "CloudTrail log retention in days"
  type        = number
  default     = 90
}

variable "enable_security_hub" {
  description = "Enable AWS Security Hub"
  type        = bool
  default     = true
}

variable "enable_inspector" {
  description = "Enable AWS Inspector"
  type        = bool
  default     = true
}

variable "enable_macie" {
  description = "Enable AWS Macie"
  type        = bool
  default     = false
}

variable "enable_waf" {
  description = "Enable AWS WAF"
  type        = bool
  default     = true
}

variable "waf_rate_limit" {
  description = "WAF rate limit per 5-minute period"
  type        = number
  default     = 2000
}

variable "enable_shield_advanced" {
  description = "Enable AWS Shield Advanced"
  type        = bool
  default     = false
}

variable "notification_email" {
  description = "Email address for notifications"
  type        = string
  default     = "admin@hackai.com"
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications"
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_cost_anomaly_detection" {
  description = "Enable AWS Cost Anomaly Detection"
  type        = bool
  default     = true
}

variable "cost_anomaly_threshold" {
  description = "Cost anomaly detection threshold in USD"
  type        = number
  default     = 100
}

variable "enable_trusted_advisor" {
  description = "Enable AWS Trusted Advisor notifications"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
