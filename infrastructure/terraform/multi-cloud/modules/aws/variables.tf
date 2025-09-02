# Enhanced AWS EKS Module Variables

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

variable "kubernetes_version" {
  description = "Kubernetes version for the EKS cluster"
  type        = string
  default     = "1.28"
}

variable "vpc_id" {
  description = "ID of the VPC where the cluster will be created"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for the EKS cluster"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for node groups"
  type        = list(string)
}

variable "endpoint_private_access" {
  description = "Enable private API server endpoint"
  type        = bool
  default     = true
}

variable "endpoint_public_access" {
  description = "Enable public API server endpoint"
  type        = bool
  default     = true
}

variable "public_access_cidrs" {
  description = "List of CIDR blocks that can access the public endpoint"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "enabled_cluster_log_types" {
  description = "List of control plane logging to enable"
  type        = list(string)
  default     = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
}

variable "log_retention_days" {
  description = "Number of days to retain cluster logs"
  type        = number
  default     = 7
}

variable "enable_encryption" {
  description = "Enable encryption for EKS secrets"
  type        = bool
  default     = true
}

variable "enable_irsa" {
  description = "Enable IAM Roles for Service Accounts"
  type        = bool
  default     = true
}

variable "enable_cluster_autoscaler" {
  description = "Enable cluster autoscaler IAM role"
  type        = bool
  default     = true
}

variable "node_groups" {
  description = "Map of EKS node group configurations"
  type = map(object({
    instance_types               = list(string)
    ami_type                    = string
    capacity_type               = string
    disk_size                   = number
    desired_size                = number
    max_size                    = number
    min_size                    = number
    max_unavailable_percentage  = number
    enable_remote_access        = bool
    ssh_key_name               = string
    labels                     = map(string)
    taints = list(object({
      key    = string
      value  = string
      effect = string
    }))
    tags = map(string)
    launch_template = object({
      id      = string
      version = string
    })
  }))
  default = {}
}

variable "fargate_profiles" {
  description = "Map of EKS Fargate profile configurations"
  type = map(object({
    selectors = list(object({
      namespace = string
      labels    = map(string)
    }))
  }))
  default = {}
}

variable "cluster_addons" {
  description = "Map of cluster addon configurations"
  type = map(object({
    version                  = string
    resolve_conflicts        = string
    service_account_role_arn = string
  }))
  default = {
    coredns = {
      version                  = null
      resolve_conflicts        = "OVERWRITE"
      service_account_role_arn = null
    }
    kube-proxy = {
      version                  = null
      resolve_conflicts        = "OVERWRITE"
      service_account_role_arn = null
    }
    vpc-cni = {
      version                  = null
      resolve_conflicts        = "OVERWRITE"
      service_account_role_arn = null
    }
    aws-ebs-csi-driver = {
      version                  = null
      resolve_conflicts        = "OVERWRITE"
      service_account_role_arn = null
    }
  }
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}

# RDS Variables
variable "enable_rds" {
  description = "Enable RDS database"
  type        = bool
  default     = true
}

variable "rds_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.medium"
}

variable "rds_engine" {
  description = "RDS engine type"
  type        = string
  default     = "postgres"
}

variable "rds_engine_version" {
  description = "RDS engine version"
  type        = string
  default     = "15.4"
}

variable "rds_allocated_storage" {
  description = "RDS allocated storage in GB"
  type        = number
  default     = 100
}

variable "rds_max_allocated_storage" {
  description = "RDS maximum allocated storage in GB"
  type        = number
  default     = 1000
}

variable "rds_multi_az" {
  description = "Enable RDS Multi-AZ deployment"
  type        = bool
  default     = true
}

variable "rds_backup_retention_period" {
  description = "RDS backup retention period in days"
  type        = number
  default     = 7
}

variable "rds_backup_window" {
  description = "RDS backup window"
  type        = string
  default     = "03:00-04:00"
}

variable "rds_maintenance_window" {
  description = "RDS maintenance window"
  type        = string
  default     = "sun:04:00-sun:05:00"
}

variable "rds_deletion_protection" {
  description = "Enable RDS deletion protection"
  type        = bool
  default     = true
}

variable "rds_skip_final_snapshot" {
  description = "Skip final snapshot when deleting RDS"
  type        = bool
  default     = false
}

# ElastiCache Variables
variable "enable_elasticache" {
  description = "Enable ElastiCache Redis cluster"
  type        = bool
  default     = true
}

variable "elasticache_node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.t3.micro"
}

variable "elasticache_num_cache_nodes" {
  description = "Number of cache nodes"
  type        = number
  default     = 2
}

variable "elasticache_parameter_group_name" {
  description = "ElastiCache parameter group name"
  type        = string
  default     = "default.redis7"
}

variable "elasticache_port" {
  description = "ElastiCache port"
  type        = number
  default     = 6379
}

variable "elasticache_maintenance_window" {
  description = "ElastiCache maintenance window"
  type        = string
  default     = "sun:05:00-sun:06:00"
}

variable "elasticache_snapshot_retention_limit" {
  description = "ElastiCache snapshot retention limit"
  type        = number
  default     = 5
}

variable "elasticache_snapshot_window" {
  description = "ElastiCache snapshot window"
  type        = string
  default     = "06:00-07:00"
}

# S3 Variables
variable "enable_s3" {
  description = "Enable S3 buckets"
  type        = bool
  default     = true
}

variable "s3_bucket_names" {
  description = "List of S3 bucket names to create"
  type        = list(string)
  default     = ["artifacts", "backups", "logs"]
}

variable "s3_enable_versioning" {
  description = "Enable S3 bucket versioning"
  type        = bool
  default     = true
}

variable "s3_enable_encryption" {
  description = "Enable S3 bucket encryption"
  type        = bool
  default     = true
}

variable "s3_lifecycle_rules" {
  description = "S3 lifecycle rules"
  type = list(object({
    id     = string
    status = string
    expiration = object({
      days = number
    })
    noncurrent_version_expiration = object({
      days = number
    })
  }))
  default = [
    {
      id     = "delete_old_versions"
      status = "Enabled"
      expiration = {
        days = 365
      }
      noncurrent_version_expiration = {
        days = 30
      }
    }
  ]
}

# CloudWatch Variables
variable "enable_cloudwatch" {
  description = "Enable CloudWatch monitoring"
  type        = bool
  default     = true
}

variable "cloudwatch_log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

# Route53 Variables
variable "enable_route53" {
  description = "Enable Route53 hosted zone"
  type        = bool
  default     = false
}

variable "domain_name" {
  description = "Domain name for Route53 hosted zone"
  type        = string
  default     = ""
}

# ALB Variables
variable "enable_alb" {
  description = "Enable Application Load Balancer"
  type        = bool
  default     = true
}

variable "alb_internal" {
  description = "Create internal ALB"
  type        = bool
  default     = false
}

variable "alb_enable_deletion_protection" {
  description = "Enable ALB deletion protection"
  type        = bool
  default     = true
}

# WAF Variables
variable "enable_waf" {
  description = "Enable AWS WAF"
  type        = bool
  default     = true
}

variable "waf_rate_limit" {
  description = "WAF rate limit per 5 minutes"
  type        = number
  default     = 2000
}
