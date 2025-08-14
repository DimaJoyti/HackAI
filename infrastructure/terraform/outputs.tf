# Outputs for HackAI Infrastructure

# VPC Outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = module.vpc.vpc_cidr_block
}

output "private_subnets" {
  description = "List of IDs of private subnets"
  value       = module.vpc.private_subnets
}

output "public_subnets" {
  description = "List of IDs of public subnets"
  value       = module.vpc.public_subnets
}

output "nat_gateway_ids" {
  description = "List of IDs of the NAT Gateways"
  value       = module.vpc.natgw_ids
}

# EKS Outputs
output "cluster_id" {
  description = "EKS cluster ID"
  value       = module.eks.cluster_id
}

output "cluster_arn" {
  description = "EKS cluster ARN"
  value       = module.eks.cluster_arn
}

output "cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.eks.cluster_endpoint
}

output "cluster_version" {
  description = "The Kubernetes version for the EKS cluster"
  value       = module.eks.cluster_version
}

output "cluster_platform_version" {
  description = "Platform version for the EKS cluster"
  value       = module.eks.cluster_platform_version
}

output "cluster_status" {
  description = "Status of the EKS cluster"
  value       = module.eks.cluster_status
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = module.eks.cluster_security_group_id
}

output "node_security_group_id" {
  description = "ID of the EKS node shared security group"
  value       = module.eks.node_security_group_id
}

output "oidc_provider_arn" {
  description = "The ARN of the OIDC Provider if enabled"
  value       = module.eks.oidc_provider_arn
}

# Database Outputs
output "db_instance_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.hackai.endpoint
  sensitive   = true
}

output "db_instance_id" {
  description = "RDS instance ID"
  value       = aws_db_instance.hackai.id
}

output "db_instance_port" {
  description = "RDS instance port"
  value       = aws_db_instance.hackai.port
}

output "db_instance_name" {
  description = "RDS instance name"
  value       = aws_db_instance.hackai.db_name
}

output "db_instance_username" {
  description = "RDS instance root username"
  value       = aws_db_instance.hackai.username
  sensitive   = true
}

output "db_instance_password" {
  description = "RDS instance password"
  value       = random_password.db_password.result
  sensitive   = true
}

# Redis Outputs
output "redis_cluster_id" {
  description = "ElastiCache Redis cluster ID"
  value       = aws_elasticache_replication_group.hackai.id
}

output "redis_primary_endpoint" {
  description = "ElastiCache Redis primary endpoint"
  value       = aws_elasticache_replication_group.hackai.primary_endpoint_address
  sensitive   = true
}

output "redis_reader_endpoint" {
  description = "ElastiCache Redis reader endpoint"
  value       = aws_elasticache_replication_group.hackai.reader_endpoint_address
  sensitive   = true
}

output "redis_port" {
  description = "ElastiCache Redis port"
  value       = aws_elasticache_replication_group.hackai.port
}

output "redis_auth_token" {
  description = "ElastiCache Redis auth token"
  value       = random_password.redis_password.result
  sensitive   = true
}

# Load Balancer Outputs
output "load_balancer_arn" {
  description = "ARN of the load balancer"
  value       = aws_lb.hackai.arn
}

output "load_balancer_dns_name" {
  description = "DNS name of the load balancer"
  value       = aws_lb.hackai.dns_name
}

output "load_balancer_zone_id" {
  description = "Zone ID of the load balancer"
  value       = aws_lb.hackai.zone_id
}

# S3 Outputs
output "s3_bucket_data" {
  description = "Name of the S3 bucket for application data"
  value       = aws_s3_bucket.hackai_data.bucket
}

output "s3_bucket_alb_logs" {
  description = "Name of the S3 bucket for ALB logs"
  value       = aws_s3_bucket.alb_logs.bucket
}

# DNS Outputs (if managing DNS)
output "route53_zone_id" {
  description = "Route53 zone ID"
  value       = var.manage_dns ? aws_route53_zone.hackai[0].zone_id : null
}

output "route53_zone_name" {
  description = "Route53 zone name"
  value       = var.manage_dns ? aws_route53_zone.hackai[0].name : null
}

output "route53_name_servers" {
  description = "Route53 name servers"
  value       = var.manage_dns ? aws_route53_zone.hackai[0].name_servers : null
}

# Certificate Outputs (if managing DNS)
output "acm_certificate_arn" {
  description = "ARN of the ACM certificate"
  value       = var.manage_dns ? aws_acm_certificate.hackai[0].arn : null
}

output "acm_certificate_status" {
  description = "Status of the ACM certificate"
  value       = var.manage_dns ? aws_acm_certificate.hackai[0].status : null
}

# Security Group Outputs
output "rds_security_group_id" {
  description = "ID of the RDS security group"
  value       = aws_security_group.rds.id
}

output "redis_security_group_id" {
  description = "ID of the Redis security group"
  value       = aws_security_group.redis.id
}

output "alb_security_group_id" {
  description = "ID of the ALB security group"
  value       = aws_security_group.alb.id
}

# CloudWatch Outputs
output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group"
  value       = aws_cloudwatch_log_group.hackai.name
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group"
  value       = aws_cloudwatch_log_group.hackai.arn
}

# Kubectl Configuration
output "kubectl_config" {
  description = "kubectl config as generated by the module"
  value = templatefile("${path.module}/templates/kubeconfig.tpl", {
    cluster_name     = module.eks.cluster_name
    cluster_endpoint = module.eks.cluster_endpoint
    cluster_ca       = module.eks.cluster_certificate_authority_data
    aws_region       = var.aws_region
  })
  sensitive = true
}

# Connection Information
output "connection_info" {
  description = "Connection information for the deployed infrastructure"
  value = {
    cluster_name     = module.eks.cluster_name
    cluster_endpoint = module.eks.cluster_endpoint
    db_endpoint      = aws_db_instance.hackai.endpoint
    redis_endpoint   = aws_elasticache_replication_group.hackai.primary_endpoint_address
    load_balancer    = aws_lb.hackai.dns_name
    s3_bucket        = aws_s3_bucket.hackai_data.bucket
  }
  sensitive = true
}

# Environment Configuration
output "environment_config" {
  description = "Environment configuration for applications"
  value = {
    environment = var.environment
    aws_region  = var.aws_region
    domain_name = var.domain_name
    
    database = {
      host     = aws_db_instance.hackai.endpoint
      port     = aws_db_instance.hackai.port
      name     = aws_db_instance.hackai.db_name
      username = aws_db_instance.hackai.username
    }
    
    redis = {
      host = aws_elasticache_replication_group.hackai.primary_endpoint_address
      port = aws_elasticache_replication_group.hackai.port
    }
    
    storage = {
      bucket = aws_s3_bucket.hackai_data.bucket
    }
    
    monitoring = {
      log_group = aws_cloudwatch_log_group.hackai.name
    }
  }
  sensitive = true
}

# Deployment Commands
output "deployment_commands" {
  description = "Commands to deploy applications"
  value = {
    kubectl_config = "aws eks update-kubeconfig --region ${var.aws_region} --name ${module.eks.cluster_name}"
    helm_install   = "helm install hackai ./deployments/helm/hackai --namespace hackai --create-namespace"
    kubectl_apply  = "kubectl apply -f ./deployments/kubernetes/ --namespace hackai"
  }
}

# Monitoring URLs (when deployed)
output "monitoring_urls" {
  description = "URLs for monitoring services (after deployment)"
  value = var.manage_dns ? {
    grafana    = "https://monitoring.${var.domain_name}/grafana"
    prometheus = "https://monitoring.${var.domain_name}/prometheus"
    jaeger     = "https://monitoring.${var.domain_name}/jaeger"
  } : {
    grafana    = "https://${aws_lb.hackai.dns_name}/grafana"
    prometheus = "https://${aws_lb.hackai.dns_name}/prometheus"
    jaeger     = "https://${aws_lb.hackai.dns_name}/jaeger"
  }
}

# Application URLs (when deployed)
output "application_urls" {
  description = "URLs for the application (after deployment)"
  value = var.manage_dns ? {
    api = "https://api.${var.domain_name}"
    web = "https://app.${var.domain_name}"
  } : {
    api = "https://${aws_lb.hackai.dns_name}/api"
    web = "https://${aws_lb.hackai.dns_name}"
  }
}
