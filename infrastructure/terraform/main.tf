# HackAI Infrastructure as Code
# Terraform configuration for deploying HackAI platform infrastructure

terraform {
  required_version = ">= 1.5"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.10"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
  
  backend "s3" {
    bucket         = "hackai-terraform-state"
    key            = "infrastructure/terraform.tfstate"
    region         = "us-west-2"
    encrypt        = true
    dynamodb_table = "hackai-terraform-locks"
  }
}

# Configure providers
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "HackAI"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "HackAI-Team"
    }
  }
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}

# Data sources
data "aws_availability_zones" "available" {
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_caller_identity" "current" {}

# Local values
locals {
  name            = "hackai-${var.environment}"
  cluster_version = "1.29"
  
  vpc_cidr = "10.0.0.0/16"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)
  
  tags = {
    Project     = "HackAI"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# VPC Module
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
  
  name = local.name
  cidr = local.vpc_cidr
  
  azs             = local.azs
  private_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k)]
  public_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 48)]
  intra_subnets   = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 52)]
  
  enable_nat_gateway   = true
  single_nat_gateway   = var.environment == "development"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  # VPC Flow Logs
  enable_flow_log                      = true
  create_flow_log_cloudwatch_iam_role  = true
  create_flow_log_cloudwatch_log_group = true
  
  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }
  
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }
  
  tags = local.tags
}

# EKS Module
module "eks" {
  source = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"
  
  cluster_name    = local.name
  cluster_version = local.cluster_version
  
  vpc_id                         = module.vpc.vpc_id
  subnet_ids                     = module.vpc.private_subnets
  cluster_endpoint_public_access = true
  
  # EKS Managed Node Groups
  eks_managed_node_groups = {
    main = {
      name = "main"
      
      instance_types = ["m5.large"]
      
      min_size     = 2
      max_size     = 10
      desired_size = 3
      
      pre_bootstrap_user_data = <<-EOT
        #!/bin/bash
        /etc/eks/bootstrap.sh ${local.name}
      EOT
      
      vpc_security_group_ids = [aws_security_group.additional.id]
      
      tags = {
        ExtraTag = "EKS managed node group"
      }
    }
    
    spot = {
      name = "spot"
      
      instance_types = ["m5.large", "m5a.large", "m5d.large"]
      capacity_type  = "SPOT"
      
      min_size     = 0
      max_size     = 5
      desired_size = 2
      
      vpc_security_group_ids = [aws_security_group.additional.id]
      
      tags = {
        ExtraTag = "EKS managed node group - spot instances"
      }
    }
  }
  
  # Enable cluster creator admin permissions
  enable_cluster_creator_admin_permissions = true

  # Cluster access entries
  access_entries = {
    admin = {
      kubernetes_groups = []
      principal_arn     = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"

      policy_associations = {
        admin = {
          policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = {
            type = "cluster"
          }
        }
      }
    }
  }
  
  # EKS Addons
  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
    aws-ebs-csi-driver = {
      most_recent = true
    }
  }
  
  tags = local.tags
}

# Additional security group for EKS nodes
resource "aws_security_group" "additional" {
  name_prefix = "${local.name}-additional"
  vpc_id      = module.vpc.vpc_id
  
  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16",
    ]
  }
  
  tags = local.tags
}

# RDS Subnet Group
resource "aws_db_subnet_group" "hackai" {
  name       = "${local.name}-db"
  subnet_ids = module.vpc.private_subnets
  
  tags = merge(local.tags, {
    Name = "${local.name}-db"
  })
}

# RDS Instance
resource "aws_db_instance" "hackai" {
  identifier = "${local.name}-db"
  
  engine         = "postgres"
  engine_version = "16.1"
  instance_class = var.db_instance_class
  
  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true
  
  db_name  = "hackai"
  username = "hackai"
  password = random_password.db_password.result
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.hackai.name
  
  backup_retention_period = var.environment == "production" ? 7 : 1
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  skip_final_snapshot = var.environment != "production"
  deletion_protection = var.environment == "production"
  
  performance_insights_enabled = true
  monitoring_interval         = 60
  monitoring_role_arn         = aws_iam_role.rds_monitoring.arn
  
  tags = merge(local.tags, {
    Name = "${local.name}-db"
  })
}

# RDS Security Group
resource "aws_security_group" "rds" {
  name_prefix = "${local.name}-rds"
  vpc_id      = module.vpc.vpc_id
  
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(local.tags, {
    Name = "${local.name}-rds"
  })
}

# ElastiCache Subnet Group
resource "aws_elasticache_subnet_group" "hackai" {
  name       = "${local.name}-cache"
  subnet_ids = module.vpc.private_subnets
}

# ElastiCache Redis Cluster
resource "aws_elasticache_replication_group" "hackai" {
  replication_group_id       = "${local.name}-redis"
  description                = "Redis cluster for HackAI"
  
  node_type            = var.redis_node_type
  port                 = 6379
  parameter_group_name = "default.redis7"
  
  num_cache_clusters = 2
  
  subnet_group_name  = aws_elasticache_subnet_group.hackai.name
  security_group_ids = [aws_security_group.redis.id]
  
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.redis_password.result
  
  automatic_failover_enabled = true
  multi_az_enabled          = true
  
  tags = local.tags
}

# Redis Security Group
resource "aws_security_group" "redis" {
  name_prefix = "${local.name}-redis"
  vpc_id      = module.vpc.vpc_id
  
  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(local.tags, {
    Name = "${local.name}-redis"
  })
}

# Random passwords
resource "random_password" "db_password" {
  length  = 16
  special = true
}

resource "random_password" "redis_password" {
  length  = 32
  special = false
}

# IAM Role for RDS monitoring
resource "aws_iam_role" "rds_monitoring" {
  name = "${local.name}-rds-monitoring"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })
  
  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# S3 Bucket for application data
resource "aws_s3_bucket" "hackai_data" {
  bucket = "${local.name}-data-${random_id.bucket_suffix.hex}"
  
  tags = local.tags
}

resource "aws_s3_bucket_versioning" "hackai_data" {
  bucket = aws_s3_bucket.hackai_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "hackai_data" {
  bucket = aws_s3_bucket.hackai_data.id
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "hackai_data" {
  bucket = aws_s3_bucket.hackai_data.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "hackai" {
  name              = "/aws/eks/${local.name}/cluster"
  retention_in_days = var.environment == "production" ? 30 : 7
  
  tags = local.tags
}

# Application Load Balancer
resource "aws_lb" "hackai" {
  name               = "${local.name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = module.vpc.public_subnets
  
  enable_deletion_protection = var.environment == "production"
  
  access_logs {
    bucket  = aws_s3_bucket.alb_logs.bucket
    prefix  = "alb"
    enabled = true
  }
  
  tags = local.tags
}

# ALB Security Group
resource "aws_security_group" "alb" {
  name_prefix = "${local.name}-alb"
  vpc_id      = module.vpc.vpc_id
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(local.tags, {
    Name = "${local.name}-alb"
  })
}

# S3 Bucket for ALB logs
resource "aws_s3_bucket" "alb_logs" {
  bucket = "${local.name}-alb-logs-${random_id.bucket_suffix.hex}"
  
  tags = local.tags
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_elb_service_account.main.id}:root"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs.arn}/*"
      }
    ]
  })
}

data "aws_elb_service_account" "main" {}

# Route53 Hosted Zone (if managing DNS)
resource "aws_route53_zone" "hackai" {
  count = var.manage_dns ? 1 : 0
  name  = var.domain_name
  
  tags = local.tags
}

# ACM Certificate
resource "aws_acm_certificate" "hackai" {
  count           = var.manage_dns ? 1 : 0
  domain_name     = var.domain_name
  subject_alternative_names = [
    "*.${var.domain_name}"
  ]
  validation_method = "DNS"
  
  lifecycle {
    create_before_destroy = true
  }
  
  tags = local.tags
}

# Certificate validation
resource "aws_acm_certificate_validation" "hackai" {
  count           = var.manage_dns ? 1 : 0
  certificate_arn = aws_acm_certificate.hackai[0].arn
  validation_record_fqdns = [
    for record in aws_route53_record.cert_validation : record.fqdn
  ]
}

resource "aws_route53_record" "cert_validation" {
  for_each = var.manage_dns ? {
    for dvo in aws_acm_certificate.hackai[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}
  
  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = aws_route53_zone.hackai[0].zone_id
}
