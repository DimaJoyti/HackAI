# Enhanced AWS EKS Module with Advanced Features

# Data sources
data "aws_availability_zones" "available" {
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_caller_identity" "current" {}

# KMS Key for EKS encryption
resource "aws_kms_key" "eks" {
  count = var.enable_encryption ? 1 : 0
  
  description             = "EKS Secret Encryption Key for ${var.cluster_name}"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-eks-encryption-key"
  })
}

resource "aws_kms_alias" "eks" {
  count = var.enable_encryption ? 1 : 0
  
  name          = "alias/${var.cluster_name}-eks-encryption"
  target_key_id = aws_kms_key.eks[0].key_id
}

# Enhanced EKS Cluster with all features
resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  role_arn = aws_iam_role.cluster.arn
  version  = var.kubernetes_version

  vpc_config {
    subnet_ids              = concat(module.vpc.public_subnets, module.vpc.private_subnets)
    endpoint_private_access = var.endpoint_private_access
    endpoint_public_access  = var.endpoint_public_access
    public_access_cidrs     = var.public_access_cidrs
    security_group_ids      = [aws_security_group.cluster.id]
  }

  # Enable all logging types
  enabled_cluster_log_types = var.enabled_cluster_log_types

  # Encryption configuration
  dynamic "encryption_config" {
    for_each = var.enable_encryption ? [1] : []
    content {
      provider {
        key_arn = aws_kms_key.eks[0].arn
      }
      resources = ["secrets"]
    }
  }

  # Add-ons configuration
  depends_on = [
    aws_iam_role_policy_attachment.cluster_AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.cluster_AmazonEKSVPCResourceController,
    aws_cloudwatch_log_group.cluster,
  ]

  tags = merge(var.tags, {
    Name = var.cluster_name
  })
}

# CloudWatch Log Group for EKS
resource "aws_cloudwatch_log_group" "cluster" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.enable_encryption ? aws_kms_key.eks[0].arn : null

  tags = var.tags
}

# Enhanced Security Group for EKS Cluster
resource "aws_security_group" "cluster" {
  name_prefix = "${var.cluster_name}-cluster-"
  vpc_id      = module.vpc.vpc_id
  description = "Security group for EKS cluster ${var.cluster_name}"

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  # Allow inbound traffic from node groups (will be added via separate rule)
  # Removed to avoid circular dependency

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-cluster-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Enhanced Security Group for Node Groups
resource "aws_security_group" "node_group" {
  name_prefix = "${var.cluster_name}-node-"
  vpc_id      = module.vpc.vpc_id
  description = "Security group for EKS node groups in cluster ${var.cluster_name}"

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  # Allow inbound traffic from cluster (will be added via separate rule)
  # Removed to avoid circular dependency

  # Allow node-to-node communication
  ingress {
    from_port = 0
    to_port   = 65535
    protocol  = "tcp"
    self      = true
    description = "Allow node-to-node communication"
  }

  # Allow HTTPS from cluster (will be added via separate rule)
  # Removed to avoid circular dependency

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-node-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Separate security group rules to avoid circular dependencies
resource "aws_security_group_rule" "cluster_ingress_node_https" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.node_group.id
  security_group_id        = aws_security_group.cluster.id
  description              = "Allow HTTPS from node groups"
}

resource "aws_security_group_rule" "node_ingress_cluster" {
  type                     = "ingress"
  from_port                = 1025
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.cluster.id
  security_group_id        = aws_security_group.node_group.id
  description              = "Allow traffic from cluster"
}

resource "aws_security_group_rule" "node_ingress_cluster_https" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.cluster.id
  security_group_id        = aws_security_group.node_group.id
  description              = "Allow HTTPS from cluster"
}

# Enhanced Node Groups with multiple configurations
resource "aws_eks_node_group" "main" {
  for_each = var.node_groups

  cluster_name    = aws_eks_cluster.main.name
  node_group_name = each.key
  node_role_arn   = aws_iam_role.node_group.arn
  subnet_ids      = module.vpc.private_subnets

  # Instance configuration
  instance_types = each.value.instance_types
  ami_type       = each.value.ami_type
  capacity_type  = each.value.capacity_type
  disk_size      = each.value.disk_size

  # Scaling configuration
  scaling_config {
    desired_size = each.value.desired_size
    max_size     = each.value.max_size
    min_size     = each.value.min_size
  }

  # Update configuration
  update_config {
    max_unavailable_percentage = each.value.max_unavailable_percentage
  }

  # Launch template configuration
  dynamic "launch_template" {
    for_each = each.value.launch_template != null ? [each.value.launch_template] : []
    content {
      id      = launch_template.value.id
      version = launch_template.value.version
    }
  }

  # Remote access configuration
  dynamic "remote_access" {
    for_each = each.value.enable_remote_access ? [1] : []
    content {
      ec2_ssh_key               = each.value.ssh_key_name
      source_security_group_ids = [aws_security_group.node_group.id]
    }
  }

  # Taints configuration
  dynamic "taint" {
    for_each = each.value.taints
    content {
      key    = taint.value.key
      value  = taint.value.value
      effect = taint.value.effect
    }
  }

  labels = merge(each.value.labels, {
    "node-group" = each.key
  })

  tags = merge(var.tags, each.value.tags, {
    Name = "${var.cluster_name}-${each.key}"
  })

  depends_on = [
    aws_iam_role_policy_attachment.node_group_AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.node_group_AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.node_group_AmazonEC2ContainerRegistryReadOnly,
  ]

  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }
}

# Fargate Profiles for serverless workloads
resource "aws_eks_fargate_profile" "main" {
  for_each = var.fargate_profiles

  cluster_name           = aws_eks_cluster.main.name
  fargate_profile_name   = each.key
  pod_execution_role_arn = aws_iam_role.fargate_profile.arn
  subnet_ids             = module.vpc.private_subnets

  dynamic "selector" {
    for_each = each.value.selectors
    content {
      namespace = selector.value.namespace
      labels    = selector.value.labels
    }
  }

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-${each.key}"
  })

  depends_on = [
    aws_iam_role_policy_attachment.fargate_profile_AmazonEKSFargatePodExecutionRolePolicy,
  ]
}

# EKS Add-ons
resource "aws_eks_addon" "main" {
  for_each = var.cluster_addons

  cluster_name                    = aws_eks_cluster.main.name
  addon_name                      = each.key
  addon_version                   = each.value.version
  resolve_conflicts_on_create     = try(each.value.resolve_conflicts, "OVERWRITE")
  resolve_conflicts_on_update     = try(each.value.resolve_conflicts, "OVERWRITE")
  service_account_role_arn        = each.value.service_account_role_arn

  tags = var.tags

  depends_on = [
    aws_eks_node_group.main,
    aws_eks_fargate_profile.main,
  ]
}

# OIDC Identity Provider for IRSA
data "tls_certificate" "cluster" {
  url = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "cluster" {
  count = var.enable_irsa ? 1 : 0

  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.cluster.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-irsa"
  })
}

# Cluster Autoscaler IAM Role (example IRSA role)
resource "aws_iam_role" "cluster_autoscaler" {
  count = var.enable_cluster_autoscaler ? 1 : 0

  name = "${var.cluster_name}-cluster-autoscaler"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = var.enable_irsa ? aws_iam_openid_connect_provider.cluster[0].arn : null
        }
        Condition = {
          StringEquals = {
            "${replace(aws_eks_cluster.main.identity[0].oidc[0].issuer, "https://", "")}:sub" = "system:serviceaccount:kube-system:cluster-autoscaler"
            "${replace(aws_eks_cluster.main.identity[0].oidc[0].issuer, "https://", "")}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "cluster_autoscaler" {
  count = var.enable_cluster_autoscaler ? 1 : 0

  name = "${var.cluster_name}-cluster-autoscaler"
  role = aws_iam_role.cluster_autoscaler[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:DescribeAutoScalingInstances",
          "autoscaling:DescribeLaunchConfigurations",
          "autoscaling:DescribeTags",
          "autoscaling:SetDesiredCapacity",
          "autoscaling:TerminateInstanceInAutoScalingGroup",
          "ec2:DescribeLaunchTemplateVersions"
        ]
        Resource = "*"
      }
    ]
  })
}
