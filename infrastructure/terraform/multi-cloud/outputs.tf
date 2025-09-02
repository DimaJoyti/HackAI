# Multi-Cloud Infrastructure Outputs for HackAI

# Global Outputs
output "project_name" {
  description = "Project name"
  value       = var.project_name
}

output "environment" {
  description = "Environment name"
  value       = var.environment
}

output "primary_cloud" {
  description = "Primary cloud provider"
  value       = var.primary_cloud
}

# AWS Outputs
output "aws_infrastructure" {
  description = "AWS infrastructure details"
  value = var.enable_aws ? {
    region   = var.aws_region
    vpc_id   = module.aws_infrastructure[0].vpc_id
    vpc_cidr = module.aws_infrastructure[0].vpc_cidr

    # Networking
    public_subnets  = module.aws_infrastructure[0].public_subnets
    private_subnets = module.aws_infrastructure[0].private_subnets

    # EKS Cluster
    cluster_id       = module.aws_infrastructure[0].cluster_id
    cluster_arn      = module.aws_infrastructure[0].cluster_arn
    cluster_endpoint = module.aws_infrastructure[0].cluster_endpoint
    cluster_version  = module.aws_infrastructure[0].cluster_version

    # Database
    db_endpoint = module.aws_infrastructure[0].db_endpoint
    db_port     = module.aws_infrastructure[0].db_port

    # Cache
    redis_endpoint = module.aws_infrastructure[0].redis_endpoint
    redis_port     = module.aws_infrastructure[0].redis_port

    # Storage
    s3_bucket = module.aws_infrastructure[0].s3_bucket

    # Load Balancer
    alb_dns_name = module.aws_infrastructure[0].alb_dns_name
    alb_zone_id  = module.aws_infrastructure[0].alb_zone_id
  } : null
}

# GCP Outputs
output "gcp_infrastructure" {
  description = "GCP infrastructure details"
  value = var.enable_gcp ? {
    project_id = var.gcp_project_id
    region     = var.gcp_region

    # Networking
    vpc_name    = module.gcp_infrastructure[0].vpc_name
    vpc_id      = module.gcp_infrastructure[0].vpc_id
    subnet_name = module.gcp_infrastructure[0].subnet_name
    subnet_id   = module.gcp_infrastructure[0].subnet_id

    # GKE Cluster
    cluster_id       = module.gcp_infrastructure[0].cluster_id
    cluster_name     = module.gcp_infrastructure[0].cluster_name
    cluster_endpoint = module.gcp_infrastructure[0].cluster_endpoint
    cluster_location = module.gcp_infrastructure[0].cluster_location

    # Database
    database_connection_name = module.gcp_infrastructure[0].database_connection_name
    database_private_ip      = module.gcp_infrastructure[0].database_private_ip
    database_name            = module.gcp_infrastructure[0].database_name

    # Storage
    storage_bucket_name = module.gcp_infrastructure[0].storage_bucket_name
    storage_bucket_url  = module.gcp_infrastructure[0].storage_bucket_url

    # Service Account
    gke_service_account_email = module.gcp_infrastructure[0].gke_service_account_email
  } : null
}

# Azure Outputs
output "azure_infrastructure" {
  description = "Azure infrastructure details"
  value = var.enable_azure ? {
    subscription_id = var.azure_subscription_id
    location        = var.azure_location

    # Resource Group
    resource_group_name = module.azure_infrastructure[0].resource_group_name

    # Networking
    vnet_name   = module.azure_infrastructure[0].vnet_name
    vnet_id     = module.azure_infrastructure[0].vnet_id
    subnet_name = module.azure_infrastructure[0].subnet_name
    subnet_id   = module.azure_infrastructure[0].subnet_id

    # AKS Cluster
    cluster_id      = module.azure_infrastructure[0].cluster_id
    cluster_name    = module.azure_infrastructure[0].cluster_name
    cluster_fqdn    = module.azure_infrastructure[0].cluster_fqdn
    cluster_version = module.azure_infrastructure[0].cluster_version

    # Database
    db_fqdn = module.azure_infrastructure[0].db_fqdn
    db_port = module.azure_infrastructure[0].db_port

    # Cache
    redis_hostname = module.azure_infrastructure[0].redis_hostname
    redis_port     = module.azure_infrastructure[0].redis_port

    # Storage
    storage_account_name = module.azure_infrastructure[0].storage_account_name
    storage_container    = module.azure_infrastructure[0].storage_container

    # Load Balancer
    lb_public_ip = module.azure_infrastructure[0].lb_public_ip
  } : null
}

# Serverless Functions Outputs
output "serverless_functions" {
  description = "Serverless functions details"
  value = var.enable_serverless ? {
    # AWS Lambda
    aws_functions = var.enable_aws ? {
      function_names  = module.serverless_functions[0].aws_function_names
      function_arns   = module.serverless_functions[0].aws_function_arns
      api_gateway_url = module.serverless_functions[0].aws_api_gateway_url
    } : null

    # GCP Cloud Functions
    gcp_functions = var.enable_gcp ? {
      function_names = module.serverless_functions[0].gcp_function_names
      function_urls  = module.serverless_functions[0].gcp_function_urls
      pubsub_topic   = module.serverless_functions[0].gcp_pubsub_topic
    } : null

    # Azure Functions
    azure_functions = var.enable_azure ? {
      function_app_name    = module.serverless_functions[0].azure_function_app_name
      function_names       = module.serverless_functions[0].azure_function_names
      function_urls        = module.serverless_functions[0].azure_function_urls
      servicebus_namespace = module.serverless_functions[0].azure_servicebus_namespace
    } : null
  } : null
}

# Monitoring Outputs
output "monitoring" {
  description = "Cross-cloud monitoring details"
  value = var.enable_monitoring ? {
    # AWS CloudWatch
    aws_monitoring = var.enable_aws ? {
      log_group_name = module.cross_cloud_monitoring[0].aws_log_group_name
      dashboard_url  = module.cross_cloud_monitoring[0].aws_dashboard_url
    } : null

    # GCP Monitoring
    gcp_monitoring = var.enable_gcp ? {
      workspace_name = module.cross_cloud_monitoring[0].gcp_workspace_name
      dashboard_url  = module.cross_cloud_monitoring[0].gcp_dashboard_url
    } : null

    # Azure Monitor
    azure_monitoring = var.enable_azure ? {
      workspace_name = module.cross_cloud_monitoring[0].azure_workspace_name
      dashboard_url  = module.cross_cloud_monitoring[0].azure_dashboard_url
    } : null
  } : null
}

# Security Outputs
output "security" {
  description = "Cross-cloud security details"
  value = var.enable_security_scanning ? {
    # AWS Security
    aws_security = var.enable_aws ? {
      security_group_ids = module.cross_cloud_security[0].aws_security_group_ids
      iam_roles          = module.cross_cloud_security[0].aws_iam_roles
      kms_key_id         = module.cross_cloud_security[0].aws_kms_key_id
    } : null

    # GCP Security
    gcp_security = var.enable_gcp ? {
      firewall_rules   = module.cross_cloud_security[0].gcp_firewall_rules
      service_accounts = module.cross_cloud_security[0].gcp_service_accounts
      kms_key_id       = module.cross_cloud_security[0].gcp_kms_key_id
    } : null

    # Azure Security
    azure_security = var.enable_azure ? {
      network_security_groups = module.cross_cloud_security[0].azure_network_security_groups
      managed_identities      = module.cross_cloud_security[0].azure_managed_identities
      key_vault_id            = module.cross_cloud_security[0].azure_key_vault_id
    } : null
  } : null
}

# Kubernetes Configuration Commands
output "kubernetes_config_commands" {
  description = "Commands to configure kubectl for each cluster"
  value = {
    aws   = var.enable_aws ? "aws eks update-kubeconfig --region ${var.aws_region} --name ${module.aws_infrastructure[0].cluster_name}" : null
    gcp   = var.enable_gcp ? "gcloud container clusters get-credentials ${module.gcp_infrastructure[0].cluster_name} --region ${var.gcp_region} --project ${var.gcp_project_id}" : null
    azure = var.enable_azure ? "az aks get-credentials --resource-group ${module.azure_infrastructure[0].resource_group_name} --name ${module.azure_infrastructure[0].cluster_name}" : null
  }
}

# Application Deployment Commands
output "deployment_commands" {
  description = "Commands to deploy applications"
  value = {
    helm_install  = "helm install hackai ./deployments/helm/hackai --namespace hackai --create-namespace"
    kubectl_apply = "kubectl apply -f ./deployments/kubernetes/ --namespace hackai"

    # Multi-cloud specific deployments
    aws_deploy = var.enable_aws ? {
      context = "aws"
      command = "kubectl apply -f ./deployments/multi-cloud/aws/ --context=aws"
    } : null

    gcp_deploy = var.enable_gcp ? {
      context = "gcp"
      command = "kubectl apply -f ./deployments/multi-cloud/gcp/ --context=gcp"
    } : null

    azure_deploy = var.enable_azure ? {
      context = "azure"
      command = "kubectl apply -f ./deployments/multi-cloud/azure/ --context=azure"
    } : null
  }
}

# Cost Estimation
output "estimated_monthly_costs" {
  description = "Estimated monthly costs for each cloud provider"
  value = {
    aws_estimated_cost = var.enable_aws ? {
      eks_cluster     = "$73.00",
      node_groups     = "$${var.aws_node_group_desired_size * 50}.00",
      rds_postgres    = var.aws_db_instance_class == "db.t3.micro" ? "$15.00" : "$50.00",
      elasticache     = var.aws_redis_node_type == "cache.t3.micro" ? "$15.00" : "$30.00",
      total_estimated = format("$%.2f", 73 + (var.aws_node_group_desired_size * 50) + (var.aws_db_instance_class == "db.t3.micro" ? 15 : 50) + (var.aws_redis_node_type == "cache.t3.micro" ? 15 : 30))
    } : null,

    gcp_estimated_cost = var.enable_gcp ? {
      gke_cluster     = "$73.00",
      node_pools      = "$${var.gcp_node_pool_initial_count * 40}.00",
      cloud_sql       = "$30.00",
      memorystore     = "$25.00",
      total_estimated = format("$%.2f", 73 + (var.gcp_node_pool_initial_count * 40) + 30 + 25)
    } : null,

    azure_estimated_cost = var.enable_azure ? {
      aks_cluster     = "$73.00",
      node_pools      = "$${var.azure_node_pool_node_count * 45}.00",
      postgresql      = "$35.00",
      redis_cache     = "$30.00",
      total_estimated = format("$%.2f", 73 + (var.azure_node_pool_node_count * 45) + 35 + 30)
    } : null
  }
}

# Health Check URLs
output "health_check_urls" {
  description = "Health check URLs for each cloud deployment"
  value = {
    aws_health_url   = var.enable_aws ? "https://${module.aws_infrastructure[0].alb_dns_name}/health" : null
    gcp_health_url   = var.enable_gcp ? "https://${module.gcp_infrastructure[0].lb_ip_address}/health" : null
    azure_health_url = var.enable_azure ? "https://${module.azure_infrastructure[0].lb_public_ip}/health" : null
  }
}

# Summary
output "deployment_summary" {
  description = "Summary of the multi-cloud deployment"
  value = {
    enabled_clouds = [
      var.enable_aws ? "AWS" : null,
      var.enable_gcp ? "GCP" : null,
      var.enable_azure ? "Azure" : null
    ]
    primary_cloud      = var.primary_cloud
    serverless_enabled = var.enable_serverless
    monitoring_enabled = var.enable_monitoring
    security_enabled   = var.enable_security_scanning
    total_clusters     = (var.enable_aws ? 1 : 0) + (var.enable_gcp ? 1 : 0) + (var.enable_azure ? 1 : 0)
  }
}
