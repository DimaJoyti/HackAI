# Monitoring Module Outputs

# AWS Outputs
output "aws_log_group_name" {
  description = "Name of the AWS CloudWatch log group"
  value       = var.enable_aws ? aws_cloudwatch_log_group.main[0].name : null
}

output "aws_log_group_arn" {
  description = "ARN of the AWS CloudWatch log group"
  value       = var.enable_aws ? aws_cloudwatch_log_group.main[0].arn : null
}

output "aws_dashboard_url" {
  description = "URL of the AWS CloudWatch dashboard"
  value       = var.enable_aws ? "https://console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.main[0].dashboard_name}" : null
}

output "aws_dashboard_name" {
  description = "Name of the AWS CloudWatch dashboard"
  value       = var.enable_aws ? aws_cloudwatch_dashboard.main[0].dashboard_name : null
}

# GCP Outputs
output "gcp_workspace_name" {
  description = "Name of the GCP monitoring workspace"
  value       = var.enable_gcp ? "projects/${var.gcp_project_id}" : null
}

output "gcp_dashboard_url" {
  description = "URL of the GCP monitoring dashboard"
  value       = var.enable_gcp ? "https://console.cloud.google.com/monitoring/dashboards/custom/${google_monitoring_dashboard.main[0].id}?project=${var.gcp_project_id}" : null
}

output "gcp_dashboard_name" {
  description = "Name of the GCP monitoring dashboard"
  value       = var.enable_gcp ? google_monitoring_dashboard.main[0].id : null
}

# Azure Outputs
output "azure_workspace_name" {
  description = "Name of the Azure Log Analytics workspace"
  value       = var.enable_azure ? azurerm_log_analytics_workspace.main[0].name : null
}

output "azure_workspace_id" {
  description = "ID of the Azure Log Analytics workspace"
  value       = var.enable_azure ? azurerm_log_analytics_workspace.main[0].id : null
}

output "azure_dashboard_url" {
  description = "URL of the Azure Monitor dashboard"
  value       = var.enable_azure ? "https://portal.azure.com/#@/dashboard/arm${azurerm_portal_dashboard.main[0].id}" : null
}

output "azure_dashboard_name" {
  description = "Name of the Azure Monitor dashboard"
  value       = var.enable_azure ? azurerm_portal_dashboard.main[0].name : null
}

# Summary Outputs
output "monitoring_summary" {
  description = "Summary of monitoring resources"
  value = {
    aws_enabled   = var.enable_aws
    gcp_enabled   = var.enable_gcp
    azure_enabled = var.enable_azure
    log_retention = var.log_retention_days
  }
}
