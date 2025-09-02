# Security Module Outputs

# AWS Outputs
output "aws_security_group_ids" {
  description = "List of AWS security group IDs"
  value       = var.enable_aws ? [aws_security_group.additional[0].id] : []
}

output "aws_iam_roles" {
  description = "List of AWS IAM role ARNs"
  value       = var.enable_aws ? [aws_iam_role.security_scanner[0].arn] : []
}

output "aws_kms_key_id" {
  description = "AWS KMS key ID"
  value       = var.enable_aws ? aws_kms_key.main[0].id : null
}

output "aws_kms_key_arn" {
  description = "AWS KMS key ARN"
  value       = var.enable_aws ? aws_kms_key.main[0].arn : null
}

output "aws_kms_alias" {
  description = "AWS KMS key alias"
  value       = var.enable_aws ? aws_kms_alias.main[0].name : null
}

# GCP Outputs
output "gcp_firewall_rules" {
  description = "List of GCP firewall rule names"
  value = var.enable_gcp ? [
    google_compute_firewall.deny_all[0].name,
    google_compute_firewall.allow_internal[0].name
  ] : []
}

output "gcp_service_accounts" {
  description = "List of GCP service account emails"
  value       = var.enable_gcp ? [google_service_account.security[0].email] : []
}

output "gcp_kms_key_id" {
  description = "GCP KMS key ID"
  value       = var.enable_gcp ? google_kms_crypto_key.security[0].id : null
}

output "gcp_kms_key_ring" {
  description = "GCP KMS key ring name"
  value       = var.enable_gcp ? google_kms_key_ring.security[0].name : null
}

# Azure Outputs
output "azure_network_security_groups" {
  description = "List of Azure network security group IDs"
  value       = var.enable_azure ? [azurerm_network_security_group.main[0].id] : []
}

output "azure_managed_identities" {
  description = "List of Azure managed identity IDs"
  value       = var.enable_azure ? [azurerm_user_assigned_identity.main[0].id] : []
}

output "azure_key_vault_id" {
  description = "Azure Key Vault ID"
  value       = var.enable_azure && var.create_key_vault ? azurerm_key_vault.security[0].id : null
}

output "azure_key_vault_uri" {
  description = "Azure Key Vault URI"
  value       = var.enable_azure && var.create_key_vault ? azurerm_key_vault.security[0].vault_uri : null
}

# Summary Outputs
output "security_summary" {
  description = "Summary of security resources"
  value = {
    aws_enabled   = var.enable_aws
    gcp_enabled   = var.enable_gcp
    azure_enabled = var.enable_azure
    encryption_enabled = var.enable_encryption
    network_policies_enabled = var.enable_network_policies
  }
}
