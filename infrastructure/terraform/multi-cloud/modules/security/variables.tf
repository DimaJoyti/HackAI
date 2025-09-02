# Security Module Variables

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "hackai"
}

variable "environment" {
  description = "Environment name (development, staging, production)"
  type        = string
  default     = "development"
}

variable "owner" {
  description = "Owner of the infrastructure"
  type        = string
  default     = "HackAI-Team"
}

# Cloud Provider Flags
variable "enable_aws" {
  description = "Enable AWS security resources"
  type        = bool
  default     = true
}

variable "enable_gcp" {
  description = "Enable GCP security resources"
  type        = bool
  default     = true
}

variable "enable_azure" {
  description = "Enable Azure security resources"
  type        = bool
  default     = true
}

# AWS Configuration
variable "aws_vpc_id" {
  description = "AWS VPC ID"
  type        = string
  default     = ""
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

# GCP Configuration
variable "gcp_project_id" {
  description = "GCP project ID"
  type        = string
  default     = ""
}

variable "gcp_region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "gcp_network_name" {
  description = "GCP network name"
  type        = string
  default     = ""
}

variable "gcp_vpc_cidr" {
  description = "GCP VPC CIDR"
  type        = string
  default     = "10.1.0.0/16"
}

# Azure Configuration
variable "azure_location" {
  description = "Azure location"
  type        = string
  default     = "East US"
}

variable "azure_resource_group_name" {
  description = "Azure resource group name"
  type        = string
  default     = ""
}

variable "create_key_vault" {
  description = "Create Azure Key Vault for security"
  type        = bool
  default     = false
}

# Security Configuration
variable "enable_encryption" {
  description = "Enable encryption at rest"
  type        = bool
  default     = true
}

variable "enable_network_policies" {
  description = "Enable network security policies"
  type        = bool
  default     = true
}

variable "enable_vulnerability_scanning" {
  description = "Enable vulnerability scanning"
  type        = bool
  default     = true
}

# Common tags
variable "tags" {
  description = "Tags for security resources"
  type        = map(string)
  default     = {}
}
