# Multi-Cloud Security and Compliance Policies for HackAI
# Open Policy Agent (OPA) Policies

package hackai.multicloud

import rego.v1

# Default deny policy
default allow := false

# Global configuration
project_name := "hackai"
allowed_environments := {"development", "staging", "production"}
allowed_cloud_providers := {"aws", "gcp", "azure"}

# Resource naming conventions
resource_name_pattern := "^hackai-(development|staging|production)-[a-z0-9-]+$"

# Security Policies

# Policy: All resources must have required tags
required_tags := {
    "Project",
    "Environment", 
    "ManagedBy",
    "Owner",
    "CloudProvider"
}

# Policy: Encryption at rest must be enabled
encryption_at_rest_required if {
    input.resource_type in {
        "aws_db_instance",
        "aws_s3_bucket", 
        "google_sql_database_instance",
        "azurerm_storage_account"
    }
}

# Policy: Network security groups must not allow unrestricted access
deny contains msg if {
    input.resource_type in {
        "aws_security_group",
        "google_compute_firewall",
        "azurerm_network_security_group"
    }
    
    some rule in input.ingress_rules
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.from_port <= 22
    rule.to_port >= 22
    
    msg := sprintf("Security group %s allows unrestricted SSH access", [input.resource_name])
}

# Policy: Database instances must not be publicly accessible
deny contains msg if {
    input.resource_type in {
        "aws_db_instance",
        "google_sql_database_instance", 
        "azurerm_postgresql_server"
    }
    
    input.publicly_accessible == true
    
    msg := sprintf("Database %s must not be publicly accessible", [input.resource_name])
}

# Policy: Kubernetes clusters must have logging enabled
deny contains msg if {
    input.resource_type in {
        "aws_eks_cluster",
        "google_container_cluster",
        "azurerm_kubernetes_cluster"
    }
    
    not input.logging_enabled
    
    msg := sprintf("Kubernetes cluster %s must have logging enabled", [input.resource_name])
}

# Policy: Storage buckets must have versioning enabled
deny contains msg if {
    input.resource_type in {
        "aws_s3_bucket",
        "google_storage_bucket",
        "azurerm_storage_container"
    }
    
    not input.versioning_enabled
    
    msg := sprintf("Storage bucket %s must have versioning enabled", [input.resource_name])
}

# Compliance Policies

# SOC2 Compliance
soc2_compliant if {
    encryption_at_rest_enabled
    access_logging_enabled
    network_security_configured
    backup_enabled
}

# ISO27001 Compliance  
iso27001_compliant if {
    information_security_controls
    risk_management_controls
    access_control_measures
    incident_management_procedures
}

# GDPR Compliance
gdpr_compliant if {
    data_protection_measures
    privacy_by_design
    data_subject_rights
    breach_notification_procedures
}

# Cost Optimization Policies

# Policy: Prevent oversized instances in non-production environments
deny contains msg if {
    input.environment != "production"
    input.resource_type in {
        "aws_instance",
        "google_compute_instance",
        "azurerm_virtual_machine"
    }
    
    instance_size_oversized
    
    msg := sprintf("Instance %s is oversized for %s environment", [input.resource_name, input.environment])
}

instance_size_oversized if {
    input.instance_type in {
        "m5.4xlarge", "m5.8xlarge", "m5.12xlarge",
        "n1-standard-16", "n1-standard-32",
        "Standard_D16s_v3", "Standard_D32s_v3"
    }
}

# Policy: Require spot instances for development workloads
warn contains msg if {
    input.environment == "development"
    input.resource_type in {
        "aws_instance",
        "aws_autoscaling_group"
    }
    
    not input.spot_instances_enabled
    
    msg := sprintf("Consider using spot instances for development workload %s", [input.resource_name])
}

# Multi-Cloud Governance Policies

# Policy: Ensure consistent resource naming across clouds
deny contains msg if {
    not regex.match(resource_name_pattern, input.resource_name)
    
    msg := sprintf("Resource name %s does not follow naming convention", [input.resource_name])
}

# Policy: Validate required tags are present
deny contains msg if {
    some required_tag in required_tags
    not input.tags[required_tag]
    
    msg := sprintf("Resource %s missing required tag: %s", [input.resource_name, required_tag])
}

# Policy: Ensure environment tag matches actual environment
deny contains msg if {
    input.tags.Environment != input.environment
    
    msg := sprintf("Environment tag mismatch for resource %s", [input.resource_name])
}

# Policy: Validate cloud provider tag
deny contains msg if {
    not input.tags.CloudProvider in allowed_cloud_providers
    
    msg := sprintf("Invalid cloud provider tag for resource %s", [input.resource_name])
}

# Operational Policies

# Policy: Backup must be enabled for critical resources
deny contains msg if {
    input.resource_type in {
        "aws_db_instance",
        "google_sql_database_instance",
        "azurerm_postgresql_server"
    }
    
    input.tags.Backup == "Required"
    not input.backup_enabled
    
    msg := sprintf("Backup must be enabled for critical resource %s", [input.resource_name])
}

# Policy: Monitoring must be enabled for production resources
deny contains msg if {
    input.environment == "production"
    input.tags.Monitoring == "Critical"
    not input.monitoring_enabled
    
    msg := sprintf("Monitoring must be enabled for production resource %s", [input.resource_name])
}

# Policy: High availability configuration for production
deny contains msg if {
    input.environment == "production"
    input.resource_type in {
        "aws_db_instance",
        "google_sql_database_instance",
        "azurerm_postgresql_server"
    }
    
    not input.multi_az_enabled
    
    msg := sprintf("Production database %s must have multi-AZ enabled", [input.resource_name])
}

# Network Security Policies

# Policy: VPC flow logs must be enabled
deny contains msg if {
    input.resource_type in {
        "aws_vpc",
        "google_compute_network",
        "azurerm_virtual_network"
    }
    
    not input.flow_logs_enabled
    
    msg := sprintf("VPC flow logs must be enabled for %s", [input.resource_name])
}

# Policy: Network ACLs must be configured
deny contains msg if {
    input.resource_type in {
        "aws_subnet",
        "google_compute_subnetwork",
        "azurerm_subnet"
    }
    
    not input.network_acl_configured
    
    msg := sprintf("Network ACL must be configured for subnet %s", [input.resource_name])
}

# Helper functions
encryption_at_rest_enabled if {
    input.encryption_at_rest == true
}

access_logging_enabled if {
    input.access_logging == true
}

network_security_configured if {
    input.security_groups_configured == true
}

backup_enabled if {
    input.backup_retention_days > 0
}

information_security_controls if {
    encryption_at_rest_enabled
    access_logging_enabled
}

risk_management_controls if {
    input.risk_assessment_completed == true
}

access_control_measures if {
    input.rbac_enabled == true
}

incident_management_procedures if {
    input.incident_response_plan == true
}

data_protection_measures if {
    encryption_at_rest_enabled
    input.data_classification == true
}

privacy_by_design if {
    input.privacy_impact_assessment == true
}

data_subject_rights if {
    input.data_subject_access_procedures == true
}

breach_notification_procedures if {
    input.breach_notification_plan == true
}

# Allow policy - resources that pass all checks
allow if {
    count(deny) == 0
    count(violation) == 0
}

# Collect all violations
violation contains msg if {
    deny[msg]
}

# Collect all warnings
warning contains msg if {
    warn[msg]
}
