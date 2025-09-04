package database

// getInitialSchemaSQL returns the SQL for creating the initial schema
func getInitialSchemaSQL() string {
	return `
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'user' CHECK (role IN ('admin', 'moderator', 'user', 'guest')),
    status VARCHAR(50) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended', 'pending', 'deleted')),
    firebase_uid VARCHAR(255) UNIQUE,
    display_name VARCHAR(255),
    phone_number VARCHAR(50),
    email_verified BOOLEAN DEFAULT FALSE,
    organization VARCHAR(255),
    avatar TEXT,
    bio TEXT,
    company VARCHAR(255),
    location VARCHAR(255),
    website VARCHAR(255),
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    last_login_at TIMESTAMP,
    password_changed_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP
);

-- User sessions table
CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(512) UNIQUE NOT NULL,
    device_id VARCHAR(255),
    user_agent TEXT,
    ip_address INET,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- User permissions table
CREATE TABLE IF NOT EXISTS user_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    resource VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    granted BOOLEAN DEFAULT TRUE,
    granted_by UUID REFERENCES users(id),
    granted_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP
);

-- User activities table
CREATE TABLE IF NOT EXISTS user_activities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action VARCHAR(255) NOT NULL,
    resource VARCHAR(255),
    details TEXT,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Vulnerability scans table
CREATE TABLE IF NOT EXISTS vulnerability_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target VARCHAR(255) NOT NULL,
    scan_type VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    progress INTEGER DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    results JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Vulnerabilities table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES vulnerability_scans(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(50) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status VARCHAR(50) DEFAULT 'open' CHECK (status IN ('open', 'fixed', 'verified', 'ignored', 'false_positive')),
    cve_id VARCHAR(50),
    cvss_score DECIMAL(3,1),
    affected_component VARCHAR(255),
    solution TEXT,
    references TEXT[],
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Network scans table
CREATE TABLE IF NOT EXISTS network_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target VARCHAR(255) NOT NULL,
    scan_type VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    progress INTEGER DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    results JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Network hosts table
CREATE TABLE IF NOT EXISTS network_hosts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES network_scans(id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    hostname VARCHAR(255),
    mac_address VARCHAR(17),
    os_name VARCHAR(255),
    os_version VARCHAR(255),
    status VARCHAR(50) DEFAULT 'up' CHECK (status IN ('up', 'down', 'unknown')),
    response_time INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Network ports table
CREATE TABLE IF NOT EXISTS network_ports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id UUID NOT NULL REFERENCES network_hosts(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK (port >= 1 AND port <= 65535),
    protocol VARCHAR(10) NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    state VARCHAR(20) NOT NULL CHECK (state IN ('open', 'closed', 'filtered')),
    service VARCHAR(255),
    version VARCHAR(255),
    banner TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(255) NOT NULL,
    resource VARCHAR(255),
    resource_id VARCHAR(255),
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    status VARCHAR(50) DEFAULT 'success' CHECK (status IN ('success', 'failure', 'error', 'warning')),
    risk_level VARCHAR(50) DEFAULT 'low' CHECK (risk_level IN ('critical', 'high', 'medium', 'low', 'info')),
    severity VARCHAR(50) DEFAULT 'info' CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    tags TEXT[],
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Security events table
CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status VARCHAR(50) DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'resolved', 'closed', 'ignored')),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    source_ip INET,
    target_ip INET,
    user_id UUID REFERENCES users(id),
    confidence DECIMAL(3,2) CHECK (confidence >= 0 AND confidence <= 1),
    indicators JSONB,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Threat intelligence table
CREATE TABLE IF NOT EXISTS threat_intelligence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(100) NOT NULL,
    value VARCHAR(255) NOT NULL,
    source VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence DECIMAL(3,2) CHECK (confidence >= 0 AND confidence <= 1),
    description TEXT,
    tags TEXT[],
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- System metrics table
CREATE TABLE IF NOT EXISTS system_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service VARCHAR(255) NOT NULL,
    metric_name VARCHAR(255) NOT NULL,
    metric_value DECIMAL(15,6) NOT NULL,
    unit VARCHAR(50),
    tags JSONB,
    timestamp TIMESTAMP DEFAULT NOW()
);

-- Data retention policies table
CREATE TABLE IF NOT EXISTS data_retention_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(255) NOT NULL,
    retention_days INTEGER NOT NULL CHECK (retention_days > 0),
    enabled BOOLEAN DEFAULT TRUE,
    last_cleanup TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Backup records table
CREATE TABLE IF NOT EXISTS backup_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(50) NOT NULL CHECK (type IN ('full', 'incremental', 'differential')),
    status VARCHAR(50) NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    file_path VARCHAR(500),
    file_size BIGINT,
    checksum VARCHAR(128),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);
`
}

// getInitialSchemaRollbackSQL returns the SQL for rolling back the initial schema
func getInitialSchemaRollbackSQL() string {
	return `
-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS backup_records;
DROP TABLE IF EXISTS data_retention_policies;
DROP TABLE IF EXISTS system_metrics;
DROP TABLE IF EXISTS threat_intelligence;
DROP TABLE IF EXISTS security_events;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS network_ports;
DROP TABLE IF EXISTS network_hosts;
DROP TABLE IF EXISTS network_scans;
DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS vulnerability_scans;
DROP TABLE IF EXISTS user_activities;
DROP TABLE IF EXISTS user_permissions;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS users;

-- Drop extensions (optional, might be used by other applications)
-- DROP EXTENSION IF EXISTS "pgcrypto";
-- DROP EXTENSION IF EXISTS "uuid-ossp";
`
}

// getSecurityIndexesSQL returns the SQL for creating security-related indexes
func getSecurityIndexesSQL() string {
	return `
-- User management indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email_active ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_username_active ON users(username) WHERE deleted_at IS NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_firebase_uid ON users(firebase_uid) WHERE firebase_uid IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_role_status ON users(role, status);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_last_login ON users(last_login_at DESC);

-- Session indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_token_active ON user_sessions(token) WHERE expires_at > NOW();
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_user_expires ON user_sessions(user_id, expires_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_ip_created ON user_sessions(ip_address, created_at DESC);

-- Permission indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_permissions_user_resource ON user_permissions(user_id, resource, action);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_permissions_granted_expires ON user_permissions(granted, expires_at);

-- Activity indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_activities_user_created ON user_activities(user_id, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_activities_action_created ON user_activities(action, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_activities_ip_created ON user_activities(ip_address, created_at DESC);

-- Vulnerability scan indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerability_scans_user_created ON vulnerability_scans(user_id, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerability_scans_status_created ON vulnerability_scans(status, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerability_scans_target ON vulnerability_scans(target);

-- Vulnerability indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerabilities_scan_severity ON vulnerabilities(scan_id, severity);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerabilities_status_severity ON vulnerabilities(status, severity);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities(cve_id) WHERE cve_id IS NOT NULL;

-- Network scan indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_scans_user_created ON network_scans(user_id, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_scans_status_created ON network_scans(status, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_scans_target ON network_scans(target);

-- Network host indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_hosts_scan_ip ON network_hosts(scan_id, ip_address);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_hosts_ip_status ON network_hosts(ip_address, status);

-- Network port indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_ports_host_port ON network_ports(host_id, port, protocol);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_ports_port_state ON network_ports(port, state);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_ports_service ON network_ports(service) WHERE service IS NOT NULL;

-- Audit log indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_user_created ON audit_logs(user_id, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_action_resource ON audit_logs(action, resource);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_ip_created ON audit_logs(ip_address, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_risk_severity ON audit_logs(risk_level, severity);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_status_created ON audit_logs(status, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_tags ON audit_logs USING GIN(tags);

-- Security event indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_type_severity ON security_events(type, severity);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_status_created ON security_events(status, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_source_ip ON security_events(source_ip);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_user_created ON security_events(user_id, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_confidence ON security_events(confidence DESC);

-- Threat intelligence indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_intelligence_value ON threat_intelligence(value);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_intelligence_type_source ON threat_intelligence(type, source);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_intelligence_active ON threat_intelligence(expires_at) WHERE expires_at IS NULL OR expires_at > NOW();
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_intelligence_severity ON threat_intelligence(severity);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_intelligence_tags ON threat_intelligence USING GIN(tags);

-- System metrics indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_system_metrics_timestamp ON system_metrics(timestamp DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_system_metrics_service_metric ON system_metrics(service, metric_name, timestamp DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_system_metrics_tags ON system_metrics USING GIN(tags);
`
}

// getSecurityIndexesRollbackSQL returns the SQL for dropping security indexes
func getSecurityIndexesRollbackSQL() string {
	return `
-- Drop all security-related indexes
DROP INDEX CONCURRENTLY IF EXISTS idx_users_email_active;
DROP INDEX CONCURRENTLY IF EXISTS idx_users_username_active;
DROP INDEX CONCURRENTLY IF EXISTS idx_users_firebase_uid;
DROP INDEX CONCURRENTLY IF EXISTS idx_users_role_status;
DROP INDEX CONCURRENTLY IF EXISTS idx_users_last_login;
DROP INDEX CONCURRENTLY IF EXISTS idx_user_sessions_token_active;
DROP INDEX CONCURRENTLY IF EXISTS idx_user_sessions_user_expires;
DROP INDEX CONCURRENTLY IF EXISTS idx_user_sessions_ip_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_user_permissions_user_resource;
DROP INDEX CONCURRENTLY IF EXISTS idx_user_permissions_granted_expires;
DROP INDEX CONCURRENTLY IF EXISTS idx_user_activities_user_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_user_activities_action_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_user_activities_ip_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_vulnerability_scans_user_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_vulnerability_scans_status_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_vulnerability_scans_target;
DROP INDEX CONCURRENTLY IF EXISTS idx_vulnerabilities_scan_severity;
DROP INDEX CONCURRENTLY IF EXISTS idx_vulnerabilities_status_severity;
DROP INDEX CONCURRENTLY IF EXISTS idx_vulnerabilities_cve_id;
DROP INDEX CONCURRENTLY IF EXISTS idx_network_scans_user_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_network_scans_status_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_network_scans_target;
DROP INDEX CONCURRENTLY IF EXISTS idx_network_hosts_scan_ip;
DROP INDEX CONCURRENTLY IF EXISTS idx_network_hosts_ip_status;
DROP INDEX CONCURRENTLY IF EXISTS idx_network_ports_host_port;
DROP INDEX CONCURRENTLY IF EXISTS idx_network_ports_port_state;
DROP INDEX CONCURRENTLY IF EXISTS idx_network_ports_service;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_user_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_action_resource;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_ip_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_risk_severity;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_status_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_tags;
DROP INDEX CONCURRENTLY IF EXISTS idx_security_events_type_severity;
DROP INDEX CONCURRENTLY IF EXISTS idx_security_events_status_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_security_events_source_ip;
DROP INDEX CONCURRENTLY IF EXISTS idx_security_events_user_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_security_events_confidence;
DROP INDEX CONCURRENTLY IF EXISTS idx_threat_intelligence_value;
DROP INDEX CONCURRENTLY IF EXISTS idx_threat_intelligence_type_source;
DROP INDEX CONCURRENTLY IF EXISTS idx_threat_intelligence_active;
DROP INDEX CONCURRENTLY IF EXISTS idx_threat_intelligence_severity;
DROP INDEX CONCURRENTLY IF EXISTS idx_threat_intelligence_tags;
DROP INDEX CONCURRENTLY IF EXISTS idx_system_metrics_timestamp;
DROP INDEX CONCURRENTLY IF EXISTS idx_system_metrics_service_metric;
DROP INDEX CONCURRENTLY IF EXISTS idx_system_metrics_tags;
`
}

// getLLMSecurityTablesSQL returns the SQL for creating LLM security tables
func getLLMSecurityTablesSQL() string {
	return `
-- LLM request logs table
CREATE TABLE IF NOT EXISTS llm_request_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    provider VARCHAR(100) NOT NULL,
    model VARCHAR(255) NOT NULL,
    request_id VARCHAR(255) UNIQUE NOT NULL,
    prompt TEXT NOT NULL,
    response TEXT,
    tokens_used INTEGER DEFAULT 0,
    cost DECIMAL(10,6) DEFAULT 0,
    duration_ms INTEGER,
    status_code INTEGER,
    error_message TEXT,
    threat_score DECIMAL(3,2) DEFAULT 0 CHECK (threat_score >= 0 AND threat_score <= 1),
    blocked BOOLEAN DEFAULT FALSE,
    block_reason VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- LLM providers table
CREATE TABLE IF NOT EXISTS llm_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    type VARCHAR(100) NOT NULL,
    endpoint VARCHAR(500) NOT NULL,
    api_key_encrypted TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    rate_limit INTEGER DEFAULT 100,
    rate_limit_window INTEGER DEFAULT 60,
    timeout_seconds INTEGER DEFAULT 30,
    max_tokens INTEGER DEFAULT 4096,
    temperature DECIMAL(3,2) DEFAULT 0.7,
    configuration JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- LLM models table
CREATE TABLE IF NOT EXISTS llm_models (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES llm_providers(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    description TEXT,
    max_tokens INTEGER DEFAULT 4096,
    cost_per_token DECIMAL(10,8) DEFAULT 0,
    enabled BOOLEAN DEFAULT TRUE,
    capabilities TEXT[],
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(provider_id, name)
);

-- LLM usage quotas table
CREATE TABLE IF NOT EXISTS llm_usage_quotas (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id UUID REFERENCES llm_providers(id) ON DELETE CASCADE,
    quota_type VARCHAR(50) NOT NULL CHECK (quota_type IN ('requests', 'tokens', 'cost')),
    quota_limit BIGINT NOT NULL,
    quota_used BIGINT DEFAULT 0,
    quota_period VARCHAR(50) NOT NULL CHECK (quota_period IN ('hourly', 'daily', 'weekly', 'monthly')),
    reset_at TIMESTAMP NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, provider_id, quota_type, quota_period)
);

-- Security policies table
CREATE TABLE IF NOT EXISTS security_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    policy_type VARCHAR(100) NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    priority INTEGER DEFAULT 100,
    conditions JSONB NOT NULL,
    actions JSONB NOT NULL,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Policy violations table
CREATE TABLE IF NOT EXISTS policy_violations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES security_policies(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    request_id VARCHAR(255),
    violation_type VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    description TEXT,
    action_taken VARCHAR(255),
    blocked BOOLEAN DEFAULT FALSE,
    ip_address INET,
    user_agent TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Policy rules table
CREATE TABLE IF NOT EXISTS policy_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES security_policies(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    rule_type VARCHAR(100) NOT NULL,
    pattern TEXT,
    threshold DECIMAL(5,2),
    enabled BOOLEAN DEFAULT TRUE,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Policy templates table
CREATE TABLE IF NOT EXISTS policy_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    category VARCHAR(100) NOT NULL,
    template JSONB NOT NULL,
    variables JSONB,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Policy executions table
CREATE TABLE IF NOT EXISTS policy_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES security_policies(id) ON DELETE CASCADE,
    request_id VARCHAR(255),
    user_id UUID REFERENCES users(id),
    execution_time_ms INTEGER,
    result VARCHAR(50) NOT NULL CHECK (result IN ('allow', 'block', 'warn', 'log')),
    matched_rules TEXT[],
    score DECIMAL(5,2),
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);
`
}

// getLLMSecurityTablesRollbackSQL returns the SQL for dropping LLM security tables
func getLLMSecurityTablesRollbackSQL() string {
	return `
-- Drop LLM security tables in reverse dependency order
DROP TABLE IF EXISTS policy_executions;
DROP TABLE IF EXISTS policy_templates;
DROP TABLE IF EXISTS policy_rules;
DROP TABLE IF EXISTS policy_violations;
DROP TABLE IF EXISTS security_policies;
DROP TABLE IF EXISTS llm_usage_quotas;
DROP TABLE IF EXISTS llm_models;
DROP TABLE IF EXISTS llm_providers;
DROP TABLE IF EXISTS llm_request_logs;
`
}

// getAuditEnhancementsSQL returns the SQL for audit enhancements
func getAuditEnhancementsSQL() string {
	return `
-- Add additional indexes for LLM security tables
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_llm_request_logs_user_created ON llm_request_logs(user_id, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_llm_request_logs_provider_model ON llm_request_logs(provider, model);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_llm_request_logs_threat_score ON llm_request_logs(threat_score DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_llm_request_logs_blocked ON llm_request_logs(blocked, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_llm_request_logs_status_code ON llm_request_logs(status_code);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_llm_request_logs_ip_created ON llm_request_logs(ip_address, created_at DESC);

-- LLM provider indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_llm_providers_enabled ON llm_providers(enabled);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_llm_providers_type ON llm_providers(type);

-- LLM model indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_llm_models_provider_enabled ON llm_models(provider_id, enabled);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_llm_models_name ON llm_models(name);

-- LLM usage quota indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_llm_usage_quotas_user_provider ON llm_usage_quotas(user_id, provider_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_llm_usage_quotas_reset_at ON llm_usage_quotas(reset_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_llm_usage_quotas_enabled ON llm_usage_quotas(enabled);

-- Security policy indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_policies_enabled_priority ON security_policies(enabled, priority);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_policies_type ON security_policies(policy_type);

-- Policy violation indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_violations_policy_created ON policy_violations(policy_id, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_violations_user_created ON policy_violations(user_id, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_violations_severity ON policy_violations(severity);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_violations_blocked ON policy_violations(blocked, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_violations_ip_created ON policy_violations(ip_address, created_at DESC);

-- Policy rule indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_rules_policy_enabled ON policy_rules(policy_id, enabled);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_rules_type ON policy_rules(rule_type);

-- Policy execution indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_executions_policy_created ON policy_executions(policy_id, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_executions_user_created ON policy_executions(user_id, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_executions_result ON policy_executions(result);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_executions_score ON policy_executions(score DESC);

-- Add audit triggers for automatic logging
CREATE OR REPLACE FUNCTION audit_trigger_function()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_logs (action, resource, resource_id, new_values, created_at)
        VALUES ('INSERT', TG_TABLE_NAME, NEW.id::text, to_jsonb(NEW), NOW());
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit_logs (action, resource, resource_id, old_values, new_values, created_at)
        VALUES ('UPDATE', TG_TABLE_NAME, NEW.id::text, to_jsonb(OLD), to_jsonb(NEW), NOW());
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO audit_logs (action, resource, resource_id, old_values, created_at)
        VALUES ('DELETE', TG_TABLE_NAME, OLD.id::text, to_jsonb(OLD), NOW());
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create audit triggers for critical tables
CREATE TRIGGER audit_users_trigger
    AFTER INSERT OR UPDATE OR DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();

CREATE TRIGGER audit_security_policies_trigger
    AFTER INSERT OR UPDATE OR DELETE ON security_policies
    FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();

CREATE TRIGGER audit_llm_providers_trigger
    AFTER INSERT OR UPDATE OR DELETE ON llm_providers
    FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();

-- Add data retention cleanup function
CREATE OR REPLACE FUNCTION cleanup_old_data()
RETURNS void AS $$
DECLARE
    policy RECORD;
    cleanup_date TIMESTAMP;
    deleted_count INTEGER;
BEGIN
    FOR policy IN SELECT * FROM data_retention_policies WHERE enabled = true LOOP
        cleanup_date := NOW() - INTERVAL '1 day' * policy.retention_days;

        CASE policy.table_name
            WHEN 'audit_logs' THEN
                DELETE FROM audit_logs WHERE created_at < cleanup_date;
                GET DIAGNOSTICS deleted_count = ROW_COUNT;
            WHEN 'llm_request_logs' THEN
                DELETE FROM llm_request_logs WHERE created_at < cleanup_date;
                GET DIAGNOSTICS deleted_count = ROW_COUNT;
            WHEN 'user_activities' THEN
                DELETE FROM user_activities WHERE created_at < cleanup_date;
                GET DIAGNOSTICS deleted_count = ROW_COUNT;
            WHEN 'system_metrics' THEN
                DELETE FROM system_metrics WHERE timestamp < cleanup_date;
                GET DIAGNOSTICS deleted_count = ROW_COUNT;
            ELSE
                CONTINUE;
        END CASE;

        UPDATE data_retention_policies
        SET last_cleanup = NOW()
        WHERE id = policy.id;

        INSERT INTO audit_logs (action, resource, resource_id, metadata, created_at)
        VALUES ('CLEANUP', policy.table_name, policy.id::text,
                jsonb_build_object('deleted_count', deleted_count, 'cleanup_date', cleanup_date),
                NOW());
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Insert default data retention policies
INSERT INTO data_retention_policies (table_name, retention_days, enabled) VALUES
    ('audit_logs', 365, true),
    ('llm_request_logs', 90, true),
    ('user_activities', 180, true),
    ('system_metrics', 30, true),
    ('policy_violations', 365, true),
    ('security_events', 365, true)
ON CONFLICT (table_name) DO NOTHING;
`
}

// getAuditEnhancementsRollbackSQL returns the SQL for rolling back audit enhancements
func getAuditEnhancementsRollbackSQL() string {
	return `
-- Drop audit triggers
DROP TRIGGER IF EXISTS audit_users_trigger ON users;
DROP TRIGGER IF EXISTS audit_security_policies_trigger ON security_policies;
DROP TRIGGER IF EXISTS audit_llm_providers_trigger ON llm_providers;

-- Drop audit functions
DROP FUNCTION IF EXISTS audit_trigger_function();
DROP FUNCTION IF EXISTS cleanup_old_data();

-- Drop LLM security indexes
DROP INDEX CONCURRENTLY IF EXISTS idx_llm_request_logs_user_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_llm_request_logs_provider_model;
DROP INDEX CONCURRENTLY IF EXISTS idx_llm_request_logs_threat_score;
DROP INDEX CONCURRENTLY IF EXISTS idx_llm_request_logs_blocked;
DROP INDEX CONCURRENTLY IF EXISTS idx_llm_request_logs_status_code;
DROP INDEX CONCURRENTLY IF EXISTS idx_llm_request_logs_ip_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_llm_providers_enabled;
DROP INDEX CONCURRENTLY IF EXISTS idx_llm_providers_type;
DROP INDEX CONCURRENTLY IF EXISTS idx_llm_models_provider_enabled;
DROP INDEX CONCURRENTLY IF EXISTS idx_llm_models_name;
DROP INDEX CONCURRENTLY IF EXISTS idx_llm_usage_quotas_user_provider;
DROP INDEX CONCURRENTLY IF EXISTS idx_llm_usage_quotas_reset_at;
DROP INDEX CONCURRENTLY IF EXISTS idx_llm_usage_quotas_enabled;
DROP INDEX CONCURRENTLY IF EXISTS idx_security_policies_enabled_priority;
DROP INDEX CONCURRENTLY IF EXISTS idx_security_policies_type;
DROP INDEX CONCURRENTLY IF EXISTS idx_policy_violations_policy_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_policy_violations_user_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_policy_violations_severity;
DROP INDEX CONCURRENTLY IF EXISTS idx_policy_violations_blocked;
DROP INDEX CONCURRENTLY IF EXISTS idx_policy_violations_ip_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_policy_rules_policy_enabled;
DROP INDEX CONCURRENTLY IF EXISTS idx_policy_rules_type;
DROP INDEX CONCURRENTLY IF EXISTS idx_policy_executions_policy_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_policy_executions_user_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_policy_executions_result;
DROP INDEX CONCURRENTLY IF EXISTS idx_policy_executions_score;

-- Remove default data retention policies
DELETE FROM data_retention_policies WHERE table_name IN (
    'audit_logs', 'llm_request_logs', 'user_activities',
    'system_metrics', 'policy_violations', 'security_events'
);
`
}
