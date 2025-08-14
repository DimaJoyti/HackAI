-- HackAI Database Initialization Script

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create database if it doesn't exist
-- Note: This script runs as part of docker-entrypoint-initdb.d
-- The database is already created by the POSTGRES_DB environment variable

-- Create schemas
CREATE SCHEMA IF NOT EXISTS public;

-- Set default permissions
GRANT ALL PRIVILEGES ON SCHEMA public TO hackai;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO hackai;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO hackai;

-- Create custom types
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('admin', 'moderator', 'user', 'guest');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE user_status AS ENUM ('active', 'inactive', 'suspended', 'pending');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE scan_type AS ENUM ('web', 'network', 'port', 'ssl', 'dns', 'subdomain', 'directory', 'api');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE vulnerability_type AS ENUM (
        'sql_injection', 'xss', 'csrf', 'open_redirect', 'path_traversal',
        'command_injection', 'file_upload', 'auth_bypass', 'info_disclosure',
        'ssl_issue', 'misconfiguration'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE vuln_status AS ENUM ('open', 'fixed', 'verified', 'ignored', 'false_positive');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE network_scan_type AS ENUM ('ping', 'port_scan', 'service_scan', 'os_scan', 'full_scan');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create functions for updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create function to generate random UUIDs
CREATE OR REPLACE FUNCTION gen_random_uuid() RETURNS uuid
    LANGUAGE sql
    AS $$SELECT uuid_generate_v4()$$;

-- Create audit log function
CREATE OR REPLACE FUNCTION audit_trigger_function()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_log (table_name, operation, new_data, user_id, timestamp)
        VALUES (TG_TABLE_NAME, TG_OP, row_to_json(NEW), 
                COALESCE(current_setting('app.current_user_id', true)::uuid, '00000000-0000-0000-0000-000000000000'),
                CURRENT_TIMESTAMP);
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit_log (table_name, operation, old_data, new_data, user_id, timestamp)
        VALUES (TG_TABLE_NAME, TG_OP, row_to_json(OLD), row_to_json(NEW),
                COALESCE(current_setting('app.current_user_id', true)::uuid, '00000000-0000-0000-0000-000000000000'),
                CURRENT_TIMESTAMP);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO audit_log (table_name, operation, old_data, user_id, timestamp)
        VALUES (TG_TABLE_NAME, TG_OP, row_to_json(OLD),
                COALESCE(current_setting('app.current_user_id', true)::uuid, '00000000-0000-0000-0000-000000000000'),
                CURRENT_TIMESTAMP);
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create audit log table
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(255) NOT NULL,
    operation VARCHAR(10) NOT NULL,
    old_data JSONB,
    new_data JSONB,
    user_id UUID,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for audit log
CREATE INDEX IF NOT EXISTS idx_audit_log_table_name ON audit_log(table_name);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);

-- Create performance monitoring table
CREATE TABLE IF NOT EXISTS performance_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_name VARCHAR(255) NOT NULL,
    endpoint VARCHAR(255),
    method VARCHAR(10),
    response_time_ms INTEGER,
    status_code INTEGER,
    user_id UUID,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance metrics
CREATE INDEX IF NOT EXISTS idx_performance_metrics_service ON performance_metrics(service_name);
CREATE INDEX IF NOT EXISTS idx_performance_metrics_endpoint ON performance_metrics(endpoint);
CREATE INDEX IF NOT EXISTS idx_performance_metrics_timestamp ON performance_metrics(timestamp);

-- Create system configuration table
CREATE TABLE IF NOT EXISTS system_config (
    key VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Insert default system configuration
INSERT INTO system_config (key, value, description) VALUES
    ('max_concurrent_scans', '10', 'Maximum number of concurrent scans per user'),
    ('scan_timeout_minutes', '30', 'Default scan timeout in minutes'),
    ('rate_limit_requests_per_minute', '100', 'Rate limit for API requests per minute'),
    ('max_file_upload_size_mb', '100', 'Maximum file upload size in MB'),
    ('session_timeout_hours', '24', 'Session timeout in hours'),
    ('password_min_length', '8', 'Minimum password length'),
    ('enable_two_factor', 'false', 'Enable two-factor authentication requirement')
ON CONFLICT (key) DO NOTHING;

-- Create trigger for system_config updated_at
CREATE TRIGGER update_system_config_updated_at
    BEFORE UPDATE ON system_config
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create notification settings table
CREATE TABLE IF NOT EXISTS notification_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    email_notifications BOOLEAN DEFAULT true,
    push_notifications BOOLEAN DEFAULT true,
    scan_completion BOOLEAN DEFAULT true,
    vulnerability_found BOOLEAN DEFAULT true,
    security_alerts BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for notification settings
CREATE INDEX IF NOT EXISTS idx_notification_settings_user_id ON notification_settings(user_id);

-- Create trigger for notification_settings updated_at
CREATE TRIGGER update_notification_settings_updated_at
    BEFORE UPDATE ON notification_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create API keys table for external integrations
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    permissions JSONB DEFAULT '[]',
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for API keys
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active) WHERE is_active = true;

-- Create trigger for api_keys updated_at
CREATE TRIGGER update_api_keys_updated_at
    BEFORE UPDATE ON api_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Grant permissions to hackai user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO hackai;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO hackai;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO hackai;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO hackai;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO hackai;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO hackai;
