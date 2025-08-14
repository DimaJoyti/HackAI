# Security Configuration System

The Security Configuration System provides comprehensive, centralized configuration management for all security components in the HackAI platform. It supports multiple environments, hot reloading, feature toggles, and runtime configuration updates.

## Features

### 🔧 **Unified Configuration Management**
- **Centralized Configuration** - Single source of truth for all security settings
- **Environment-specific Profiles** - Pre-configured templates for different environments
- **Configuration Validation** - Comprehensive validation with detailed error messages
- **Hot Reloading** - Runtime configuration updates without service restart
- **Configuration Watching** - Automatic detection and application of configuration changes

### 📊 **Multiple Configuration Sources**
- **File-based Configuration** - YAML and JSON configuration files
- **Environment Variables** - Override any configuration setting via environment variables
- **Template-based Generation** - Pre-defined security profiles for different use cases
- **Runtime Updates** - Programmatic configuration updates via API
- **Configuration Overrides** - Environment-specific override files

### 🎛️ **Feature Management**
- **Feature Toggles** - Enable/disable security features at runtime
- **Threshold Management** - Dynamic adjustment of security thresholds
- **Maintenance Mode** - System-wide maintenance mode control
- **Debug Mode** - Enhanced logging and debugging capabilities
- **Experimental Features** - Safe testing of new security features

## Quick Start

### Installation

```bash
# Build the security configuration CLI tool
go build -o security-config cmd/security-config/main.go
```

### Generate Configuration Template

```bash
# Generate development configuration
./security-config -command=generate -profile=development -output=security-dev.yaml

# Generate production configuration
./security-config -command=generate -profile=production -output=security-prod.yaml

# Generate high security configuration
./security-config -command=generate -profile=high_security -output=security-high.yaml
```

### Validate Configuration

```bash
# Validate configuration file
./security-config -command=validate -config=security.yaml
```

### View Configuration

```bash
# Show configuration in YAML format
./security-config -command=show -config=security.yaml -format=yaml

# Show configuration in JSON format
./security-config -command=show -config=security.yaml -format=json
```

### Update Configuration

```bash
# Update AI firewall block threshold
./security-config -command=update -config=security.yaml \
  -component=ai_firewall -threshold=block -value=0.8

# Update agentic framework threat response threshold
./security-config -command=update -config=security.yaml \
  -component=agentic_framework -threshold=threat_response -value=0.7

# Enable feature toggle
./security-config -command=feature -config=security.yaml \
  -feature=advanced_threat_detection -enabled=true
```

## Configuration Profiles

### Development Profile
- **Relaxed Security** - Higher thresholds, disabled auto-blocking
- **Enhanced Logging** - Debug-level logging for development
- **Disabled Features** - Performance-heavy features disabled
- **Local Access** - Whitelisted local IPs and relaxed authentication

### Staging Profile
- **Moderate Security** - Balanced security settings for testing
- **Production-like** - Similar to production but with debug capabilities
- **Feature Testing** - Safe environment for testing new features
- **Monitoring Enabled** - Full monitoring and alerting capabilities

### Production Profile
- **Standard Security** - Balanced security for production workloads
- **Auto-blocking** - Automatic threat blocking enabled
- **Full Monitoring** - Comprehensive monitoring and alerting
- **Compliance Ready** - Basic compliance features enabled

### High Security Profile
- **Strict Security** - Maximum security settings
- **Low Thresholds** - Aggressive threat detection and blocking
- **Enhanced Authentication** - Strong password policies and MFA required
- **Minimal Attack Surface** - Reduced functionality for maximum security

### Compliance Profile
- **Regulatory Compliance** - GDPR, HIPAA, SOX, PCI compliance features
- **Audit Logging** - Comprehensive audit trails
- **Data Protection** - Enhanced encryption and data handling
- **Long Retention** - Extended log and data retention periods

## Environment Variables

The system supports comprehensive environment variable overrides:

### Core Security Components
```bash
# Agentic Framework
export SECURITY_AGENTIC_ENABLED=true
export SECURITY_AGENTIC_THRESHOLD=0.7
export SECURITY_AGENTIC_AUTO_BLOCK=true

# AI Firewall
export SECURITY_FIREWALL_ENABLED=true
export SECURITY_FIREWALL_BLOCK_THRESHOLD=0.8
export SECURITY_FIREWALL_ALERT_THRESHOLD=0.6

# Input/Output Filter
export SECURITY_FILTER_ENABLED=true
export SECURITY_FILTER_STRICT_MODE=true
export SECURITY_FILTER_MAX_INPUT_LENGTH=100000

# Prompt Guard
export SECURITY_PROMPT_GUARD_ENABLED=true
export SECURITY_PROMPT_GUARD_THRESHOLD=0.7
```

### Web Layer Security
```bash
# Web Layer
export SECURITY_WEB_LAYER_ENABLED=true
export SECURITY_WEB_LAYER_MAX_REQUEST_SIZE=10485760
export SECURITY_WEB_LAYER_REQUEST_TIMEOUT=30s

# Content Security Policy
export SECURITY_CSP_ENABLED=true
export SECURITY_CSP_POLICY="default-src 'self'; script-src 'self'"

# HTTP Strict Transport Security
export SECURITY_HSTS_ENABLED=true
export SECURITY_HSTS_MAX_AGE=31536000
```

### Authentication & Authorization
```bash
# Password Policy
export SECURITY_PASSWORD_MIN_LENGTH=12

# Multi-Factor Authentication
export SECURITY_MFA_ENABLED=true
export SECURITY_MFA_REQUIRED=true

# Session Management
export SECURITY_SESSION_TIMEOUT=8h
export SECURITY_SESSION_SECURE_COOKIES=true
```

### Monitoring & Logging
```bash
# Monitoring
export SECURITY_MONITORING_ENABLED=true
export SECURITY_METRICS_ENABLED=true
export SECURITY_TRACING_ENABLED=true

# Logging
export SECURITY_LOG_LEVEL=info
export SECURITY_LOG_FORMAT=json
export SECURITY_LOG_OUTPUT=file,syslog

# Feature Toggles
export SECURITY_MAINTENANCE_MODE=false
export SECURITY_DEBUG_MODE=false
```

## Programmatic Usage

### Basic Configuration Management

```go
package main

import (
    "github.com/dimajoyti/hackai/pkg/config"
)

func main() {
    // Create configuration manager
    logger := &SimpleLogger{}
    manager := config.NewSecurityConfigManager("security.yaml", logger)
    
    // Load configuration
    if err := manager.LoadConfig(); err != nil {
        panic(err)
    }
    
    // Get current configuration
    cfg := manager.GetConfig()
    fmt.Printf("Environment: %s\n", cfg.Environment)
    
    // Update feature toggle
    err := manager.UpdateFeatureToggle("advanced_threat_detection", true)
    if err != nil {
        panic(err)
    }
    
    // Update threshold
    err = manager.UpdateThreshold("ai_firewall", "block", 0.8)
    if err != nil {
        panic(err)
    }
    
    // Save configuration
    if err := manager.SaveConfig(); err != nil {
        panic(err)
    }
}
```

### Configuration Watching

```go
// Implement ConfigWatcher interface
type MyConfigWatcher struct{}

func (w *MyConfigWatcher) OnConfigChange(config *config.UnifiedSecurityConfig) error {
    fmt.Printf("Configuration updated: %s\n", config.Version)
    // Apply configuration changes to your components
    return nil
}

// Add watcher to manager
watcher := &MyConfigWatcher{}
manager.AddWatcher(watcher)

// Start watching for changes
if err := manager.StartConfigWatcher(); err != nil {
    panic(err)
}
```

### Configuration Loading with Overrides

```go
// Create loader with environment-specific overrides
loader := config.NewSecurityConfigLoader("security.yaml", "production")

// Load configuration with all overrides applied
cfg, err := loader.LoadSecurityConfig()
if err != nil {
    panic(err)
}

// Configuration is now loaded with:
// 1. Base configuration from file
// 2. Environment-specific overrides from overrides-production.yaml
// 3. Environment variable overrides
```

## Configuration Structure

### Core Components Configuration

```yaml
# Agentic Security Framework
agentic_framework:
  enabled: true
  real_time_analysis: true
  threat_response_threshold: 0.7
  auto_block_enabled: true
  learning_mode: true
  max_concurrent_analysis: 20
  threat_retention_duration: "24h"
  alert_cooldown_period: "5m"
  confidence_threshold: 0.8

# AI Firewall
ai_firewall:
  enabled: true
  ml_detection: true
  behavior_analysis: true
  anomaly_detection: true
  geo_blocking: true
  rate_limiting: true
  block_threshold: 0.7
  alert_threshold: 0.5
  rules:
    - id: "sql_injection"
      name: "SQL Injection Detection"
      enabled: true
      priority: 100
      pattern: "(?i)(union|select|insert|update|delete|drop)\\s+"
      action: "block"
      severity: "high"
      confidence: 0.8
```

### Authentication & Authorization

```yaml
# Authentication Configuration
authentication:
  password_policy:
    min_length: 12
    require_uppercase: true
    require_lowercase: true
    require_numbers: true
    require_special: true
    history_count: 10
    max_age: "2160h"  # 90 days
    complexity_score: 80
  
  multi_factor_auth:
    enabled: true
    required: true
    methods: ["totp", "sms", "email"]
    totp_issuer: "HackAI"
    backup_codes: true
  
  session_management:
    timeout: "8h"
    max_concurrent_sessions: 3
    secure_cookies: true
    http_only_cookies: true
    same_site_cookies: "Strict"
    session_rotation: true
    idle_timeout: "30m"
```

### Monitoring & Alerting

```yaml
# Monitoring Configuration
monitoring:
  enabled: true
  metrics_enabled: true
  tracing_enabled: true
  health_checks: true
  dashboards: true
  exporters: ["prometheus", "jaeger"]
  sample_rate: 1.0
  retention_period: "720h"  # 30 days

# Alerting Configuration
alerting:
  enabled: true
  channels:
    - type: "slack"
      enabled: true
      config:
        webhook_url: "https://hooks.slack.com/..."
      severity: ["critical", "high"]
    - type: "email"
      enabled: true
      config:
        smtp_server: "smtp.company.com"
        recipients: "security@company.com"
      severity: ["critical", "high", "medium"]
```

## Best Practices

### Configuration Management

1. **Use Version Control** - Store configuration files in version control
2. **Environment Separation** - Use different configurations for each environment
3. **Secure Secrets** - Never store secrets in configuration files
4. **Regular Validation** - Validate configurations before deployment
5. **Change Tracking** - Monitor and log configuration changes

### Security Considerations

1. **Principle of Least Privilege** - Start with restrictive settings
2. **Gradual Relaxation** - Gradually relax settings based on monitoring
3. **Regular Review** - Periodically review and update configurations
4. **Incident Response** - Have procedures for emergency configuration changes
5. **Backup Configurations** - Maintain backup configurations for rollback

### Performance Optimization

1. **Profile-based Tuning** - Use appropriate profiles for each environment
2. **Resource Monitoring** - Monitor resource usage and adjust accordingly
3. **Feature Toggles** - Disable unnecessary features in production
4. **Threshold Tuning** - Optimize thresholds based on false positive rates
5. **Caching Configuration** - Cache frequently accessed configuration values

## CLI Reference

### Commands

- `generate` - Generate configuration template
- `validate` - Validate configuration file
- `show` - Display current configuration
- `update` - Update configuration threshold
- `feature` - Update feature toggle
- `watch` - Watch configuration for changes
- `env-vars` - Show supported environment variables

### Options

- `-config` - Path to configuration file
- `-profile` - Security profile (development, staging, production, high_security, compliance)
- `-output` - Output file path
- `-format` - Output format (yaml, json)
- `-component` - Component name for updates
- `-threshold` - Threshold name for updates
- `-value` - New value for updates
- `-feature` - Feature toggle name
- `-enabled` - Enable/disable feature toggle

## Integration Examples

See the `examples/` directory for complete integration examples:

- `security_config_example.go` - Basic configuration management
- `config_watcher_example.go` - Configuration change handling
- `environment_override_example.go` - Environment-specific configurations
- `feature_toggle_example.go` - Runtime feature management
