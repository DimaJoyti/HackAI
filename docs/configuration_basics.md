# Configuration Basics

Essential configuration guide for the HackAI Security Platform. This guide covers basic configuration concepts, common settings, environment-specific configurations, and best practices.

## 📋 **Configuration Overview**

The HackAI Security Platform uses a hierarchical configuration system that supports:
- **YAML configuration files** (primary method)
- **Environment variables** (overrides and secrets)
- **Command-line flags** (runtime overrides)
- **Runtime configuration updates** (dynamic changes)

### **Configuration Priority**
1. Command-line flags (highest priority)
2. Environment variables
3. Configuration file
4. Default values (lowest priority)

## 📁 **Configuration File Structure**

### **Basic Configuration Template**

```yaml
# config/basic.yaml
# Basic HackAI Security Platform Configuration

# Server Configuration
server:
  host: "0.0.0.0"              # Bind address
  port: 8080                   # HTTP port
  read_timeout: "30s"          # Request read timeout
  write_timeout: "30s"         # Response write timeout
  max_header_bytes: 1048576    # Max header size (1MB)
  
  # TLS Configuration
  tls:
    enabled: false             # Enable HTTPS
    cert_file: ""              # TLS certificate file
    key_file: ""               # TLS private key file
    min_version: "1.2"         # Minimum TLS version

# Security Configuration
security:
  enabled: true                # Enable security features
  
  # AI Firewall
  ai_firewall:
    enabled: true              # Enable AI firewall
    prompt_injection_protection: true
    semantic_analysis: true
    confidence_threshold: 0.7  # Threat detection threshold
    max_input_size: 100000     # Max input size (bytes)
    
  # Input Filtering
  input_filtering:
    enabled: true
    max_input_size: 1048576    # 1MB limit
    blocked_patterns: []       # Regex patterns to block
    allowed_file_types: ["txt", "json", "csv"]
    
  # Output Filtering
  output_filtering:
    enabled: true
    sanitization: true         # Enable output sanitization
    max_output_size: 524288    # 512KB limit
    
  # Authentication
  authentication:
    enabled: true
    method: "jwt"              # jwt, api_key, oauth
    secret_key: "change-me"    # JWT secret key
    token_expiry: "24h"        # Token expiration
    
  # Rate Limiting
  rate_limiting:
    enabled: true
    requests_per_minute: 100   # Requests per minute per IP
    burst_size: 10             # Burst allowance
    window_size: "1m"          # Rate limiting window

# Database Configuration
database:
  type: "sqlite"               # sqlite, postgres, mysql
  connection_string: "data/hackai.db"
  max_connections: 25          # Connection pool size
  connection_timeout: "30s"    # Connection timeout
  
  # PostgreSQL specific
  postgres:
    host: "localhost"
    port: 5432
    database: "hackai"
    username: "hackai"
    password: ""               # Use environment variable
    ssl_mode: "disable"        # disable, require, verify-full
    
# Cache Configuration
cache:
  type: "memory"               # memory, redis
  ttl: "5m"                    # Time to live
  max_size: 1000               # Max cache entries
  
  # Redis specific
  redis:
    host: "localhost"
    port: 6379
    password: ""               # Use environment variable
    database: 0               # Redis database number

# Threat Intelligence
threat_intelligence:
  enabled: true
  update_interval: "1h"        # Feed update frequency
  cache_timeout: "4h"          # Cache timeout
  max_cache_size: 10000        # Max cached indicators
  
  # IOC Types
  ioc_types: ["ip", "domain", "hash", "url"]
  
  # Feed Sources
  sources: ["internal"]        # internal, external feeds
  
  # API Keys for external feeds
  api_keys: {}                 # Use environment variables

# Logging Configuration
logging:
  level: "info"                # debug, info, warn, error
  format: "json"               # json, text
  output: "stdout"             # stdout, file, both
  file: "logs/hackai.log"      # Log file path
  max_size: "100MB"            # Max log file size
  max_backups: 5               # Number of backup files
  max_age: "30d"               # Max age of log files
  
# Metrics Configuration
metrics:
  enabled: true
  endpoint: "/metrics"         # Metrics endpoint path
  port: 9090                   # Metrics server port
  
  # Custom metrics
  custom_metrics:
    enabled: true
    collection_interval: "30s"
    
# Performance Configuration
performance:
  max_concurrent_requests: 1000  # Max concurrent requests
  worker_pool_size: 50           # Worker goroutines
  request_timeout: "30s"         # Request processing timeout
  
  # Memory management
  gc_percent: 100                # Garbage collection target
  memory_limit: "2GB"            # Memory usage limit
  
  # Optimization flags
  fast_mode: false               # Trade accuracy for speed
  parallel_analysis: true        # Enable parallel processing
```

## 🌍 **Environment-Specific Configurations**

### **Development Configuration**

```yaml
# config/development.yaml
server:
  port: 8080
  
security:
  # Relaxed security for development
  ai_firewall:
    confidence_threshold: 0.5  # Lower threshold
  authentication:
    enabled: false             # Disable auth for testing
  rate_limiting:
    enabled: false             # Disable rate limiting
    
database:
  type: "sqlite"
  connection_string: "dev.db"
  
logging:
  level: "debug"               # Verbose logging
  format: "text"               # Human-readable logs
  output: "stdout"
  
metrics:
  enabled: true
  
performance:
  max_concurrent_requests: 100 # Lower limits for dev
```

### **Staging Configuration**

```yaml
# config/staging.yaml
server:
  port: 8080
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/staging.crt"
    key_file: "/etc/ssl/private/staging.key"
    
security:
  # Production-like security
  ai_firewall:
    confidence_threshold: 0.7
  authentication:
    enabled: true
    method: "jwt"
  rate_limiting:
    enabled: true
    requests_per_minute: 200
    
database:
  type: "postgres"
  postgres:
    host: "staging-db.internal"
    database: "hackai_staging"
    
cache:
  type: "redis"
  redis:
    host: "staging-redis.internal"
    
logging:
  level: "info"
  format: "json"
  output: "both"
  file: "/var/log/hackai/staging.log"
  
threat_intelligence:
  enabled: true
  sources: ["internal", "external"]
```

### **Production Configuration**

```yaml
# config/production.yaml
server:
  port: 8080
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/production.crt"
    key_file: "/etc/ssl/private/production.key"
    min_version: "1.3"
    
security:
  # Maximum security
  ai_firewall:
    enabled: true
    confidence_threshold: 0.8  # Higher threshold
  authentication:
    enabled: true
    method: "jwt"
    token_expiry: "8h"         # Shorter expiry
  rate_limiting:
    enabled: true
    requests_per_minute: 500   # Higher limits
    
database:
  type: "postgres"
  postgres:
    host: "prod-db-cluster.internal"
    database: "hackai_production"
    ssl_mode: "require"
  max_connections: 50
  
cache:
  type: "redis"
  redis:
    host: "prod-redis-cluster.internal"
  max_size: 50000              # Larger cache
  
logging:
  level: "warn"                # Less verbose
  format: "json"
  output: "file"
  file: "/var/log/hackai/production.log"
  
threat_intelligence:
  enabled: true
  sources: ["internal", "commercial", "government"]
  update_interval: "30m"       # More frequent updates
  
performance:
  max_concurrent_requests: 2000 # High performance
  worker_pool_size: 100
  parallel_analysis: true
  
metrics:
  enabled: true
  custom_metrics:
    enabled: true
    collection_interval: "15s" # More frequent collection
```

## 🔐 **Environment Variables**

### **Core Environment Variables**

```bash
# Server Configuration
export HACKAI_SERVER_HOST="0.0.0.0"
export HACKAI_SERVER_PORT="8080"
export HACKAI_SERVER_TLS_ENABLED="false"

# Security Configuration
export HACKAI_SECURITY_ENABLED="true"
export HACKAI_AI_FIREWALL_ENABLED="true"
export HACKAI_AUTH_SECRET_KEY="your-secret-key-here"
export HACKAI_AUTH_TOKEN_EXPIRY="24h"

# Database Configuration
export HACKAI_DB_TYPE="postgres"
export HACKAI_DB_HOST="localhost"
export HACKAI_DB_PORT="5432"
export HACKAI_DB_NAME="hackai"
export HACKAI_DB_USER="hackai"
export HACKAI_DB_PASSWORD="secure-password"

# Cache Configuration
export HACKAI_CACHE_TYPE="redis"
export HACKAI_REDIS_HOST="localhost"
export HACKAI_REDIS_PORT="6379"
export HACKAI_REDIS_PASSWORD="redis-password"

# Logging Configuration
export HACKAI_LOG_LEVEL="info"
export HACKAI_LOG_FORMAT="json"
export HACKAI_LOG_OUTPUT="stdout"

# Threat Intelligence
export HACKAI_THREAT_INTEL_ENABLED="true"
export HACKAI_THREAT_INTEL_API_KEY_VIRUSTOTAL="your-vt-api-key"
export HACKAI_THREAT_INTEL_API_KEY_ALIENVAULT="your-av-api-key"
```

### **Security Best Practices for Environment Variables**

```bash
# Use a .env file for development (never commit to git)
# .env
HACKAI_AUTH_SECRET_KEY=dev-secret-key-change-in-production
HACKAI_DB_PASSWORD=dev-password
HACKAI_REDIS_PASSWORD=dev-redis-password

# Use secrets management in production
# Docker Secrets
docker secret create hackai_db_password db_password.txt
docker service create --secret hackai_db_password hackai/security-platform

# Kubernetes Secrets
kubectl create secret generic hackai-secrets \
  --from-literal=db-password=secure-password \
  --from-literal=redis-password=redis-password \
  --from-literal=auth-secret=jwt-secret-key
```

## ⚙️ **Configuration Management**

### **Configuration Validation**

```bash
# Validate configuration file
hackai config validate --config config.yaml

# Validate with strict mode (all required fields)
hackai config validate --config config.yaml --strict

# Check configuration syntax
hackai config check --config config.yaml
```

### **Configuration Generation**

```bash
# Generate default configuration
hackai config init

# Generate configuration for specific environment
hackai config init --template production

# Generate with custom values
hackai config init --set server.port=8081 --set security.enabled=true
```

### **Runtime Configuration Updates**

```bash
# Get current configuration
hackai config get

# Get specific configuration section
hackai config get security.ai_firewall

# Update configuration (requires restart)
hackai config set security.confidence_threshold 0.8

# Update multiple values
hackai config set \
  security.confidence_threshold=0.8 \
  performance.max_concurrent_requests=2000
```

## 🔧 **Common Configuration Patterns**

### **High Security Configuration**

```yaml
security:
  ai_firewall:
    enabled: true
    confidence_threshold: 0.9    # Very strict
    prompt_injection_protection: true
    semantic_analysis: true
    
  authentication:
    enabled: true
    method: "jwt"
    token_expiry: "4h"           # Short expiry
    
  rate_limiting:
    enabled: true
    requests_per_minute: 50      # Conservative limits
    burst_size: 5
    
  input_filtering:
    enabled: true
    max_input_size: 50000        # Smaller limits
    blocked_patterns:
      - "(?i)(password|secret|key)"
      - "(?i)(ignore|bypass|override)"
```

### **High Performance Configuration**

```yaml
performance:
  max_concurrent_requests: 5000  # High throughput
  worker_pool_size: 200
  request_timeout: "10s"         # Fast timeouts
  parallel_analysis: true
  fast_mode: true                # Speed over accuracy
  
cache:
  type: "redis"
  ttl: "10m"                     # Longer cache
  max_size: 100000               # Large cache
  
security:
  ai_firewall:
    confidence_threshold: 0.6    # Lower threshold for speed
    
database:
  max_connections: 100           # Large connection pool
  connection_timeout: "5s"       # Fast connections
```

### **Development-Friendly Configuration**

```yaml
security:
  authentication:
    enabled: false               # No auth for testing
  rate_limiting:
    enabled: false               # No rate limits
    
logging:
  level: "debug"                 # Verbose logging
  format: "text"                 # Human-readable
  output: "stdout"
  
database:
  type: "sqlite"                 # Simple database
  connection_string: "test.db"
  
metrics:
  enabled: true                  # Enable monitoring
  
performance:
  max_concurrent_requests: 100   # Lower limits
```

## 📊 **Configuration Monitoring**

### **Configuration Health Checks**

```bash
# Check configuration health
hackai health config

# Validate all configuration sections
hackai config validate --all

# Check for deprecated settings
hackai config deprecated
```

### **Configuration Metrics**

```yaml
metrics:
  enabled: true
  custom_metrics:
    enabled: true
    
    # Track configuration changes
    config_changes:
      enabled: true
      
    # Monitor configuration validation
    config_validation:
      enabled: true
```

## 🔍 **Troubleshooting Configuration**

### **Common Configuration Issues**

```bash
# Invalid YAML syntax
hackai config validate --config config.yaml
# Error: yaml: line 15: mapping values are not allowed in this context

# Missing required fields
hackai config validate --strict
# Error: required field 'security.auth.secret_key' is missing

# Invalid values
hackai config validate
# Error: invalid value for 'server.port': must be between 1 and 65535
```

### **Configuration Debugging**

```bash
# Show effective configuration (after merging all sources)
hackai config show --effective

# Show configuration sources
hackai config sources

# Debug configuration loading
hackai start --debug-config
```

This configuration guide provides the foundation for properly configuring the HackAI Security Platform for different environments and use cases.
