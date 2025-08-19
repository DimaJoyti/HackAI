# LLM Security Proxy - Configuration Guide

This directory contains environment-specific configurations for the LLM Security Proxy. The configuration system supports multiple deployment environments with appropriate security policies and system settings.

## 📁 Directory Structure

```
configs/
├── config.yaml                    # Base configuration template
├── environments/                  # Environment-specific configurations
│   ├── development.yaml           # Development environment
│   ├── staging.yaml               # Staging environment
│   └── production.yaml            # Production environment
└── README.md                      # This file
```

## 🌍 Environment Configurations

### Development Environment (`development.yaml`)

**Purpose**: Local development with relaxed security and enhanced debugging

**Key Features**:
- ✅ Debug mode enabled
- ✅ Verbose logging (debug level)
- ✅ Hot reload support
- ✅ All development tools included
- ⚠️ Relaxed security policies
- ⚠️ No TLS encryption
- ⚠️ Sensitive data not masked

**Use Cases**:
- Local development
- Feature testing
- Debugging and troubleshooting
- Integration testing

**Services Included**:
- LLM Security Proxy
- PostgreSQL database
- Redis cache
- Jaeger tracing
- Prometheus metrics
- Grafana dashboards
- pgAdmin (database management)
- Redis Commander
- MailHog (email testing)

### Staging Environment (`staging.yaml`)

**Purpose**: Production-like testing and validation environment

**Key Features**:
- ✅ Production-like security settings
- ✅ TLS encryption enabled
- ✅ Comprehensive monitoring
- ✅ Load testing capabilities
- ✅ Security scanning
- ⚠️ Some testing features enabled
- ⚠️ Shorter data retention

**Use Cases**:
- Pre-production testing
- Performance testing
- Security validation
- User acceptance testing
- Load testing

**Services Included**:
- LLM Security Proxy (multiple replicas)
- PostgreSQL with SSL
- Redis with authentication
- Nginx load balancer
- Full monitoring stack
- Log aggregation (Loki)
- Load testing tools (k6)

### Production Environment (`production.yaml`)

**Purpose**: Secure, high-performance production deployment

**Key Features**:
- ✅ Maximum security enforcement
- ✅ Strict mode enabled
- ✅ TLS encryption required
- ✅ Sensitive data masking
- ✅ High availability setup
- ✅ Auto-scaling support
- ✅ Comprehensive backup
- ❌ Debug features disabled
- ❌ Testing features disabled

**Use Cases**:
- Production deployment
- Live customer traffic
- Mission-critical operations

**Services Included**:
- LLM Security Proxy (HA cluster)
- Managed database services
- Load balancing and SSL termination
- Production monitoring
- Security scanning
- Automated backups

## 🔧 Configuration Management

### Loading Configurations

The application automatically loads the appropriate configuration based on the `ENVIRONMENT` variable:

```bash
# Development
export ENVIRONMENT=development

# Staging
export ENVIRONMENT=staging

# Production
export ENVIRONMENT=production
```

### Configuration Hierarchy

1. **Base Configuration** (`config.yaml`) - Default values and structure
2. **Environment Configuration** - Environment-specific overrides
3. **Environment Variables** - Runtime overrides for sensitive data

### Environment Variables

Sensitive configuration values are loaded from environment variables:

```yaml
# In configuration files
database:
  password: "${DB_PASSWORD}"
  
jwt:
  secret: "${JWT_SECRET}"
```

## 🛡️ Security Considerations

### Development Environment
- **Security Level**: Low (for ease of development)
- **Data Sensitivity**: Test data only
- **Network**: Local only
- **Authentication**: Simplified
- **Encryption**: Disabled

### Staging Environment
- **Security Level**: High (production-like)
- **Data Sensitivity**: Anonymized production data
- **Network**: Private with controlled access
- **Authentication**: Full authentication
- **Encryption**: TLS enabled

### Production Environment
- **Security Level**: Maximum
- **Data Sensitivity**: Live customer data
- **Network**: Secure with WAF protection
- **Authentication**: Multi-factor authentication
- **Encryption**: End-to-end encryption

## 📊 Monitoring and Observability

### Development
- **Logging**: Debug level, human-readable format
- **Metrics**: Basic metrics collection
- **Tracing**: Full tracing (100% sampling)
- **Alerts**: Disabled

### Staging
- **Logging**: Info level, JSON format
- **Metrics**: Comprehensive metrics
- **Tracing**: Sampled tracing (10%)
- **Alerts**: Test alerts enabled

### Production
- **Logging**: Warn level, structured JSON
- **Metrics**: Production metrics with SLIs
- **Tracing**: Minimal sampling (1%)
- **Alerts**: Critical alerts only

## 🚀 Quick Start

### 1. Development Setup

```bash
# Copy development environment variables
cp .env.development .env

# Start development environment
make dev

# Access services
open http://localhost:8080        # LLM Security Proxy
open http://localhost:3000        # Grafana (admin/admin)
open http://localhost:16686       # Jaeger Tracing
```

### 2. Staging Deployment

```bash
# Set up staging environment variables
cp .env.staging .env

# Configure staging secrets
export STAGING_DB_PASSWORD="your-staging-db-password"
export STAGING_JWT_SECRET="your-staging-jwt-secret"

# Deploy to staging
make staging-deploy
```

### 3. Production Deployment

```bash
# Set up production environment variables
cp .env.production .env

# Configure production secrets (use secret management)
export PROD_DB_PASSWORD="$(vault kv get -field=password secret/prod/db)"
export PROD_JWT_SECRET="$(vault kv get -field=secret secret/prod/jwt)"

# Deploy to production
make prod-deploy
```

## 🔍 Configuration Validation

Validate your configurations before deployment:

```bash
# Validate all configurations
./scripts/validate-config.sh

# Validate specific environment
make config-validate

# Check configuration syntax
yq eval '.' configs/environments/production.yaml
```

## 📝 Customization

### Adding New Environments

1. Create new environment file: `configs/environments/custom.yaml`
2. Create corresponding Docker Compose: `docker-compose.custom.yml`
3. Create environment variables: `.env.custom`
4. Add Makefile targets for the new environment

### Modifying Configurations

1. Edit the appropriate environment file
2. Validate changes: `./scripts/validate-config.sh`
3. Test in development first
4. Deploy through staging before production

### Environment Variables

Add new environment variables to:
- Configuration files (using `${VAR_NAME}` syntax)
- Environment-specific `.env` files
- Docker Compose files
- Documentation

## 🔒 Security Best Practices

### Secrets Management
- ✅ Use environment variables for secrets
- ✅ Never commit secrets to version control
- ✅ Use secret management services in production
- ✅ Rotate secrets regularly

### Configuration Security
- ✅ Validate all configurations
- ✅ Use least privilege principles
- ✅ Enable audit logging
- ✅ Monitor configuration changes

### Network Security
- ✅ Use TLS in staging and production
- ✅ Implement proper firewall rules
- ✅ Use private networks where possible
- ✅ Enable DDoS protection

## 📚 Additional Resources

- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [YAML Specification](https://yaml.org/spec/)
- [Environment Variables Best Practices](https://12factor.net/config)
- [Security Configuration Guide](../docs/security.md)
- [Monitoring Setup Guide](../docs/monitoring.md)

## 🆘 Troubleshooting

### Common Issues

1. **Configuration Validation Errors**
   ```bash
   # Check YAML syntax
   yq eval '.' configs/environments/development.yaml
   
   # Validate Docker Compose
   docker-compose -f docker-compose.development.yml config
   ```

2. **Environment Variable Issues**
   ```bash
   # Check environment variables
   env | grep -E "(DB_|REDIS_|JWT_)"
   
   # Validate .env file
   source .env && echo $ENVIRONMENT
   ```

3. **Service Connection Issues**
   ```bash
   # Check service health
   make health
   
   # View service logs
   make logs
   ```

### Getting Help

- Check the [troubleshooting guide](../docs/troubleshooting.md)
- Review service logs: `make logs`
- Validate configurations: `./scripts/validate-config.sh`
- Open an issue on GitHub
