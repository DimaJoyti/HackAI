# 🔒 HackAI Security Guide

This document outlines security best practices and procedures for the HackAI platform.

## 🚨 Critical Security Requirements

### Environment Variables & Secrets Management

**NEVER commit secrets to version control!** All sensitive information must be stored as environment variables.

#### Required Environment Variables

| Variable | Description | Required | Example |
|----------|-------------|----------|---------|
| `DB_PASSWORD` | Database password | ✅ | Strong 12+ char password |
| `JWT_SECRET` | JWT signing secret | ✅ | 32+ character random string |
| `ENCRYPTION_KEY` | Data encryption key | ✅ | 32+ character random string |
| `REDIS_PASSWORD` | Redis password | 🔶 | Required for production |
| `OPENAI_API_KEY` | OpenAI API key | ✅ | sk-... |
| `ANTHROPIC_API_KEY` | Anthropic API key | 🔶 | Optional |

#### Secret Strength Requirements

- **Minimum length**: 12 characters for passwords, 32 for keys
- **No weak patterns**: Avoid "password", "123456", "admin", etc.
- **Random generation**: Use cryptographically secure random generators
- **Regular rotation**: Rotate secrets every 90 days in production

## 🛠️ Security Tools & Scripts

### Quick Setup

```bash
# Generate secure secrets and create .env file
make setup-secrets

# Validate existing secrets
make validate-secrets

# Run comprehensive security audit
make security-audit

# Run all security checks
make audit
```

### Manual Secret Generation

```bash
# Generate a secure password (24 characters)
openssl rand -base64 24 | tr -d "=+/" | cut -c1-24

# Generate a JWT secret (32 characters)
openssl rand -base64 32 | tr -d "=+/" | cut -c1-32

# Generate an encryption key (32 characters)
openssl rand -hex 16
```

## 🔧 Configuration Security

### Development Environment

```yaml
# configs/environments/development.yaml
database:
  password: "${DB_PASSWORD:-}"  # Empty default for local dev
jwt:
  secret: "${JWT_SECRET:-dev-secret-key-not-for-production}"
```

### Production Environment

```yaml
# configs/environments/production.yaml
database:
  password: "${DB_PASSWORD}"  # Required, no default
jwt:
  secret: "${JWT_SECRET}"     # Required, no default
```

## ☸️ Kubernetes Security

### Secret Management

**DO NOT** use hardcoded secrets in Kubernetes manifests!

#### Secure Secret Creation

```bash
# Generate and create secrets
kubectl create secret generic hackai-secrets \
  --from-literal=db-password="$(openssl rand -base64 32)" \
  --from-literal=jwt-secret="$(openssl rand -base64 32)" \
  --from-literal=encryption-key="$(openssl rand -base64 32)" \
  --namespace=hackai

# Or use the provided script
./scripts/setup-secrets.sh k8s
```

#### External Secret Management (Recommended)

Use external secret management systems:

- **AWS**: AWS Secrets Manager + External Secrets Operator
- **Azure**: Azure Key Vault + External Secrets Operator  
- **GCP**: Google Secret Manager + External Secrets Operator
- **HashiCorp Vault**: Vault + External Secrets Operator

## 🔍 Security Auditing

### Automated Checks

The security audit script checks for:

- ✅ Hardcoded secrets in source code
- ✅ Weak password patterns
- ✅ Exposed configuration files
- ✅ Committed environment files
- ✅ File permission issues

### Running Security Audits

```bash
# Run comprehensive security audit
./scripts/security-audit.sh

# Check specific areas
make security-scan        # Code vulnerability scan
make vulnerability-check  # Dependency vulnerabilities
make security-audit      # Hardcoded secrets audit
```

## 🚀 Deployment Security

### Pre-deployment Checklist

- [ ] All secrets use environment variables
- [ ] No hardcoded credentials in code
- [ ] Strong, unique secrets generated
- [ ] Security audit passes
- [ ] Dependencies updated
- [ ] SSL/TLS enabled
- [ ] Network policies configured

### CI/CD Security

Add to your CI/CD pipeline:

```yaml
# .github/workflows/security.yml
- name: Security Audit
  run: |
    make security-audit
    make vulnerability-check
```

## 🔄 Secret Rotation

### Regular Rotation Schedule

- **Development**: Every 6 months
- **Staging**: Every 3 months  
- **Production**: Every 90 days

### Rotation Process

```bash
# 1. Generate new secrets
./scripts/setup-secrets.sh rotate

# 2. Update external systems (databases, etc.)
# 3. Deploy updated configuration
# 4. Verify all services are working
# 5. Revoke old secrets
```

## 🚨 Incident Response

### If Secrets Are Exposed

1. **Immediate Actions**:
   - Rotate all exposed secrets immediately
   - Revoke API keys and tokens
   - Check logs for unauthorized access
   - Notify security team

2. **Investigation**:
   - Determine scope of exposure
   - Check git history for commits
   - Review access logs
   - Document timeline

3. **Recovery**:
   - Generate new secrets
   - Update all systems
   - Monitor for suspicious activity
   - Update security procedures

## 📋 Security Checklist

### Development

- [ ] `.env` files are gitignored
- [ ] No secrets in source code
- [ ] Environment variables used for all config
- [ ] Security audit passes locally

### Production

- [ ] External secret management configured
- [ ] Strong, unique secrets generated
- [ ] Regular secret rotation scheduled
- [ ] Monitoring and alerting enabled
- [ ] Network security configured
- [ ] SSL/TLS certificates valid

## 🔗 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [External Secrets Operator](https://external-secrets.io/)

## 📞 Security Contacts

- **Security Team**: security@hackai.com
- **Incident Response**: incident@hackai.com
- **Bug Bounty**: security-bounty@hackai.com

---

**Remember**: Security is everyone's responsibility. When in doubt, ask the security team!
