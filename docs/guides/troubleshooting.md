# 🔧 HackAI LLM Security Proxy - Troubleshooting Guide

Comprehensive troubleshooting guide for common issues, performance problems, and debugging techniques.

## 📋 Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Common Issues](#common-issues)
- [Performance Troubleshooting](#performance-troubleshooting)
- [Security Issues](#security-issues)
- [Database Problems](#database-problems)
- [Network Issues](#network-issues)
- [Configuration Problems](#configuration-problems)
- [Monitoring & Debugging](#monitoring--debugging)
- [Log Analysis](#log-analysis)
- [Recovery Procedures](#recovery-procedures)

## 🩺 Quick Diagnostics

### Health Check Commands

```bash
# Service health check
curl -f http://localhost:8080/health

# Readiness check
curl -f http://localhost:8080/ready

# Metrics endpoint
curl http://localhost:8080/metrics

# Service status
make status

# View logs
make logs

# Configuration validation
./scripts/validate-config.sh
```

### System Status Overview

```bash
# Check all services
docker-compose ps

# Check resource usage
docker stats

# Check disk space
df -h

# Check memory usage
free -h

# Check network connectivity
netstat -tulpn | grep 8080
```

## ❗ Common Issues

### 1. Service Won't Start

**Symptoms:**
- Container exits immediately
- "Connection refused" errors
- Service not responding

**Diagnosis:**
```bash
# Check container logs
docker-compose logs llm-security-proxy

# Check container status
docker-compose ps

# Check port conflicts
netstat -tulpn | grep 8080

# Validate configuration
./scripts/validate-config.sh
```

**Solutions:**

#### Port Already in Use
```bash
# Find process using port
lsof -i :8080

# Kill process
kill -9 <PID>

# Or change port in configuration
export SERVER_PORT=8081
```

#### Configuration Errors
```bash
# Validate YAML syntax
yq eval '.' configs/environments/development.yaml

# Check environment variables
env | grep -E "(DB_|REDIS_|JWT_)"

# Reset to default configuration
cp .env.example .env
```

#### Missing Dependencies
```bash
# Check database connection
docker-compose exec postgres psql -U postgres -c "SELECT 1;"

# Check Redis connection
docker-compose exec redis redis-cli ping

# Restart dependencies
docker-compose restart postgres redis
```

### 2. Authentication Failures

**Symptoms:**
- "Unauthorized" errors
- JWT token validation failures
- Login endpoint not working

**Diagnosis:**
```bash
# Test login endpoint
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password"}'

# Check JWT secret
echo $JWT_SECRET | wc -c  # Should be >= 32 characters

# Verify database user table
docker-compose exec postgres psql -U postgres -d hackai_dev \
  -c "SELECT id, email FROM users LIMIT 5;"
```

**Solutions:**

#### Invalid JWT Secret
```bash
# Generate new JWT secret
export JWT_SECRET=$(openssl rand -base64 32)

# Update environment file
echo "JWT_SECRET=$JWT_SECRET" >> .env

# Restart service
docker-compose restart llm-security-proxy
```

#### Database Connection Issues
```bash
# Check database logs
docker-compose logs postgres

# Reset database
docker-compose down -v
docker-compose up -d postgres
make db-migrate
```

### 3. LLM Provider Errors

**Symptoms:**
- "Provider not available" errors
- API key validation failures
- Timeout errors

**Diagnosis:**
```bash
# Test provider connectivity
curl -X GET http://localhost:8080/api/v1/llm/providers

# Check API keys
echo $OPENAI_API_KEY | head -c 10

# Test direct provider access
curl -X POST https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"test"}]}'
```

**Solutions:**

#### Invalid API Keys
```bash
# Verify API key format
if [[ $OPENAI_API_KEY =~ ^sk-[a-zA-Z0-9]{48}$ ]]; then
  echo "Valid OpenAI API key format"
else
  echo "Invalid OpenAI API key format"
fi

# Test API key
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
  https://api.openai.com/v1/models
```

#### Rate Limiting
```bash
# Check rate limit headers
curl -I -X POST https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY"

# Implement exponential backoff
# (handled automatically by the proxy)
```

### 4. High Memory Usage

**Symptoms:**
- Out of memory errors
- Slow response times
- Container restarts

**Diagnosis:**
```bash
# Check memory usage
docker stats llm-security-proxy

# Memory profiling
curl http://localhost:6060/debug/pprof/heap > heap.prof
go tool pprof heap.prof

# Check for memory leaks
curl http://localhost:6060/debug/pprof/goroutine?debug=1
```

**Solutions:**

#### Reduce Memory Usage
```yaml
# Adjust configuration
audit:
  logger:
    batch_size: 50        # Reduce from 100
    max_queue_size: 5000  # Reduce from 10000

database:
  max_open_conns: 10      # Reduce from 25
  max_idle_conns: 2       # Reduce from 5
```

#### Increase Container Limits
```yaml
# docker-compose.yml
services:
  llm-security-proxy:
    deploy:
      resources:
        limits:
          memory: 2G      # Increase from 1G
        reservations:
          memory: 1G
```

## 🚀 Performance Troubleshooting

### 1. Slow Response Times

**Diagnosis:**
```bash
# Check response times
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8080/health

# CPU profiling
curl http://localhost:6060/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof cpu.prof

# Check database performance
docker-compose exec postgres psql -U postgres -d hackai_dev \
  -c "SELECT query, mean_time, calls FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;"
```

**Solutions:**

#### Database Optimization
```sql
-- Add indexes for common queries
CREATE INDEX CONCURRENTLY idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX CONCURRENTLY idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX CONCURRENTLY idx_security_events_threat_score ON security_events(threat_score);

-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM audit_logs WHERE user_id = 'user123' ORDER BY timestamp DESC LIMIT 10;
```

#### Caching Configuration
```yaml
# Enable Redis caching
redis:
  enabled: true
  cache_ttl: "5m"
  max_memory: "256mb"
  eviction_policy: "allkeys-lru"

# Application caching
security:
  policy_engine:
    cache_enabled: true
    cache_ttl: "10m"
```

### 2. High CPU Usage

**Diagnosis:**
```bash
# Check CPU usage
top -p $(docker inspect --format '{{.State.Pid}}' hackai_llm-security-proxy_1)

# CPU profiling
curl http://localhost:6060/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof -http=:8081 cpu.prof
```

**Solutions:**

#### Optimize Security Scanning
```yaml
security:
  content_filter:
    scan_timeout: "5s"     # Reduce from 10s
    max_content_length: 50000  # Reduce from 100000
  
  threat_detection:
    batch_processing: true
    batch_size: 10
```

#### Load Balancing
```yaml
# Scale horizontally
services:
  llm-security-proxy:
    deploy:
      replicas: 3
```

## 🔒 Security Issues

### 1. High Threat Scores

**Symptoms:**
- Many requests being blocked
- False positive detections
- Legitimate requests flagged

**Diagnosis:**
```bash
# Check threat score distribution
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/monitoring/metrics?metric=threats&time_range=1h"

# Analyze blocked requests
docker-compose logs llm-security-proxy | grep "REQUEST_BLOCKED" | tail -10

# Review security policies
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/policies"
```

**Solutions:**

#### Adjust Threat Thresholds
```yaml
security:
  threat_score_threshold: 0.9  # Increase from 0.8
  content_filter:
    toxicity_threshold: 0.8    # Increase from 0.7
```

#### Whitelist Patterns
```json
{
  "name": "Whitelist Policy",
  "type": "whitelist",
  "rules": [
    {
      "condition": "user_in_whitelist",
      "users": ["admin@company.com", "trusted@company.com"],
      "action": "allow"
    },
    {
      "condition": "content_pattern",
      "patterns": ["legitimate business term"],
      "action": "allow"
    }
  ]
}
```

### 2. Policy Conflicts

**Diagnosis:**
```bash
# Test policy conflicts
curl -X POST http://localhost:8080/api/v1/policies/test \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"content":"test content","policies":["policy1","policy2"]}'

# Review policy order
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/policies?sort=priority"
```

**Solutions:**

#### Policy Prioritization
```json
{
  "policies": [
    {
      "id": "whitelist",
      "priority": 1,
      "action": "allow"
    },
    {
      "id": "content_filter",
      "priority": 2,
      "action": "filter"
    },
    {
      "id": "rate_limit",
      "priority": 3,
      "action": "throttle"
    }
  ]
}
```

## 🗄️ Database Problems

### 1. Connection Pool Exhaustion

**Symptoms:**
- "Too many connections" errors
- Slow database queries
- Connection timeouts

**Diagnosis:**
```sql
-- Check active connections
SELECT count(*) FROM pg_stat_activity;

-- Check connection limits
SHOW max_connections;

-- Check long-running queries
SELECT pid, now() - pg_stat_activity.query_start AS duration, query 
FROM pg_stat_activity 
WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes';
```

**Solutions:**

#### Optimize Connection Pool
```yaml
database:
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: "5m"
  conn_max_idle_time: "1m"
```

#### Kill Long-Running Queries
```sql
-- Kill specific query
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid = <PID>;

-- Kill all idle connections
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle';
```

### 2. Slow Queries

**Diagnosis:**
```sql
-- Enable query logging
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_min_duration_statement = 1000;  -- Log queries > 1s
SELECT pg_reload_conf();

-- Check slow queries
SELECT query, mean_time, calls, total_time
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;
```

**Solutions:**

#### Add Indexes
```sql
-- Common indexes for audit logs
CREATE INDEX CONCURRENTLY idx_audit_logs_user_timestamp 
ON audit_logs(user_id, timestamp DESC);

CREATE INDEX CONCURRENTLY idx_audit_logs_threat_score 
ON audit_logs(threat_score) WHERE threat_score > 0.5;

-- Analyze table statistics
ANALYZE audit_logs;
```

## 🌐 Network Issues

### 1. Connection Timeouts

**Diagnosis:**
```bash
# Test network connectivity
curl -v http://localhost:8080/health

# Check DNS resolution
nslookup api.openai.com

# Test provider connectivity
curl -I https://api.openai.com/v1/models

# Check firewall rules
iptables -L
```

**Solutions:**

#### Adjust Timeouts
```yaml
server:
  read_timeout: "60s"    # Increase from 30s
  write_timeout: "60s"   # Increase from 30s

ai:
  providers:
    openai:
      timeout: "60s"     # Increase from 30s
      max_retries: 5     # Increase from 3
```

#### Configure Proxy
```bash
# Set HTTP proxy
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080

# Configure in application
curl -x http://proxy.company.com:8080 https://api.openai.com/v1/models
```

## ⚙️ Configuration Problems

### 1. Environment Variable Issues

**Diagnosis:**
```bash
# Check all environment variables
env | grep -E "(HACKAI|DB_|REDIS_|JWT_|OPENAI_)"

# Validate required variables
required_vars=("DB_HOST" "DB_PASSWORD" "JWT_SECRET" "OPENAI_API_KEY")
for var in "${required_vars[@]}"; do
  if [[ -z "${!var}" ]]; then
    echo "Missing required variable: $var"
  fi
done

# Check variable formats
if [[ ${#JWT_SECRET} -lt 32 ]]; then
  echo "JWT_SECRET too short (minimum 32 characters)"
fi
```

**Solutions:**

#### Environment Variable Template
```bash
# Create .env from template
cp .env.example .env

# Generate secure secrets
export JWT_SECRET=$(openssl rand -base64 32)
export DB_PASSWORD=$(openssl rand -base64 16)

# Update .env file
sed -i "s/JWT_SECRET=.*/JWT_SECRET=$JWT_SECRET/" .env
sed -i "s/DB_PASSWORD=.*/DB_PASSWORD=$DB_PASSWORD/" .env
```

### 2. YAML Configuration Errors

**Diagnosis:**
```bash
# Validate YAML syntax
yq eval '.' configs/environments/development.yaml

# Check for common errors
yamllint configs/environments/development.yaml

# Validate configuration schema
./scripts/validate-config.sh
```

**Solutions:**

#### Fix YAML Syntax
```bash
# Common YAML issues:
# 1. Incorrect indentation (use spaces, not tabs)
# 2. Missing quotes around special characters
# 3. Incorrect list syntax

# Example fix:
# Wrong:
# items:
# - item1
# - item2

# Correct:
# items:
#   - item1
#   - item2
```

## 📊 Monitoring & Debugging

### 1. Enable Debug Logging

```yaml
# Development configuration
observability:
  logging:
    level: "debug"
    format: "text"
    add_source: true

debug:
  enabled: true
  verbose_logging: true
  log_sql_queries: true
```

### 2. Performance Profiling

```bash
# CPU profiling
curl http://localhost:6060/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof -http=:8081 cpu.prof

# Memory profiling
curl http://localhost:6060/debug/pprof/heap > heap.prof
go tool pprof -http=:8082 heap.prof

# Goroutine analysis
curl http://localhost:6060/debug/pprof/goroutine?debug=1
```

### 3. Distributed Tracing

```bash
# Check Jaeger traces
open http://localhost:16686

# Search for slow requests
# Filter by: service=llm-security-proxy duration>1s

# Analyze trace spans
# Look for: database queries, external API calls, security scans
```

## 📋 Log Analysis

### 1. Common Log Patterns

```bash
# Error patterns
grep -E "(ERROR|FATAL)" logs/app.log

# Security violations
grep "threat_score" logs/app.log | jq '.threat_score'

# Performance issues
grep "processing_time" logs/app.log | jq '.processing_time_ms' | sort -n

# Database errors
grep "database" logs/app.log | grep -i error
```

### 2. Log Analysis Scripts

```bash
#!/bin/bash
# analyze-logs.sh

# Top error messages
echo "=== Top Error Messages ==="
grep ERROR logs/app.log | cut -d'"' -f4 | sort | uniq -c | sort -nr | head -10

# Threat score distribution
echo "=== Threat Score Distribution ==="
grep "threat_score" logs/app.log | jq -r '.threat_score' | \
  awk '{
    if ($1 < 0.3) low++
    else if ($1 < 0.6) medium++
    else if ($1 < 0.8) high++
    else critical++
  }
  END {
    print "Low: " low
    print "Medium: " medium  
    print "High: " high
    print "Critical: " critical
  }'

# Response time percentiles
echo "=== Response Time Percentiles ==="
grep "processing_time_ms" logs/app.log | jq -r '.processing_time_ms' | \
  sort -n | awk '
  {
    times[NR] = $1
  }
  END {
    print "50th percentile: " times[int(NR*0.5)]
    print "90th percentile: " times[int(NR*0.9)]
    print "95th percentile: " times[int(NR*0.95)]
    print "99th percentile: " times[int(NR*0.99)]
  }'
```

## 🔄 Recovery Procedures

### 1. Service Recovery

```bash
# Graceful restart
docker-compose restart llm-security-proxy

# Force restart
docker-compose stop llm-security-proxy
docker-compose up -d llm-security-proxy

# Full environment restart
docker-compose down
docker-compose up -d
```

### 2. Database Recovery

```bash
# Restore from backup
docker-compose exec postgres pg_restore -U postgres -d hackai_dev /backups/latest.sql

# Reset database
docker-compose down -v
docker-compose up -d postgres
make db-migrate
make db-seed
```

### 3. Configuration Recovery

```bash
# Reset to default configuration
git checkout configs/environments/development.yaml
cp .env.example .env

# Validate and restart
./scripts/validate-config.sh
docker-compose restart llm-security-proxy
```

### 4. Emergency Procedures

```bash
# Disable security features temporarily
export SECURITY_ENABLED=false
export RATE_LIMITING_ENABLED=false
docker-compose restart llm-security-proxy

# Enable maintenance mode
curl -X POST http://localhost:8080/api/v1/admin/maintenance \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"enabled": true, "message": "System maintenance in progress"}'

# Drain traffic
# (Configure load balancer to stop sending traffic)
```

## 📞 Getting Help

### 1. Collect Diagnostic Information

```bash
#!/bin/bash
# collect-diagnostics.sh

echo "=== System Information ==="
uname -a
docker --version
docker-compose --version

echo "=== Service Status ==="
docker-compose ps

echo "=== Resource Usage ==="
docker stats --no-stream

echo "=== Recent Logs ==="
docker-compose logs --tail=100 llm-security-proxy

echo "=== Configuration ==="
./scripts/validate-config.sh

echo "=== Network ==="
netstat -tulpn | grep -E "(8080|5432|6379)"
```

### 2. Support Channels

- **GitHub Issues**: https://github.com/DimaJoyti/HackAI/issues
- **Documentation**: https://docs.hackai.dev
- **Community Forum**: https://community.hackai.dev
- **Security Issues**: security@hackai.dev

### 3. Information to Include

When reporting issues, include:

- Error messages and stack traces
- Configuration files (sanitized)
- Log excerpts
- System information
- Steps to reproduce
- Expected vs actual behavior

For more detailed troubleshooting, see the [Advanced Debugging Guide](advanced-debugging.md).
