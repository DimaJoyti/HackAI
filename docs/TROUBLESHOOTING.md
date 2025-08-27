# 🔧 HackAI Platform - Comprehensive Troubleshooting Guide

## 🎯 Overview

This comprehensive troubleshooting guide covers common issues, solutions, and best practices for the HackAI platform. Whether you're experiencing installation problems, runtime errors, or performance issues, this guide will help you resolve them quickly.

## 🚨 Quick Diagnostic Checklist

Before diving into specific issues, run through this quick checklist:

```bash
# 1. Check Go version
go version  # Should be 1.21+

# 2. Verify dependencies
go mod verify
go mod tidy

# 3. Check system resources
free -h     # Memory usage
df -h       # Disk space
top         # CPU usage

# 4. Test basic connectivity
curl http://localhost:8080/api/realtime/health

# 5. Check logs
tail -f logs/hackai.log
```

## 🏗️ Installation & Setup Issues

### Issue: Go Version Compatibility
**Problem**: Build fails with Go version errors
```
go: module requires Go 1.21 or later
```

**Solution**:
```bash
# Update Go to latest version
# On Ubuntu/Debian:
sudo rm -rf /usr/local/go
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

# Update PATH
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc

# Verify installation
go version
```

### Issue: Dependency Download Failures
**Problem**: `go mod download` fails with network errors
```
go: module github.com/dimajoyti/hackai: reading https://proxy.golang.org/...
```

**Solutions**:
```bash
# Option 1: Use direct module fetching
export GOPROXY=direct
go mod download

# Option 2: Configure proxy
export GOPROXY=https://goproxy.io,direct
go mod download

# Option 3: Disable proxy for private repos
export GOPRIVATE=github.com/dimajoyti/*
go mod download

# Option 4: Clear module cache
go clean -modcache
go mod download
```

### Issue: Permission Denied Errors
**Problem**: Cannot write to directories or execute binaries
```
permission denied: ./hackai-demo
mkdir: cannot create directory 'logs': Permission denied
```

**Solutions**:
```bash
# Fix file permissions
chmod +x ./hackai-demo
chmod 755 ./scripts/*

# Fix directory permissions
sudo chown -R $USER:$USER .
chmod 755 logs/
chmod 644 configs/*

# For Docker issues
sudo usermod -aG docker $USER
newgrp docker
```

## 🔧 Runtime Issues

### Issue: Port Already in Use
**Problem**: Cannot bind to port 8080
```
listen tcp :8080: bind: address already in use
```

**Solutions**:
```bash
# Find process using port
lsof -i :8080
netstat -tulpn | grep :8080

# Kill process
sudo kill -9 <PID>

# Or use different port
export HACKAI_PORT=8081
go run ./cmd/realtime-systems-demo
```

### Issue: Database Connection Failures
**Problem**: Cannot connect to PostgreSQL/Redis
```
failed to connect to database: dial tcp 127.0.0.1:5432: connect: connection refused
```

**Solutions**:
```bash
# Check if services are running
sudo systemctl status postgresql
sudo systemctl status redis-server

# Start services
sudo systemctl start postgresql
sudo systemctl start redis-server

# Check connection
psql -h localhost -U hackai -d hackai
redis-cli ping

# Update connection strings
export HACKAI_DB_HOST=localhost
export HACKAI_DB_PORT=5432
export HACKAI_REDIS_HOST=localhost
export HACKAI_REDIS_PORT=6379
```

### Issue: Memory Issues
**Problem**: Out of memory errors or high memory usage
```
runtime: out of memory: cannot allocate 1073741824-byte block
```

**Solutions**:
```bash
# Check memory usage
free -h
ps aux --sort=-%mem | head

# Increase system memory limits
ulimit -v unlimited
ulimit -m unlimited

# Optimize Go garbage collector
export GOGC=100
export GOMEMLIMIT=4GiB

# Monitor memory usage
go tool pprof http://localhost:8080/debug/pprof/heap
```

## 🛡️ Security Issues

### Issue: Prompt Injection Detection False Positives
**Problem**: Legitimate content being blocked as malicious
```
Content blocked: Risk score 0.85 (threshold: 0.7)
```

**Solutions**:
```go
// Adjust sensitivity level
securityConfig := security.Config{
    SensitivityLevel: security.SensitivityMedium, // Instead of High
    CustomThreshold:  0.9, // Increase threshold
}

// Add whitelist patterns
guard.AddWhitelistPattern("legitimate business terms")

// Use context-aware analysis
result, err := guard.AnalyzeWithContext(ctx, content, &security.AnalysisContext{
    UserRole:    "admin",
    ContentType: "business_document",
})
```

### Issue: Authentication Failures
**Problem**: JWT token validation errors
```
invalid token: token is expired
invalid token: signature verification failed
```

**Solutions**:
```bash
# Check system time
date
sudo ntpdate -s time.nist.gov

# Verify JWT secret
echo $JWT_SECRET | base64 -d

# Check token expiration
jwt-cli decode $TOKEN

# Regenerate tokens
curl -X POST /api/v1/auth/refresh \
  -H "Authorization: Bearer $REFRESH_TOKEN"
```

## 📡 Real-time Communication Issues

### Issue: WebSocket Connection Failures
**Problem**: WebSocket connections not establishing
```
WebSocket connection failed: Error during WebSocket handshake
```

**Solutions**:
```javascript
// Check WebSocket URL
const ws = new WebSocket('ws://localhost:8080/ws');

// Add error handling
ws.onerror = function(error) {
    console.error('WebSocket error:', error);
};

// Check for proxy issues
ws.onopen = function() {
    console.log('WebSocket connected');
};

// Verify CORS settings
// In server configuration:
AllowedOrigins: []string{"*"}, // For development only
```

```bash
# Test WebSocket connection
wscat -c ws://localhost:8080/ws

# Check firewall
sudo ufw status
sudo iptables -L

# Verify reverse proxy config (if using nginx)
nginx -t
sudo systemctl reload nginx
```

### Issue: Message Delivery Failures
**Problem**: Messages not reaching subscribers
```
Message published but no subscribers received it
```

**Solutions**:
```go
// Check subscription status
subscriptions := pubsubManager.GetSubscriptions()
fmt.Printf("Active subscriptions: %d\n", len(subscriptions))

// Verify channel names match
err := realtimeSystem.Subscribe(ctx, connectionID, "exact-channel-name")

// Check message routing
router.RegisterRoute("debug", "*", debugHandler, 10)

// Enable debug logging
logger.SetLevel("debug")
```

## 🤖 Multi-Agent Issues

### Issue: Agent Task Timeouts
**Problem**: Agent tasks timing out before completion
```
Task timeout: task_123 exceeded 300s limit
```

**Solutions**:
```go
// Increase task timeout
config := &multiagent.OrchestratorConfig{
    TaskTimeout: 10 * time.Minute, // Increase from 5 minutes
}

// Add progress monitoring
task.ProgressCallback = func(progress float64) {
    fmt.Printf("Task progress: %.1f%%\n", progress*100)
}

// Implement task checkpointing
task.EnableCheckpointing = true
task.CheckpointInterval = 30 * time.Second
```

### Issue: Agent Communication Failures
**Problem**: Agents cannot communicate with each other
```
Agent communication failed: connection refused
```

**Solutions**:
```go
// Check agent registration
agents := orchestrator.GetRegisteredAgents()
for _, agent := range agents {
    fmt.Printf("Agent: %s, Status: %s\n", agent.ID, agent.Status)
}

// Verify network connectivity
err := orchestrator.PingAgent(ctx, "agent-id")

// Enable agent health checks
config.HealthCheckInterval = 30 * time.Second
config.EnableFailover = true
```

## 📊 Performance Issues

### Issue: High Latency
**Problem**: API responses taking too long
```
Request took 5.2s (expected < 1s)
```

**Solutions**:
```bash
# Profile the application
go tool pprof http://localhost:8080/debug/pprof/profile

# Check database queries
EXPLAIN ANALYZE SELECT * FROM security_events WHERE created_at > NOW() - INTERVAL '1 hour';

# Optimize database indexes
CREATE INDEX CONCURRENTLY idx_security_events_created_at ON security_events(created_at);

# Enable caching
export HACKAI_CACHE_ENABLED=true
export HACKAI_CACHE_TTL=300
```

```go
// Add request timeouts
client := &http.Client{
    Timeout: 30 * time.Second,
}

// Implement connection pooling
db.SetMaxOpenConns(25)
db.SetMaxIdleConns(5)
db.SetConnMaxLifetime(5 * time.Minute)

// Use context with timeout
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
```

### Issue: High Memory Usage
**Problem**: Memory usage continuously increasing
```
Memory usage: 2.5GB (expected < 500MB)
```

**Solutions**:
```bash
# Profile memory usage
go tool pprof http://localhost:8080/debug/pprof/heap

# Check for memory leaks
go tool pprof -alloc_space http://localhost:8080/debug/pprof/heap

# Monitor garbage collection
GODEBUG=gctrace=1 go run ./cmd/server
```

```go
// Implement proper cleanup
defer func() {
    if r := recover(); r != nil {
        cleanup()
    }
}()

// Use object pools for frequent allocations
var bufferPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 1024)
    },
}

// Set garbage collection target
debug.SetGCPercent(50)
```

## 🔍 Debugging Tools & Techniques

### Enable Debug Logging
```go
// In configuration
logger, _ := logger.New(logger.Config{
    Level:  "debug",
    Format: "json",
})

// Runtime logging level change
logger.SetLevel("debug")

// Component-specific debugging
export HACKAI_DEBUG_SECURITY=true
export HACKAI_DEBUG_AGENTS=true
export HACKAI_DEBUG_REALTIME=true
```

### Performance Profiling
```bash
# CPU profiling
go tool pprof http://localhost:8080/debug/pprof/profile?seconds=30

# Memory profiling
go tool pprof http://localhost:8080/debug/pprof/heap

# Goroutine profiling
go tool pprof http://localhost:8080/debug/pprof/goroutine

# Block profiling
go tool pprof http://localhost:8080/debug/pprof/block
```

### Health Check Endpoints
```bash
# System health
curl http://localhost:8080/api/realtime/health

# Component status
curl http://localhost:8080/api/realtime/status

# Metrics
curl http://localhost:8080/api/realtime/metrics

# Debug info
curl http://localhost:8080/debug/vars
```

## 🚨 Emergency Procedures

### System Recovery
```bash
# Stop all services
sudo systemctl stop hackai
sudo systemctl stop postgresql
sudo systemctl stop redis-server

# Clear temporary files
rm -rf /tmp/hackai-*
rm -rf logs/*.log

# Reset database (if needed)
sudo -u postgres psql -c "DROP DATABASE IF EXISTS hackai;"
sudo -u postgres psql -c "CREATE DATABASE hackai;"

# Restart services
sudo systemctl start postgresql
sudo systemctl start redis-server
sudo systemctl start hackai
```

### Data Recovery
```bash
# Backup current state
pg_dump hackai > backup_$(date +%Y%m%d_%H%M%S).sql
redis-cli BGSAVE

# Restore from backup
psql hackai < backup_20240120_143000.sql
redis-cli FLUSHALL
redis-cli DEBUG RELOAD
```

## 📞 Getting Additional Help

### Log Analysis
```bash
# Search for errors
grep -i error logs/hackai.log | tail -20

# Find performance issues
grep -i "slow\|timeout\|failed" logs/hackai.log

# Monitor real-time logs
tail -f logs/hackai.log | grep -i "error\|warn"
```

### Community Support
- **GitHub Issues**: Report bugs with detailed logs
- **Documentation**: Check comprehensive guides
- **Examples**: Review working code examples
- **Stack Overflow**: Search for similar issues

### Professional Support
- **Enterprise Support**: Available for production deployments
- **Consulting Services**: Custom implementation assistance
- **Training Programs**: Team training and certification

---

## ✅ Prevention Best Practices

### Regular Maintenance
```bash
# Weekly tasks
go mod tidy
go mod verify
go clean -cache

# Monthly tasks
go get -u ./...  # Update dependencies
go vet ./...     # Static analysis
golangci-lint run # Comprehensive linting
```

### Monitoring Setup
```go
// Implement health checks
func (app *Application) healthCheck() error {
    // Check database
    if err := app.db.Ping(); err != nil {
        return fmt.Errorf("database unhealthy: %w", err)
    }
    
    // Check Redis
    if err := app.redis.Ping().Err(); err != nil {
        return fmt.Errorf("redis unhealthy: %w", err)
    }
    
    return nil
}

// Set up alerts
alertManager.AddRule("high_memory", "memory_usage > 80%")
alertManager.AddRule("high_latency", "avg_response_time > 1s")
```

---

**This comprehensive troubleshooting guide covers the most common issues and their solutions. Keep this guide handy for quick reference during development and production operations.**
