# Troubleshooting Guide

Comprehensive troubleshooting guide for the HackAI Security Platform. This guide covers common issues, diagnostic procedures, performance optimization, and resolution strategies.

## 🔍 **Diagnostic Tools**

### **Built-in Diagnostics**

```bash
# System health check
hackai health --detailed

# Configuration validation
hackai config validate

# Component status
hackai status --all

# Performance metrics
hackai metrics --system

# Log analysis
hackai logs --level error --since "1h"
```

### **External Diagnostic Commands**

```bash
# System resources
free -h                    # Memory usage
df -h                      # Disk usage
top -p $(pgrep hackai)     # CPU usage
netstat -tulpn | grep 8080 # Port usage

# Network connectivity
curl -I http://localhost:8080/health
ping -c 3 api.hackai.security
nslookup threat-feeds.hackai.security

# Service status
systemctl status hackai
journalctl -u hackai --since "1 hour ago"
```

## 🚨 **Common Issues and Solutions**

### **Installation Issues**

#### **Binary Not Found**
```bash
# Symptoms
hackai: command not found

# Solutions
# 1. Check if binary is in PATH
which hackai
echo $PATH

# 2. Add to PATH
export PATH=$PATH:/usr/local/bin

# 3. Reinstall binary
sudo cp hackai /usr/local/bin/
sudo chmod +x /usr/local/bin/hackai
```

#### **Permission Denied**
```bash
# Symptoms
Permission denied: /usr/local/bin/hackai

# Solutions
# 1. Fix binary permissions
sudo chmod +x /usr/local/bin/hackai

# 2. Fix directory permissions
sudo chown -R hackai:hackai /opt/hackai
sudo chmod -R 755 /opt/hackai

# 3. Run with sudo (not recommended for production)
sudo hackai start
```

#### **Missing Dependencies**
```bash
# Symptoms
error while loading shared libraries

# Solutions
# 1. Install missing libraries (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install libc6-dev

# 2. Install missing libraries (CentOS/RHEL)
sudo yum install glibc-devel

# 3. Use static binary
wget https://github.com/dimajoyti/hackai/releases/latest/download/hackai-linux-static
```

### **Configuration Issues**

#### **Invalid Configuration**
```bash
# Symptoms
Error: invalid configuration file

# Diagnosis
hackai config validate --config config.yaml

# Solutions
# 1. Check YAML syntax
yamllint config.yaml

# 2. Validate against schema
hackai config validate --strict

# 3. Generate new configuration
hackai config init --output config-new.yaml
```

#### **Missing Configuration File**
```bash
# Symptoms
Error: configuration file not found

# Solutions
# 1. Create default configuration
hackai config init

# 2. Specify configuration path
hackai start --config /path/to/config.yaml

# 3. Use environment variables
export HACKAI_CONFIG_PATH=/path/to/config.yaml
```

#### **Environment Variable Issues**
```bash
# Symptoms
Configuration not loading from environment

# Diagnosis
env | grep HACKAI

# Solutions
# 1. Check variable names (case sensitive)
export HACKAI_LOG_LEVEL=debug  # Correct
export hackai_log_level=debug  # Incorrect

# 2. Restart service after setting variables
sudo systemctl restart hackai

# 3. Use configuration file instead
hackai start --config config.yaml
```

### **Network and Connectivity Issues**

#### **Port Already in Use**
```bash
# Symptoms
Error: bind: address already in use

# Diagnosis
sudo netstat -tulpn | grep :8080
sudo lsof -i :8080

# Solutions
# 1. Kill process using port
sudo kill -9 $(sudo lsof -t -i:8080)

# 2. Change port in configuration
hackai config set server.port 8081

# 3. Use different port temporarily
hackai start --port 8081
```

#### **Firewall Blocking Connections**
```bash
# Symptoms
Connection refused or timeout

# Diagnosis
telnet localhost 8080
curl -v http://localhost:8080/health

# Solutions
# 1. Check firewall status
sudo ufw status
sudo firewall-cmd --list-all

# 2. Open required ports
sudo ufw allow 8080
sudo firewall-cmd --add-port=8080/tcp --permanent

# 3. Disable firewall temporarily (testing only)
sudo ufw disable
```

#### **DNS Resolution Issues**
```bash
# Symptoms
Cannot resolve threat intelligence feeds

# Diagnosis
nslookup threat-feeds.hackai.security
dig threat-feeds.hackai.security

# Solutions
# 1. Check DNS configuration
cat /etc/resolv.conf

# 2. Use alternative DNS
echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf

# 3. Configure local DNS cache
sudo systemctl restart systemd-resolved
```

### **Database Issues**

#### **Database Connection Failed**
```bash
# Symptoms
Error: failed to connect to database

# Diagnosis
# For PostgreSQL
psql -h localhost -U hackai -d hackai -c "SELECT 1;"

# For SQLite
sqlite3 data/hackai.db ".tables"

# Solutions
# 1. Check database service
sudo systemctl status postgresql
sudo systemctl start postgresql

# 2. Verify credentials
hackai config get database

# 3. Test connection manually
psql "postgresql://hackai:password@localhost:5432/hackai"
```

#### **Database Migration Failed**
```bash
# Symptoms
Error: migration failed

# Diagnosis
hackai db status
hackai db version

# Solutions
# 1. Run migrations manually
hackai db migrate

# 2. Reset database (development only)
hackai db reset --confirm

# 3. Restore from backup
hackai db restore --file backup.sql
```

#### **Database Performance Issues**
```bash
# Symptoms
Slow database queries

# Diagnosis
# Check database performance
hackai metrics --database

# PostgreSQL specific
psql -d hackai -c "SELECT * FROM pg_stat_activity;"

# Solutions
# 1. Optimize database configuration
# 2. Add database indexes
hackai db optimize

# 3. Increase connection pool
hackai config set database.max_connections 50
```

### **Memory and Performance Issues**

#### **High Memory Usage**
```bash
# Symptoms
Out of memory errors, system slowdown

# Diagnosis
free -h
ps aux | grep hackai
hackai metrics --memory

# Solutions
# 1. Reduce cache size
hackai config set cache.max_size 1000

# 2. Limit concurrent requests
hackai config set performance.max_concurrent_requests 100

# 3. Enable memory optimization
hackai config set performance.memory_optimization true

# 4. Restart service
sudo systemctl restart hackai
```

#### **High CPU Usage**
```bash
# Symptoms
System slowdown, high load average

# Diagnosis
top -p $(pgrep hackai)
hackai metrics --cpu

# Solutions
# 1. Reduce worker threads
hackai config set performance.worker_pool_size 10

# 2. Enable request throttling
hackai config set rate_limiting.enabled true

# 3. Optimize analysis settings
hackai config set security.fast_mode true
```

#### **Slow Response Times**
```bash
# Symptoms
API requests taking too long

# Diagnosis
curl -w "@curl-format.txt" http://localhost:8080/api/v1/analyze
hackai metrics --performance

# Solutions
# 1. Enable caching
hackai config set cache.enabled true
hackai config set cache.ttl "5m"

# 2. Optimize database queries
hackai db optimize

# 3. Increase timeout values
hackai config set performance.request_timeout "30s"
```

### **Security Component Issues**

#### **AI Firewall Not Working**
```bash
# Symptoms
Threats not being detected or blocked

# Diagnosis
hackai test firewall --input "malicious content"
hackai logs --component ai_firewall

# Solutions
# 1. Check firewall configuration
hackai config get security.ai_firewall

# 2. Update threat detection rules
hackai rules update

# 3. Adjust confidence threshold
hackai config set security.confidence_threshold 0.7
```

#### **Threat Intelligence Feeds Failing**
```bash
# Symptoms
Threat intelligence not updating

# Diagnosis
hackai threat-intel status
hackai logs --component threat_intelligence

# Solutions
# 1. Check feed URLs
hackai threat-intel test-feeds

# 2. Verify API keys
hackai config get threat_intelligence.api_keys

# 3. Manual feed update
hackai threat-intel update --force
```

#### **Authentication Issues**
```bash
# Symptoms
Authentication failures, invalid tokens

# Diagnosis
hackai auth test --token "your-token"
hackai logs --component authentication

# Solutions
# 1. Check secret key
hackai config get authentication.secret_key

# 2. Regenerate tokens
hackai auth token create --user admin

# 3. Reset authentication
hackai auth reset --confirm
```

## 📊 **Performance Optimization**

### **Memory Optimization**

```bash
# Optimize memory usage
hackai config set cache.max_size 5000
hackai config set performance.gc_percent 10
hackai config set performance.memory_limit "2GB"

# Enable memory profiling
hackai profile memory --duration 60s
```

### **CPU Optimization**

```bash
# Optimize CPU usage
hackai config set performance.max_goroutines 1000
hackai config set performance.worker_pool_size 20
hackai config set security.parallel_analysis true

# Enable CPU profiling
hackai profile cpu --duration 60s
```

### **Database Optimization**

```bash
# Optimize database performance
hackai db optimize
hackai config set database.max_connections 25
hackai config set database.connection_timeout "30s"

# Enable database connection pooling
hackai config set database.pool_enabled true
```

### **Network Optimization**

```bash
# Optimize network performance
hackai config set server.read_timeout "30s"
hackai config set server.write_timeout "30s"
hackai config set server.max_header_bytes 1048576

# Enable compression
hackai config set server.compression true
```

## 🔧 **Advanced Troubleshooting**

### **Debug Mode**

```bash
# Enable debug logging
hackai config set logging.level debug
sudo systemctl restart hackai

# Enable debug mode
hackai start --debug

# Enable verbose output
hackai start --verbose
```

### **Profiling and Analysis**

```bash
# CPU profiling
hackai profile cpu --output cpu.prof
go tool pprof cpu.prof

# Memory profiling
hackai profile memory --output mem.prof
go tool pprof mem.prof

# Goroutine analysis
hackai profile goroutine --output goroutine.prof
```

### **Log Analysis**

```bash
# Analyze error patterns
grep -E "(ERROR|FATAL)" /opt/hackai/logs/hackai.log | tail -20

# Check for memory leaks
grep -i "memory" /opt/hackai/logs/hackai.log

# Monitor performance metrics
grep "response_time" /opt/hackai/logs/hackai.log | tail -10
```

### **Network Debugging**

```bash
# Monitor network connections
netstat -an | grep :8080

# Trace network calls
strace -e trace=network -p $(pgrep hackai)

# Monitor bandwidth usage
iftop -i eth0
```

## 🆘 **Emergency Procedures**

### **Service Recovery**

```bash
# Quick service restart
sudo systemctl restart hackai

# Force kill and restart
sudo pkill -9 hackai
sudo systemctl start hackai

# Rollback to previous version
hackai rollback --version v1.9.0
```

### **Database Recovery**

```bash
# Backup current database
hackai db backup --output emergency-backup.sql

# Restore from backup
hackai db restore --file last-good-backup.sql

# Reset to clean state (last resort)
hackai db reset --confirm
hackai db migrate
```

### **Configuration Recovery**

```bash
# Backup current configuration
cp config.yaml config-backup.yaml

# Restore default configuration
hackai config init --force

# Restore from backup
cp config-backup.yaml config.yaml
```

## 📞 **Getting Additional Help**

### **Collecting Diagnostic Information**

```bash
#!/bin/bash
# collect-diagnostics.sh

echo "Collecting HackAI diagnostic information..."

# System information
echo "=== System Information ===" > diagnostics.txt
uname -a >> diagnostics.txt
free -h >> diagnostics.txt
df -h >> diagnostics.txt

# HackAI status
echo "=== HackAI Status ===" >> diagnostics.txt
hackai version >> diagnostics.txt
hackai health --detailed >> diagnostics.txt
hackai config validate >> diagnostics.txt

# Logs
echo "=== Recent Logs ===" >> diagnostics.txt
tail -100 /opt/hackai/logs/hackai.log >> diagnostics.txt

# Service status
echo "=== Service Status ===" >> diagnostics.txt
systemctl status hackai >> diagnostics.txt

echo "Diagnostics collected in diagnostics.txt"
```

### **Support Channels**

- **Emergency Support**: [emergency@hackai.security](mailto:emergency@hackai.security)
- **Technical Support**: [support@hackai.security](mailto:support@hackai.security)
- **Community Forum**: [community.hackai.security](https://community.hackai.security)
- **Documentation**: [docs.hackai.security](https://docs.hackai.security)
- **Issue Tracker**: [github.com/dimajoyti/hackai/issues](https://github.com/dimajoyti/hackai/issues)

### **When Reporting Issues**

Include the following information:
1. **System Information**: OS, version, hardware specs
2. **HackAI Version**: `hackai version`
3. **Configuration**: Sanitized configuration file
4. **Error Messages**: Complete error messages and stack traces
5. **Logs**: Relevant log entries
6. **Steps to Reproduce**: Detailed reproduction steps
7. **Expected vs Actual Behavior**: What should happen vs what actually happens

---

This troubleshooting guide should help you resolve most common issues with the HackAI Security Platform. For issues not covered here, please contact our support team with detailed diagnostic information.
