# Installation Guide

Complete installation guide for the HackAI Security Platform. This guide covers all installation methods, system requirements, configuration, and troubleshooting.

## 📋 **System Requirements**

### **Minimum Requirements**
- **Operating System**: Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+), macOS 11+, Windows 10+
- **CPU**: 2 cores, 2.0 GHz
- **Memory**: 4 GB RAM
- **Storage**: 10 GB available disk space
- **Network**: Internet access for threat intelligence feeds

### **Recommended Requirements**
- **Operating System**: Linux (Ubuntu 22.04 LTS recommended)
- **CPU**: 4+ cores, 3.0+ GHz
- **Memory**: 8+ GB RAM
- **Storage**: 50+ GB SSD storage
- **Network**: High-speed internet connection

### **Production Requirements**
- **Operating System**: Linux (Ubuntu 22.04 LTS or RHEL 9)
- **CPU**: 8+ cores, 3.5+ GHz
- **Memory**: 16+ GB RAM
- **Storage**: 100+ GB NVMe SSD
- **Network**: Dedicated network interface, load balancer support

## 🛠️ **Prerequisites**

### **Required Software**
- **Go**: Version 1.21 or later
- **Git**: For source code management
- **Make**: For build automation

### **Optional Dependencies**
- **Docker**: For containerized deployment
- **Docker Compose**: For multi-container orchestration
- **Kubernetes**: For production orchestration
- **PostgreSQL**: For persistent data storage
- **Redis**: For caching and session management

### **Network Requirements**
- **Inbound Ports**: 8080 (HTTP), 8443 (HTTPS), 9090 (Metrics)
- **Outbound Access**: HTTPS (443) for threat intelligence feeds
- **Firewall**: Configure to allow required ports

## 📦 **Installation Methods**

### **Method 1: Binary Installation (Recommended)**

#### **Linux/macOS**

```bash
# Download latest release
curl -L https://github.com/dimajoyti/hackai/releases/latest/download/hackai-linux-amd64.tar.gz -o hackai.tar.gz

# Extract archive
tar -xzf hackai.tar.gz

# Move to system path
sudo mv hackai /usr/local/bin/

# Make executable
sudo chmod +x /usr/local/bin/hackai

# Verify installation
hackai --version
```

#### **Windows**

```powershell
# Download Windows binary
Invoke-WebRequest -Uri "https://github.com/dimajoyti/hackai/releases/latest/download/hackai-windows-amd64.zip" -OutFile "hackai.zip"

# Extract archive
Expand-Archive -Path "hackai.zip" -DestinationPath "C:\Program Files\HackAI"

# Add to PATH
$env:PATH += ";C:\Program Files\HackAI"

# Verify installation
hackai --version
```

### **Method 2: Source Installation**

```bash
# Clone repository
git clone https://github.com/dimajoyti/hackai.git
cd hackai

# Install Go dependencies
go mod download

# Build from source
make build

# Install binary
sudo make install

# Verify installation
hackai --version
```

### **Method 3: Docker Installation**

#### **Docker Run**

```bash
# Pull latest image
docker pull hackai/security-platform:latest

# Run container
docker run -d \
  --name hackai-security \
  -p 8080:8080 \
  -p 8443:8443 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  hackai/security-platform:latest
```

#### **Docker Compose**

```yaml
# docker-compose.yml
version: '3.8'

services:
  hackai-security:
    image: hackai/security-platform:latest
    container_name: hackai-security
    ports:
      - "8080:8080"
      - "8443:8443"
      - "9090:9090"
    environment:
      - HACKAI_CONFIG_PATH=/app/config/config.yaml
      - HACKAI_LOG_LEVEL=info
      - HACKAI_DB_HOST=postgres
      - HACKAI_REDIS_HOST=redis
    volumes:
      - ./config:/app/config:ro
      - ./data:/app/data
      - ./logs:/app/logs
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    
  postgres:
    image: postgres:15-alpine
    container_name: hackai-postgres
    environment:
      - POSTGRES_DB=hackai
      - POSTGRES_USER=hackai
      - POSTGRES_PASSWORD=secure_password_here
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped
    
  redis:
    image: redis:7-alpine
    container_name: hackai-redis
    command: redis-server --requirepass secure_password_here
    volumes:
      - redis_data:/data
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
```

```bash
# Start services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f hackai-security
```

### **Method 4: Kubernetes Installation**

#### **Helm Installation**

```bash
# Add Helm repository
helm repo add hackai https://charts.hackai.security
helm repo update

# Create namespace
kubectl create namespace hackai-system

# Install with Helm
helm install hackai-security hackai/security-platform \
  --namespace hackai-system \
  --set image.tag=latest \
  --set service.type=LoadBalancer \
  --set persistence.enabled=true \
  --set postgresql.enabled=true \
  --set redis.enabled=true
```

#### **Manual Kubernetes Deployment**

```yaml
# kubernetes/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hackai-security
  namespace: hackai-system
spec:
  replicas: 3
  selector:
    matchLabels:
      app: hackai-security
  template:
    metadata:
      labels:
        app: hackai-security
    spec:
      containers:
      - name: hackai-security
        image: hackai/security-platform:latest
        ports:
        - containerPort: 8080
        - containerPort: 8443
        env:
        - name: HACKAI_CONFIG_PATH
          value: "/app/config/config.yaml"
        - name: HACKAI_DB_HOST
          value: "postgres-service"
        - name: HACKAI_REDIS_HOST
          value: "redis-service"
        volumeMounts:
        - name: config
          mountPath: /app/config
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
      volumes:
      - name: config
        configMap:
          name: hackai-config
```

```bash
# Apply Kubernetes manifests
kubectl apply -f kubernetes/
```

## ⚙️ **Configuration**

### **Basic Configuration**

Create a configuration file:

```bash
# Create config directory
mkdir -p config

# Generate default configuration
hackai config init --output config/config.yaml
```

### **Configuration File Example**

```yaml
# config/config.yaml
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: false
    cert_file: ""
    key_file: ""

security:
  enabled: true
  
  # AI Security Features
  ai_firewall:
    enabled: true
    prompt_injection_protection: true
    semantic_analysis: true
    confidence_threshold: 0.7
    
  # Input/Output Filtering
  input_filtering:
    enabled: true
    max_input_size: 1048576  # 1MB
    blocked_patterns: []
    
  output_filtering:
    enabled: true
    sanitization: true
    
  # Authentication
  authentication:
    enabled: true
    method: "jwt"
    secret_key: "your-secret-key-here"
    token_expiry: "24h"
    
  # Threat Intelligence
  threat_intelligence:
    enabled: true
    update_interval: "1h"
    sources: ["internal"]
    
# Database Configuration
database:
  type: "sqlite"  # sqlite, postgres
  connection_string: "data/hackai.db"
  
# Cache Configuration  
cache:
  type: "memory"  # memory, redis
  ttl: "5m"
  max_size: 1000

# Logging Configuration
logging:
  level: "info"
  format: "json"
  output: "stdout"
  file: "logs/hackai.log"
  
# Metrics Configuration
metrics:
  enabled: true
  endpoint: "/metrics"
  port: 9090
```

### **Environment Variables**

```bash
# Core Configuration
export HACKAI_CONFIG_PATH="/path/to/config.yaml"
export HACKAI_LOG_LEVEL="info"
export HACKAI_SERVER_PORT="8080"

# Security Configuration
export HACKAI_SECURITY_ENABLED="true"
export HACKAI_AI_FIREWALL_ENABLED="true"
export HACKAI_THREAT_INTEL_ENABLED="true"

# Authentication
export HACKAI_AUTH_SECRET_KEY="your-secret-key"
export HACKAI_AUTH_TOKEN_EXPIRY="24h"

# Database Configuration
export HACKAI_DB_TYPE="postgres"
export HACKAI_DB_HOST="localhost"
export HACKAI_DB_PORT="5432"
export HACKAI_DB_NAME="hackai"
export HACKAI_DB_USER="hackai"
export HACKAI_DB_PASSWORD="password"

# Cache Configuration
export HACKAI_CACHE_TYPE="redis"
export HACKAI_REDIS_HOST="localhost"
export HACKAI_REDIS_PORT="6379"
export HACKAI_REDIS_PASSWORD="password"
```

## 🚀 **Starting the Service**

### **Basic Startup**

```bash
# Start with default configuration
hackai start

# Start with custom configuration
hackai start --config config/config.yaml

# Start with environment variables
HACKAI_CONFIG_PATH=config/config.yaml hackai start

# Start in background
nohup hackai start --config config/config.yaml > logs/hackai.log 2>&1 &
```

### **Systemd Service (Linux)**

Create a systemd service file:

```bash
# Create service file
sudo tee /etc/systemd/system/hackai.service > /dev/null <<EOF
[Unit]
Description=HackAI Security Platform
After=network.target

[Service]
Type=simple
User=hackai
Group=hackai
WorkingDirectory=/opt/hackai
ExecStart=/usr/local/bin/hackai start --config /opt/hackai/config/config.yaml
Restart=always
RestartSec=5
Environment=HACKAI_LOG_LEVEL=info

[Install]
WantedBy=multi-user.target
EOF

# Create user and directories
sudo useradd -r -s /bin/false hackai
sudo mkdir -p /opt/hackai/{config,data,logs}
sudo chown -R hackai:hackai /opt/hackai

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable hackai
sudo systemctl start hackai

# Check status
sudo systemctl status hackai
```

## ✅ **Verification**

### **Health Check**

```bash
# Basic health check
curl http://localhost:8080/health

# Detailed health check
curl http://localhost:8080/health/detailed

# Check specific components
curl http://localhost:8080/health/components
```

### **API Test**

```bash
# Test API endpoint
curl -X POST http://localhost:8080/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "content": "What is machine learning?",
    "type": "text",
    "analysis_types": ["prompt_injection"]
  }'
```

### **Metrics Check**

```bash
# Check metrics endpoint
curl http://localhost:9090/metrics

# Check security metrics
curl http://localhost:8080/api/v1/metrics/security
```

## 🔧 **Post-Installation Setup**

### **Create Admin User**

```bash
# Create admin user
hackai user create \
  --username admin \
  --password secure_password \
  --role admin \
  --email admin@yourdomain.com
```

### **Generate API Keys**

```bash
# Generate API key
hackai api-key create \
  --name "Production API Key" \
  --permissions "read,write" \
  --expires "2025-12-31"
```

### **Configure SSL/TLS**

```bash
# Generate self-signed certificate (development)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Update configuration
hackai config set server.tls.enabled true
hackai config set server.tls.cert_file cert.pem
hackai config set server.tls.key_file key.pem
```

### **Setup Log Rotation**

```bash
# Create logrotate configuration
sudo tee /etc/logrotate.d/hackai > /dev/null <<EOF
/opt/hackai/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 hackai hackai
    postrotate
        systemctl reload hackai
    endscript
}
EOF
```

## 🔍 **Troubleshooting**

### **Common Issues**

#### **Port Already in Use**
```bash
# Check what's using the port
sudo netstat -tulpn | grep :8080

# Kill process using port
sudo kill -9 $(sudo lsof -t -i:8080)

# Or change port in configuration
hackai config set server.port 8081
```

#### **Permission Denied**
```bash
# Fix file permissions
sudo chown -R hackai:hackai /opt/hackai
sudo chmod -R 755 /opt/hackai

# Fix binary permissions
sudo chmod +x /usr/local/bin/hackai
```

#### **Database Connection Failed**
```bash
# Check database status
sudo systemctl status postgresql

# Test database connection
psql -h localhost -U hackai -d hackai -c "SELECT 1;"

# Check configuration
hackai config get database
```

#### **Memory Issues**
```bash
# Check memory usage
free -h

# Adjust configuration for lower memory
hackai config set cache.max_size 500
hackai config set security.max_concurrent_requests 50
```

### **Log Analysis**

```bash
# View recent logs
tail -f /opt/hackai/logs/hackai.log

# Search for errors
grep -i error /opt/hackai/logs/hackai.log

# Check startup logs
journalctl -u hackai -f
```

### **Performance Tuning**

```bash
# Optimize for high load
hackai config set performance.max_concurrent_requests 1000
hackai config set performance.worker_pool_size 50
hackai config set cache.ttl "10m"
hackai config set cache.max_size 10000
```

## 📞 **Getting Help**

### **Support Resources**
- **Documentation**: [docs.hackai.security](https://docs.hackai.security)
- **Community Forum**: [community.hackai.security](https://community.hackai.security)
- **Issue Tracker**: [github.com/dimajoyti/hackai/issues](https://github.com/dimajoyti/hackai/issues)
- **Email Support**: [support@hackai.security](mailto:support@hackai.security)

### **Diagnostic Information**

When reporting issues, include:

```bash
# System information
hackai version
hackai config validate
hackai health --detailed

# System resources
free -h
df -h
uname -a

# Service status
systemctl status hackai
journalctl -u hackai --since "1 hour ago"
```

---

**Congratulations!** You have successfully installed the HackAI Security Platform. The system is now ready to protect your AI applications and infrastructure.
