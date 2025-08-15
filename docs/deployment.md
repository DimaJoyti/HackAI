# 🚀 HackAI Deployment Guide

This guide covers deploying HackAI in various environments, from development to production.

## 📋 Prerequisites

### System Requirements

**Minimum Requirements:**
- CPU: 4 cores
- RAM: 8GB
- Storage: 50GB SSD
- Network: 1Gbps

**Recommended for Production:**
- CPU: 8+ cores
- RAM: 16GB+
- Storage: 100GB+ SSD
- Network: 10Gbps
- Load Balancer
- CDN

### Software Dependencies

- **Docker 24.0+**
- **Docker Compose 2.20+**
- **Kubernetes 1.28+** (for K8s deployment)
- **PostgreSQL 13+**
- **Redis 6+**
- **Node.js 18+** (for building frontend)
- **Go 1.21+** (for building backend)

## 🐳 Docker Deployment

### Quick Start with Docker Compose

```bash
# Clone repository
git clone https://github.com/dimajoyti/hackai.git
cd hackai

# Copy environment configuration
cp .env.example .env

# Edit configuration
nano .env

# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f
```

### Production Docker Compose

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: ${DB_NAME}
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER}"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  api-gateway:
    build:
      context: .
      dockerfile: deployments/docker/Dockerfile.api-gateway
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
      - JWT_SECRET=${JWT_SECRET}
      - LOG_LEVEL=${LOG_LEVEL}
    ports:
      - "8080:8080"
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  auth-service:
    build:
      context: .
      dockerfile: deployments/docker/Dockerfile.auth-service
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
      - JWT_SECRET=${JWT_SECRET}
    ports:
      - "8081:8081"
    depends_on:
      - postgres
      - redis
    restart: unless-stopped

  ai-service:
    build:
      context: .
      dockerfile: deployments/docker/Dockerfile.ai-service
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - AI_MODEL_ENDPOINT=${AI_MODEL_ENDPOINT}
      - AI_API_KEY=${AI_API_KEY}
    ports:
      - "8082:8082"
    depends_on:
      - postgres
    restart: unless-stopped

  security-service:
    build:
      context: .
      dockerfile: deployments/docker/Dockerfile.security-service
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
    ports:
      - "8083:8083"
    depends_on:
      - postgres
      - redis
    restart: unless-stopped

  education-service:
    build:
      context: .
      dockerfile: deployments/docker/Dockerfile.education-service
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
    ports:
      - "8084:8084"
    depends_on:
      - postgres
      - redis
    restart: unless-stopped

  web:
    build:
      context: ./web
      dockerfile: Dockerfile.prod
    environment:
      - NEXT_PUBLIC_API_URL=${API_URL}
      - NEXT_PUBLIC_WS_URL=${WS_URL}
    ports:
      - "3000:3000"
    depends_on:
      - api-gateway
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./deployments/nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./deployments/nginx/ssl:/etc/nginx/ssl
    depends_on:
      - web
      - api-gateway
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./deployments/monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
    volumes:
      - grafana_data:/var/lib/grafana
      - ./deployments/monitoring/grafana:/etc/grafana/provisioning
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
  prometheus_data:
  grafana_data:

networks:
  default:
    driver: bridge
```

## ☸️ Kubernetes Deployment

### Prerequisites

```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

### Namespace and Secrets

```bash
# Create namespace
kubectl create namespace hackai

# Create secrets
kubectl create secret generic hackai-secrets \
  --from-literal=db-password=${DB_PASSWORD} \
  --from-literal=redis-password=${REDIS_PASSWORD} \
  --from-literal=jwt-secret=${JWT_SECRET} \
  --from-literal=ai-api-key=${AI_API_KEY} \
  -n hackai

# Create TLS secret
kubectl create secret tls hackai-tls \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key \
  -n hackai
```

### Database Deployment

```yaml
# deployments/k8s/postgres.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: hackai
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15-alpine
        env:
        - name: POSTGRES_DB
          value: "hackai"
        - name: POSTGRES_USER
          value: "hackai"
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: hackai-secrets
              key: db-password
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
  volumeClaimTemplates:
  - metadata:
      name: postgres-storage
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 20Gi
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: hackai
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
  type: ClusterIP
```

### Application Deployment

```yaml
# deployments/k8s/api-gateway.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
  namespace: hackai
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api-gateway
  template:
    metadata:
      labels:
        app: api-gateway
    spec:
      containers:
      - name: api-gateway
        image: hackai/api-gateway:latest
        env:
        - name: DATABASE_URL
          value: "postgres://hackai:$(DB_PASSWORD)@postgres:5432/hackai?sslmode=disable"
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: hackai-secrets
              key: db-password
        - name: REDIS_URL
          value: "redis://:$(REDIS_PASSWORD)@redis:6379/0"
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: hackai-secrets
              key: redis-password
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: hackai-secrets
              key: jwt-secret
        ports:
        - containerPort: 8080
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: api-gateway
  namespace: hackai
spec:
  selector:
    app: api-gateway
  ports:
  - port: 8080
    targetPort: 8080
  type: ClusterIP
```

### Ingress Configuration

```yaml
# deployments/k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: hackai-ingress
  namespace: hackai
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "50m"
    nginx.ingress.kubernetes.io/rate-limit: "100"
spec:
  tls:
  - hosts:
    - hackai.com
    - api.hackai.com
    secretName: hackai-tls
  rules:
  - host: hackai.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: web
            port:
              number: 3000
  - host: api.hackai.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-gateway
            port:
              number: 8080
```

## ☁️ Cloud Deployments

### AWS ECS Deployment

```bash
# Install AWS CLI and ECS CLI
pip install awscli
curl -Lo ecs-cli https://amazon-ecs-cli.s3.amazonaws.com/ecs-cli-linux-amd64-latest
chmod +x ecs-cli && sudo mv ecs-cli /usr/local/bin

# Configure ECS CLI
ecs-cli configure --cluster hackai --default-launch-type EC2 --config-name hackai --region us-west-2

# Create cluster
ecs-cli up --keypair my-key --capability-iam --size 3 --instance-type t3.medium

# Deploy services
ecs-cli compose --file deployments/aws/docker-compose.yml service up
```

### Google Cloud Run Deployment

```bash
# Install gcloud CLI
curl https://sdk.cloud.google.com | bash

# Authenticate and set project
gcloud auth login
gcloud config set project hackai-project

# Build and deploy
gcloud builds submit --tag gcr.io/hackai-project/api-gateway
gcloud run deploy api-gateway --image gcr.io/hackai-project/api-gateway --platform managed --region us-central1
```

### Azure Container Instances

```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Login and create resource group
az login
az group create --name hackai-rg --location eastus

# Deploy container group
az container create --resource-group hackai-rg --file deployments/azure/container-group.yaml
```

## 🔧 Configuration Management

### Environment Variables

```bash
# .env.production
NODE_ENV=production
LOG_LEVEL=info

# Database
DATABASE_URL=postgres://user:pass@host:5432/hackai
DB_MAX_CONNECTIONS=100
DB_IDLE_TIMEOUT=300s

# Redis
REDIS_URL=redis://user:pass@host:6379/0
REDIS_MAX_CONNECTIONS=50

# Security
JWT_SECRET=your-super-secret-jwt-key
ENCRYPTION_KEY=your-32-byte-encryption-key
CORS_ORIGINS=https://hackai.com,https://app.hackai.com

# AI Services
AI_MODEL_ENDPOINT=https://api.openai.com/v1
AI_API_KEY=your-openai-api-key
AI_MODEL_NAME=gpt-4

# Monitoring
PROMETHEUS_ENDPOINT=http://prometheus:9090
JAEGER_ENDPOINT=http://jaeger:14268/api/traces
GRAFANA_URL=http://grafana:3000

# External Services
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=noreply@hackai.com
SMTP_PASS=your-smtp-password

# Storage
S3_BUCKET=hackai-storage
S3_REGION=us-west-2
S3_ACCESS_KEY=your-access-key
S3_SECRET_KEY=your-secret-key
```

### Configuration Validation

```bash
# Validate configuration
make validate-config

# Check service connectivity
make health-check

# Verify database migrations
make db-migrate-status

# Test external dependencies
make test-dependencies
```

## 📊 Monitoring Setup

### Prometheus Configuration

```yaml
# deployments/monitoring/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

scrape_configs:
  - job_name: 'api-gateway'
    static_configs:
      - targets: ['api-gateway:8080']
    metrics_path: /metrics
    scrape_interval: 10s

  - job_name: 'auth-service'
    static_configs:
      - targets: ['auth-service:8081']

  - job_name: 'ai-service'
    static_configs:
      - targets: ['ai-service:8082']

  - job_name: 'security-service'
    static_configs:
      - targets: ['security-service:8083']

  - job_name: 'education-service'
    static_configs:
      - targets: ['education-service:8084']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### Grafana Dashboards

```json
{
  "dashboard": {
    "title": "HackAI System Overview",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{service}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "singlestat",
        "targets": [
          {
            "expr": "rate(http_requests_total{status=~\"5..\"}[5m]) / rate(http_requests_total[5m])",
            "legendFormat": "Error Rate"
          }
        ]
      }
    ]
  }
}
```

## 🔒 Security Considerations

### SSL/TLS Configuration

```nginx
# deployments/nginx/nginx.conf
server {
    listen 443 ssl http2;
    server_name hackai.com;

    ssl_certificate /etc/nginx/ssl/hackai.com.crt;
    ssl_certificate_key /etc/nginx/ssl/hackai.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    location / {
        proxy_pass http://web:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/ {
        proxy_pass http://api-gateway:8080/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Network Security

```yaml
# Network policies for Kubernetes
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: hackai-network-policy
  namespace: hackai
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
  - from:
    - podSelector:
        matchLabels:
          app: api-gateway
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
```

## 🚨 Troubleshooting

### Common Issues

**Service Won't Start**
```bash
# Check logs
docker-compose logs service-name
kubectl logs -f deployment/service-name -n hackai

# Check configuration
docker-compose config
kubectl describe pod pod-name -n hackai

# Verify connectivity
docker-compose exec service-name ping postgres
kubectl exec -it pod-name -n hackai -- ping postgres
```

**Database Connection Issues**
```bash
# Test database connection
docker-compose exec postgres psql -U hackai -d hackai -c "SELECT 1;"
kubectl exec -it postgres-0 -n hackai -- psql -U hackai -d hackai -c "SELECT 1;"

# Check database logs
docker-compose logs postgres
kubectl logs postgres-0 -n hackai
```

**Performance Issues**
```bash
# Monitor resource usage
docker stats
kubectl top pods -n hackai

# Check application metrics
curl http://localhost:8080/metrics
kubectl port-forward svc/api-gateway 8080:8080 -n hackai
```

### Health Checks

```bash
# Service health endpoints
curl http://localhost:8080/health
curl http://localhost:8081/health
curl http://localhost:8082/health

# Database health
curl http://localhost:8080/health/db

# Redis health
curl http://localhost:8080/health/redis
```

## 📈 Scaling

### Horizontal Scaling

```bash
# Docker Compose scaling
docker-compose up -d --scale api-gateway=3 --scale auth-service=2

# Kubernetes scaling
kubectl scale deployment api-gateway --replicas=5 -n hackai
kubectl autoscale deployment api-gateway --cpu-percent=70 --min=2 --max=10 -n hackai
```

### Load Balancing

```yaml
# HAProxy configuration
global
    daemon

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend hackai_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/hackai.pem
    redirect scheme https if !{ ssl_fc }
    default_backend hackai_backend

backend hackai_backend
    balance roundrobin
    option httpchk GET /health
    server api1 api-gateway-1:8080 check
    server api2 api-gateway-2:8080 check
    server api3 api-gateway-3:8080 check
```

This deployment guide provides comprehensive instructions for deploying HackAI in various environments, from development to production-scale deployments.
