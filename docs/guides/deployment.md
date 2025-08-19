# 🚀 HackAI LLM Security Proxy - Deployment Guide

Complete guide for deploying the HackAI LLM Security Proxy in various environments from development to production.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Development Deployment](#development-deployment)
- [Staging Deployment](#staging-deployment)
- [Production Deployment](#production-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Cloud Deployments](#cloud-deployments)
- [Monitoring & Observability](#monitoring--observability)
- [Security Hardening](#security-hardening)
- [Troubleshooting](#troubleshooting)

## 🔧 Prerequisites

### System Requirements

**Minimum Requirements:**
- CPU: 2 cores
- RAM: 4GB
- Storage: 20GB
- Network: 1Gbps

**Recommended for Production:**
- CPU: 8 cores
- RAM: 16GB
- Storage: 100GB SSD
- Network: 10Gbps

### Software Dependencies

- **Docker**: 20.10+
- **Docker Compose**: 2.0+
- **Go**: 1.21+ (for building from source)
- **PostgreSQL**: 15+
- **Redis**: 7+

### External Services

- **LLM Provider API Keys**: OpenAI, Anthropic, Azure OpenAI
- **Monitoring**: Prometheus, Grafana, Jaeger (optional)
- **Secret Management**: HashiCorp Vault, AWS Secrets Manager (production)

## ⚡ Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/DimaJoyti/HackAI.git
cd HackAI
```

### 2. Set Environment Variables

```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

### 3. Start Development Environment

```bash
# Start all services
make dev

# Or using Docker Compose directly
docker-compose -f docker-compose.development.yml up -d
```

### 4. Verify Deployment

```bash
# Check service health
curl http://localhost:8080/health

# View logs
make logs

# Check status
make status
```

## 🛠️ Development Deployment

### Environment Setup

```bash
# Set development environment
export ENVIRONMENT=development

# Copy development configuration
cp .env.development .env

# Start development stack
make dev
```

### Development Services

The development environment includes:

- **LLM Security Proxy**: `http://localhost:8080`
- **Grafana Dashboard**: `http://localhost:3000` (admin/admin)
- **Jaeger Tracing**: `http://localhost:16686`
- **Prometheus**: `http://localhost:9090`
- **pgAdmin**: `http://localhost:5050` (dev@hackai.dev/admin)
- **Redis Commander**: `http://localhost:8081`
- **MailHog**: `http://localhost:8025`

### Development Configuration

```yaml
# configs/environments/development.yaml
server:
  port: 8080
  host: "localhost"
  tls_enabled: false

security:
  strict_mode: false
  block_high_threat_score: false

debug:
  enabled: true
  pprof_enabled: true
  verbose_logging: true
```

### Hot Reload Setup

```bash
# Install air for hot reload
go install github.com/cosmtrek/air@latest

# Start with hot reload
air
```

## 🧪 Staging Deployment

### Environment Setup

```bash
# Set staging environment
export ENVIRONMENT=staging

# Configure staging secrets
export STAGING_DB_PASSWORD="secure-staging-password"
export STAGING_JWT_SECRET="staging-jwt-secret-32-chars-minimum"
export OPENAI_API_KEY_STAGING="sk-staging-key"

# Copy staging configuration
cp .env.staging .env

# Deploy to staging
make staging-deploy
```

### Staging Configuration

```yaml
# configs/environments/staging.yaml
server:
  port: 8080
  host: "0.0.0.0"
  tls_enabled: true
  cert_file: "/etc/ssl/certs/staging.crt"
  key_file: "/etc/ssl/private/staging.key"

security:
  strict_mode: false  # Allow testing flexibility
  block_high_threat_score: true
  threat_score_threshold: 0.8

database:
  ssl_mode: "require"
  max_open_conns: 20

audit:
  enabled: true
  retention_period: "30d"
```

### Load Testing

```bash
# Run load tests
make staging-test

# Custom load test
docker-compose -f docker-compose.staging.yml --profile load-testing run --rm k6 run /scripts/custom-test.js
```

## 🏭 Production Deployment

### Environment Setup

```bash
# Set production environment
export ENVIRONMENT=production

# Configure production secrets (use secret management)
export PROD_DB_PASSWORD="$(vault kv get -field=password secret/prod/db)"
export PROD_JWT_SECRET="$(vault kv get -field=secret secret/prod/jwt)"
export OPENAI_API_KEY="$(vault kv get -field=key secret/prod/openai)"

# Copy production configuration
cp .env.production .env

# Deploy to production
make prod-deploy
```

### Production Configuration

```yaml
# configs/environments/production.yaml
server:
  port: 8080
  host: "0.0.0.0"
  tls_enabled: true
  cert_file: "/etc/ssl/certs/production.crt"
  key_file: "/etc/ssl/private/production.key"

security:
  strict_mode: true
  block_high_threat_score: true
  threat_score_threshold: 0.7

database:
  ssl_mode: "require"
  max_open_conns: 50

audit:
  enabled: true
  retention_period: "90d"
  logger:
    include_request_body: false
    include_response_body: false
    mask_sensitive_data: true

observability:
  logging:
    level: "warn"
    format: "json"
  tracing:
    sample_rate: 0.01  # 1% sampling
```

### High Availability Setup

```yaml
# docker-compose.production.yml
services:
  llm-security-proxy:
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 30s
        failure_action: rollback
      restart_policy:
        condition: on-failure
        max_attempts: 3
```

### Production Checklist

- [ ] SSL/TLS certificates configured
- [ ] Database backups automated
- [ ] Monitoring and alerting setup
- [ ] Log aggregation configured
- [ ] Security scanning enabled
- [ ] Rate limiting configured
- [ ] Circuit breakers enabled
- [ ] Health checks configured
- [ ] Secrets management setup
- [ ] Network security configured

## ☸️ Kubernetes Deployment

### Namespace Setup

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: hackai
  labels:
    name: hackai
```

### ConfigMap

```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: hackai-config
  namespace: hackai
data:
  config.yaml: |
    server:
      port: 8080
      host: "0.0.0.0"
    database:
      host: "postgres-service"
      port: "5432"
    redis:
      host: "redis-service"
      port: "6379"
```

### Secrets

```yaml
# k8s/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: hackai-secrets
  namespace: hackai
type: Opaque
data:
  db-password: <base64-encoded-password>
  jwt-secret: <base64-encoded-secret>
  openai-api-key: <base64-encoded-key>
```

### Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hackai-llm-proxy
  namespace: hackai
spec:
  replicas: 3
  selector:
    matchLabels:
      app: hackai-llm-proxy
  template:
    metadata:
      labels:
        app: hackai-llm-proxy
    spec:
      containers:
      - name: llm-proxy
        image: hackai/llm-security-proxy:latest
        ports:
        - containerPort: 8080
        env:
        - name: ENVIRONMENT
          value: "production"
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: hackai-secrets
              key: db-password
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: hackai-secrets
              key: jwt-secret
        volumeMounts:
        - name: config
          mountPath: /app/configs
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
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
      volumes:
      - name: config
        configMap:
          name: hackai-config
```

### Service

```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: hackai-llm-proxy-service
  namespace: hackai
spec:
  selector:
    app: hackai-llm-proxy
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: ClusterIP
```

### Ingress

```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: hackai-ingress
  namespace: hackai
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
spec:
  tls:
  - hosts:
    - api.hackai.dev
    secretName: hackai-tls
  rules:
  - host: api.hackai.dev
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: hackai-llm-proxy-service
            port:
              number: 80
```

### Deploy to Kubernetes

```bash
# Apply all manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n hackai

# View logs
kubectl logs -f deployment/hackai-llm-proxy -n hackai

# Port forward for testing
kubectl port-forward service/hackai-llm-proxy-service 8080:80 -n hackai
```

## ☁️ Cloud Deployments

### AWS Deployment

#### ECS with Fargate

```json
{
  "family": "hackai-llm-proxy",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::account:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "llm-proxy",
      "image": "your-account.dkr.ecr.region.amazonaws.com/hackai:latest",
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "ENVIRONMENT",
          "value": "production"
        }
      ],
      "secrets": [
        {
          "name": "DB_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:hackai/db-password"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/hackai-llm-proxy",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

#### Terraform Configuration

```hcl
# terraform/main.tf
resource "aws_ecs_cluster" "hackai" {
  name = "hackai-cluster"
}

resource "aws_ecs_service" "llm_proxy" {
  name            = "hackai-llm-proxy"
  cluster         = aws_ecs_cluster.hackai.id
  task_definition = aws_ecs_task_definition.llm_proxy.arn
  desired_count   = 3
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [aws_security_group.llm_proxy.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.llm_proxy.arn
    container_name   = "llm-proxy"
    container_port   = 8080
  }
}
```

### Google Cloud Platform

#### Cloud Run Deployment

```yaml
# cloudrun.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: hackai-llm-proxy
  annotations:
    run.googleapis.com/ingress: all
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/maxScale: "10"
        run.googleapis.com/cpu-throttling: "false"
    spec:
      containerConcurrency: 100
      containers:
      - image: gcr.io/project-id/hackai-llm-proxy:latest
        ports:
        - containerPort: 8080
        env:
        - name: ENVIRONMENT
          value: "production"
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: hackai-secrets
              key: db-password
        resources:
          limits:
            cpu: "2"
            memory: "2Gi"
```

```bash
# Deploy to Cloud Run
gcloud run deploy hackai-llm-proxy \
  --image gcr.io/project-id/hackai-llm-proxy:latest \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars ENVIRONMENT=production
```

### Azure Container Instances

```yaml
# azure-container-instance.yaml
apiVersion: 2019-12-01
location: eastus
name: hackai-llm-proxy
properties:
  containers:
  - name: llm-proxy
    properties:
      image: your-registry.azurecr.io/hackai-llm-proxy:latest
      ports:
      - port: 8080
        protocol: TCP
      environmentVariables:
      - name: ENVIRONMENT
        value: production
      - name: DB_PASSWORD
        secureValue: your-secure-password
      resources:
        requests:
          cpu: 2
          memoryInGB: 4
  osType: Linux
  ipAddress:
    type: Public
    ports:
    - protocol: TCP
      port: 8080
```

## 📊 Monitoring & Observability

### Prometheus Configuration

```yaml
# configs/prometheus/production.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'hackai-llm-proxy'
    static_configs:
      - targets: ['llm-security-proxy:8080']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:5432']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']
```

### Grafana Dashboards

```json
{
  "dashboard": {
    "title": "HackAI LLM Security Proxy",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(hackai_requests_total[5m])",
            "legendFormat": "Requests/sec"
          }
        ]
      },
      {
        "title": "Threat Score Distribution",
        "type": "histogram",
        "targets": [
          {
            "expr": "hackai_threat_score_bucket",
            "legendFormat": "Threat Score"
          }
        ]
      }
    ]
  }
}
```

### Alerting Rules

```yaml
# configs/prometheus/alerts.yml
groups:
  - name: hackai-alerts
    rules:
      - alert: HighThreatScore
        expr: rate(hackai_high_threat_requests_total[5m]) > 0.1
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High threat score requests detected"
          description: "{{ $value }} high threat requests per second"

      - alert: ServiceDown
        expr: up{job="hackai-llm-proxy"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "HackAI LLM Proxy is down"
```

## 🔒 Security Hardening

### Network Security

```bash
# Firewall rules (iptables)
iptables -A INPUT -p tcp --dport 8080 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP

# Or using ufw
ufw allow from 10.0.0.0/8 to any port 8080
ufw deny 8080
```

### SSL/TLS Configuration

```nginx
# nginx SSL configuration
server {
    listen 443 ssl http2;
    server_name api.hackai.dev;

    ssl_certificate /etc/ssl/certs/hackai.crt;
    ssl_certificate_key /etc/ssl/private/hackai.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;
    
    location / {
        proxy_pass http://llm-security-proxy:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Secret Management

```bash
# Using HashiCorp Vault
vault kv put secret/hackai/prod \
  db_password="secure-password" \
  jwt_secret="secure-jwt-secret" \
  openai_api_key="sk-secure-key"

# Using AWS Secrets Manager
aws secretsmanager create-secret \
  --name "hackai/prod/db-password" \
  --secret-string "secure-password"
```

## 🔧 Troubleshooting

### Common Issues

#### Service Won't Start

```bash
# Check logs
docker-compose logs llm-security-proxy

# Check configuration
./scripts/validate-config.sh

# Check ports
netstat -tulpn | grep 8080
```

#### Database Connection Issues

```bash
# Test database connection
docker-compose exec postgres psql -U postgres -d hackai_dev -c "SELECT 1;"

# Check database logs
docker-compose logs postgres
```

#### High Memory Usage

```bash
# Check memory usage
docker stats

# Enable memory profiling
curl http://localhost:6060/debug/pprof/heap > heap.prof
go tool pprof heap.prof
```

#### Performance Issues

```bash
# Check CPU profiling
curl http://localhost:6060/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof cpu.prof

# Check goroutines
curl http://localhost:6060/debug/pprof/goroutine?debug=1
```

### Health Checks

```bash
# Service health
curl http://localhost:8080/health

# Readiness check
curl http://localhost:8080/ready

# Metrics endpoint
curl http://localhost:8080/metrics
```

### Log Analysis

```bash
# View real-time logs
docker-compose logs -f llm-security-proxy

# Search for errors
docker-compose logs llm-security-proxy | grep ERROR

# Analyze threat patterns
docker-compose logs llm-security-proxy | grep "threat_score" | jq '.threat_score'
```

For more detailed troubleshooting, see the [Troubleshooting Guide](troubleshooting.md).
