# HackAI Deployment Guide

## 🚀 Production Deployment

This guide covers deploying the HackAI AI Agent Orchestration system with LangChain, LangGraph, vector databases, and cybersecurity AI agents.

## 📋 Prerequisites

### System Requirements
- **CPU**: 8+ cores (16+ recommended for production)
- **RAM**: 16GB minimum (32GB+ recommended)
- **Storage**: 100GB+ SSD
- **Network**: High-bandwidth internet connection

### Software Dependencies
- **Go**: 1.21+
- **PostgreSQL**: 15+ with pgvector extension
- **Redis**: 7.0+
- **Docker**: 24.0+
- **Kubernetes**: 1.28+ (for container orchestration)

### External Services
- **OpenAI API**: GPT-4 access
- **Supabase**: Vector database (optional)
- **Qdrant**: Vector search engine (optional)
- **Observability**: Jaeger, Prometheus, Grafana

## 🏗️ Infrastructure Setup

### 1. Database Setup

#### PostgreSQL with pgvector
```bash
# Install PostgreSQL 15+
sudo apt update
sudo apt install postgresql-15 postgresql-contrib-15

# Install pgvector extension
git clone https://github.com/pgvector/pgvector.git
cd pgvector
make
sudo make install

# Enable extension
sudo -u postgres psql -c "CREATE EXTENSION vector;"
```

#### Redis Setup
```bash
# Install Redis
sudo apt install redis-server

# Configure Redis for production
sudo nano /etc/redis/redis.conf
# Set: maxmemory 8gb
# Set: maxmemory-policy allkeys-lru
# Set: save 900 1 300 10 60 10000

sudo systemctl restart redis-server
```

### 2. Vector Database Setup

#### Supabase (Managed)
```bash
# Create Supabase project at supabase.com
# Enable pgvector extension in SQL editor:
CREATE EXTENSION IF NOT EXISTS vector;

# Create documents table
CREATE TABLE documents (
    id TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    embedding vector(1536),
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

# Create vector index
CREATE INDEX ON documents USING ivfflat (embedding vector_cosine_ops)
WITH (lists = 100);
```

#### Qdrant (Self-hosted)
```bash
# Using Docker
docker run -p 6333:6333 -p 6334:6334 \
    -v $(pwd)/qdrant_storage:/qdrant/storage:z \
    qdrant/qdrant

# Or using Docker Compose
cat > docker-compose.qdrant.yml << EOF
version: '3.8'
services:
  qdrant:
    image: qdrant/qdrant:latest
    ports:
      - "6333:6333"
      - "6334:6334"
    volumes:
      - ./qdrant_storage:/qdrant/storage
    environment:
      - QDRANT__SERVICE__HTTP_PORT=6333
      - QDRANT__SERVICE__GRPC_PORT=6334
EOF

docker-compose -f docker-compose.qdrant.yml up -d
```

### 3. Application Configuration

#### Environment Variables
```bash
# Create .env file
cat > .env << EOF
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/hackai
REDIS_URL=redis://localhost:6379

# LLM Providers
OPENAI_API_KEY=your_openai_api_key
ANTHROPIC_API_KEY=your_anthropic_api_key

# Vector Databases
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_supabase_anon_key
QDRANT_URL=http://localhost:6333
QDRANT_API_KEY=your_qdrant_api_key

# Observability
JAEGER_ENDPOINT=http://localhost:14268/api/traces
PROMETHEUS_ENDPOINT=http://localhost:9090

# Security
JWT_SECRET=your_jwt_secret_key
ENCRYPTION_KEY=your_32_byte_encryption_key

# Application
APP_ENV=production
LOG_LEVEL=info
PORT=8080
EOF
```

#### Configuration File
```yaml
# config/production.yaml
database:
  host: localhost
  port: 5432
  name: hackai
  user: hackai_user
  password: ${DATABASE_PASSWORD}
  ssl_mode: require
  max_connections: 100
  max_idle_connections: 10

redis:
  url: ${REDIS_URL}
  max_retries: 3
  pool_size: 100

llm:
  providers:
    openai:
      api_key: ${OPENAI_API_KEY}
      model: gpt-4
      max_tokens: 4000
      temperature: 0.7
      timeout: 30s
    anthropic:
      api_key: ${ANTHROPIC_API_KEY}
      model: claude-3-sonnet-20240229
      max_tokens: 4000
      temperature: 0.7

vector_db:
  primary_provider: supabase
  fallback_providers: [qdrant, postgres]
  health_check_interval: 30s
  retry_attempts: 3
  retry_delay: 1s

ingestion:
  worker_count: 8
  batch_size: 20
  chunk_size: 1000
  chunk_overlap: 200
  queue_size: 1000
  max_retries: 3

retrieval:
  vector_weight: 0.7
  keyword_weight: 0.2
  semantic_weight: 0.1
  max_results: 20
  min_score: 0.1
  enable_reranking: true
  enable_fallback: true
  timeout: 30s

security:
  threat_threshold: 0.7
  max_analysis_time: 5m
  enable_realtime_monitoring: true
  frameworks: [MITRE ATT&CK, OWASP, NIST]
  compliance: [SOC2, ISO27001, GDPR]

observability:
  tracing:
    enabled: true
    endpoint: ${JAEGER_ENDPOINT}
    service_name: hackai
  metrics:
    enabled: true
    endpoint: ${PROMETHEUS_ENDPOINT}
    interval: 15s
  logging:
    level: info
    format: json
    output: stdout
```

## 🐳 Docker Deployment

### 1. Build Docker Image
```dockerfile
# Dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o hackai cmd/server/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/hackai .
COPY --from=builder /app/config ./config

EXPOSE 8080
CMD ["./hackai"]
```

### 2. Docker Compose
```yaml
# docker-compose.yml
version: '3.8'

services:
  hackai:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgresql://postgres:password@postgres:5432/hackai
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
      - qdrant
    volumes:
      - ./config:/app/config
      - ./logs:/app/logs

  postgres:
    image: pgvector/pgvector:pg15
    environment:
      POSTGRES_DB: hackai
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  qdrant:
    image: qdrant/qdrant:latest
    ports:
      - "6333:6333"
      - "6334:6334"
    volumes:
      - qdrant_data:/qdrant/storage

  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"
      - "14268:14268"
    environment:
      - COLLECTOR_OTLP_ENABLED=true

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana

volumes:
  postgres_data:
  redis_data:
  qdrant_data:
  grafana_data:
```

### 3. Deploy with Docker Compose
```bash
# Build and start services
docker-compose up -d

# Check service health
docker-compose ps

# View logs
docker-compose logs -f hackai

# Scale the application
docker-compose up -d --scale hackai=3
```

## ☸️ Kubernetes Deployment

### 1. Namespace and ConfigMap
```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: hackai

---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: hackai-config
  namespace: hackai
data:
  config.yaml: |
    # Your configuration here
```

### 2. Secrets
```yaml
# k8s/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: hackai-secrets
  namespace: hackai
type: Opaque
data:
  openai-api-key: <base64-encoded-key>
  database-password: <base64-encoded-password>
  jwt-secret: <base64-encoded-secret>
```

### 3. Deployment
```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hackai
  namespace: hackai
spec:
  replicas: 3
  selector:
    matchLabels:
      app: hackai
  template:
    metadata:
      labels:
        app: hackai
    spec:
      containers:
      - name: hackai
        image: hackai:latest
        ports:
        - containerPort: 8080
        env:
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: hackai-secrets
              key: openai-api-key
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: hackai-secrets
              key: database-password
        volumeMounts:
        - name: config
          mountPath: /app/config
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
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
      volumes:
      - name: config
        configMap:
          name: hackai-config
```

### 4. Service and Ingress
```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: hackai-service
  namespace: hackai
spec:
  selector:
    app: hackai
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP

---
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: hackai-ingress
  namespace: hackai
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - hackai.yourdomain.com
    secretName: hackai-tls
  rules:
  - host: hackai.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: hackai-service
            port:
              number: 80
```

### 5. Deploy to Kubernetes
```bash
# Apply all configurations
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n hackai
kubectl get services -n hackai
kubectl get ingress -n hackai

# View logs
kubectl logs -f deployment/hackai -n hackai

# Scale deployment
kubectl scale deployment hackai --replicas=5 -n hackai
```

## 📊 Monitoring and Observability

### 1. Prometheus Configuration
```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'hackai'
    static_configs:
      - targets: ['hackai:8080']
    metrics_path: /metrics
    scrape_interval: 15s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:5432']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']
```

### 2. Grafana Dashboards
```json
{
  "dashboard": {
    "title": "HackAI AI Agent Metrics",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{status}}"
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
        "title": "AI Agent Performance",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(ai_agent_requests_total[5m])",
            "legendFormat": "{{agent_type}}"
          }
        ]
      }
    ]
  }
}
```

## 🔒 Security Hardening

### 1. Network Security
```bash
# Configure firewall
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw deny 5432/tcp  # Restrict database access
sudo ufw deny 6379/tcp  # Restrict Redis access
```

### 2. SSL/TLS Configuration
```nginx
# nginx.conf
server {
    listen 443 ssl http2;
    server_name hackai.yourdomain.com;

    ssl_certificate /etc/ssl/certs/hackai.crt;
    ssl_certificate_key /etc/ssl/private/hackai.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 3. Database Security
```sql
-- Create dedicated user
CREATE USER hackai_app WITH PASSWORD 'strong_password';
GRANT CONNECT ON DATABASE hackai TO hackai_app;
GRANT USAGE ON SCHEMA public TO hackai_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO hackai_app;

-- Enable row-level security
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY documents_policy ON documents FOR ALL TO hackai_app;
```

## 🚀 Performance Optimization

### 1. Database Optimization
```sql
-- Optimize PostgreSQL for vector operations
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements,auto_explain';
ALTER SYSTEM SET max_connections = 200;
ALTER SYSTEM SET shared_buffers = '4GB';
ALTER SYSTEM SET effective_cache_size = '12GB';
ALTER SYSTEM SET work_mem = '256MB';
ALTER SYSTEM SET maintenance_work_mem = '1GB';

-- Create optimized indexes
CREATE INDEX CONCURRENTLY idx_documents_embedding_cosine 
ON documents USING ivfflat (embedding vector_cosine_ops) 
WITH (lists = 1000);

CREATE INDEX CONCURRENTLY idx_documents_metadata_gin 
ON documents USING gin (metadata);
```

### 2. Application Tuning
```go
// Optimize Go runtime
export GOGC=100
export GOMAXPROCS=8
export GOMEMLIMIT=8GiB
```

### 3. Caching Strategy
```yaml
# Redis caching configuration
cache:
  embedding_cache:
    ttl: 24h
    max_size: 10000
  
  retrieval_cache:
    ttl: 1h
    max_size: 5000
  
  analysis_cache:
    ttl: 30m
    max_size: 1000
```

## 📈 Scaling Guidelines

### Horizontal Scaling
- **API Servers**: Scale based on CPU/memory usage
- **Workers**: Scale based on queue depth
- **Databases**: Use read replicas for read-heavy workloads

### Vertical Scaling
- **Memory**: 32GB+ for large vector operations
- **CPU**: 16+ cores for concurrent processing
- **Storage**: NVMe SSD for database performance

### Auto-scaling Configuration
```yaml
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: hackai-hpa
  namespace: hackai
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: hackai
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## 🔧 Maintenance

### Backup Strategy
```bash
#!/bin/bash
# backup.sh
DATE=$(date +%Y%m%d_%H%M%S)

# Database backup
pg_dump $DATABASE_URL > backups/hackai_${DATE}.sql

# Vector data backup
docker exec qdrant_container tar czf - /qdrant/storage > backups/qdrant_${DATE}.tar.gz

# Configuration backup
tar czf backups/config_${DATE}.tar.gz config/
```

### Health Checks
```bash
#!/bin/bash
# health_check.sh

# Check application health
curl -f http://localhost:8080/health || exit 1

# Check database connectivity
pg_isready -h localhost -p 5432 -U hackai_user || exit 1

# Check Redis connectivity
redis-cli ping || exit 1

# Check vector database
curl -f http://localhost:6333/health || exit 1
```

### Log Rotation
```bash
# /etc/logrotate.d/hackai
/var/log/hackai/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 hackai hackai
    postrotate
        systemctl reload hackai
    endscript
}
```

This deployment guide provides a comprehensive approach to deploying the HackAI AI Agent Orchestration system in production environments with proper security, monitoring, and scaling considerations.
