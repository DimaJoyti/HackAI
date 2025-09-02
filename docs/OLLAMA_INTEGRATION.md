# 🤖 HackAI OLLAMA Integration & Local AI Models

## Overview

The HackAI OLLAMA Integration & Local AI Models system provides a comprehensive, production-ready platform for managing and deploying local AI models using OLLAMA. This system enables secure, private AI inference without relying on external APIs, ensuring data privacy and reducing latency.

## 🏗️ Architecture

### Core Components

1. **OLLAMA Service** (`cmd/ollama-service`)
   - Standalone microservice for AI model management
   - RESTful API for model operations
   - Integration with OLLAMA runtime
   - Performance monitoring and metrics

2. **OLLAMA Manager** (`pkg/ollama/manager.go`)
   - Model lifecycle management
   - Health monitoring
   - Statistics tracking
   - Configuration management

3. **OLLAMA Orchestrator** (`pkg/ollama/orchestrator.go`)
   - AI inference operations
   - Model presets and templates
   - Request routing and load balancing
   - Response optimization

4. **Model Management Use Case** (`internal/usecase/model_management.go`)
   - Business logic for model operations
   - Audit logging
   - Performance tracking
   - Security validation

5. **Inference Use Case** (`internal/usecase/inference.go`)
   - AI inference workflows
   - Request/response handling
   - Token counting and billing
   - Quality assurance

6. **OLLAMA Handler** (`internal/handler/ollama.go`)
   - HTTP API endpoints
   - Request validation
   - Response formatting
   - Error handling

## 🚀 Features

### Model Management
- ✅ Model discovery and listing
- ✅ Model pulling from OLLAMA registry
- ✅ Model deletion and cleanup
- ✅ Model copying and versioning
- ✅ Model health monitoring
- ✅ Usage statistics tracking
- ✅ Capability detection
- ✅ Metadata management

### AI Inference
- ✅ Text generation
- ✅ Chat completion
- ✅ Code generation
- ✅ Embedding generation
- ✅ Streaming responses
- ✅ Batch processing
- ✅ Custom prompts and templates
- ✅ Parameter optimization

### Model Presets
- ✅ Predefined configurations
- ✅ General purpose AI
- ✅ Code generation
- ✅ Security analysis
- ✅ Creative writing
- ✅ Custom preset creation
- ✅ Preset management
- ✅ Template system

### Performance & Monitoring
- ✅ Real-time metrics
- ✅ Performance analytics
- ✅ Usage tracking
- ✅ Health monitoring
- ✅ Resource utilization
- ✅ Request/response logging
- ✅ Error tracking
- ✅ Latency monitoring

### Security & Privacy
- ✅ Local processing
- ✅ Data privacy protection
- ✅ Secure model storage
- ✅ Access control
- ✅ Audit logging
- ✅ Request validation
- ✅ Rate limiting
- ✅ Security scanning

## 📡 API Endpoints

### Model Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/models` | List all available models |
| GET | `/api/v1/models/{model}` | Get specific model info |
| GET | `/api/v1/models/{model}/info` | Get detailed model information |
| POST | `/api/v1/models/pull` | Pull model from registry |
| DELETE | `/api/v1/models/{model}` | Delete model |
| POST | `/api/v1/models/copy` | Copy model |
| POST | `/api/v1/models/create` | Create custom model |
| POST | `/api/v1/models/push` | Push model to registry |

### AI Inference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/generate` | Text generation |
| POST | `/api/v1/chat` | Chat completion |
| POST | `/api/v1/embeddings` | Generate embeddings |
| POST | `/api/v1/generate/stream` | Streaming text generation |
| POST | `/api/v1/chat/stream` | Streaming chat completion |

### Batch Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/batch/generate` | Batch text generation |
| POST | `/api/v1/batch/embeddings` | Batch embedding generation |

### Model Presets

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/presets` | List all presets |
| GET | `/api/v1/presets/{preset}` | Get specific preset |
| POST | `/api/v1/presets` | Create new preset |
| PUT | `/api/v1/presets/{preset}` | Update preset |
| DELETE | `/api/v1/presets/{preset}` | Delete preset |

### Monitoring & Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/status` | Service status |
| GET | `/api/v1/stats` | Service statistics |
| GET | `/api/v1/config` | Service configuration |
| PUT | `/api/v1/config` | Update configuration |
| GET | `/api/v1/monitoring/performance` | Performance metrics |
| GET | `/api/v1/monitoring/usage` | Usage metrics |

### Health & Diagnostics

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Service health check |
| GET | `/ready` | Service readiness |
| GET | `/metrics` | Prometheus metrics |

## 🔧 Configuration

### Environment Variables

```bash
# Service Configuration
PORT=9089
HOST=0.0.0.0

# OLLAMA Configuration
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_TIMEOUT=60s
OLLAMA_MAX_RETRIES=3
OLLAMA_AUTO_PULL=false
OLLAMA_MAX_CONCURRENT=10

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=hackai
DB_USER=hackai
DB_PASSWORD=hackai_password

# Observability
JAEGER_ENDPOINT=http://localhost:14268/api/traces
LOG_LEVEL=info
```

### OLLAMA Configuration

```yaml
ollama:
  base_url: "http://localhost:11434"
  timeout: "60s"
  max_retries: 3
  models:
    - "llama2"
    - "codellama"
    - "mistral"
  default_model: "llama2"
  auto_pull: false
  embedding_model: "nomic-embed-text"
  max_concurrent: 10
  health_check_period: "30s"
```

## 🚀 Quick Start

### Prerequisites
- Go 1.21+
- OLLAMA installed and running
- PostgreSQL 13+
- Redis 6+ (optional)

### Installation

1. **Install OLLAMA**
```bash
# Install OLLAMA
curl -fsSL https://ollama.ai/install.sh | sh

# Start OLLAMA service
ollama serve

# Pull some models
ollama pull llama2
ollama pull codellama
ollama pull mistral
```

2. **Build and run the service**
```bash
# Build OLLAMA service
make build-ollama

# Run OLLAMA service
make run-ollama
```

3. **Test the integration**
```bash
# Run the demo
./bin/ollama-demo
```

### Docker Deployment

```bash
# Start with Docker Compose
docker-compose up ollama-service

# Or start all services
docker-compose up
```

## 📝 Usage Examples

### Text Generation

```bash
curl -X POST http://localhost:9089/api/v1/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama2",
    "prompt": "Explain quantum computing in simple terms.",
    "system": "You are a helpful AI assistant."
  }'
```

### Chat Completion

```bash
curl -X POST http://localhost:9089/api/v1/chat \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama2",
    "messages": [
      {"role": "user", "content": "What are the benefits of local AI?"}
    ]
  }'
```

### Code Generation

```bash
curl -X POST http://localhost:9089/api/v1/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "codellama",
    "prompt": "Write a Python function to sort a list of dictionaries by a key."
  }'
```

### List Models

```bash
curl http://localhost:9089/api/v1/models
```

### Pull Model

```bash
curl -X POST http://localhost:9089/api/v1/models/pull \
  -H "Content-Type: application/json" \
  -d '{"name": "mistral"}'
```

## 🎛️ Model Presets

### Available Presets

1. **General** - General purpose conversational AI
   - Model: llama2
   - Temperature: 0.7
   - Use case: General questions and conversations

2. **Coding** - Specialized for code generation
   - Model: codellama
   - Temperature: 0.1
   - Use case: Programming tasks and code analysis

3. **Security** - Focused on security analysis
   - Model: llama2
   - Temperature: 0.2
   - Use case: Security assessments and threat analysis

4. **Creative** - Optimized for creative content
   - Model: mistral
   - Temperature: 0.9
   - Use case: Creative writing and content generation

### Creating Custom Presets

```bash
curl -X POST http://localhost:9089/api/v1/presets \
  -H "Content-Type: application/json" \
  -d '{
    "name": "technical_writing",
    "model": "llama2",
    "temperature": 0.3,
    "max_tokens": 2048,
    "system_prompt": "You are a technical writer. Create clear, concise documentation.",
    "description": "Optimized for technical documentation"
  }'
```

## 📊 Monitoring & Analytics

### Performance Metrics
- Request latency and throughput
- Model loading times
- Memory and CPU usage
- GPU utilization (if available)
- Token generation rates
- Error rates and types

### Usage Analytics
- Model usage statistics
- Popular models and presets
- Request patterns and trends
- User behavior analysis
- Resource consumption tracking

### Health Monitoring
- Service availability
- Model health status
- OLLAMA connectivity
- Database connectivity
- Resource thresholds

## 🔒 Security Features

### Data Privacy
- Local processing ensures data never leaves your infrastructure
- No external API calls for inference
- Secure model storage and management
- Encrypted communication channels

### Access Control
- API authentication and authorization
- Role-based access control
- Request rate limiting
- IP-based restrictions

### Audit & Compliance
- Comprehensive audit logging
- Request/response tracking
- Security event monitoring
- Compliance reporting

## 🧪 Testing

### Unit Tests
```bash
go test ./pkg/ollama/...
go test ./internal/usecase/...
go test ./internal/handler/...
```

### Integration Tests
```bash
go test ./cmd/ollama-service/...
```

### Demo Testing
```bash
# Build and run the demo
go build -o bin/ollama-demo ./cmd/ollama-demo
./bin/ollama-demo
```

## 🚀 Production Deployment

### Performance Optimization
- Model caching and preloading
- Request batching and queuing
- Resource pooling and management
- Load balancing across instances

### Scaling Considerations
- Horizontal scaling support
- Model distribution strategies
- Resource allocation optimization
- Performance monitoring and alerting

### Security Hardening
- Network security configuration
- Access control implementation
- Audit logging setup
- Backup and recovery procedures

## 📚 Related Documentation

- [OLLAMA Official Documentation](https://ollama.ai/docs)
- [Model Management Guide](./guides/model_management.md)
- [API Documentation](./API.md)
- [Configuration Guide](./CONFIGURATION.md)
- [Deployment Guide](./DEPLOYMENT.md)
