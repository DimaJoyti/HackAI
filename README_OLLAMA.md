# 🤖 HackAI OLLAMA Integration & Local AI Models

A comprehensive, production-ready system for managing and deploying local AI models using OLLAMA, providing secure, private AI inference capabilities without external dependencies.

## ✨ Features

### 🧠 AI Capabilities
- **Text Generation** - Advanced natural language generation
- **Code Generation** - Specialized programming assistance
- **Chat Completion** - Interactive conversational AI
- **Embedding Generation** - Vector representations for semantic search
- **Creative Writing** - Content creation and storytelling
- **Security Analysis** - Cybersecurity insights and threat assessment

### 🛠️ Model Management
- **Model Discovery** - Automatic detection of available models
- **Model Pulling** - Download models from OLLAMA registry
- **Model Versioning** - Copy and manage model versions
- **Health Monitoring** - Real-time model status tracking
- **Usage Analytics** - Comprehensive usage statistics
- **Capability Detection** - Automatic feature identification

### 🎛️ Advanced Features
- **Model Presets** - Predefined configurations for different use cases
- **Batch Processing** - Efficient bulk operations
- **Streaming Responses** - Real-time response generation
- **Performance Monitoring** - Detailed metrics and analytics
- **Security Scanning** - Built-in security validation
- **Audit Logging** - Complete operation tracking

## 🚀 Quick Start

### Prerequisites
- Go 1.21+
- OLLAMA installed and running
- PostgreSQL 13+ (optional, for persistence)

### Installation

1. **Install OLLAMA**
```bash
# Install OLLAMA
curl -fsSL https://ollama.ai/install.sh | sh

# Start OLLAMA service
ollama serve

# Pull recommended models
ollama pull llama2
ollama pull codellama
ollama pull mistral
```

2. **Clone and build**
```bash
git clone https://github.com/DimaJoyti/HackAI.git
cd HackAI

# Build OLLAMA service
make build-ollama

# Run OLLAMA service
make run-ollama
```

3. **Test the integration**
```bash
# Run comprehensive demo
./bin/ollama-demo
```

### Docker Deployment

```bash
# Start OLLAMA service with Docker
docker-compose up ollama-service

# Or start complete stack
docker-compose up
```

## 📡 API Overview

### Model Management
```bash
# List available models
curl http://localhost:9089/api/v1/models

# Pull a new model
curl -X POST http://localhost:9089/api/v1/models/pull \
  -H "Content-Type: application/json" \
  -d '{"name": "mistral"}'

# Get model information
curl http://localhost:9089/api/v1/models/llama2
```

### AI Inference
```bash
# Generate text
curl -X POST http://localhost:9089/api/v1/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama2",
    "prompt": "Explain artificial intelligence in simple terms."
  }'

# Chat completion
curl -X POST http://localhost:9089/api/v1/chat \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama2",
    "messages": [
      {"role": "user", "content": "What are the benefits of local AI?"}
    ]
  }'

# Code generation
curl -X POST http://localhost:9089/api/v1/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "codellama",
    "prompt": "Write a Python function to calculate fibonacci numbers."
  }'
```

### Model Presets
```bash
# List available presets
curl http://localhost:9089/api/v1/presets

# Use a preset for generation
curl -X POST http://localhost:9089/api/v1/presets/coding \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Create a REST API endpoint in Go"}'
```

## 🎛️ Model Presets

### Built-in Presets

| Preset | Model | Temperature | Use Case |
|--------|-------|-------------|----------|
| **General** | llama2 | 0.7 | General conversations and Q&A |
| **Coding** | codellama | 0.1 | Programming and code analysis |
| **Security** | llama2 | 0.2 | Security analysis and threat assessment |
| **Creative** | mistral | 0.9 | Creative writing and content generation |

### Custom Presets
Create specialized configurations for your specific use cases:

```bash
curl -X POST http://localhost:9089/api/v1/presets \
  -H "Content-Type: application/json" \
  -d '{
    "name": "technical_docs",
    "model": "llama2",
    "temperature": 0.3,
    "max_tokens": 2048,
    "system_prompt": "You are a technical writer. Create clear, concise documentation.",
    "description": "Optimized for technical documentation"
  }'
```

## 📊 Monitoring & Analytics

### Performance Metrics
- **Latency Tracking** - Request/response times
- **Throughput Monitoring** - Requests per second
- **Resource Usage** - CPU, memory, and GPU utilization
- **Token Analytics** - Generation rates and efficiency
- **Error Tracking** - Failure rates and types

### Usage Analytics
- **Model Popularity** - Most used models and presets
- **Request Patterns** - Usage trends and peaks
- **User Behavior** - Interaction patterns
- **Cost Analysis** - Resource consumption tracking

### Health Monitoring
```bash
# Service health
curl http://localhost:9089/health

# Detailed statistics
curl http://localhost:9089/api/v1/stats

# Performance metrics
curl http://localhost:9089/api/v1/monitoring/performance
```

## 🔒 Security & Privacy

### Data Privacy
- **Local Processing** - All AI inference happens locally
- **No External Calls** - No data sent to external APIs
- **Secure Storage** - Encrypted model and data storage
- **Private Networks** - Isolated deployment options

### Access Control
- **Authentication** - API key and token-based auth
- **Authorization** - Role-based access control
- **Rate Limiting** - Request throttling and quotas
- **Audit Logging** - Complete operation tracking

### Security Features
- **Input Validation** - Comprehensive request sanitization
- **Output Filtering** - Response content validation
- **Security Scanning** - Built-in threat detection
- **Compliance** - Audit trails and reporting

## 🏗️ Architecture

### Core Components
- **OLLAMA Service** - Main service orchestrator
- **Model Manager** - Lifecycle and health management
- **Inference Engine** - AI processing and optimization
- **API Gateway** - Request routing and validation
- **Monitoring System** - Metrics and analytics

### Integration Points
- **Database Layer** - Model metadata and usage tracking
- **Observability Stack** - Metrics, tracing, and logging
- **Security Framework** - Authentication and authorization
- **Cache Layer** - Performance optimization

## 🧪 Testing

### Automated Testing
```bash
# Unit tests
go test ./pkg/ollama/...

# Integration tests
go test ./internal/usecase/...

# API tests
go test ./internal/handler/...
```

### Manual Testing
```bash
# Comprehensive demo
./bin/ollama-demo

# Health check
curl http://localhost:9089/health

# Model listing
curl http://localhost:9089/api/v1/models
```

## 🚀 Production Deployment

### Performance Optimization
- **Model Caching** - Preload frequently used models
- **Request Batching** - Efficient bulk processing
- **Resource Pooling** - Optimal resource utilization
- **Load Balancing** - Distribute requests across instances

### Scaling Strategies
- **Horizontal Scaling** - Multiple service instances
- **Model Distribution** - Spread models across nodes
- **Resource Allocation** - Dynamic resource management
- **Auto-scaling** - Demand-based scaling

### Monitoring Setup
- **Prometheus Integration** - Metrics collection
- **Grafana Dashboards** - Visualization and alerting
- **Jaeger Tracing** - Distributed request tracing
- **Log Aggregation** - Centralized logging

## 📈 Performance Benchmarks

### Typical Performance
- **Text Generation**: 50-100 tokens/second
- **Code Generation**: 30-80 tokens/second
- **Chat Completion**: 40-90 tokens/second
- **Model Loading**: 2-10 seconds (depending on size)
- **API Latency**: <100ms (excluding generation time)

### Resource Requirements
- **CPU**: 4+ cores recommended
- **Memory**: 8GB+ RAM (16GB+ for larger models)
- **Storage**: 50GB+ for model storage
- **GPU**: Optional but recommended for performance

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📖 [Documentation](docs/OLLAMA_INTEGRATION.md)
- 🐛 [Issue Tracker](https://github.com/DimaJoyti/HackAI/issues)
- 💬 [Discussions](https://github.com/DimaJoyti/HackAI/discussions)

## 🙏 Acknowledgments

- Built with [OLLAMA](https://ollama.ai/) for local AI model management
- Powered by Go and modern cloud-native technologies
- Designed for enterprise-grade AI deployments
- Focused on privacy, security, and performance
