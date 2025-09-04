# HackAI LLM Security Proxy

## Overview

The HackAI LLM Security Proxy is an enterprise-grade security gateway that sits between your applications and Large Language Model (LLM) providers. It provides comprehensive security, monitoring, and control capabilities to ensure safe and compliant AI interactions.

## 🛡️ Key Features

### 1. **Advanced Content Filtering**
- **Prompt Injection Detection**: Detects and blocks sophisticated prompt injection attempts
- **Jailbreak Prevention**: Prevents attempts to bypass AI safety guidelines
- **PII Protection**: Identifies and redacts personally identifiable information
- **Toxicity Filtering**: Blocks harmful, toxic, or inappropriate content
- **Custom Content Rules**: Flexible rule engine for organization-specific content policies

### 2. **Multi-Tier Rate Limiting**
- **User-Level Limits**: Per-user request quotas and rate limits
- **Provider-Level Limits**: Rate limiting per LLM provider (OpenAI, Anthropic, etc.)
- **Model-Level Limits**: Specific limits for different AI models
- **Token Bucket Algorithm**: Smooth rate limiting with burst capacity
- **Cost Control**: Budget limits and cost tracking per user/organization

### 3. **Request & Response Validation**
- **Schema Validation**: Ensures requests conform to expected structure
- **Parameter Validation**: Validates temperature, max_tokens, and other parameters
- **Size Limits**: Enforces maximum request and response sizes
- **Format Validation**: Ensures proper JSON formatting and structure
- **Model Compatibility**: Validates requests against model capabilities

### 4. **Real-Time Threat Detection**
- **SQL Injection Detection**: Identifies SQL injection attempts in prompts
- **XSS Prevention**: Detects cross-site scripting attempts
- **Command Injection**: Blocks command injection attempts
- **Malware Scanning**: Scans content for malicious patterns
- **Behavioral Analysis**: ML-based anomaly detection for unusual patterns

### 5. **Security Policy Engine**
- **Flexible Rules**: Custom security policies with complex conditions
- **Policy Templates**: Pre-built policies for common security scenarios
- **Dynamic Updates**: Real-time policy updates without service restart
- **Compliance Frameworks**: Built-in support for SOC2, GDPR, HIPAA
- **Audit Trail**: Complete audit log of policy decisions

### 6. **Provider Integration**
- **Multi-Provider Support**: OpenAI, Anthropic, Cohere, Hugging Face, OLLAMA
- **Load Balancing**: Intelligent routing across multiple providers
- **Failover**: Automatic failover to backup providers
- **Health Monitoring**: Real-time provider health checks
- **Cost Optimization**: Route requests to most cost-effective providers

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client App    │───▶│  Security Proxy │───▶│  LLM Provider   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │  Security Logs  │
                       │   & Analytics   │
                       └─────────────────┘
```

### Core Components

1. **Security Gateway**: Main proxy service handling all requests
2. **Content Filter**: Advanced content analysis and filtering
3. **Rate Limiter**: Multi-tier rate limiting with Redis backend
4. **Policy Engine**: Flexible rule evaluation engine
5. **Audit Logger**: Comprehensive security event logging
6. **Provider Manager**: Multi-provider integration and routing

## 🚀 Quick Start

### 1. Configuration

```yaml
# config/llm-security-proxy.yaml
server:
  port: 8080
  host: "0.0.0.0"

security:
  content_filter:
    enabled: true
    strict_mode: true
    threat_threshold: 0.7
  
  rate_limiting:
    enabled: true
    user_requests_per_minute: 60
    user_requests_per_hour: 1000
    user_requests_per_day: 10000
  
  policies:
    - name: "prompt_injection_protection"
      enabled: true
      type: "content_safety"
    - name: "pii_protection"
      enabled: true
      type: "data_privacy"

providers:
  openai:
    api_key: "${OPENAI_API_KEY}"
    base_url: "https://api.openai.com/v1"
    models: ["gpt-3.5-turbo", "gpt-4"]
  
  anthropic:
    api_key: "${ANTHROPIC_API_KEY}"
    base_url: "https://api.anthropic.com/v1"
    models: ["claude-3-sonnet", "claude-3-opus"]
```

### 2. Running the Proxy

```bash
# Start the LLM Security Proxy
./bin/llm-security-proxy --config config/llm-security-proxy.yaml

# Or with Docker
docker run -p 8080:8080 \
  -v $(pwd)/config:/config \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  hackai/llm-security-proxy
```

### 3. Making Requests

```bash
# Secure LLM request through proxy
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [
      {"role": "user", "content": "What is machine learning?"}
    ],
    "max_tokens": 100
  }'
```

## 🔧 API Endpoints

### Core Proxy Endpoints

- `POST /v1/chat/completions` - OpenAI-compatible chat completions
- `POST /v1/completions` - Text completions
- `POST /v1/embeddings` - Text embeddings
- `POST /anthropic/v1/messages` - Anthropic messages API

### Management Endpoints

- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics
- `GET /policies` - List security policies
- `POST /policies` - Create/update security policies
- `GET /audit/logs` - Retrieve audit logs

## 📊 Monitoring & Analytics

### Metrics

The proxy exposes comprehensive metrics for monitoring:

```
# Request metrics
llm_proxy_requests_total{provider="openai", model="gpt-3.5-turbo", status="success"}
llm_proxy_request_duration_seconds{provider="openai", model="gpt-3.5-turbo"}
llm_proxy_tokens_used_total{provider="openai", model="gpt-3.5-turbo"}

# Security metrics
llm_proxy_threats_detected_total{type="prompt_injection"}
llm_proxy_requests_blocked_total{reason="rate_limit"}
llm_proxy_content_filtered_total{type="pii"}

# Provider metrics
llm_proxy_provider_health{provider="openai", status="healthy"}
llm_proxy_provider_latency_seconds{provider="openai"}
```

### Dashboards

Pre-built Grafana dashboards for:
- Request volume and latency
- Security threat detection
- Rate limiting and quotas
- Provider health and performance
- Cost tracking and optimization

## 🔒 Security Features

### Content Security

- **Prompt Injection Detection**: Advanced pattern matching and ML-based detection
- **Jailbreak Prevention**: Detects attempts to bypass AI safety measures
- **PII Redaction**: Automatic detection and redaction of sensitive information
- **Content Classification**: Categorizes content by safety level

### Access Control

- **API Key Management**: Secure API key validation and rotation
- **User Authentication**: Integration with OAuth2, JWT, and SAML
- **Role-Based Access**: Fine-grained permissions per user/role
- **IP Whitelisting**: Restrict access by IP address or CIDR blocks

### Audit & Compliance

- **Complete Audit Trail**: Every request and response logged
- **Compliance Reports**: Automated compliance reporting for SOC2, GDPR
- **Data Retention**: Configurable data retention policies
- **Encryption**: End-to-end encryption of sensitive data

## 🎯 Use Cases

### Enterprise AI Applications
- **Customer Support**: Secure AI-powered chatbots and support systems
- **Content Generation**: Safe content creation with compliance controls
- **Code Assistance**: Secure AI coding assistants with IP protection
- **Document Analysis**: Secure document processing with PII protection

### Regulated Industries
- **Healthcare**: HIPAA-compliant AI applications
- **Financial Services**: SOX and PCI-compliant AI systems
- **Government**: FedRAMP-ready AI security controls
- **Legal**: Attorney-client privilege protection

### Multi-Tenant SaaS
- **Tenant Isolation**: Secure multi-tenant AI applications
- **Usage Quotas**: Per-tenant rate limiting and cost control
- **Custom Policies**: Tenant-specific security policies
- **Billing Integration**: Usage-based billing and cost allocation

## 🔧 Advanced Configuration

### Custom Content Filters

```yaml
content_filters:
  - name: "financial_pii"
    type: "regex"
    patterns:
      - "\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b"  # Credit cards
      - "\\b\\d{3}-\\d{2}-\\d{4}\\b"  # SSN
    action: "block"
    severity: "high"

  - name: "code_injection"
    type: "ml_classifier"
    model: "code_injection_detector_v1"
    threshold: 0.8
    action: "flag"
```

### Rate Limiting Policies

```yaml
rate_limits:
  tiers:
    free:
      requests_per_minute: 10
      requests_per_day: 100
      max_tokens_per_request: 1000
    
    premium:
      requests_per_minute: 100
      requests_per_day: 10000
      max_tokens_per_request: 4000
    
    enterprise:
      requests_per_minute: 1000
      requests_per_day: 100000
      max_tokens_per_request: 8000
```

## 📈 Performance

### Benchmarks

- **Latency Overhead**: < 10ms additional latency
- **Throughput**: 10,000+ requests per second
- **Memory Usage**: < 512MB for typical workloads
- **CPU Usage**: < 5% additional CPU overhead

### Optimization

- **Connection Pooling**: Efficient connection management
- **Request Batching**: Batch processing for improved throughput
- **Caching**: Intelligent caching of security decisions
- **Async Processing**: Non-blocking request processing

## 🛠️ Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/DimaJoyti/HackAI.git
cd HackAI

# Build the proxy
go build -o bin/llm-security-proxy ./cmd/llm-security-proxy

# Run tests
go test ./pkg/llm/... -v
go test ./pkg/security/... -v
```

### Testing

```bash
# Run the comprehensive test suite
./bin/llm-security-proxy-test

# Run specific test categories
go test ./pkg/security -run TestContentFilter
go test ./pkg/security -run TestRateLimiter
```

## 📚 Documentation

- [API Reference](./API_REFERENCE.md)
- [Security Guide](./SECURITY_GUIDE.md)
- [Deployment Guide](./DEPLOYMENT_GUIDE.md)
- [Troubleshooting](./TROUBLESHOOTING.md)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](./CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

---

**The HackAI LLM Security Proxy provides enterprise-grade security for AI applications, ensuring safe, compliant, and controlled access to Large Language Models.**
