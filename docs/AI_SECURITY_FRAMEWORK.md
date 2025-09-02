# AI Security Framework

## Overview

The HackAI AI Security Framework provides comprehensive security assessment and protection for Large Language Model (LLM) applications. It implements industry-standard security frameworks including MITRE ATLAS and OWASP AI Top 10, along with advanced threat detection capabilities.

## Features

### 🛡️ Core Security Components

1. **MITRE ATLAS Integration**
   - Real-time threat mapping
   - Adversarial attack detection
   - Automated mitigation strategies
   - Comprehensive threat intelligence

2. **OWASP AI Top 10 Compliance**
   - Prompt injection detection
   - Data poisoning prevention
   - Model theft protection
   - Supply chain security

3. **Advanced Prompt Injection Guard**
   - Semantic analysis
   - Context-aware detection
   - Pattern-based filtering
   - Machine learning detection

4. **Threat Detection Engine**
   - Model inversion detection
   - Membership inference attacks
   - Adversarial example detection
   - Data extraction prevention

5. **Content Filtering**
   - Toxicity detection
   - Bias identification
   - PII protection
   - Malware scanning

6. **Policy Engine**
   - Real-time enforcement
   - Custom policy rules
   - Compliance monitoring
   - Violation reporting

7. **AI Firewall**
   - Request filtering
   - Rate limiting
   - Threat intelligence integration
   - Auto-blocking capabilities

### 📊 Monitoring & Observability

- **Real-time Monitoring**: Continuous assessment of all LLM requests
- **Distributed Tracing**: Full request lifecycle tracking with OpenTelemetry
- **Metrics Collection**: Comprehensive security metrics and KPIs
- **Alerting**: Real-time alerts for security events
- **Compliance Reporting**: Automated compliance status reports

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   LLM Request   │───▶│  AI Security     │───▶│   Assessment    │
│                 │    │   Framework      │    │    Results      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Security        │
                    │  Components      │
                    │                  │
                    │ • MITRE ATLAS    │
                    │ • OWASP AI Top10 │
                    │ • Prompt Guard   │
                    │ • Threat Engine  │
                    │ • Content Filter │
                    │ • Policy Engine  │
                    │ • AI Firewall    │
                    └──────────────────┘
```

## API Endpoints

### Security Assessment

**POST** `/api/v1/ai-security/assess`

Performs comprehensive security assessment on an LLM request.

```json
{
  "request_id": "req_123",
  "user_id": "user_456",
  "session_id": "session_789",
  "content": "What is the weather like today?",
  "model": "gpt-4",
  "provider": "openai",
  "metadata": {}
}
```

**Response:**
```json
{
  "assessment": {
    "id": "assessment_123",
    "timestamp": "2024-01-15T10:30:00Z",
    "request_id": "req_123",
    "overall_threat_score": 0.15,
    "risk_level": "low",
    "compliance_status": "compliant",
    "blocked": false,
    "recommendations": [],
    "mitigations": [],
    "processing_duration": "45ms"
  },
  "success": true,
  "message": "Security assessment completed successfully"
}
```

### Security Status

**GET** `/api/v1/ai-security/status`

Returns the current status of the AI security framework.

```json
{
  "status": "active",
  "components_active": {
    "mitre_atlas": true,
    "owasp_ai_top10": true,
    "prompt_injection": true,
    "threat_detection": true,
    "content_filtering": true,
    "policy_engine": true,
    "rate_limiting": true,
    "ai_firewall": true,
    "threat_intelligence": true
  },
  "configuration": {
    "real_time_monitoring": true,
    "auto_mitigation": false,
    "threat_threshold": 0.7,
    "continuous_learning": true,
    "alerting_enabled": true,
    "compliance_reporting": true
  },
  "last_update": "2024-01-15T10:30:00Z",
  "success": true,
  "message": "AI Security Framework is operational"
}
```

### Security Metrics

**GET** `/api/v1/ai-security/metrics`

Returns security metrics and statistics.

```json
{
  "metrics": {
    "total_assessments": 1000,
    "blocked_requests": 25,
    "high_risk_detections": 15,
    "prompt_injections": 8,
    "threat_score_average": 0.15,
    "compliance_rate": 0.98,
    "response_time_avg_ms": 45,
    "last_24h": {
      "assessments": 150,
      "blocked": 3,
      "high_risk": 2,
      "prompt_injections": 1
    },
    "top_threats": [
      {"type": "prompt_injection", "count": 8, "percentage": 32.0},
      {"type": "suspicious_content", "count": 7, "percentage": 28.0},
      {"type": "policy_violation", "count": 6, "percentage": 24.0},
      {"type": "rate_limit_exceeded", "count": 4, "percentage": 16.0}
    ]
  },
  "success": true,
  "message": "Security metrics retrieved successfully"
}
```

## Configuration

### Environment Variables

- `PORT`: Service port (default: 9086)
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `JAEGER_ENDPOINT`: Jaeger tracing endpoint

### Security Configuration

```go
type AISecurityConfig struct {
    EnableMITREATLAS         bool          // Enable MITRE ATLAS framework
    EnableOWASPAITop10       bool          // Enable OWASP AI Top 10 compliance
    EnablePromptInjection    bool          // Enable prompt injection detection
    EnableThreatDetection    bool          // Enable advanced threat detection
    EnableContentFiltering   bool          // Enable content filtering
    EnablePolicyEngine       bool          // Enable policy enforcement
    EnableRateLimiting       bool          // Enable rate limiting
    EnableAIFirewall         bool          // Enable AI firewall
    EnableThreatIntelligence bool          // Enable threat intelligence
    RealTimeMonitoring       bool          // Enable real-time monitoring
    AutoMitigation           bool          // Enable automatic mitigation
    ThreatThreshold          float64       // Threat score threshold (0.0-1.0)
    ScanInterval             time.Duration // Background scan interval
    LogDetailedAnalysis      bool          // Log detailed analysis results
    EnableContinuousLearning bool          // Enable ML model updates
    MaxConcurrentScans       int           // Maximum concurrent assessments
    AlertingEnabled          bool          // Enable security alerting
    ComplianceReporting      bool          // Enable compliance reporting
}
```

## Deployment

### Docker Compose

The AI Security Service is included in the main Docker Compose configuration:

```yaml
ai-security-service:
  build:
    context: ..
    dockerfile: deployments/docker/Dockerfile.ai-security
  container_name: hackai-ai-security-service
  ports:
    - "9086:9086"
  environment:
    - PORT=9086
    - DB_HOST=postgres
    - DB_PORT=5432
    - DB_NAME=hackai
    - DB_USER=hackai
    - DB_PASSWORD=hackai_password
    - REDIS_HOST=redis
    - REDIS_PORT=6379
    - JAEGER_ENDPOINT=http://jaeger:14268/api/traces
  depends_on:
    postgres:
      condition: service_healthy
    redis:
      condition: service_healthy
  networks:
    - hackai-network
  restart: unless-stopped
```

### Standalone Deployment

```bash
# Build the service
go build -o ai-security-service ./cmd/ai-security-service

# Run the service
./ai-security-service
```

## Security Best Practices

1. **Threat Threshold**: Set appropriate threat thresholds based on your risk tolerance
2. **Auto-Mitigation**: Use with caution in production environments
3. **Monitoring**: Enable comprehensive logging and monitoring
4. **Updates**: Keep security models and threat intelligence updated
5. **Testing**: Regularly test security controls with known attack patterns

## Integration Examples

### Basic Assessment

```go
// Create AI Security Framework
framework, err := usecase.NewAISecurityFramework(logger, securityRepo, auditRepo, config)
if err != nil {
    log.Fatal(err)
}

// Assess LLM request
request := &security.LLMRequest{
    ID:       "req_123",
    Body:     []byte("User prompt here"),
    Model:    "gpt-4",
    Provider: "openai",
}

assessment, err := framework.AssessLLMRequest(ctx, request)
if err != nil {
    log.Error(err)
}

// Check if request should be blocked
if assessment.Blocked {
    log.Warn("Request blocked:", assessment.BlockReason)
}
```

### HTTP Client Integration

```javascript
const response = await fetch('/api/v1/ai-security/assess', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    content: userPrompt,
    model: 'gpt-4',
    provider: 'openai'
  })
});

const assessment = await response.json();

if (assessment.assessment.blocked) {
  console.warn('Request blocked:', assessment.assessment.block_reason);
} else {
  // Proceed with LLM request
}
```

## Monitoring and Alerting

The AI Security Framework provides comprehensive monitoring through:

- **Prometheus Metrics**: Security metrics exported for monitoring
- **Jaeger Tracing**: Distributed tracing for performance analysis
- **Structured Logging**: Detailed security event logging
- **Health Checks**: Service health and readiness endpoints

## Compliance

The framework helps maintain compliance with:

- **OWASP AI Security Top 10**
- **MITRE ATLAS Framework**
- **NIST AI Risk Management Framework**
- **ISO/IEC 23053 (AI Risk Management)**
- **Industry-specific AI security standards**

## Support

For questions, issues, or contributions:

1. Check the documentation
2. Review existing issues
3. Create a new issue with detailed information
4. Follow the contribution guidelines

## License

This AI Security Framework is part of the HackAI platform and follows the same licensing terms.
