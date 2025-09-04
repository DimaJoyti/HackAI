# Security MCP Service

The Security MCP (Model Context Protocol) Service provides a comprehensive security interface for AI systems, enabling secure communication and advanced security operations through the MCP protocol.

## Overview

The Security MCP Service implements the Model Context Protocol to provide:

- **Threat Analysis**: AI-powered threat detection and analysis
- **Vulnerability Scanning**: Automated security vulnerability assessment
- **Compliance Checking**: Security framework compliance validation
- **Incident Response**: Security incident management and response
- **Threat Intelligence**: Real-time threat intelligence integration

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Security MCP Service                     │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │   MCP Server    │  │   MCP Client    │  │ HTTP Handler│ │
│  │                 │  │                 │  │             │ │
│  │ • Protocol      │  │ • Connection    │  │ • REST API  │ │
│  │ • Tools         │  │ • Requests      │  │ • Health    │ │
│  │ • Resources     │  │ • Responses     │  │ • Metrics   │ │
│  │ • Prompts       │  │ • Events        │  │             │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │ AI Security     │  │ Threat Intel    │  │ Compliance  │ │
│  │ Framework       │  │ Orchestrator    │  │ Engine      │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │   Database      │  │     Redis       │  │ Observability│ │
│  │   (PostgreSQL)  │  │    (Cache)      │  │ (OTEL)      │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Features

### MCP Protocol Support

- **Full MCP 2024-11-05 Compliance**: Complete implementation of the Model Context Protocol
- **Bidirectional Communication**: Support for requests, responses, and notifications
- **Error Handling**: Comprehensive error handling with proper MCP error codes
- **Authentication**: Secure authentication and authorization mechanisms

### Security Tools

#### 1. Threat Analysis Tool
```json
{
  "name": "threat_analysis",
  "description": "Analyze input for security threats using AI-powered detection",
  "parameters": {
    "input": "Text to analyze for threats",
    "context": "Security context for analysis"
  }
}
```

#### 2. Vulnerability Scan Tool
```json
{
  "name": "vulnerability_scan",
  "description": "Perform vulnerability scanning on targets",
  "parameters": {
    "target": "Target to scan (URL, IP, etc.)",
    "scan_type": "Type of scan (web, network, api, container)",
    "options": "Additional scan options"
  }
}
```

#### 3. Compliance Check Tool
```json
{
  "name": "compliance_check",
  "description": "Check compliance against security frameworks",
  "parameters": {
    "framework": "Compliance framework (OWASP, NIST, ISO27001, SOC2, GDPR)",
    "target": "Target system or application",
    "scope": "Specific controls or areas to check"
  }
}
```

#### 4. Incident Response Tool
```json
{
  "name": "incident_response",
  "description": "Manage security incidents and response actions",
  "parameters": {
    "action": "Action to perform (create, update, escalate, resolve, investigate)",
    "incident_id": "Incident ID (for update/escalate/resolve actions)",
    "details": "Incident details"
  }
}
```

#### 5. Threat Intelligence Tool
```json
{
  "name": "threat_intelligence",
  "description": "Query threat intelligence feeds and databases",
  "parameters": {
    "query_type": "Type of query (ioc, cve, mitre, reputation, feed)",
    "indicators": "Indicators of compromise to query",
    "sources": "Specific threat intelligence sources"
  }
}
```

### Security Resources

#### 1. Security Reports
- **URI**: `security://reports`
- **Description**: Access to security scan reports and analysis results
- **Format**: JSON

#### 2. Threat Intelligence
- **URI**: `security://threat-intel`
- **Description**: Access to threat intelligence data and feeds
- **Format**: JSON

#### 3. Compliance Reports
- **URI**: `security://compliance`
- **Description**: Access to compliance check results and frameworks
- **Format**: JSON

#### 4. Security Metrics
- **URI**: `security://metrics`
- **Description**: Access to security metrics and KPIs
- **Format**: JSON

### Security Prompts

#### 1. Threat Analysis Prompt
- **Name**: `threat_analysis_prompt`
- **Description**: Generate prompts for threat analysis and security assessment
- **Arguments**: `input_type`, `analysis_depth`

#### 2. Security Assessment Prompt
- **Name**: `security_assessment_prompt`
- **Description**: Generate prompts for comprehensive security assessments
- **Arguments**: `target_type`, `framework`

#### 3. Incident Response Prompt
- **Name**: `incident_response_prompt`
- **Description**: Generate prompts for incident response procedures
- **Arguments**: `incident_type`, `severity`

## Configuration

### Server Configuration

```yaml
security:
  mcp:
    server_name: "HackAI Security MCP Server"
    server_version: "1.0.0"
    max_concurrent_scans: 10
    scan_timeout: "5m"
    enable_realtime_alerts: true
    threat_threshold: 0.7
    log_level: "info"
    enable_audit_logging: true
```

### Client Configuration

```yaml
security:
  mcp_client:
    client_name: "HackAI Security MCP Client"
    client_version: "1.0.0"
    timeout: "30s"
    max_retries: 3
    retry_delay: "1s"
    enable_tracing: true
    enable_metrics: true
```

## API Endpoints

### Health Endpoints

- `GET /health` - Health check
- `GET /ready` - Readiness check

### MCP Endpoints

- `POST /mcp` - Main MCP protocol endpoint
- `POST /api/v1/mcp` - Versioned MCP endpoint

## Usage Examples

### Using the MCP Client

```go
package main

import (
    "context"
    "log"
    
    "github.com/dimajoyti/hackai/pkg/mcp"
    "github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
    // Create client
    config := mcp.DefaultSecurityMCPClientConfig()
    logger := logger.New(logger.Config{Level: "info"})
    client := mcp.NewSecurityMCPClient(config, logger)
    
    // Connect to server
    ctx := context.Background()
    err := client.Connect(ctx, "http://localhost:9087/mcp")
    if err != nil {
        log.Fatal(err)
    }
    defer client.Disconnect(ctx)
    
    // Analyze threat
    result, err := client.AnalyzeThreat(ctx, "suspicious input", map[string]interface{}{
        "user_id": "user123",
        "session_id": "session456",
    })
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Threat analysis result: %+v", result)
}
```

### Using HTTP API

```bash
# Health check
curl http://localhost:9087/health

# MCP request
curl -X POST http://localhost:9087/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "tools/call",
    "params": {
      "name": "threat_analysis",
      "arguments": {
        "input": "test input for analysis"
      }
    }
  }'
```

## Deployment

### Docker

```bash
# Build image
docker build -f deployments/docker/security-mcp-service.Dockerfile -t hackai/security-mcp-service:latest .

# Run container
docker run -p 9087:9087 \
  -e DATABASE_URL="postgres://..." \
  -e REDIS_URL="redis://..." \
  hackai/security-mcp-service:latest
```

### Kubernetes

```bash
# Deploy to Kubernetes
kubectl apply -f deployments/k8s/security-mcp-service.yaml

# Check status
kubectl get pods -l app=security-mcp-service

# View logs
kubectl logs -l app=security-mcp-service -f
```

## Security Considerations

### Authentication & Authorization

- JWT-based authentication for API access
- Role-based access control (RBAC)
- API key authentication for MCP clients
- Rate limiting and request throttling

### Data Protection

- Encryption in transit (TLS 1.3)
- Encryption at rest for sensitive data
- Secure credential management
- Data retention policies

### Network Security

- Network policies for Kubernetes deployment
- Firewall rules for Docker deployment
- VPC isolation in cloud environments
- DDoS protection and mitigation

## Monitoring & Observability

### Metrics

- Request/response metrics
- Security scan metrics
- Threat detection metrics
- Performance metrics

### Logging

- Structured JSON logging
- Security audit logs
- Request/response logging
- Error and exception logging

### Tracing

- OpenTelemetry distributed tracing
- Request correlation IDs
- Performance profiling
- Dependency tracking

## Troubleshooting

### Common Issues

1. **Connection Refused**
   - Check if service is running
   - Verify port configuration
   - Check firewall rules

2. **Authentication Errors**
   - Verify JWT token validity
   - Check API key configuration
   - Validate user permissions

3. **Timeout Errors**
   - Increase timeout configuration
   - Check network connectivity
   - Monitor resource usage

### Debug Mode

Enable debug logging:

```yaml
observability:
  logging:
    level: "debug"
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
