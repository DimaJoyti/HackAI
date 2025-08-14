# Secure Web Layer Integration

The Secure Web Layer Integration provides comprehensive security middleware that integrates all security components into a unified web layer. It offers real-time threat detection, request/response filtering, security metrics collection, alerting, and health monitoring.

## Features

### 🛡️ **Multi-Layer Security Protection**
- **AI Firewall Integration** - Advanced threat detection and blocking
- **Input/Output Filtering** - Comprehensive content validation and sanitization
- **Prompt Injection Protection** - AI-specific attack prevention
- **Agentic Security Framework** - Autonomous threat response
- **Threat Intelligence** - Real-time threat data correlation

### 📊 **Advanced Monitoring & Analytics**
- **Real-time Security Metrics** - Comprehensive statistics collection
- **Security Event Correlation** - Pattern detection and analysis
- **Health Monitoring** - Component status tracking
- **Performance Metrics** - Request processing analytics

### 🚨 **Alerting & Notification**
- **Multi-channel Alerting** - Slack, Email, Webhook notifications
- **Threat Score-based Alerts** - Configurable alert thresholds
- **Correlation Pattern Alerts** - Advanced attack pattern detection
- **Real-time Notifications** - Immediate threat response

### 🔧 **Enhanced Security Headers**
- **Content Security Policy (CSP)** - XSS protection
- **HTTP Strict Transport Security (HSTS)** - HTTPS enforcement
- **X-Frame-Options** - Clickjacking prevention
- **Additional Security Headers** - Comprehensive protection

## Quick Start

### Basic Usage

```go
package main

import (
    "net/http"
    "github.com/dimajoyti/hackai/pkg/logger"
    "github.com/dimajoyti/hackai/pkg/middleware"
)

func main() {
    // Create logger
    log, _ := logger.New(logger.Config{Level: "info", Output: "stdout"})
    
    // Create secure web layer with default configuration
    config := middleware.DefaultSecureWebConfig()
    secureLayer := middleware.NewSecureWebLayer(config, log)
    
    // Create your HTTP handler
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, Secure World!"))
    })
    
    // Wrap with security middleware
    secureHandler := secureLayer.SecureMiddleware()(mux)
    
    // Start server
    http.ListenAndServe(":8080", secureHandler)
}
```

### Advanced Configuration

```go
// Create custom configuration
config := &middleware.SecureWebConfig{
    // Core Security Features
    EnableAgenticSecurity:    true,
    EnableAIFirewall:         true,
    EnableInputFiltering:     true,
    EnableOutputFiltering:    true,
    EnablePromptProtection:   true,
    EnableThreatIntelligence: true,
    
    // Monitoring & Analytics
    EnableRealTimeMonitoring: true,
    EnableSecurityMetrics:    true,
    EnableEventCorrelation:   true,
    EnableHealthChecks:       true,
    
    // Alerting & Notifications
    EnableAlerting:           true,
    EnableMetricsExport:      true,
    
    // Security Thresholds
    BlockThreshold:           0.8,  // Block requests with threat score >= 0.8
    AlertThreshold:           0.6,  // Send alerts for threat score >= 0.6
    
    // Request Limits
    MaxRequestSize:           5 * 1024 * 1024, // 5MB
    RequestTimeout:           30 * time.Second,
    
    // Security Headers
    EnableCSP:                true,
    CSPPolicy:                "default-src 'self'; script-src 'self'",
    EnableHSTS:               true,
    HSTSMaxAge:               31536000, // 1 year
    EnableXFrameOptions:      true,
    XFrameOptionsValue:       "DENY",
    
    // Alerting Configuration
    AlertConfig: &middleware.AlertConfig{
        EnableSlack:    true,
        SlackWebhook:   "https://hooks.slack.com/...",
        EnableEmail:    true,
        EmailRecipient: "security@company.com",
        AlertThreshold: 0.7,
    },
    
    // Metrics Configuration
    MetricsConfig: &middleware.MetricsConfig{
        EnablePrometheus: true,
        PrometheusPort:   9090,
        ExportInterval:   30 * time.Second,
    },
}

secureLayer := middleware.NewSecureWebLayer(config, log)
```

## Security Features

### Request Processing Flow

1. **Enhanced Security Headers** - Applied to all responses
2. **Request Size Validation** - Enforces maximum request size limits
3. **AI Firewall Processing** - Advanced threat detection and blocking
4. **Input Filtering** - Content validation and threat scanning
5. **Prompt Injection Protection** - AI-specific attack prevention
6. **Agentic Security Analysis** - Autonomous threat assessment
7. **Output Filtering** - Response sanitization and filtering
8. **Security Event Processing** - Event correlation and analysis
9. **Metrics Collection** - Performance and security statistics
10. **Alerting** - Real-time threat notifications

### Threat Detection Capabilities

- **SQL Injection** - Advanced pattern detection
- **Cross-Site Scripting (XSS)** - Script injection prevention
- **Command Injection** - System command attack detection
- **Path Traversal** - Directory traversal prevention
- **Prompt Injection** - AI-specific attack patterns
- **Malware Signatures** - Known threat pattern matching
- **Shellcode Detection** - Binary exploit identification
- **High Entropy Content** - Obfuscation detection

## Monitoring & Metrics

### Security Metrics

```go
// Get current security metrics
metrics := secureLayer.GetSecurityMetrics()

fmt.Printf("Total Requests: %d\n", metrics.TotalRequests)
fmt.Printf("Blocked Requests: %d\n", metrics.BlockedRequests)
fmt.Printf("Threats Detected: %d\n", metrics.ThreatsDetected)
fmt.Printf("Average Risk Score: %.2f\n", metrics.AverageRiskScore)
fmt.Printf("Average Processing Time: %v\n", metrics.AverageProcessingTime)
```

### Health Monitoring

```go
// Get health status
healthStatus := secureLayer.GetHealthStatus()

fmt.Printf("Overall Health: %s\n", healthStatus.Overall)
for _, component := range healthStatus.Components {
    fmt.Printf("Component %s: %s\n", component.Name, component.Status)
}
```

### Security Events

```go
// Get recent security events
events := secureLayer.GetSecurityEvents(50) // Last 50 events

for _, event := range events {
    fmt.Printf("Event: %s, Severity: %s, IP: %s\n", 
        event.Type, event.Severity, event.IPAddress)
}
```

## API Endpoints

The secure web layer provides built-in endpoints for monitoring:

### Health Check
```
GET /health
```
Returns the health status of all security components.

### Security Metrics
```
GET /metrics
```
Returns comprehensive security metrics and statistics.

### Security Events
```
GET /security/events
```
Returns recent security events for analysis.

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `EnableAgenticSecurity` | bool | true | Enable autonomous security framework |
| `EnableAIFirewall` | bool | true | Enable AI-powered firewall |
| `EnableInputFiltering` | bool | true | Enable input validation and filtering |
| `EnableOutputFiltering` | bool | true | Enable output sanitization |
| `EnablePromptProtection` | bool | true | Enable prompt injection protection |
| `EnableThreatIntelligence` | bool | true | Enable threat intelligence integration |
| `EnableRealTimeMonitoring` | bool | true | Enable real-time monitoring |
| `EnableSecurityMetrics` | bool | true | Enable metrics collection |
| `EnableAlerting` | bool | true | Enable alerting system |
| `EnableEventCorrelation` | bool | true | Enable event correlation |
| `EnableMetricsExport` | bool | true | Enable metrics export |
| `EnableHealthChecks` | bool | true | Enable health monitoring |
| `BlockThreshold` | float64 | 0.7 | Threat score threshold for blocking |
| `AlertThreshold` | float64 | 0.5 | Threat score threshold for alerts |
| `MaxRequestSize` | int64 | 10MB | Maximum request size limit |
| `RequestTimeout` | duration | 30s | Request processing timeout |
| `LogSecurityEvents` | bool | true | Enable security event logging |
| `EnableCSP` | bool | true | Enable Content Security Policy |
| `EnableHSTS` | bool | true | Enable HTTP Strict Transport Security |
| `EnableXFrameOptions` | bool | true | Enable X-Frame-Options header |
| `StrictMode` | bool | false | Enable strict security mode |

## Best Practices

### Production Deployment

1. **Configure Appropriate Thresholds**
   - Set `BlockThreshold` to 0.8 for production
   - Set `AlertThreshold` to 0.6 for early warning

2. **Enable Comprehensive Monitoring**
   - Enable all monitoring features
   - Configure alerting channels
   - Set up metrics export to monitoring systems

3. **Security Headers**
   - Customize CSP policy for your application
   - Enable HSTS with appropriate max-age
   - Configure X-Frame-Options based on requirements

4. **Performance Optimization**
   - Adjust request size limits based on needs
   - Configure appropriate timeouts
   - Monitor processing times

### Security Considerations

1. **Regular Updates**
   - Keep threat intelligence feeds updated
   - Review and update security rules
   - Monitor for new attack patterns

2. **Incident Response**
   - Set up proper alerting channels
   - Define incident response procedures
   - Regularly review security events

3. **Testing**
   - Test security configurations
   - Validate alert mechanisms
   - Perform regular security assessments

## Example Implementation

See `examples/secure_web_server.go` for a complete implementation example showing:

- Server setup with security middleware
- Custom route handlers
- Health and metrics endpoints
- Graceful shutdown handling
- Production-ready configuration

## Integration with Other Components

The Secure Web Layer seamlessly integrates with:

- **AI Firewall** - Advanced threat detection
- **Input/Output Filtering** - Content validation
- **Prompt Injection Guard** - AI-specific protection
- **Agentic Security Framework** - Autonomous response
- **Threat Intelligence** - Real-time threat data
- **Security Metrics** - Comprehensive monitoring
- **Alerting System** - Multi-channel notifications
