# 🚀 HackAI Platform - Getting Started Guide

## 🎯 Welcome to HackAI

HackAI is a comprehensive AI-powered security and orchestration platform that provides cutting-edge capabilities for cybersecurity, multi-agent coordination, real-time communication, and intelligent automation. This guide will help you get up and running quickly.

## 📋 Prerequisites

### System Requirements
- **Go**: Version 1.21 or higher
- **Memory**: Minimum 4GB RAM (8GB recommended)
- **Storage**: At least 2GB free space
- **Network**: Internet connection for dependencies

### Optional Dependencies
- **Redis**: For advanced caching and real-time features
- **PostgreSQL**: For persistent data storage
- **Docker**: For containerized deployment

## ⚡ Quick Start (5 Minutes)

### 1. Clone and Setup
```bash
# Clone the repository
git clone https://github.com/DimaJoyti/HackAI.git
cd HackAI

# Install dependencies
go mod download

# Verify installation
go version
```

### 2. Run Your First Demo
```bash
# Run the basic AI demo
go run ./cmd/ai-demo-simple

# Expected output:
# 🤖 HackAI Basic AI Demo
# ✅ AI system initialized
# ✅ Security framework active
# ✅ Demo completed successfully
```

### 3. Explore Interactive Demos
```bash
# Multi-agent orchestration demo
go run ./cmd/multiagent-orchestration-demo

# Real-time systems demo
go run ./cmd/realtime-systems-demo

# Security framework demo
go run ./cmd/security-framework-demo
```

## 🛡️ Security-First Setup

### 1. Initialize Security Framework
```go
package main

import (
    "context"
    "log"
    
    "github.com/dimajoyti/hackai/pkg/security"
    "github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
    // Initialize logger
    logger, _ := logger.New(logger.Config{
        Level:  "info",
        Format: "json",
    })
    
    // Setup security manager
    securityManager := security.NewManager(security.Config{
        EnablePromptInjectionDetection: true,
        EnableThreatIntelligence:       true,
        EnableRealTimeMonitoring:       true,
        EnableAuditLogging:             true,
    }, logger)
    
    // Start security services
    ctx := context.Background()
    if err := securityManager.Start(ctx); err != nil {
        log.Fatal("Failed to start security manager:", err)
    }
    defer securityManager.Stop()
    
    log.Println("✅ HackAI Security Framework Active")
}
```

### 2. Test Security Features
```bash
# Run security examples
go run ./examples/security/prompt_injection_protection.go

# Expected output:
# 🛡️ HackAI Prompt Injection Protection Example
# ✅ BLOCKED (Expected) - Risk Score: 0.95
# ✅ ALLOWED (Expected) - Risk Score: 0.15
# Success Rate: 100.0%
```

## 🤖 Multi-Agent Orchestration

### 1. Basic Agent Setup
```go
package main

import (
    "context"
    "time"
    
    "github.com/dimajoyti/hackai/pkg/agents/multiagent"
    "github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
    logger, _ := logger.New(logger.Config{Level: "info"})
    
    // Configure orchestrator
    config := &multiagent.OrchestratorConfig{
        MaxConcurrentTasks:     10,
        ConflictResolutionMode: "consensus",
        ConsensusThreshold:     0.7,
        EnableLoadBalancing:    true,
        MetricsEnabled:         true,
    }
    
    // Create orchestrator
    orchestrator := multiagent.NewMultiAgentOrchestrator(config, logger)
    
    // Start orchestrator
    ctx := context.Background()
    orchestrator.Start(ctx)
    defer orchestrator.Stop()
    
    log.Println("✅ Multi-Agent Orchestrator Active")
}
```

### 2. Test Agent Coordination
```bash
# Run multi-agent examples
go run ./examples/agents/multi_agent_orchestration.go

# Expected output:
# 🤖 HackAI Multi-Agent Orchestration Example
# ✅ Sequential workflow completed in 450ms
# ✅ Parallel workflow completed in 180ms
# ✅ Consensus achieved in 200ms
```

## 📡 Real-time Communication

### 1. WebSocket Setup
```go
package main

import (
    "context"
    "time"
    
    "github.com/dimajoyti/hackai/pkg/realtime"
    "github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
    logger, _ := logger.New(logger.Config{Level: "info"})
    
    // Configure real-time system
    config := &realtime.RealtimeConfig{
        WebSocketConfig: realtime.WebSocketConfig{
            ReadBufferSize:  1024,
            WriteBufferSize: 1024,
            MaxMessageSize:  512 * 1024,
        },
        MaxConnections:    1000,
        HeartbeatInterval: 30 * time.Second,
        MetricsEnabled:    true,
    }
    
    // Create real-time system
    realtimeSystem := realtime.NewRealtimeSystem(config, nil, nil, logger)
    
    // Start system
    ctx := context.Background()
    realtimeSystem.Start(ctx)
    defer realtimeSystem.Stop()
    
    log.Println("✅ Real-time Communication System Active")
}
```

### 2. Test Real-time Features
```bash
# Run real-time examples
go run ./examples/realtime/websocket_example.go

# Open browser to: http://localhost:8080
# Test WebSocket connections and real-time messaging
```

## 🔧 Configuration

### 1. Environment Configuration
Create a `.env` file in the project root:
```bash
# Basic Configuration
HACKAI_LOG_LEVEL=info
HACKAI_LOG_FORMAT=json

# Security Configuration
HACKAI_SECURITY_ENABLED=true
HACKAI_PROMPT_INJECTION_DETECTION=true
HACKAI_THREAT_INTELLIGENCE=true

# Database Configuration (Optional)
HACKAI_DB_HOST=localhost
HACKAI_DB_PORT=5432
HACKAI_DB_NAME=hackai
HACKAI_DB_USER=hackai
HACKAI_DB_PASSWORD=your_password

# Redis Configuration (Optional)
HACKAI_REDIS_HOST=localhost
HACKAI_REDIS_PORT=6379
HACKAI_REDIS_PASSWORD=

# Real-time Configuration
HACKAI_REALTIME_ENABLED=true
HACKAI_WEBSOCKET_PORT=8080
HACKAI_MAX_CONNECTIONS=1000
```

### 2. Configuration Loading
```go
package main

import (
    "github.com/dimajoyti/hackai/pkg/config"
)

func main() {
    // Load configuration
    cfg, err := config.Load()
    if err != nil {
        log.Fatal("Failed to load configuration:", err)
    }
    
    // Use configuration
    log.Printf("Security enabled: %v", cfg.Security.Enabled)
    log.Printf("Real-time enabled: %v", cfg.Realtime.Enabled)
}
```

## 📊 Monitoring & Observability

### 1. Enable Monitoring
```go
package main

import (
    "github.com/dimajoyti/hackai/pkg/monitoring"
    "github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
    logger, _ := logger.New(logger.Config{Level: "info"})
    
    // Setup monitoring
    monitor := monitoring.NewMonitor(monitoring.Config{
        EnableMetrics:     true,
        EnableTracing:     true,
        EnableHealthCheck: true,
        MetricsPort:       9090,
    }, logger)
    
    // Start monitoring
    ctx := context.Background()
    monitor.Start(ctx)
    defer monitor.Stop()
    
    log.Println("✅ Monitoring System Active")
}
```

### 2. View Metrics
```bash
# Check system health
curl http://localhost:8080/api/realtime/health

# Get system metrics
curl http://localhost:8080/api/realtime/metrics

# View system status
curl http://localhost:8080/api/realtime/status
```

## 🎓 Learning Path

### Beginner (Week 1)
1. **Day 1-2**: Complete this getting started guide
2. **Day 3-4**: Explore security examples
3. **Day 5-7**: Try multi-agent orchestration examples

### Intermediate (Week 2)
1. **Day 1-3**: Build custom agents
2. **Day 4-5**: Implement real-time features
3. **Day 6-7**: Create custom security policies

### Advanced (Week 3+)
1. **Week 3**: Deploy to production environment
2. **Week 4**: Integrate with external systems
3. **Week 5+**: Contribute to the platform

## 📚 Next Steps

### Essential Documentation
- **[Security Blueprint](SECURITY_BLUEPRINT.md)** - Comprehensive security guide
- **[Multi-Agent Orchestration](MULTI_AGENT_ORCHESTRATION.md)** - Agent coordination
- **[Real-time Systems](REAL_TIME_SYSTEMS_INTEGRATION.md)** - Communication systems
- **[API Documentation](API_DOCUMENTATION.md)** - Complete API reference

### Hands-on Examples
- **[Security Examples](../examples/security/)** - Security implementation patterns
- **[Agent Examples](../examples/agents/)** - Multi-agent coordination
- **[Real-time Examples](../examples/realtime/)** - Communication examples
- **[Integration Examples](../examples/integration/)** - System integration

### Community Resources
- **[GitHub Repository](https://github.com/DimaJoyti/HackAI)** - Source code and issues
- **[Documentation](../docs/)** - Complete documentation
- **[Examples](../examples/)** - Working code examples

## 🆘 Troubleshooting

### Common Issues

#### 1. Build Errors
```bash
# Update dependencies
go mod tidy
go mod download

# Clean build cache
go clean -cache
go clean -modcache
```

#### 2. Port Conflicts
```bash
# Check port usage
lsof -i :8080

# Use different port
export HACKAI_PORT=8081
```

#### 3. Permission Issues
```bash
# Fix file permissions
chmod +x ./scripts/*
sudo chown -R $USER:$USER .
```

### Getting Help
- **Check Documentation**: Review relevant docs in `/docs/`
- **Run Examples**: Try working examples in `/examples/`
- **Check Logs**: Enable debug logging for detailed information
- **GitHub Issues**: Report bugs or request features

## ✅ Verification Checklist

After completing this guide, you should be able to:

- [ ] Run basic HackAI demos successfully
- [ ] Initialize the security framework
- [ ] Create and coordinate multiple agents
- [ ] Establish real-time communication
- [ ] Configure the system for your needs
- [ ] Monitor system health and metrics
- [ ] Access comprehensive documentation
- [ ] Run working code examples

## 🎉 Success!

Congratulations! You've successfully set up the HackAI platform. You now have access to:

- **🛡️ Advanced Security**: AI-powered threat detection and prevention
- **🤖 Multi-Agent Systems**: Sophisticated agent coordination
- **📡 Real-time Communication**: WebSocket, SSE, and streaming
- **📊 Comprehensive Monitoring**: Full observability and analytics
- **🔧 Flexible Configuration**: Customizable for any environment
- **📚 Complete Documentation**: Extensive guides and examples

## 🔮 What's Next?

### Immediate Actions
1. **Explore Examples**: Try different examples in `/examples/`
2. **Read Documentation**: Deep dive into specific components
3. **Build Custom Agents**: Create agents for your use case
4. **Implement Security**: Set up security policies
5. **Deploy to Production**: Follow deployment guides

### Advanced Features
- **Custom Security Policies**: Implement domain-specific security
- **Advanced Agent Workflows**: Create complex orchestration patterns
- **Real-time Analytics**: Build custom monitoring dashboards
- **Third-party Integrations**: Connect with external systems
- **Performance Optimization**: Tune for your specific requirements

---

**Welcome to the HackAI ecosystem! You're now ready to build secure, intelligent, and scalable AI-powered applications.**
