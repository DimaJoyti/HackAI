# 🏗️ Core Infrastructure Setup
## Enterprise-Grade Infrastructure for HackAI Platform

This package provides comprehensive infrastructure management for the HackAI platform, including database connections, caching, security, monitoring, and LLM-specific infrastructure components.

## 🎯 Features

### Core Infrastructure
- **Database Management**: PostgreSQL with vector extensions (pgvector)
- **Caching Layer**: Redis with LLM-optimized caching
- **Health Monitoring**: Comprehensive health checks and system metrics
- **Security Framework**: Input validation, output filtering, audit logging
- **Rate Limiting**: Distributed rate limiting with Redis backend
- **Observability**: OpenTelemetry integration with metrics and tracing

### LLM-Specific Infrastructure
- **Vector Database**: Optimized for embeddings and similarity search
- **Memory Systems**: Conversation, episodic, and fact memory
- **Security Validation**: Prompt injection detection and prevention
- **Session Management**: Secure session handling for LLM interactions
- **Attack Pattern Storage**: Database of known attack patterns and signatures

## 🚀 Quick Start

### Basic Setup

```go
package main

import (
    "context"
    "github.com/dimajoyti/hackai/pkg/config"
    "github.com/dimajoyti/hackai/pkg/infrastructure"
    "github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
    // Load configuration
    cfg, err := config.Load()
    if err != nil {
        panic(err)
    }

    // Create logger
    logger, err := logger.New(logger.Config{
        Level:  logger.LevelInfo,
        Format: "json",
        Output: "stdout",
    })
    if err != nil {
        panic(err)
    }

    // Create infrastructure manager
    infraManager, err := infrastructure.NewInfrastructureManager(cfg, logger)
    if err != nil {
        panic(err)
    }

    // Initialize and start infrastructure
    ctx := context.Background()
    if err := infraManager.Initialize(ctx); err != nil {
        panic(err)
    }

    if err := infraManager.Start(ctx); err != nil {
        panic(err)
    }

    // Use infrastructure components
    healthManager := infraManager.GetHealthManager()
    llmCache := infraManager.GetLLMCache()
    securityValidator := infraManager.GetSecurityValidator()

    // Your application logic here...

    // Graceful shutdown
    infraManager.Stop(ctx)
}
```

### Docker Setup

```bash
# Start infrastructure services
docker-compose up -d postgres redis jaeger prometheus grafana

# Verify services are running
docker-compose ps
```

## 🔧 Configuration

### Environment Variables

Copy `.env.infrastructure` to `.env` and customize:

```bash
# Core Infrastructure
DB_HOST=localhost
DB_PORT=5432
REDIS_HOST=localhost
REDIS_PORT=6379

# LLM Configuration
LLM_ORCHESTRATION_ENABLED=true
VECTOR_DB_ENABLED=true
OPENAI_API_KEY=your-key-here

# Security
LLM_INPUT_VALIDATION=true
LLM_OUTPUT_FILTERING=true
RATE_LIMIT_ENABLED=true

# Monitoring
MONITORING_METRICS=true
MONITORING_TRACING=true
```

### Programmatic Configuration

```go
// Load LLM infrastructure configuration
llmConfig, err := infrastructure.LoadLLMInfrastructureConfig()
if err != nil {
    panic(err)
}

// Customize configuration
llmConfig.Orchestration.MaxConcurrentChains = 200
llmConfig.Security.MaxPromptLength = 20000
llmConfig.RateLimit.RequestsPerMinute = 1000
```

## 🗄️ Database Setup

### PostgreSQL with Vector Extensions

The infrastructure automatically sets up PostgreSQL with pgvector for vector operations:

```sql
-- Vector embeddings table
CREATE TABLE llm_embeddings (
    id SERIAL PRIMARY KEY,
    content_hash VARCHAR(64) UNIQUE NOT NULL,
    content TEXT NOT NULL,
    embedding vector(1536),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Vector similarity search index
CREATE INDEX llm_embeddings_embedding_idx 
ON llm_embeddings USING ivfflat (embedding vector_cosine_ops) 
WITH (lists = 100);
```

### Memory Tables

- **Conversation Memory**: Short-term conversation history
- **Episodic Memory**: Long-term important events and interactions
- **Fact Memory**: Structured knowledge in subject-predicate-object format
- **Attack Patterns**: Security testing patterns and signatures

## 🔒 Security Features

### Input Validation

```go
validator := infraManager.GetSecurityValidator()

result := validator.ValidateInput(ctx, userInput)
if !result.Valid {
    // Handle validation failure
    log.Printf("Validation failed: %v", result.Issues)
}

if result.SensitiveDataFound {
    // Use sanitized input
    safeInput := result.SanitizedInput
}
```

### Rate Limiting

```go
rateLimiter := infraManager.GetRateLimiter()

allowed, err := rateLimiter.Allow(ctx, userID)
if !allowed {
    // Rate limit exceeded
    http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
    return
}
```

### Audit Logging

```go
auditLogger := infraManager.GetAuditLogger()

auditLogger.LogLLMRequest(ctx, userID, prompt, "gpt-4")
auditLogger.LogLLMResponse(ctx, userID, response, "gpt-4", tokensUsed)
```

## 📊 Health Monitoring

### Health Checks

```go
healthManager := infraManager.GetHealthManager()

// Get current health status
health := healthManager.CheckHealth(ctx)
fmt.Printf("System Status: %s\n", health.Status)

// Register custom health checker
healthManager.RegisterChecker(&CustomHealthChecker{})

// HTTP health endpoint
http.Handle("/health", healthManager.HTTPHandler())
```

### System Metrics

The health system automatically collects:
- Memory usage and garbage collection stats
- Database connection pool status
- Redis connectivity and performance
- Rate limiter status
- Security validator status

## 🚀 LLM Cache

### Basic Caching

```go
cache := infraManager.GetLLMCache()

// Cache LLM response
response := "Generated response from LLM"
err := cache.Set(ctx, "prompt-hash", response, 1*time.Hour)

// Retrieve cached response
var cached string
err = cache.Get(ctx, "prompt-hash", &cached)
if err == infrastructure.ErrCacheMiss {
    // Cache miss - generate new response
}
```

### Advanced Caching

```go
// Atomic cache operations
success, err := cache.SetNX(ctx, "lock-key", "locked", 5*time.Minute)
if success {
    // Lock acquired, perform operation
    defer cache.Delete(ctx, "lock-key")
}

// Check existence
exists, err := cache.Exists(ctx, "key")
```

## 🔄 Session Management

```go
sessionManager := infraManager.GetSessionManager()

// Create session
sessionData := &infrastructure.SessionData{
    UserID:   "user123",
    Username: "john_doe",
    Email:    "john@example.com",
    Roles:    []string{"user"},
    Metadata: map[string]interface{}{
        "preferences": map[string]string{
            "theme": "dark",
        },
    },
}

err := sessionManager.CreateSession(ctx, sessionID, sessionData)

// Get session
session, err := sessionManager.GetSession(ctx, sessionID)
if err == infrastructure.ErrSessionNotFound {
    // Session expired or not found
}
```

## 🌐 HTTP Middleware

```go
// Get middleware stack
middleware := infraManager.GetMiddleware()

// Apply to HTTP server
var handler http.Handler = mux
for _, mw := range middleware {
    handler = mw(handler)
}

server := &http.Server{
    Addr:    ":8080",
    Handler: handler,
}
```

The middleware stack includes:
1. **Security Middleware**: Input validation, security headers
2. **Rate Limiting Middleware**: Request rate limiting
3. **Audit Middleware**: Request/response logging

## 📈 Observability

### OpenTelemetry Integration

All infrastructure components are automatically instrumented with:
- **Distributed Tracing**: Request tracing across components
- **Metrics Collection**: Performance and usage metrics
- **Structured Logging**: JSON-formatted logs with correlation IDs

### Monitoring Endpoints

- `/health` - Health check endpoint
- `/metrics` - Prometheus metrics
- `/debug/pprof` - Go profiling (if enabled)

## 🧪 Testing

### Unit Tests

```bash
# Run infrastructure tests
go test ./pkg/infrastructure/... -v

# Run with coverage
go test ./pkg/infrastructure/... -cover
```

### Integration Tests

```bash
# Run integration tests (requires Docker)
go test ./test/infrastructure/... -v
```

### Demo Application

```bash
# Build and run demo
go build ./cmd/infrastructure-demo
./infrastructure-demo

# Test endpoints
curl http://localhost:8080/health
curl -X POST http://localhost:8080/api/demo/cache?key=test \
  -d '{"message": "Hello World"}'
```

## 🔧 Advanced Configuration

### Custom Health Checkers

```go
type CustomHealthChecker struct{}

func (c *CustomHealthChecker) Name() string {
    return "custom-service"
}

func (c *CustomHealthChecker) Check(ctx context.Context) infrastructure.ComponentHealth {
    // Your health check logic
    return infrastructure.ComponentHealth{
        Name:        c.Name(),
        Status:      infrastructure.HealthStatusHealthy,
        Message:     "Service is healthy",
        LastChecked: time.Now(),
    }
}

// Register the checker
healthManager.RegisterChecker(&CustomHealthChecker{})
```

### Custom Rate Limiters

```go
// Use Redis-based distributed rate limiter
redisLimiter := infrastructure.NewRedisRateLimiter(
    redisClient, 
    rateLimitConfig, 
    logger,
)

// Use in-memory rate limiter for single instance
memoryLimiter := infrastructure.NewTokenBucketLimiter(
    rateLimitConfig,
    logger,
)
```

## 🚨 Production Considerations

### Security
- Enable TLS for all connections
- Use strong passwords and API keys
- Enable audit logging
- Configure proper CORS settings
- Implement proper authentication

### Performance
- Tune database connection pools
- Configure Redis memory limits
- Set appropriate rate limits
- Monitor resource usage

### Reliability
- Enable health checks
- Configure proper timeouts
- Implement circuit breakers
- Set up monitoring and alerting

---

**🏗️ Building Robust Infrastructure for AI Security Testing 🏗️**

*This infrastructure provides the foundation for enterprise-grade AI security testing with comprehensive monitoring, security, and scalability features.*
