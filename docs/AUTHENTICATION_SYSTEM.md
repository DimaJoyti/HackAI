# 🔐 HackAI Authentication & Authorization System

## Overview

The HackAI Authentication & Authorization System provides a comprehensive, production-ready security framework with JWT-based authentication, role-based access control (RBAC), session management, and advanced security features.

## 🏗️ Architecture

### Core Components

1. **Authentication Service** (`cmd/auth-service`)
   - Standalone microservice for authentication
   - RESTful API endpoints
   - JWT token management
   - Session handling

2. **Enhanced Auth Service** (`pkg/auth/service.go`)
   - Core authentication logic
   - Password management
   - TOTP/2FA support
   - Security auditing

3. **JWT Manager** (`pkg/auth/jwt.go`)
   - Token generation and validation
   - Claims management
   - Token refresh logic

4. **Auth Middleware** (`pkg/middleware/auth.go`)
   - Request authentication
   - Role-based authorization
   - Permission checking

5. **Auth Handler** (`internal/handler/auth.go`)
   - HTTP request handling
   - API endpoint implementation
   - Response formatting

## 🚀 Features

### Authentication Features
- ✅ JWT-based authentication
- ✅ Access and refresh tokens
- ✅ Password hashing (bcrypt)
- ✅ Account lockout protection
- ✅ Rate limiting
- ✅ Session management
- ✅ TOTP/2FA support
- ✅ Password reset functionality
- ✅ User registration

### Authorization Features
- ✅ Role-based access control (RBAC)
- ✅ Permission-based authorization
- ✅ Resource-level access control
- ✅ Admin/User/Moderator roles
- ✅ Dynamic permission checking

### Security Features
- ✅ Secure password policies
- ✅ Account lockout after failed attempts
- ✅ IP-based security monitoring
- ✅ Audit logging
- ✅ CSRF protection
- ✅ Security headers
- ✅ Request validation

### Monitoring & Observability
- ✅ Authentication metrics
- ✅ Security event logging
- ✅ Health checks
- ✅ Performance monitoring
- ✅ OpenTelemetry integration

## 📡 API Endpoints

### Public Endpoints (No Authentication Required)

#### Health & Status
```http
GET /health                    # Service health check
GET /ready                     # Service readiness check
GET /metrics                   # Service metrics
```

#### Authentication
```http
POST /api/v1/auth/login        # User login
POST /api/v1/auth/refresh      # Refresh access token
POST /api/v1/auth/validate     # Validate token
POST /api/v1/auth/register     # User registration (if enabled)
POST /api/v1/auth/forgot-password    # Initiate password reset
POST /api/v1/auth/reset-password     # Complete password reset
```

#### Statistics
```http
GET /api/v1/auth/stats         # Authentication statistics
```

### Protected Endpoints (Authentication Required)

#### User Management
```http
POST /api/v1/auth/logout       # User logout
GET  /api/v1/auth/profile      # Get user profile
PUT  /api/v1/auth/profile      # Update user profile
POST /api/v1/auth/change-password    # Change password
```

#### Two-Factor Authentication
```http
POST /api/v1/auth/enable-totp  # Enable TOTP/2FA
POST /api/v1/auth/disable-totp # Disable TOTP/2FA
```

#### Session Management
```http
GET    /api/v1/auth/sessions   # Get user sessions
DELETE /api/v1/auth/sessions/{id}  # Revoke session
```

#### Permissions
```http
GET /api/v1/auth/permissions   # Get user permissions
```

## 🔧 Configuration

### Environment Variables

```bash
# Service Configuration
PORT=9088
HOST=0.0.0.0

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=hackai
DB_USER=hackai
DB_PASSWORD=hackai_password

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_EXPIRY=24h
REFRESH_TOKEN_EXPIRY=168h
JWT_ISSUER=hackai-auth-service
JWT_AUDIENCE=hackai-users

# Security Configuration
PASSWORD_MIN_LENGTH=8
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_DURATION=15m
SESSION_TIMEOUT=24h

# Redis Configuration (for session storage)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Observability
JAEGER_ENDPOINT=http://localhost:14268/api/traces
LOG_LEVEL=info
```

### JWT Configuration

```yaml
jwt:
  secret: "${JWT_SECRET}"
  issuer: "hackai-auth-service"
  audience: "hackai-users"
  access_token_duration: "15m"
  refresh_token_duration: "24h"
  algorithm: "HS256"
```

### Security Configuration

```yaml
security:
  password_min_length: 8
  max_failed_attempts: 5
  lockout_duration: "15m"
  session_timeout: "24h"
  enable_totp: true
  enable_csrf: true
  rate_limit:
    requests_per_minute: 60
    burst: 10
```

## 🚀 Quick Start

### 1. Build the Service

```bash
# Build authentication service
make build-auth

# Or build all services
make build
```

### 2. Run the Service

```bash
# Run authentication service
make run-auth

# Or run all services
make run-services
```

### 3. Test the Service

```bash
# Run API demo
./bin/auth-api-demo

# Run programmatic demo
./bin/auth-demo
```

### 4. Docker Deployment

```bash
# Start with Docker Compose
docker-compose up auth-service

# Or start all services
docker-compose up
```

## 📝 Usage Examples

### Login Request

```bash
curl -X POST http://localhost:9088/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email_or_username": "user@hackai.com",
    "password": "password123",
    "remember_me": true
  }'
```

### Response

```json
{
  "user": {
    "id": "user-uuid",
    "username": "user",
    "email": "user@hackai.com",
    "role": "user"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "refresh-token-here",
  "expires_at": "2024-01-16T10:30:00Z",
  "session_id": "session-uuid"
}
```

### Protected Request

```bash
curl -X GET http://localhost:9088/api/v1/auth/profile \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Token Validation

```bash
curl -X POST http://localhost:9088/api/v1/auth/validate \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

## 🔒 Security Best Practices

### Password Security
- Minimum 8 characters
- bcrypt hashing with salt
- Password complexity requirements
- Password history tracking

### Account Protection
- Account lockout after 5 failed attempts
- 15-minute lockout duration
- IP-based monitoring
- Suspicious activity detection

### Token Security
- Short-lived access tokens (15 minutes)
- Secure refresh tokens (24 hours)
- Token rotation on refresh
- Secure token storage

### Session Management
- Secure session cookies
- Session timeout
- Multiple session support
- Session revocation

## 📊 Monitoring & Metrics

### Health Endpoints
- `/health` - Service health status
- `/ready` - Service readiness
- `/metrics` - Prometheus metrics

### Key Metrics
- Total login attempts
- Successful/failed authentications
- Active sessions
- Token validations
- Security events
- Response times

### Audit Logging
- All authentication events
- Authorization decisions
- Security violations
- Administrative actions
- User activities

## 🧪 Testing

### Unit Tests
```bash
go test ./pkg/auth/...
go test ./internal/handler/...
```

### Integration Tests
```bash
go test ./cmd/auth-service/...
```

### API Testing
```bash
# Run API demo
./bin/auth-api-demo

# Manual testing with curl
curl http://localhost:9088/health
```

## 🔧 Development

### Adding New Endpoints
1. Add handler method to `AuthHandler`
2. Register route in `setupRoutes`
3. Add middleware if needed
4. Update documentation

### Adding New Roles
1. Update `domain.UserRole` constants
2. Add role to permission mappings
3. Update middleware checks
4. Test authorization

### Custom Authentication
1. Implement `AuthService` interface
2. Add custom validation logic
3. Register with dependency injection
4. Configure middleware

## 🚀 Production Deployment

### Environment Setup
- Use strong JWT secrets
- Configure proper database connections
- Set up Redis for session storage
- Enable TLS/HTTPS
- Configure rate limiting

### Monitoring
- Set up Prometheus metrics
- Configure Jaeger tracing
- Enable audit logging
- Monitor security events

### Scaling
- Horizontal scaling support
- Stateless design
- Redis session sharing
- Load balancer compatibility

## 📚 Related Documentation

- [Security Guide](./guides/security.md)
- [API Documentation](./API.md)
- [Configuration Guide](./CONFIGURATION.md)
- [Deployment Guide](./DEPLOYMENT.md)
