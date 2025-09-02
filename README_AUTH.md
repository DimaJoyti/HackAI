# 🔐 HackAI Authentication & Authorization System

A production-ready, comprehensive authentication and authorization system built with Go, featuring JWT tokens, role-based access control, session management, and advanced security features.

## ✨ Features

### 🔑 Authentication
- **JWT-based Authentication** - Secure token-based authentication
- **Multi-factor Authentication** - TOTP/2FA support
- **Session Management** - Secure session handling and tracking
- **Password Security** - bcrypt hashing with secure policies
- **Account Protection** - Lockout protection and rate limiting

### 🛡️ Authorization
- **Role-Based Access Control (RBAC)** - Admin, User, Moderator roles
- **Permission-Based Authorization** - Fine-grained permission system
- **Resource-Level Access Control** - Protect specific resources
- **Dynamic Permission Checking** - Runtime permission validation

### 🔒 Security
- **Account Lockout Protection** - Prevent brute force attacks
- **Rate Limiting** - Protect against abuse
- **IP Security Monitoring** - Track suspicious activities
- **Audit Logging** - Complete security event tracking
- **CSRF Protection** - Cross-site request forgery protection

### 📊 Monitoring
- **Health Checks** - Service health and readiness endpoints
- **Metrics Collection** - Prometheus-compatible metrics
- **OpenTelemetry Integration** - Distributed tracing support
- **Security Analytics** - Authentication and authorization metrics

## 🚀 Quick Start

### Prerequisites
- Go 1.21+
- PostgreSQL 13+
- Redis 6+ (optional, for session storage)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/DimaJoyti/HackAI.git
cd HackAI
```

2. **Install dependencies**
```bash
go mod download
```

3. **Set up environment variables**
```bash
export JWT_SECRET="your-super-secret-jwt-key-change-in-production"
export DB_HOST="localhost"
export DB_PORT="5432"
export DB_NAME="hackai"
export DB_USER="hackai"
export DB_PASSWORD="hackai_password"
```

4. **Build and run**
```bash
# Build the authentication service
make build-auth

# Run the authentication service
make run-auth
```

### Docker Deployment

```bash
# Start with Docker Compose
docker-compose up auth-service

# Or start all services
docker-compose up
```

## 📡 API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/v1/auth/login` | User login | No |
| POST | `/api/v1/auth/logout` | User logout | Yes |
| POST | `/api/v1/auth/refresh` | Refresh access token | No |
| POST | `/api/v1/auth/validate` | Validate token | No |
| GET | `/api/v1/auth/profile` | Get user profile | Yes |
| PUT | `/api/v1/auth/profile` | Update user profile | Yes |
| POST | `/api/v1/auth/change-password` | Change password | Yes |

### Two-Factor Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/v1/auth/enable-totp` | Enable TOTP/2FA | Yes |
| POST | `/api/v1/auth/disable-totp` | Disable TOTP/2FA | Yes |

### Session Management

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/v1/auth/sessions` | Get user sessions | Yes |
| DELETE | `/api/v1/auth/sessions/{id}` | Revoke session | Yes |

### Monitoring

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/health` | Service health check | No |
| GET | `/ready` | Service readiness | No |
| GET | `/metrics` | Prometheus metrics | No |
| GET | `/api/v1/auth/stats` | Authentication statistics | No |

## 🔧 Configuration

### Environment Variables

```bash
# Service Configuration
PORT=9088                    # Service port
HOST=0.0.0.0                # Service host

# Database Configuration
DB_HOST=localhost           # Database host
DB_PORT=5432               # Database port
DB_NAME=hackai             # Database name
DB_USER=hackai             # Database user
DB_PASSWORD=password       # Database password

# JWT Configuration
JWT_SECRET=secret-key      # JWT signing secret
JWT_EXPIRY=24h            # Access token expiry
REFRESH_TOKEN_EXPIRY=168h # Refresh token expiry

# Security Configuration
PASSWORD_MIN_LENGTH=8      # Minimum password length
MAX_LOGIN_ATTEMPTS=5       # Max failed login attempts
ACCOUNT_LOCKOUT_DURATION=15m # Account lockout duration
```

## 📝 Usage Examples

### Login Example

```bash
curl -X POST http://localhost:9088/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email_or_username": "user@hackai.com",
    "password": "password123",
    "remember_me": true
  }'
```

**Response:**
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

### Protected Request Example

```bash
curl -X GET http://localhost:9088/api/v1/auth/profile \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Token Validation Example

```bash
curl -X POST http://localhost:9088/api/v1/auth/validate \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

## 🧪 Testing

### Run API Demo
```bash
# Build and run the API demo
go build -o bin/auth-api-demo ./cmd/auth-api-demo
./bin/auth-api-demo
```

### Run Programmatic Demo
```bash
# Build and run the programmatic demo
go build -o bin/auth-demo ./cmd/auth-demo
./bin/auth-demo
```

### Unit Tests
```bash
# Run authentication package tests
go test ./pkg/auth/...

# Run handler tests
go test ./internal/handler/...

# Run all tests
go test ./...
```

## 🏗️ Architecture

### Components

1. **Authentication Service** - Standalone microservice
2. **JWT Manager** - Token generation and validation
3. **Enhanced Auth Service** - Core authentication logic
4. **Auth Middleware** - Request authentication and authorization
5. **Auth Handler** - HTTP request handling

### Security Layers

1. **Transport Security** - HTTPS/TLS
2. **Authentication** - JWT token validation
3. **Authorization** - Role and permission checking
4. **Rate Limiting** - Request throttling
5. **Audit Logging** - Security event tracking

## 🔒 Security Features

### Password Security
- bcrypt hashing with salt
- Minimum length requirements
- Complexity validation
- Password history tracking

### Account Protection
- Account lockout after failed attempts
- IP-based monitoring
- Suspicious activity detection
- Rate limiting

### Token Security
- Short-lived access tokens
- Secure refresh tokens
- Token rotation
- Secure storage

## 📊 Monitoring & Observability

### Metrics
- Authentication success/failure rates
- Active session counts
- Token validation metrics
- Security event counts
- Response time metrics

### Health Checks
- Service health status
- Database connectivity
- Redis connectivity (if used)
- External service dependencies

### Logging
- Structured JSON logging
- Security event logging
- Audit trail logging
- Performance logging

## 🚀 Production Deployment

### Security Checklist
- [ ] Use strong JWT secrets
- [ ] Enable HTTPS/TLS
- [ ] Configure rate limiting
- [ ] Set up monitoring
- [ ] Enable audit logging
- [ ] Configure backup strategies

### Scaling Considerations
- Stateless design for horizontal scaling
- Redis for shared session storage
- Load balancer compatibility
- Database connection pooling

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📖 [Documentation](docs/AUTHENTICATION_SYSTEM.md)
- 🐛 [Issue Tracker](https://github.com/DimaJoyti/HackAI/issues)
- 💬 [Discussions](https://github.com/DimaJoyti/HackAI/discussions)

## 🙏 Acknowledgments

- Built with Go and modern security best practices
- Inspired by industry-standard authentication systems
- Designed for production use and scalability
