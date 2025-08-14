# HackAI - Educational Cybersecurity AI Platform

🛡️ **An advanced educational platform demonstrating AI-powered cybersecurity tools and techniques**

## 🎯 Overview

HackAI is a comprehensive educational cybersecurity platform that combines artificial intelligence with modern security practices. It provides hands-on learning experiences through interactive AI-powered security tools, real-time threat analysis, and educational modules.

## 🏗️ Architecture

### Backend (Go Microservices)
- **API Gateway**: Central routing, authentication, rate limiting
- **User Management**: Authentication, authorization, user profiles
- **AI Security Scanner**: Vulnerability detection and analysis
- **Network Analyzer**: Traffic analysis and anomaly detection
- **Threat Intelligence**: Real-time threat feeds and analysis
- **Log Analyzer**: AI-powered log parsing and threat detection
- **Notification Service**: Real-time alerts and communications

### Frontend (React/Next.js)
- **Security Dashboard**: Real-time monitoring and analytics
- **AI Tools Interface**: Interactive security tool interfaces
- **Educational Modules**: Hands-on cybersecurity learning
- **Admin Panel**: System management and configuration

### Infrastructure
- **Database**: PostgreSQL for structured data
- **Cache**: Redis for sessions and real-time data
- **Observability**: OpenTelemetry for distributed tracing
- **Containerization**: Docker for deployment

## 🚀 Features

### AI-Powered Security Tools
- **Vulnerability Scanner**: Automated security assessment
- **Network Traffic Analyzer**: Real-time network monitoring
- **Log Analysis Engine**: AI-driven log parsing and threat detection
- **Threat Intelligence**: Machine learning-based threat identification
- **Anomaly Detection**: Behavioral analysis and alerting

### Educational Components
- **Interactive Labs**: Hands-on cybersecurity exercises
- **Learning Modules**: Structured cybersecurity curriculum
- **Simulation Environment**: Safe testing environment
- **Progress Tracking**: Learning analytics and achievements

### Enterprise Features
- **Role-Based Access Control**: Granular permission management
- **Audit Logging**: Comprehensive activity tracking
- **Real-time Monitoring**: System health and performance metrics
- **Scalable Architecture**: Microservices for horizontal scaling

## 🛠️ Technology Stack

### Backend
- **Language**: Go 1.22+
- **Framework**: Standard library net/http with ServeMux
- **Architecture**: Clean Architecture with DDD principles
- **Database**: PostgreSQL with GORM
- **Cache**: Redis
- **Observability**: OpenTelemetry, Jaeger, Prometheus
- **Testing**: Go testing package with testify

### Frontend
- **Framework**: Next.js 14+ with React 18+
- **Language**: TypeScript
- **Styling**: TailwindCSS with Shadcn/UI
- **State Management**: Zustand
- **Real-time**: WebSockets
- **Testing**: Jest, React Testing Library

### DevOps
- **Containerization**: Docker & Docker Compose
- **CI/CD**: GitHub Actions
- **Monitoring**: Grafana, Prometheus
- **Logging**: Structured JSON logging

## 📁 Project Structure

```
hackai/
├── cmd/                    # Application entrypoints
│   ├── api-gateway/
│   ├── user-service/
│   ├── scanner-service/
│   └── ...
├── internal/               # Core application logic
│   ├── domain/            # Domain models and interfaces
│   ├── usecase/           # Business logic
│   ├── repository/        # Data access layer
│   └── handler/           # HTTP handlers
├── pkg/                   # Shared utilities
│   ├── auth/
│   ├── logger/
│   ├── middleware/
│   └── ...
├── api/                   # API definitions
│   ├── proto/             # gRPC definitions
│   └── openapi/           # REST API specs
├── web/                   # Frontend application
│   ├── src/
│   ├── components/
│   ├── pages/
│   └── ...
├── configs/               # Configuration files
├── deployments/           # Docker and deployment configs
├── docs/                  # Documentation
└── test/                  # Test utilities and integration tests
```

## 🚦 Getting Started

### Prerequisites
- Go 1.22+
- Node.js 18+
- Docker & Docker Compose
- PostgreSQL 15+
- Redis 7+

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/hackai.git
   cd hackai
   ```

2. **Start infrastructure services**
   ```bash
   docker-compose up -d postgres redis
   ```

3. **Run backend services**
   ```bash
   make run-services
   ```

4. **Start frontend development server**
   ```bash
   cd web
   npm install
   npm run dev
   ```

5. **Access the application**
   - Frontend: http://localhost:3000
   - API Gateway: http://localhost:8080
   - API Documentation: http://localhost:8080/docs

## 🧪 Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run integration tests
make test-integration

# Run frontend tests
cd web && npm test
```

## 📚 Documentation

- [API Documentation](./docs/api.md)
- [Architecture Guide](./docs/architecture.md)
- [Development Guide](./docs/development.md)
- [Deployment Guide](./docs/deployment.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔒 Security

This is an educational platform. Please review our [Security Policy](SECURITY.md) for responsible disclosure of security vulnerabilities.

## 📞 Support

- 📧 Email: support@hackai.dev
- 💬 Discord: [HackAI Community](https://discord.gg/hackai)
- 📖 Documentation: [docs.hackai.dev](https://docs.hackai.dev)

---

**⚠️ Educational Purpose**: This platform is designed for educational purposes to teach cybersecurity concepts. Always use responsibly and in accordance with applicable laws and regulations.
