# HackAI Architecture Documentation

## Overview

HackAI is an educational cybersecurity AI platform built with a microservices architecture using Go for the backend and React/Next.js for the frontend. The platform demonstrates AI-powered security tools and provides hands-on learning experiences.

## Architecture Principles

### Clean Architecture
- **Domain Layer**: Core business logic and entities
- **Use Case Layer**: Application-specific business rules
- **Interface Layer**: Controllers, presenters, and gateways
- **Infrastructure Layer**: External concerns (database, web, devices)

### Microservices Design
- **Single Responsibility**: Each service has a specific domain responsibility
- **Autonomous**: Services can be developed, deployed, and scaled independently
- **Decentralized**: No single point of failure
- **Fault Tolerant**: Graceful degradation when services fail

## System Components

### Backend Services

#### API Gateway (Port 8080)
- **Purpose**: Central entry point for all client requests
- **Responsibilities**:
  - Request routing and load balancing
  - Authentication and authorization
  - Rate limiting and throttling
  - Request/response transformation
  - Monitoring and logging
- **Technology**: Go with standard library HTTP server

#### User Service (Port 8081)
- **Purpose**: User management and authentication
- **Responsibilities**:
  - User registration and profile management
  - Authentication and session management
  - Role-based access control
  - User activity logging
- **Database**: PostgreSQL for user data
- **Cache**: Redis for sessions

#### Scanner Service (Port 8082)
- **Purpose**: Vulnerability scanning and assessment
- **Responsibilities**:
  - Web application security scanning
  - SSL/TLS configuration analysis
  - Directory and file enumeration
  - API endpoint discovery
- **AI Components**: Machine learning models for vulnerability detection

#### Network Service (Port 8083)
- **Purpose**: Network security analysis
- **Responsibilities**:
  - Port scanning and service detection
  - Network topology mapping
  - Traffic analysis and monitoring
  - Intrusion detection
- **Technology**: Custom network scanning engines

#### Threat Intelligence Service (Port 8084)
- **Purpose**: Threat data collection and analysis
- **Responsibilities**:
  - Threat feed aggregation
  - IOC (Indicators of Compromise) analysis
  - Threat correlation and scoring
  - Real-time threat updates
- **Data Sources**: External threat intelligence APIs

#### Log Analysis Service (Port 8085)
- **Purpose**: Log processing and analysis
- **Responsibilities**:
  - Log ingestion and parsing
  - Anomaly detection in logs
  - Security event correlation
  - Automated incident response
- **AI Components**: NLP models for log analysis

### Frontend Application

#### Next.js Web Application (Port 3000)
- **Purpose**: User interface and experience
- **Features**:
  - Real-time security dashboards
  - Interactive scanning interfaces
  - Educational modules and tutorials
  - Administrative panels
- **Technology**: React 18, Next.js 14, TypeScript, TailwindCSS

### Infrastructure Components

#### Database Layer
- **PostgreSQL**: Primary database for structured data
  - User accounts and profiles
  - Scan results and vulnerabilities
  - System configuration
  - Audit logs
- **Redis**: Caching and session storage
  - User sessions
  - Real-time data
  - Rate limiting counters

#### Observability Stack
- **Jaeger**: Distributed tracing
- **Prometheus**: Metrics collection
- **Grafana**: Visualization and alerting
- **Structured Logging**: JSON logs with correlation IDs

## Data Flow

### Authentication Flow
1. User submits credentials to API Gateway
2. Gateway forwards request to User Service
3. User Service validates credentials
4. JWT tokens generated and returned
5. Subsequent requests include JWT in Authorization header
6. Gateway validates JWT and extracts user context

### Scanning Flow
1. User initiates scan through web interface
2. Request routed through API Gateway to Scanner Service
3. Scanner Service validates request and creates scan job
4. Scan executed asynchronously with progress updates
5. Results stored in database
6. Real-time updates sent via WebSocket
7. Completed results available through API

### Real-time Updates
1. Services publish events to message queue
2. WebSocket handler subscribes to relevant events
3. Events pushed to connected clients
4. Frontend updates UI in real-time

## Security Architecture

### Authentication & Authorization
- **JWT Tokens**: Stateless authentication
- **Role-Based Access Control**: Admin, Moderator, User, Guest roles
- **Session Management**: Redis-backed sessions with expiration
- **API Key Authentication**: For service-to-service communication

### Data Protection
- **Encryption at Rest**: Database encryption
- **Encryption in Transit**: TLS 1.3 for all communications
- **Input Validation**: Comprehensive input sanitization
- **SQL Injection Prevention**: Parameterized queries

### Network Security
- **Rate Limiting**: Per-user and per-IP rate limits
- **CORS Configuration**: Strict cross-origin policies
- **Security Headers**: Comprehensive security headers
- **Firewall Rules**: Network-level access controls

## Scalability Considerations

### Horizontal Scaling
- **Stateless Services**: All services designed to be stateless
- **Load Balancing**: Multiple instances behind load balancers
- **Database Sharding**: Horizontal partitioning for large datasets
- **Caching Strategy**: Multi-level caching with Redis

### Performance Optimization
- **Connection Pooling**: Database connection management
- **Async Processing**: Background job processing
- **CDN Integration**: Static asset delivery
- **Database Indexing**: Optimized query performance

## Deployment Architecture

### Containerization
- **Docker**: All services containerized
- **Multi-stage Builds**: Optimized container images
- **Health Checks**: Container health monitoring
- **Resource Limits**: CPU and memory constraints

### Orchestration
- **Docker Compose**: Development environment
- **Kubernetes**: Production orchestration (future)
- **Service Discovery**: Automatic service registration
- **Configuration Management**: Environment-based config

## Monitoring & Observability

### Metrics Collection
- **Application Metrics**: Custom business metrics
- **Infrastructure Metrics**: System resource usage
- **Database Metrics**: Query performance and connections
- **Network Metrics**: Request rates and latencies

### Logging Strategy
- **Structured Logging**: JSON format with correlation IDs
- **Log Aggregation**: Centralized log collection
- **Log Retention**: Configurable retention policies
- **Security Logging**: Audit trail for security events

### Alerting
- **Threshold Alerts**: Metric-based alerting
- **Anomaly Detection**: ML-based anomaly alerts
- **Escalation Policies**: Multi-level alert escalation
- **Notification Channels**: Email, Slack, PagerDuty

## Development Workflow

### Code Organization
- **Domain-Driven Design**: Business domain separation
- **Clean Architecture**: Layered architecture pattern
- **Dependency Injection**: Explicit dependency management
- **Interface Segregation**: Small, focused interfaces

### Testing Strategy
- **Unit Tests**: Individual component testing
- **Integration Tests**: Service interaction testing
- **End-to-End Tests**: Full workflow testing
- **Performance Tests**: Load and stress testing

### CI/CD Pipeline
- **Automated Testing**: All tests run on commit
- **Code Quality**: Linting and static analysis
- **Security Scanning**: Vulnerability assessment
- **Automated Deployment**: Environment-specific deployments

## Future Enhancements

### Planned Features
- **Machine Learning Pipeline**: Advanced AI model training
- **Kubernetes Deployment**: Production-ready orchestration
- **Multi-tenancy**: Organization-based isolation
- **Advanced Analytics**: Predictive security analytics

### Scalability Improvements
- **Event Sourcing**: Event-driven architecture
- **CQRS**: Command Query Responsibility Segregation
- **Message Queues**: Asynchronous communication
- **Distributed Caching**: Multi-region caching

This architecture provides a solid foundation for a scalable, secure, and maintainable cybersecurity education platform while demonstrating modern software engineering practices.
