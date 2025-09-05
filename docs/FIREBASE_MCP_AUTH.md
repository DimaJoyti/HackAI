# Firebase MCP Authentication System

A comprehensive, production-ready authentication system built with Firebase MCP (Model Context Protocol) integration, featuring advanced Google OAuth, role-based access control (RBAC), and enterprise-grade security.

## 🚀 Features

### Core Authentication
- **Firebase MCP Integration**: Direct integration with Firebase MCP tools for seamless authentication
- **Advanced Google OAuth**: Enhanced Google authentication with custom scopes and offline access
- **Multi-Provider Support**: Google, GitHub, and email/password authentication
- **Token Management**: JWT token validation, refresh, and revocation
- **Session Management**: Comprehensive session tracking and invalidation

### Security & Authorization
- **Role-Based Access Control (RBAC)**: Granular permission system with hierarchical roles
- **Security Middleware**: Rate limiting, CSRF protection, and security headers
- **Custom Validators**: Extensible token validation with custom business logic
- **Audit Logging**: Comprehensive audit trails for all authentication events
- **Security Headers**: OWASP-compliant security headers and policies

### User Management
- **Profile Management**: Complete user profile system with Google sync
- **User Preferences**: Customizable user settings and preferences
- **Account Status**: User activation, suspension, and soft deletion
- **Metadata Tracking**: Login history, IP tracking, and device information

### Developer Experience
- **Comprehensive Testing**: Unit, integration, and end-to-end tests
- **Type Safety**: Full TypeScript support with proper type definitions
- **Documentation**: Extensive documentation and code examples
- **Monitoring**: Built-in observability with OpenTelemetry support

## 🏗️ Architecture

### Backend Components

```
pkg/firebase/
├── config.go              # Firebase configuration management
├── service.go              # Core Firebase service
├── mcp_service.go          # Firebase MCP integration
├── mcp_integration.go      # MCP tools integration
├── mcp_handlers.go         # HTTP handlers for MCP operations
├── profile_service.go      # User profile management
├── rbac_service.go         # Role-based access control
├── profile_handlers.go     # Profile HTTP handlers
└── types.go               # Type definitions

pkg/middleware/
├── auth_middleware.go      # Authentication middleware
├── security_middleware.go  # Security middleware
├── firebase_mcp_middleware.go # Complete middleware stack
└── middleware.go          # Base middleware utilities

cmd/
├── firebase-mcp-server/   # Firebase MCP server
└── auth-server/           # Authentication server
```

### Frontend Components

```
web/src/
├── lib/firebase.ts        # Firebase client configuration
├── contexts/
│   ├── FirebaseAuthContext.tsx      # Basic auth context
│   └── AdvancedFirebaseAuthContext.tsx # Advanced auth context
├── components/auth/
│   ├── LoginForm.tsx               # Basic login form
│   ├── AdvancedGoogleLoginForm.tsx # Advanced Google login
│   ├── UserProfileManager.tsx      # Profile management
│   └── AuthDashboard.tsx          # Authentication dashboard
└── app/auth/
    └── dashboard/page.tsx         # Dashboard page
```

## 🛠️ Installation & Setup

### Prerequisites

- Go 1.21+
- Node.js 18+
- Firebase project with Authentication enabled
- Google OAuth 2.0 credentials

### Backend Setup

1. **Clone and install dependencies:**
```bash
git clone <repository-url>
cd hackai
make deps
```

2. **Configure Firebase:**
```bash
# Copy example configuration
cp configs/firebase/config.example.yaml configs/firebase/config.yaml

# Edit configuration with your Firebase project details
vim configs/firebase/config.yaml
```

3. **Set environment variables:**
```bash
export FIREBASE_PROJECT_ID="your-project-id"
export GOOGLE_OAUTH_CLIENT_ID="your-client-id"
export GOOGLE_OAUTH_CLIENT_SECRET="your-client-secret"
export GOOGLE_APPLICATION_CREDENTIALS="./configs/firebase/service-account.json"
```

4. **Build and run:**
```bash
# Build all authentication components
make build-auth-all

# Run Firebase MCP server
make run-firebase-mcp

# Run authentication server
make run-auth-server
```

### Frontend Setup

1. **Install dependencies:**
```bash
cd web
npm install
```

2. **Configure Firebase:**
```bash
# Copy example configuration
cp .env.example .env.local

# Edit with your Firebase configuration
vim .env.local
```

3. **Run development server:**
```bash
npm run dev
```

## 🔧 Configuration

### Firebase Configuration

```yaml
# configs/firebase/config.yaml
firebase:
  project_id: "your-project-id"
  api_key: "your-api-key"
  auth_domain: "your-project.firebaseapp.com"
  storage_bucket: "your-project.appspot.com"
  messaging_sender_id: "123456789"
  app_id: "1:123456789:web:abcdef"

google_oauth:
  client_id: "your-google-client-id"
  client_secret: "your-google-client-secret"
  redirect_uri: "http://localhost:3000/auth/callback"
```

### Environment Variables

```bash
# Firebase Configuration
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_API_KEY=your-api-key
FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
FIREBASE_STORAGE_BUCKET=your-project.appspot.com

# Google OAuth
GOOGLE_OAUTH_CLIENT_ID=your-client-id
GOOGLE_OAUTH_CLIENT_SECRET=your-client-secret

# Server Configuration
PORT=8080
ENVIRONMENT=development

# Service Account
GOOGLE_APPLICATION_CREDENTIALS=./configs/firebase/service-account.json
```

## 🚀 Usage Examples

### Backend API Usage

#### Authenticate with Google
```bash
curl -X POST http://localhost:8080/api/firebase/auth/google \
  -H "Content-Type: application/json" \
  -d '{
    "id_token": "google_id_token_here",
    "scopes": ["openid", "email", "profile"]
  }'
```

#### Get User Profile
```bash
curl -X GET http://localhost:8080/api/firebase/profile/me \
  -H "Authorization: Bearer your_access_token"
```

#### Update User Profile
```bash
curl -X PUT http://localhost:8080/api/firebase/profile/me \
  -H "Authorization: Bearer your_access_token" \
  -H "Content-Type: application/json" \
  -d '{
    "display_name": "Updated Name",
    "photo_url": "https://example.com/photo.jpg"
  }'
```

### Frontend Usage

#### Basic Authentication
```typescript
import { useFirebaseAuth } from '@/contexts/FirebaseAuthContext'

function LoginComponent() {
  const { signInWithGoogle, user, loading } = useFirebaseAuth()

  const handleGoogleLogin = async () => {
    const result = await signInWithGoogle()
    if (result.error) {
      console.error('Login failed:', result.error)
    }
  }

  if (loading) return <div>Loading...</div>
  if (user) return <div>Welcome, {user.displayName}!</div>

  return (
    <button onClick={handleGoogleLogin}>
      Sign in with Google
    </button>
  )
}
```

#### Advanced Authentication with Custom Scopes
```typescript
import { useAdvancedFirebaseAuth } from '@/contexts/AdvancedFirebaseAuthContext'

function AdvancedLoginComponent() {
  const { signInWithGoogleAdvanced } = useAdvancedFirebaseAuth()

  const handleAdvancedLogin = async () => {
    const customScopes = [
      'https://www.googleapis.com/auth/calendar.readonly',
      'https://www.googleapis.com/auth/drive.readonly'
    ]
    
    const result = await signInWithGoogleAdvanced(customScopes)
    if (result.user) {
      console.log('Access token:', result.accessToken)
      console.log('Refresh token:', result.refreshToken)
    }
  }

  return (
    <button onClick={handleAdvancedLogin}>
      Sign in with Google (Advanced)
    </button>
  )
}
```

## 🧪 Testing

### Run All Tests
```bash
# Run all authentication tests
make test-auth-all

# Run specific test suites
make test-firebase-mcp      # Firebase MCP tests
make test-auth-middleware   # Middleware tests
make test-auth-integration  # Integration tests

# Run with coverage
make test-auth-coverage
```

### Test Categories

1. **Unit Tests**: Test individual components and functions
2. **Integration Tests**: Test component interactions
3. **End-to-End Tests**: Test complete authentication flows
4. **Security Tests**: Test security measures and vulnerabilities

## 🔒 Security Features

### Authentication Security
- **Token Validation**: Comprehensive JWT token validation
- **Token Refresh**: Automatic token refresh with configurable thresholds
- **Session Management**: Secure session tracking and invalidation
- **Multi-Factor Authentication**: Support for 2FA (configurable)

### Authorization Security
- **Role-Based Access Control**: Granular permission system
- **Custom Validators**: Extensible validation logic
- **Permission Inheritance**: Hierarchical permission system
- **Temporary Roles**: Time-limited role assignments

### Network Security
- **Rate Limiting**: Configurable rate limiting per endpoint
- **CSRF Protection**: Cross-site request forgery protection
- **Security Headers**: OWASP-compliant security headers
- **CORS Configuration**: Proper cross-origin resource sharing

### Data Security
- **Audit Logging**: Comprehensive audit trails
- **Data Encryption**: Encrypted sensitive data storage
- **PII Protection**: Personal information protection
- **Secure Defaults**: Security-first default configurations

## 📊 Monitoring & Observability

### Metrics
- Authentication success/failure rates
- Token refresh rates
- Session duration statistics
- API endpoint performance

### Logging
- Structured JSON logging
- Request/response logging
- Error tracking and alerting
- Security event logging

### Tracing
- OpenTelemetry integration
- Distributed tracing support
- Performance monitoring
- Dependency tracking

## 🚀 Deployment

### Docker Deployment
```bash
# Build Docker image
make docker-build

# Run with Docker Compose
docker-compose up -d
```

### Kubernetes Deployment
```bash
# Apply Kubernetes manifests
kubectl apply -f deployments/k8s/
```

### Firebase Hosting
```bash
# Deploy frontend to Firebase Hosting
cd web
npm run build
firebase deploy --only hosting
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the test examples
- Contact the development team

## 🔄 Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.
