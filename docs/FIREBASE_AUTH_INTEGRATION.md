# Firebase Authentication Integration

This document provides comprehensive guidance on the Firebase Authentication integration for the HackAI platform.

## Overview

The Firebase Auth integration provides a complete authentication solution that combines Firebase Authentication with the existing JWT-based system, offering:

- **Multi-provider authentication** (Email/Password, Google, GitHub)
- **Hybrid authentication** (Firebase + JWT)
- **Database synchronization** between Firebase and PostgreSQL
- **Role-based access control** with custom claims
- **Session management** and security features
- **Frontend React components** with TypeScript support

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend       │    │   Firebase      │
│   (React/Next)  │    │   (Go)          │    │   Auth          │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ • Auth Context  │◄──►│ • Firebase SDK  │◄──►│ • User Auth     │
│ • Login Forms   │    │ • Hybrid Auth   │    │ • Custom Claims │
│ • Protected     │    │ • Middleware    │    │ • Providers     │
│   Routes        │    │ • Sync Service  │    │ • Security      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                ▲
                                │
                                ▼
                       ┌─────────────────┐
                       │   PostgreSQL    │
                       │   Database      │
                       ├─────────────────┤
                       │ • User Profiles │
                       │ • Sessions      │
                       │ • Permissions   │
                       │ • Audit Logs    │
                       └─────────────────┘
```

## Setup Instructions

### 1. Firebase Project Setup

1. **Create Firebase Projects**:
   ```bash
   # Development
   firebase projects:create hackai-dev
   
   # Staging
   firebase projects:create hackai-staging
   
   # Production
   firebase projects:create hackai-prod
   ```

2. **Enable Authentication**:
   - Go to Firebase Console → Authentication → Sign-in method
   - Enable Email/Password, Google, GitHub providers
   - Configure OAuth settings for each provider

3. **Generate Service Account Keys**:
   - Go to Project Settings → Service Accounts
   - Generate private key for each environment
   - Save as `configs/firebase/service-accounts/hackai-{env}-service-account.json`

### 2. Backend Configuration

1. **Environment Variables**:
   ```bash
   # Add to .env file
   FIREBASE_API_KEY_DEV=your_dev_api_key
   FIREBASE_API_KEY_STAGING=your_staging_api_key
   FIREBASE_API_KEY_PROD=your_prod_api_key
   
   # OAuth Provider Settings
   GOOGLE_OAUTH_CLIENT_ID_DEV=your_google_client_id
   GOOGLE_OAUTH_CLIENT_SECRET_DEV=your_google_client_secret
   GITHUB_OAUTH_CLIENT_ID_DEV=your_github_client_id
   GITHUB_OAUTH_CLIENT_SECRET_DEV=your_github_client_secret
   ```

2. **Database Migration**:
   ```sql
   -- Add Firebase fields to users table
   ALTER TABLE users ADD COLUMN firebase_uid VARCHAR(255) UNIQUE;
   ALTER TABLE users ADD COLUMN display_name VARCHAR(255);
   ALTER TABLE users ADD COLUMN phone_number VARCHAR(50);
   ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT FALSE;
   ALTER TABLE users ADD COLUMN organization VARCHAR(255);
   
   -- Create index for Firebase UID
   CREATE INDEX idx_users_firebase_uid ON users(firebase_uid);
   ```

3. **Start Firebase Auth Service**:
   ```bash
   # Build the service
   go build -o bin/firebase-auth-service cmd/firebase-auth-service/main.go
   
   # Run the service
   ENVIRONMENT=development ./bin/firebase-auth-service
   ```

### 3. Frontend Configuration

1. **Environment Variables**:
   ```bash
   # Add to web/.env.local
   NEXT_PUBLIC_FIREBASE_API_KEY_DEV=your_dev_api_key
   NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN_DEV=hackai-dev.firebaseapp.com
   NEXT_PUBLIC_FIREBASE_PROJECT_ID_DEV=hackai-dev
   # ... other Firebase config
   ```

2. **Add Firebase Provider to App**:
   ```tsx
   // pages/_app.tsx or app/layout.tsx
   import { FirebaseAuthProvider } from '@/contexts/FirebaseAuthContext'
   
   export default function App({ Component, pageProps }) {
     return (
       <FirebaseAuthProvider>
         <Component {...pageProps} />
       </FirebaseAuthProvider>
     )
   }
   ```

## Usage Examples

### Backend Usage

#### 1. Basic Firebase Service Usage

```go
package main

import (
    "context"
    "github.com/dimajoyti/hackai/pkg/firebase"
    "github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
    // Load configuration
    config, err := firebase.LoadConfig("configs/firebase/firebase-config.yaml", "development")
    if err != nil {
        panic(err)
    }
    
    // Initialize service
    logger := logger.New(logger.Config{Level: "info"})
    service, err := firebase.NewService(config, logger, userRepo)
    if err != nil {
        panic(err)
    }
    
    // Create user
    req := &firebase.CreateUserRequest{
        Email:       "user@example.com",
        Password:    "securePassword123",
        DisplayName: "John Doe",
        Username:    "johndoe",
        Role:        "user",
    }
    
    user, err := service.CreateUser(context.Background(), req)
    if err != nil {
        panic(err)
    }
    
    // Set custom claims
    claims := map[string]interface{}{
        "role":         "user",
        "organization": "hackai",
        "permissions":  []string{"read", "write"},
    }
    
    err = service.SetCustomUserClaims(context.Background(), user.UID, claims)
    if err != nil {
        panic(err)
    }
}
```

#### 2. Hybrid Authentication

```go
// Initialize hybrid auth service
hybridAuth := firebase.NewHybridAuthService(
    firebaseService,
    jwtService,
    enhancedAuth,
    logger,
    config,
)

// Authenticate with Firebase token
req := &firebase.HybridAuthRequest{
    FirebaseIDToken: "firebase_id_token_here",
    IPAddress:       "192.168.1.1",
    UserAgent:       "Mozilla/5.0...",
    RememberMe:      true,
}

response, err := hybridAuth.Authenticate(context.Background(), req)
if err != nil {
    // Handle error
}

// Use the response
fmt.Printf("User: %s, Token: %s", response.User.Email, response.AccessToken)
```

#### 3. Middleware Usage

```go
// Setup router with Firebase middleware
router := mux.NewRouter()
middleware := firebase.NewMiddleware(firebaseService, logger)

// Protected routes
protected := router.PathPrefix("/api/protected").Subrouter()
protected.Use(middleware.AuthRequired)

// Admin routes
admin := router.PathPrefix("/api/admin").Subrouter()
admin.Use(middleware.AuthRequired)
admin.Use(middleware.RequireRole("admin"))

// Role-specific routes
moderator := router.PathPrefix("/api/moderator").Subrouter()
moderator.Use(middleware.AuthRequired)
moderator.Use(middleware.RequireRole("admin", "moderator"))
```

### Frontend Usage

#### 1. Authentication Context

```tsx
import { useFirebaseAuth } from '@/contexts/FirebaseAuthContext'

function LoginPage() {
  const { signIn, signInWithGoogle, loading, user } = useFirebaseAuth()
  
  const handleEmailLogin = async (email: string, password: string) => {
    const result = await signIn(email, password)
    if (result.error) {
      console.error('Login failed:', result.error)
    } else {
      console.log('Login successful:', result.user)
    }
  }
  
  const handleGoogleLogin = async () => {
    const result = await signInWithGoogle()
    if (result.error) {
      console.error('Google login failed:', result.error)
    }
  }
  
  if (loading) return <div>Loading...</div>
  if (user) return <div>Welcome, {user.displayName}!</div>
  
  return (
    <div>
      <button onClick={() => handleEmailLogin('user@example.com', 'password')}>
        Sign In with Email
      </button>
      <button onClick={handleGoogleLogin}>
        Sign In with Google
      </button>
    </div>
  )
}
```

#### 2. Protected Routes

```tsx
import { ProtectedRoute } from '@/components/auth/ProtectedRoute'

function Dashboard() {
  return (
    <ProtectedRoute requireEmailVerification={true}>
      <div>
        <h1>Dashboard</h1>
        <p>This content is only visible to authenticated users with verified emails.</p>
      </div>
    </ProtectedRoute>
  )
}

// Admin-only content
function AdminPanel() {
  return (
    <ProtectedRoute requiredRoles={['admin']}>
      <div>
        <h1>Admin Panel</h1>
        <p>This content is only visible to administrators.</p>
      </div>
    </ProtectedRoute>
  )
}
```

#### 3. Using Firebase Components

```tsx
import { FirebaseLoginForm } from '@/components/auth/FirebaseLoginForm'
import { FirebaseSignupForm } from '@/components/auth/FirebaseSignupForm'

function AuthPage() {
  const [isLogin, setIsLogin] = useState(true)
  
  return (
    <div>
      {isLogin ? (
        <FirebaseLoginForm
          onSuccess={() => router.push('/dashboard')}
          redirectTo="/dashboard"
        />
      ) : (
        <FirebaseSignupForm
          onSuccess={() => router.push('/dashboard')}
          redirectTo="/dashboard"
        />
      )}
      
      <button onClick={() => setIsLogin(!isLogin)}>
        {isLogin ? 'Need an account? Sign up' : 'Have an account? Sign in'}
      </button>
    </div>
  )
}
```

## API Endpoints

### Authentication Endpoints

- `POST /auth/firebase/verify` - Verify Firebase ID token
- `POST /auth/firebase/custom-token` - Create custom Firebase token
- `POST /auth/firebase/revoke-tokens` - Revoke user refresh tokens

### User Management Endpoints

- `POST /firebase/users` - Create Firebase user
- `GET /firebase/users` - List Firebase users
- `GET /firebase/users/{uid}` - Get Firebase user by UID
- `PUT /firebase/users/{uid}` - Update Firebase user
- `DELETE /firebase/users/{uid}` - Delete Firebase user
- `POST /firebase/users/{uid}/claims` - Set custom claims
- `GET /firebase/users/email/{email}` - Get user by email

### Sync Endpoints

- `POST /firebase/sync/user/{uid}/to-database` - Sync Firebase user to database
- `POST /firebase/sync/user/{user_id}/to-firebase` - Sync database user to Firebase
- `POST /firebase/sync/batch/to-firebase` - Batch sync users to Firebase

### Admin Endpoints

- `GET /firebase/admin/health` - Health check
- `GET /firebase/admin/metrics` - Service metrics

## Security Considerations

1. **Service Account Security**:
   - Never commit service account JSON files to version control
   - Use environment variables or secure secret management
   - Rotate service account keys regularly

2. **Token Validation**:
   - Always verify Firebase ID tokens on the backend
   - Implement proper token expiration handling
   - Use HTTPS for all authentication endpoints

3. **Custom Claims**:
   - Validate custom claims on the backend
   - Don't trust client-side role information
   - Implement proper authorization checks

4. **Database Security**:
   - Use prepared statements to prevent SQL injection
   - Implement proper access controls
   - Audit user actions and changes

## Troubleshooting

### Common Issues

1. **Firebase Token Verification Fails**:
   ```
   Error: failed to verify ID token
   ```
   - Check service account configuration
   - Verify Firebase project ID
   - Ensure token is not expired

2. **Database Sync Issues**:
   ```
   Error: failed to sync user to database
   ```
   - Check database connection
   - Verify user table schema
   - Check for unique constraint violations

3. **CORS Issues**:
   ```
   Error: CORS policy blocked
   ```
   - Configure CORS in the backend service
   - Add frontend domain to allowed origins
   - Check preflight request handling

### Debug Mode

Enable debug logging:

```bash
# Backend
ENVIRONMENT=development LOG_LEVEL=debug ./bin/firebase-auth-service

# Frontend
NEXT_PUBLIC_DEBUG=true npm run dev
```

## Testing

Run the test suite:

```bash
# Backend tests
go test ./pkg/firebase/...

# Frontend tests
cd web && npm test

# Integration tests
go test ./test/integration/firebase/...
```

## Migration Guide

For existing applications, follow these steps:

1. **Backup existing data**
2. **Run database migrations**
3. **Configure Firebase projects**
4. **Update environment variables**
5. **Deploy backend services**
6. **Update frontend components**
7. **Test authentication flows**
8. **Monitor for issues**

## Support

For issues and questions:

- Check the [troubleshooting section](#troubleshooting)
- Review Firebase documentation
- Check application logs
- Contact the development team
