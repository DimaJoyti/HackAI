# HackAI Firebase Auth - Production Deployment Guide

This guide provides comprehensive instructions for deploying the HackAI Firebase Authentication system to production.

## Prerequisites

### Required Tools
- [x] Firebase CLI (`npm install -g firebase-tools`)
- [x] Node.js 18+ and npm
- [x] Go 1.21+
- [x] Docker (optional, for containerized deployment)
- [x] Git

### Required Accounts & Access
- [x] Firebase project with billing enabled
- [x] Google Cloud Platform project
- [x] Domain name (for custom domain)
- [x] SSL certificates (if using custom domain)

## Pre-Deployment Checklist

### 1. Environment Configuration
- [ ] Update `.env.production` with production values
- [ ] Configure Firebase service account credentials
- [ ] Set up OAuth provider credentials (Google, GitHub)
- [ ] Configure custom domain settings
- [ ] Set up monitoring and alerting endpoints

### 2. Security Review
- [ ] Review and update Firestore security rules
- [ ] Review and update Storage security rules
- [ ] Configure CORS policies
- [ ] Set up rate limiting
- [ ] Enable Firebase App Check
- [ ] Configure Content Security Policy (CSP)
- [ ] Review authentication flow security

### 3. Testing
- [ ] Run all unit tests (`npm run test:ci`)
- [ ] Run integration tests with emulators
- [ ] Perform security testing
- [ ] Load testing (optional)
- [ ] Cross-browser testing

### 4. Backup & Recovery
- [ ] Set up automated backups for Firestore
- [ ] Document recovery procedures
- [ ] Test backup restoration process

## Deployment Steps

### Step 1: Prepare Environment

```bash
# Clone the repository
git clone https://github.com/DimaJoyti/HackAI.git
cd HackAI

# Make deployment script executable
chmod +x scripts/deploy-production.sh

# Check prerequisites
./scripts/deploy-production.sh check
```

### Step 2: Configure Production Environment

```bash
# Set up production environment variables
./scripts/deploy-production.sh env

# Update configuration files with production values
# Edit web/.env.production
# Edit configs/firebase/firebase-config-production.yaml
```

### Step 3: Build and Test

```bash
# Build and test the application
./scripts/deploy-production.sh build
```

### Step 4: Deploy Firebase Configuration

```bash
# Deploy Firebase rules and configuration
./scripts/deploy-production.sh firebase
```

### Step 5: Deploy Backend Service

```bash
# Deploy backend service (containerized)
./scripts/deploy-production.sh backend
```

### Step 6: Deploy Frontend

```bash
# Deploy frontend to Firebase Hosting
./scripts/deploy-production.sh frontend
```

### Step 7: Configure Security

```bash
# Apply security configurations
./scripts/deploy-production.sh security
```

### Step 8: Verify Deployment

```bash
# Verify all components are working
./scripts/deploy-production.sh verify
```

### Step 9: Complete Deployment

```bash
# Run complete deployment (all steps)
./scripts/deploy-production.sh all
```

## Post-Deployment Configuration

### 1. Custom Domain Setup (Optional)

1. **Add Custom Domain to Firebase Hosting:**
   ```bash
   firebase hosting:channel:deploy production --only hosting
   ```

2. **Configure DNS Records:**
   - Add A records pointing to Firebase Hosting IPs
   - Add CNAME record for www subdomain

3. **SSL Certificate:**
   - Firebase automatically provisions SSL certificates
   - Verify certificate is active

### 2. OAuth Provider Configuration

#### Google OAuth
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Navigate to APIs & Services > Credentials
3. Update authorized redirect URIs:
   - `https://hackai-auth-system.firebaseapp.com/__/auth/handler`
   - `https://yourdomain.com/__/auth/handler` (if using custom domain)

#### GitHub OAuth
1. Go to GitHub Settings > Developer settings > OAuth Apps
2. Update Authorization callback URL:
   - `https://hackai-auth-system.firebaseapp.com/__/auth/handler`

### 3. Monitoring Setup

#### Firebase Performance Monitoring
```bash
# Enable Performance Monitoring in Firebase Console
# Add performance monitoring to your app
```

#### Google Cloud Monitoring
```bash
# Set up alerting policies
# Configure notification channels
# Create custom dashboards
```

#### Error Reporting
```bash
# Enable Error Reporting in Google Cloud Console
# Configure error notifications
```

### 4. Security Configuration

#### Firebase App Check
1. Enable App Check in Firebase Console
2. Configure reCAPTCHA for web apps
3. Set enforcement mode to "Enforced"

#### Security Rules
```javascript
// Firestore Rules (firestore.rules)
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Users can only access their own data
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    
    // Admin-only collections
    match /admin/{document=**} {
      allow read, write: if request.auth != null && 
        request.auth.token.role == 'admin';
    }
  }
}
```

```javascript
// Storage Rules (storage.rules)
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    // Users can upload to their own folder
    match /users/{userId}/{allPaths=**} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

## Environment Variables

### Required Production Environment Variables

```bash
# Firebase Configuration
FIREBASE_PROJECT_ID=hackai-auth-system
FIREBASE_CLIENT_EMAIL=firebase-adminsdk-xxxxx@hackai-auth-system.iam.gserviceaccount.com
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"

# OAuth Providers
GOOGLE_OAUTH_CLIENT_ID=xxxxx.apps.googleusercontent.com
GOOGLE_OAUTH_CLIENT_SECRET=xxxxx
GITHUB_OAUTH_CLIENT_ID=xxxxx
GITHUB_OAUTH_CLIENT_SECRET=xxxxx

# Monitoring
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxxxx
SENTRY_DSN=https://xxxxx@sentry.io/xxxxx

# API Keys
NEXT_PUBLIC_GOOGLE_ANALYTICS_ID=G-XXXXXXXXXX
```

## Monitoring and Maintenance

### Health Checks
- **Frontend:** `https://yourdomain.com/health`
- **Backend:** `https://auth.hackai.com/health`
- **Firebase:** Monitor in Firebase Console

### Key Metrics to Monitor
- Authentication success/failure rates
- API response times
- Error rates
- User registration trends
- Security incidents

### Regular Maintenance Tasks
- [ ] Review security logs weekly
- [ ] Update dependencies monthly
- [ ] Review and rotate API keys quarterly
- [ ] Backup verification monthly
- [ ] Performance optimization quarterly

## Troubleshooting

### Common Issues

#### 1. Authentication Failures
```bash
# Check Firebase Auth configuration
firebase auth:export users.json

# Verify OAuth provider settings
# Check redirect URIs
# Verify API keys
```

#### 2. CORS Issues
```bash
# Update CORS configuration in firebase.json
# Verify allowed origins
# Check preflight requests
```

#### 3. Performance Issues
```bash
# Check Firebase Performance Monitoring
# Review Cloud Monitoring metrics
# Analyze slow queries
```

### Support Contacts
- **Development Team:** dev@hackai.com
- **Security Team:** security@hackai.com
- **Operations Team:** ops@hackai.com

## Rollback Procedures

### Emergency Rollback
```bash
# Rollback to previous Firebase Hosting deployment
firebase hosting:channel:deploy previous --only hosting

# Rollback backend service
docker pull gcr.io/hackai-auth-system/hackai-auth-backend:previous
# Redeploy previous version

# Rollback Firebase rules
git checkout HEAD~1 firestore.rules storage.rules
firebase deploy --only firestore:rules,storage:rules
```

### Planned Rollback
1. Notify users of maintenance window
2. Stop new user registrations (optional)
3. Deploy previous version
4. Verify functionality
5. Resume normal operations

## Security Considerations

### Data Protection
- All data encrypted in transit and at rest
- PII handling complies with GDPR/CCPA
- Regular security audits
- Incident response plan in place

### Access Control
- Principle of least privilege
- Regular access reviews
- Multi-factor authentication for admin accounts
- Audit logging for all administrative actions

### Compliance
- SOC 2 Type II compliance
- GDPR compliance
- Regular penetration testing
- Security awareness training

---

**Last Updated:** $(date)
**Version:** 1.0.0
**Maintained By:** HackAI Development Team
