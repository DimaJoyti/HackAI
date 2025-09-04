# 🔐 HackAI Security API Documentation

## Overview

The HackAI Security API provides comprehensive authentication, authorization, and security management capabilities. This documentation covers all security-related endpoints, authentication methods, and security features.

## 🔑 Authentication

### JWT Token Authentication

All protected endpoints require JWT token authentication. Include the token in the Authorization header:

```http
Authorization: Bearer <your-jwt-token>
```

### Token Types

- **Access Token**: Short-lived token (15 minutes) for API access
- **Refresh Token**: Long-lived token (24 hours) for obtaining new access tokens

## 📋 Table of Contents

- [Authentication Endpoints](#authentication-endpoints)
- [User Management](#user-management)
- [Session Management](#session-management)
- [Security Policies](#security-policies)
- [Audit and Monitoring](#audit-and-monitoring)
- [Device Management](#device-management)
- [Multi-Factor Authentication](#multi-factor-authentication)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)

## 🔐 Authentication Endpoints

### POST /api/v1/auth/login

Authenticate user and receive JWT tokens.

**Request Body:**
```json
{
  "email_or_username": "user@example.com",
  "password": "SecurePassword123!",
  "mfa_code": "123456",
  "device_id": "optional-device-id",
  "ip_address": "192.168.1.1",
  "user_agent": "Mozilla/5.0...",
  "remember_me": false,
  "trust_device": false
}
```

**Response (Success):**
```json
{
  "success": true,
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "session_id": "sess_123456789",
  "expires_at": "2024-01-01T15:00:00Z",
  "requires_mfa": false,
  "user": {
    "id": "user_123",
    "username": "johndoe",
    "email": "user@example.com",
    "role": "user",
    "permissions": ["read:profile", "write:profile"],
    "last_login_at": "2024-01-01T14:00:00Z",
    "mfa_enabled": true
  },
  "threat_score": 0.1
}
```

**Response (MFA Required):**
```json
{
  "success": false,
  "requires_mfa": true,
  "mfa_methods": ["totp", "email", "backup_codes"],
  "error": "Multi-factor authentication required."
}
```

**Response (Error):**
```json
{
  "success": false,
  "error": "Invalid credentials.",
  "threat_score": 0.8
}
```

### POST /api/v1/auth/refresh

Refresh access token using refresh token.

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_at": "2024-01-01T15:15:00Z"
}
```

### POST /api/v1/auth/logout

Terminate user session.

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "message": "Logged out successfully"
}
```

### POST /api/v1/auth/validate

Validate access token.

**Request Body:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response:**
```json
{
  "valid": true,
  "user_id": "user_123",
  "username": "johndoe",
  "email": "user@example.com",
  "role": "user",
  "permissions": ["read:profile", "write:profile"],
  "claims": {
    "user_id": "user_123",
    "username": "johndoe",
    "email": "user@example.com",
    "role": "user",
    "session_id": "sess_123456789",
    "scopes": ["read", "write"],
    "iss": "hackai-auth-service",
    "aud": "hackai-users",
    "exp": 1704117600,
    "iat": 1704116700
  }
}
```

## 👤 User Management

### GET /api/v1/users/profile

Get current user profile.

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "id": "user_123",
  "username": "johndoe",
  "email": "user@example.com",
  "role": "user",
  "permissions": ["read:profile", "write:profile"],
  "is_active": true,
  "is_locked": false,
  "mfa_enabled": true,
  "trusted_devices": ["device_1", "device_2"],
  "created_at": "2023-01-01T00:00:00Z",
  "updated_at": "2024-01-01T12:00:00Z",
  "last_login_at": "2024-01-01T14:00:00Z",
  "last_login_ip": "192.168.1.1"
}
```

### PUT /api/v1/users/profile

Update current user profile.

**Headers:**
```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "username": "newusername",
  "email": "newemail@example.com"
}
```

**Response:**
```json
{
  "message": "Profile updated successfully",
  "user": {
    "id": "user_123",
    "username": "newusername",
    "email": "newemail@example.com",
    "updated_at": "2024-01-01T15:00:00Z"
  }
}
```

### POST /api/v1/users/change-password

Change user password.

**Headers:**
```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "current_password": "CurrentPassword123!",
  "new_password": "NewPassword456!",
  "confirm_password": "NewPassword456!"
}
```

**Response:**
```json
{
  "message": "Password changed successfully"
}
```

## 📱 Session Management

### GET /api/v1/sessions

Get user sessions.

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "sessions": [
    {
      "id": "sess_123456789",
      "device_id": "device_1",
      "ip_address": "192.168.1.1",
      "user_agent": "Mozilla/5.0...",
      "created_at": "2024-01-01T14:00:00Z",
      "last_activity": "2024-01-01T14:30:00Z",
      "expires_at": "2024-01-02T14:00:00Z",
      "is_active": true,
      "mfa_verified": true,
      "is_current": true
    }
  ]
}
```

### DELETE /api/v1/sessions/{session_id}

Terminate specific session.

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "message": "Session terminated successfully"
}
```

### DELETE /api/v1/sessions/all

Terminate all user sessions except current.

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "message": "All other sessions terminated successfully",
  "terminated_count": 3
}
```

## 🔐 Multi-Factor Authentication

### POST /api/v1/mfa/setup

Setup TOTP-based MFA.

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code_url": "otpauth://totp/HackAI:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=HackAI",
  "backup_codes": [
    "12345678",
    "87654321",
    "11223344"
  ]
}
```

### POST /api/v1/mfa/verify

Verify and enable MFA.

**Headers:**
```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "code": "123456"
}
```

**Response:**
```json
{
  "message": "MFA enabled successfully",
  "backup_codes": [
    "12345678",
    "87654321",
    "11223344"
  ]
}
```

### POST /api/v1/mfa/disable

Disable MFA.

**Headers:**
```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "password": "CurrentPassword123!",
  "code": "123456"
}
```

**Response:**
```json
{
  "message": "MFA disabled successfully"
}
```

### POST /api/v1/mfa/regenerate-backup-codes

Regenerate backup codes.

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "backup_codes": [
    "98765432",
    "23456789",
    "34567890"
  ]
}
```

## 📱 Device Management

### GET /api/v1/devices

Get user devices.

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "devices": [
    {
      "id": "device_1",
      "name": "iPhone",
      "type": "mobile",
      "os": "iOS",
      "browser": "Safari",
      "ip_address": "192.168.1.100",
      "is_trusted": true,
      "is_approved": true,
      "first_seen": "2023-12-01T10:00:00Z",
      "last_seen": "2024-01-01T14:30:00Z",
      "login_count": 45
    }
  ]
}
```

### POST /api/v1/devices/{device_id}/trust

Trust a device.

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "message": "Device trusted successfully"
}
```

### DELETE /api/v1/devices/{device_id}/trust

Remove device trust.

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "message": "Device trust removed successfully"
}
```

## 🛡️ Security Policies

### GET /api/v1/security/policies

Get security policies (Admin only).

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "policies": [
    {
      "id": "policy_1",
      "name": "Password Policy",
      "type": "password",
      "rules": {
        "min_length": 8,
        "require_uppercase": true,
        "require_lowercase": true,
        "require_numbers": true,
        "require_special_chars": true,
        "password_history_count": 5,
        "password_expiry": "90d"
      },
      "enabled": true,
      "created_at": "2023-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### PUT /api/v1/security/policies/{policy_id}

Update security policy (Admin only).

**Headers:**
```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "rules": {
    "min_length": 12,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_numbers": true,
    "require_special_chars": true,
    "password_history_count": 10,
    "password_expiry": "60d"
  },
  "enabled": true
}
```

**Response:**
```json
{
  "message": "Policy updated successfully",
  "policy": {
    "id": "policy_1",
    "name": "Password Policy",
    "type": "password",
    "rules": {
      "min_length": 12,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_numbers": true,
      "require_special_chars": true,
      "password_history_count": 10,
      "password_expiry": "60d"
    },
    "enabled": true,
    "updated_at": "2024-01-01T15:00:00Z"
  }
}
```

## 📊 Audit and Monitoring

### GET /api/v1/security/events

Get security events (Admin only).

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Query Parameters:**
- `limit` (optional): Number of events to return (default: 50, max: 1000)
- `offset` (optional): Number of events to skip (default: 0)
- `type` (optional): Filter by event type
- `user_id` (optional): Filter by user ID
- `severity` (optional): Filter by severity (info, warning, critical)
- `start_date` (optional): Filter events after this date (ISO 8601)
- `end_date` (optional): Filter events before this date (ISO 8601)

**Response:**
```json
{
  "events": [
    {
      "id": "event_123",
      "type": "login_success",
      "user_id": "user_123",
      "session_id": "sess_123456789",
      "ip_address": "192.168.1.1",
      "user_agent": "Mozilla/5.0...",
      "timestamp": "2024-01-01T14:00:00Z",
      "severity": "info",
      "description": "User logged in successfully",
      "threat_score": 0.1,
      "metadata": {
        "device_id": "device_1",
        "mfa_verified": true
      },
      "resolved": false
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

### GET /api/v1/security/metrics

Get security metrics (Admin only).

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "metrics": {
    "total_users": 1250,
    "active_sessions": 89,
    "failed_logins_24h": 23,
    "successful_logins_24h": 456,
    "mfa_enabled_users": 892,
    "locked_accounts": 5,
    "high_threat_events_24h": 3,
    "average_threat_score": 0.15
  },
  "generated_at": "2024-01-01T15:00:00Z"
}
```

## ❌ Error Handling

### Error Response Format

All API errors follow a consistent format:

```json
{
  "error": "Error message",
  "code": 400,
  "path": "/api/v1/auth/login",
  "method": "POST",
  "timestamp": "2024-01-01T15:00:00Z",
  "request_id": "req_123456789"
}
```

### Common Error Codes

| Code | Description | Common Causes |
|------|-------------|---------------|
| 400 | Bad Request | Invalid request body, missing required fields |
| 401 | Unauthorized | Invalid or expired token, authentication required |
| 403 | Forbidden | Insufficient permissions, account locked |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists, conflicting operation |
| 422 | Unprocessable Entity | Validation errors, policy violations |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error, contact support |

## 🚦 Rate Limiting

### Rate Limit Headers

All responses include rate limiting headers:

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1704117600
X-RateLimit-Window: 60
```

### Rate Limits by Endpoint

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/api/v1/auth/login` | 5 requests | 15 minutes |
| `/api/v1/auth/refresh` | 10 requests | 1 hour |
| `/api/v1/mfa/*` | 5 requests | 5 minutes |
| Other endpoints | 100 requests | 1 minute |

### Rate Limit Exceeded Response

```json
{
  "error": "Rate limit exceeded. Please try again later.",
  "code": 429,
  "retry_after": 900,
  "timestamp": "2024-01-01T15:00:00Z"
}
```

## 🔒 Security Best Practices

### Token Security
- Store tokens securely (never in localStorage for web apps)
- Use HTTPS for all API communications
- Implement proper token refresh logic
- Handle token expiration gracefully

### Password Security
- Enforce strong password policies
- Implement password history checking
- Use secure password reset flows
- Enable MFA for enhanced security

### Session Security
- Implement session timeout
- Monitor for concurrent sessions
- Log security events for audit
- Use device fingerprinting for additional security

### API Security
- Validate all input data
- Implement proper error handling
- Use rate limiting to prevent abuse
- Monitor for suspicious activity

## 📚 Additional Resources

- [Security Architecture Guide](../architecture/SECURITY_ARCHITECTURE.md)
- [Authentication Flow Diagrams](../diagrams/auth_flows.md)
- [Security Configuration Guide](../configuration/SECURITY_CONFIG.md)
- [Troubleshooting Guide](../troubleshooting/SECURITY_TROUBLESHOOTING.md)

## 🆘 Support

For security-related issues or questions:
- Email: security@hackai.com
- Documentation: https://docs.hackai.com/security
- GitHub Issues: https://github.com/hackai/security/issues
