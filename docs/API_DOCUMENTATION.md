# 📚 HackAI - API Documentation

## Overview

HackAI provides a comprehensive RESTful API for cybersecurity education and AI-powered security tools. This documentation covers all available endpoints, authentication methods, request/response formats, and usage examples.

## 🔐 Authentication

### JWT Token Authentication

All API endpoints (except public ones) require JWT token authentication. Include the token in the Authorization header:

```http
Authorization: Bearer <your-jwt-token>
```

### Authentication Endpoints

#### POST /api/v1/auth/login
Authenticate user and receive JWT token.

**Request Body:**
```json
{
  "email_or_username": "user@example.com",
  "password": "SecurePassword123!",
  "remember_me": false,
  "device_id": "optional-device-id"
}
```

**Response:**
```json
{
  "user": {
    "id": "uuid",
    "username": "username",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "role": "user",
    "status": "active",
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z"
  },
  "access_token": "jwt-token-here",
  "refresh_token": "refresh-token-here",
  "expires_at": "2024-01-15T11:30:00Z",
  "session_id": "session-uuid",
  "requires_totp": false
}
```

#### POST /api/v1/auth/logout
Logout user and invalidate session.

**Headers:**
```http
Authorization: Bearer <jwt-token>
```

**Response:**
```json
{
  "message": "Successfully logged out"
}
```

#### POST /api/v1/auth/refresh
Refresh JWT token using refresh token.

**Request Body:**
```json
{
  "refresh_token": "refresh-token-here"
}
```

**Response:**
```json
{
  "access_token": "new-jwt-token",
  "expires_at": "2024-01-15T12:30:00Z"
}
```

#### POST /api/v1/auth/change-password
Change user password.

**Headers:**
```http
Authorization: Bearer <jwt-token>
```

**Request Body:**
```json
{
  "current_password": "CurrentPassword123!",
  "new_password": "NewPassword123!",
  "confirm_password": "NewPassword123!"
}
```

**Response:**
```json
{
  "message": "Password changed successfully"
}
```

#### POST /api/v1/auth/enable-totp
Enable Two-Factor Authentication.

**Headers:**
```http
Authorization: Bearer <jwt-token>
```

**Response:**
```json
{
  "secret": "base32-encoded-secret",
  "qr_code_url": "otpauth://totp/HackAI:user@example.com?secret=...",
  "backup_codes": ["code1", "code2", "..."]
}
```

#### POST /api/v1/auth/verify-totp
Verify TOTP code and complete 2FA setup.

**Headers:**
```http
Authorization: Bearer <jwt-token>
```

**Request Body:**
```json
{
  "totp_code": "123456"
}
```

**Response:**
```json
{
  "message": "TOTP verified and enabled successfully"
}
```

## 👥 User Management

#### GET /api/v1/users/profile
Get current user profile.

**Headers:**
```http
Authorization: Bearer <jwt-token>
```

**Response:**
```json
{
  "id": "uuid",
  "username": "username",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "role": "user",
  "status": "active",
  "preferences": {
    "theme": "dark",
    "notifications": true
  },
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z",
  "last_login": "2024-01-15T10:30:00Z"
}
```

#### PUT /api/v1/users/profile
Update user profile.

**Headers:**
```http
Authorization: Bearer <jwt-token>
```

**Request Body:**
```json
{
  "first_name": "John",
  "last_name": "Doe",
  "preferences": {
    "theme": "dark",
    "notifications": true
  }
}
```

**Response:**
```json
{
  "message": "Profile updated successfully",
  "user": {
    // Updated user object
  }
}
```

#### GET /api/v1/users/activity
Get user activity history.

**Headers:**
```http
Authorization: Bearer <jwt-token>
```

**Query Parameters:**
- `limit` (optional): Number of records to return (default: 50, max: 100)
- `offset` (optional): Number of records to skip (default: 0)

**Response:**
```json
{
  "activities": [
    {
      "id": "uuid",
      "action": "login",
      "resource": "authentication",
      "details": {
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0..."
      },
      "timestamp": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 150,
  "limit": 50,
  "offset": 0
}
```

## 🔍 Security Scanning

#### POST /api/v1/scans/vulnerability
Start vulnerability scan.

**Headers:**
```http
Authorization: Bearer <jwt-token>
```

**Request Body:**
```json
{
  "target": "192.168.1.100",
  "scan_type": "comprehensive",
  "options": {
    "port_range": "1-1000",
    "aggressive": false,
    "stealth": true
  }
}
```

**Response:**
```json
{
  "scan_id": "uuid",
  "status": "started",
  "target": "192.168.1.100",
  "scan_type": "comprehensive",
  "started_at": "2024-01-15T10:30:00Z",
  "estimated_duration": "15m"
}
```

#### GET /api/v1/scans/{scan_id}
Get scan status and results.

**Headers:**
```http
Authorization: Bearer <jwt-token>
```

**Response:**
```json
{
  "scan_id": "uuid",
  "status": "completed",
  "target": "192.168.1.100",
  "scan_type": "comprehensive",
  "started_at": "2024-01-15T10:30:00Z",
  "completed_at": "2024-01-15T10:45:00Z",
  "duration": "15m",
  "results": {
    "vulnerabilities": [
      {
        "id": "CVE-2024-0001",
        "severity": "high",
        "title": "Remote Code Execution",
        "description": "...",
        "affected_service": "SSH",
        "port": 22,
        "remediation": "Update to latest version"
      }
    ],
    "open_ports": [22, 80, 443],
    "services": [
      {
        "port": 22,
        "service": "SSH",
        "version": "OpenSSH 7.4"
      }
    ]
  }
}
```

#### GET /api/v1/scans
List user's scans.

**Headers:**
```http
Authorization: Bearer <jwt-token>
```

**Query Parameters:**
- `status` (optional): Filter by status (pending, running, completed, failed)
- `limit` (optional): Number of records to return (default: 20, max: 100)
- `offset` (optional): Number of records to skip (default: 0)

**Response:**
```json
{
  "scans": [
    {
      "scan_id": "uuid",
      "target": "192.168.1.100",
      "scan_type": "comprehensive",
      "status": "completed",
      "started_at": "2024-01-15T10:30:00Z",
      "completed_at": "2024-01-15T10:45:00Z",
      "vulnerability_count": 3
    }
  ],
  "total": 25,
  "limit": 20,
  "offset": 0
}
```

## 🌐 Network Analysis

#### POST /api/v1/network/analyze
Analyze network traffic.

**Headers:**
```http
Authorization: Bearer <jwt-token>
```

**Request Body:**
```json
{
  "interface": "eth0",
  "duration": "5m",
  "filters": {
    "protocol": "tcp",
    "port": 80
  }
}
```

**Response:**
```json
{
  "analysis_id": "uuid",
  "status": "started",
  "interface": "eth0",
  "duration": "5m",
  "started_at": "2024-01-15T10:30:00Z"
}
```

#### GET /api/v1/network/analysis/{analysis_id}
Get network analysis results.

**Headers:**
```http
Authorization: Bearer <jwt-token>
```

**Response:**
```json
{
  "analysis_id": "uuid",
  "status": "completed",
  "interface": "eth0",
  "duration": "5m",
  "started_at": "2024-01-15T10:30:00Z",
  "completed_at": "2024-01-15T10:35:00Z",
  "results": {
    "total_packets": 15420,
    "protocols": {
      "tcp": 12000,
      "udp": 3000,
      "icmp": 420
    },
    "top_destinations": [
      {
        "ip": "8.8.8.8",
        "packets": 500,
        "bytes": 125000
      }
    ],
    "suspicious_activity": [
      {
        "type": "port_scan",
        "source": "192.168.1.200",
        "target": "192.168.1.100",
        "severity": "medium"
      }
    ]
  }
}
```

## 🤖 AI Security Tools

#### POST /api/v1/ai/analyze-logs
Analyze logs using AI.

**Headers:**
```http
Authorization: Bearer <jwt-token>
```

**Request Body:**
```json
{
  "log_source": "apache",
  "log_data": "log entries here...",
  "analysis_type": "anomaly_detection"
}
```

**Response:**
```json
{
  "analysis_id": "uuid",
  "status": "processing",
  "log_source": "apache",
  "analysis_type": "anomaly_detection",
  "started_at": "2024-01-15T10:30:00Z"
}
```

#### GET /api/v1/ai/analysis/{analysis_id}
Get AI analysis results.

**Headers:**
```http
Authorization: Bearer <jwt-token>
```

**Response:**
```json
{
  "analysis_id": "uuid",
  "status": "completed",
  "log_source": "apache",
  "analysis_type": "anomaly_detection",
  "started_at": "2024-01-15T10:30:00Z",
  "completed_at": "2024-01-15T10:32:00Z",
  "results": {
    "anomalies": [
      {
        "timestamp": "2024-01-15T10:25:00Z",
        "severity": "high",
        "description": "Unusual request pattern detected",
        "confidence": 0.95,
        "details": {
          "source_ip": "192.168.1.200",
          "request_count": 1000,
          "time_window": "1m"
        }
      }
    ],
    "summary": {
      "total_entries": 10000,
      "anomalies_found": 5,
      "risk_score": 7.5
    }
  }
}
```

## 🛡️ Threat Intelligence

#### GET /api/v1/threats/intelligence
Get threat intelligence data.

**Headers:**
```http
Authorization: Bearer <jwt-token>
```

**Query Parameters:**
- `type` (optional): Filter by type (ip, domain, hash, url)
- `severity` (optional): Filter by severity (low, medium, high, critical)
- `limit` (optional): Number of records to return (default: 50, max: 100)
- `offset` (optional): Number of records to skip (default: 0)

**Response:**
```json
{
  "threats": [
    {
      "id": "uuid",
      "type": "ip",
      "value": "192.168.1.200",
      "severity": "high",
      "description": "Known botnet C&C server",
      "first_seen": "2024-01-10T10:30:00Z",
      "last_seen": "2024-01-15T10:30:00Z",
      "sources": ["threat_feed_1", "internal_analysis"]
    }
  ],
  "total": 150,
  "limit": 50,
  "offset": 0
}
```

#### POST /api/v1/threats/check
Check if indicators are malicious.

**Headers:**
```http
Authorization: Bearer <jwt-token>
```

**Request Body:**
```json
{
  "indicators": [
    {
      "type": "ip",
      "value": "192.168.1.200"
    },
    {
      "type": "domain",
      "value": "malicious-domain.com"
    }
  ]
}
```

**Response:**
```json
{
  "results": [
    {
      "type": "ip",
      "value": "192.168.1.200",
      "is_malicious": true,
      "severity": "high",
      "confidence": 0.95,
      "sources": ["threat_feed_1"]
    },
    {
      "type": "domain",
      "value": "malicious-domain.com",
      "is_malicious": false,
      "severity": "low",
      "confidence": 0.1,
      "sources": []
    }
  ]
}
```

## 📊 System Health & Monitoring

#### GET /api/v1/health
Get system health status.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "service": "hackai-api",
  "version": "1.0.0",
  "uptime": "2h30m15s",
  "checks": {
    "database": "healthy",
    "redis": "healthy",
    "external_apis": "healthy"
  }
}
```

#### GET /api/v1/metrics
Get system metrics (Prometheus format).

**Response:**
```
# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",path="/api/v1/health",status="200"} 1500

# HELP http_request_duration_seconds HTTP request duration
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{method="GET",path="/api/v1/health",le="0.1"} 1200
```

## 📋 Audit Logs

#### GET /api/v1/audit/logs
Get audit logs (Admin only).

**Headers:**
```http
Authorization: Bearer <jwt-token>
```

**Query Parameters:**
- `user_id` (optional): Filter by user ID
- `action` (optional): Filter by action type
- `resource` (optional): Filter by resource
- `from` (optional): Start date (ISO 8601)
- `to` (optional): End date (ISO 8601)
- `limit` (optional): Number of records to return (default: 50, max: 100)
- `offset` (optional): Number of records to skip (default: 0)

**Response:**
```json
{
  "logs": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "session_id": "uuid",
      "action": "login",
      "resource": "authentication",
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0...",
      "details": {
        "success": true,
        "method": "password"
      },
      "timestamp": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 1500,
  "limit": 50,
  "offset": 0
}
```

## 🚨 Error Handling

All API endpoints return consistent error responses:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request data",
    "details": {
      "field": "email",
      "reason": "Invalid email format"
    },
    "timestamp": "2024-01-15T10:30:00Z",
    "request_id": "uuid"
  }
}
```

### Common Error Codes

- `AUTHENTICATION_REQUIRED` (401): Missing or invalid authentication
- `AUTHORIZATION_FAILED` (403): Insufficient permissions
- `VALIDATION_ERROR` (400): Invalid request data
- `RESOURCE_NOT_FOUND` (404): Requested resource not found
- `RATE_LIMIT_EXCEEDED` (429): Too many requests
- `INTERNAL_SERVER_ERROR` (500): Server error

## 📈 Rate Limiting

API endpoints are rate limited to prevent abuse:

- **Authentication endpoints**: 5 requests per minute per IP
- **Scan endpoints**: 10 requests per hour per user
- **General endpoints**: 100 requests per minute per user

Rate limit headers are included in responses:

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642248600
```

## 🔧 SDK and Examples

### cURL Examples

**Login:**
```bash
curl -X POST https://api.hackai.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email_or_username": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

**Start Vulnerability Scan:**
```bash
curl -X POST https://api.hackai.com/api/v1/scans/vulnerability \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.100",
    "scan_type": "comprehensive"
  }'
```

### Python SDK Example

```python
import requests

class HackAIClient:
    def __init__(self, base_url, token=None):
        self.base_url = base_url
        self.token = token
        self.session = requests.Session()
        if token:
            self.session.headers.update({
                'Authorization': f'Bearer {token}'
            })
    
    def login(self, email, password):
        response = self.session.post(
            f'{self.base_url}/api/v1/auth/login',
            json={
                'email_or_username': email,
                'password': password
            }
        )
        if response.status_code == 200:
            data = response.json()
            self.token = data['access_token']
            self.session.headers.update({
                'Authorization': f'Bearer {self.token}'
            })
            return data
        else:
            raise Exception(f'Login failed: {response.text}')
    
    def start_vulnerability_scan(self, target, scan_type='comprehensive'):
        response = self.session.post(
            f'{self.base_url}/api/v1/scans/vulnerability',
            json={
                'target': target,
                'scan_type': scan_type
            }
        )
        return response.json()

# Usage
client = HackAIClient('https://api.hackai.com')
client.login('user@example.com', 'password')
scan = client.start_vulnerability_scan('192.168.1.100')
print(f"Scan started: {scan['scan_id']}")
```

## 📞 Support

For API support and questions:
- **Documentation**: https://docs.hackai.com
- **Support Email**: api-support@hackai.com
- **GitHub Issues**: https://github.com/hackai/api/issues

## 📄 License

This API documentation is part of the HackAI platform. See LICENSE file for details.
