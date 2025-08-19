# 🔌 HackAI LLM Security Proxy - API Documentation

Complete API reference for the HackAI LLM Security Proxy, providing comprehensive security, monitoring, and management endpoints.

## 📋 Table of Contents

- [Authentication](#authentication)
- [LLM Security Endpoints](#llm-security-endpoints)
- [Policy Management](#policy-management)
- [Monitoring & Analytics](#monitoring--analytics)
- [Audit & Compliance](#audit--compliance)
- [Real-time Dashboard](#real-time-dashboard)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)

## 🔐 Authentication

All API endpoints require JWT authentication unless otherwise specified.

### Headers
```http
Authorization: Bearer <jwt_token>
Content-Type: application/json
X-Request-ID: <unique_request_id>
```

### Authentication Endpoints

#### POST /api/v1/auth/login
Authenticate user and receive JWT token.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "secure_password"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_in": 900,
  "token_type": "Bearer"
}
```

#### POST /api/v1/auth/refresh
Refresh JWT token using refresh token.

**Request:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

## 🛡️ LLM Security Endpoints

### POST /api/v1/llm/proxy
Main LLM proxy endpoint for secure LLM interactions.

**Headers:**
```http
X-Provider: openai|anthropic|azure
X-Model: gpt-4|claude-3-sonnet|gpt-35-turbo
X-User-ID: user_identifier
```

**Request:**
```json
{
  "messages": [
    {
      "role": "user",
      "content": "What is the capital of France?"
    }
  ],
  "max_tokens": 150,
  "temperature": 0.7,
  "stream": false
}
```

**Response:**
```json
{
  "id": "req_123456789",
  "choices": [
    {
      "message": {
        "role": "assistant",
        "content": "The capital of France is Paris."
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 8,
    "completion_tokens": 7,
    "total_tokens": 15
  },
  "security": {
    "threat_score": 0.1,
    "violations": [],
    "policies_applied": ["content_filter", "rate_limit"]
  },
  "cost": 0.0003,
  "processing_time_ms": 1250
}
```

### GET /api/v1/llm/providers
List available LLM providers and their status.

**Response:**
```json
{
  "providers": [
    {
      "name": "openai",
      "status": "active",
      "models": ["gpt-4", "gpt-3.5-turbo"],
      "rate_limit": {
        "requests_per_minute": 60,
        "tokens_per_minute": 10000
      }
    }
  ]
}
```

### GET /api/v1/llm/stats
Get LLM usage statistics.

**Query Parameters:**
- `time_range`: `1h|24h|7d|30d` (default: 24h)
- `provider`: Filter by provider
- `user_id`: Filter by user

**Response:**
```json
{
  "total_requests": 1250,
  "successful_requests": 1200,
  "blocked_requests": 50,
  "average_threat_score": 0.15,
  "total_tokens": 125000,
  "total_cost": 25.50,
  "average_response_time": 1200,
  "top_models": [
    {
      "model": "gpt-4",
      "requests": 800,
      "cost": 20.00
    }
  ]
}
```

## 📋 Policy Management

### GET /api/v1/policies
List all security policies.

**Query Parameters:**
- `status`: `active|inactive|draft`
- `type`: `content_filter|rate_limit|threat_detection`
- `limit`: Number of results (default: 50)
- `offset`: Pagination offset

**Response:**
```json
{
  "policies": [
    {
      "id": "pol_123456",
      "name": "Content Filter Policy",
      "type": "content_filter",
      "status": "active",
      "rules": [
        {
          "condition": "contains_pii",
          "action": "block",
          "severity": "high"
        }
      ],
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 25,
  "limit": 50,
  "offset": 0
}
```

### POST /api/v1/policies
Create a new security policy.

**Request:**
```json
{
  "name": "PII Detection Policy",
  "description": "Detect and block personally identifiable information",
  "type": "content_filter",
  "rules": [
    {
      "condition": "contains_email",
      "action": "mask",
      "severity": "medium"
    },
    {
      "condition": "contains_ssn",
      "action": "block",
      "severity": "high"
    }
  ],
  "enabled": true
}
```

### PUT /api/v1/policies/{policy_id}
Update an existing policy.

### DELETE /api/v1/policies/{policy_id}
Delete a policy.

### POST /api/v1/policies/{policy_id}/test
Test a policy against sample content.

**Request:**
```json
{
  "content": "My email is john.doe@example.com and my SSN is 123-45-6789",
  "context": {
    "user_id": "user_123",
    "provider": "openai"
  }
}
```

**Response:**
```json
{
  "violations": [
    {
      "rule": "contains_email",
      "action": "mask",
      "severity": "medium",
      "matched_content": "john.doe@example.com"
    },
    {
      "rule": "contains_ssn",
      "action": "block",
      "severity": "high",
      "matched_content": "123-45-6789"
    }
  ],
  "final_action": "block",
  "threat_score": 0.8
}
```

## 📊 Monitoring & Analytics

### GET /api/v1/monitoring/dashboard
Get real-time dashboard data.

**Response:**
```json
{
  "current_stats": {
    "active_requests": 15,
    "requests_per_minute": 45,
    "average_threat_score": 0.12,
    "blocked_requests_last_hour": 8
  },
  "threat_trends": [
    {
      "timestamp": "2024-01-15T10:00:00Z",
      "threat_score": 0.15,
      "request_count": 120
    }
  ],
  "top_threats": [
    {
      "type": "prompt_injection",
      "count": 5,
      "severity": "high"
    }
  ]
}
```

### GET /api/v1/monitoring/metrics
Get detailed metrics.

**Query Parameters:**
- `metric`: `requests|tokens|cost|threats|latency`
- `time_range`: Time range for metrics
- `granularity`: `minute|hour|day`

### GET /api/v1/monitoring/alerts
Get security alerts.

**Response:**
```json
{
  "alerts": [
    {
      "id": "alert_123",
      "type": "high_threat_score",
      "severity": "critical",
      "message": "Multiple high-threat requests detected",
      "timestamp": "2024-01-15T10:30:00Z",
      "resolved": false,
      "metadata": {
        "user_id": "user_456",
        "threat_score": 0.95
      }
    }
  ]
}
```

## 📝 Audit & Compliance

### GET /api/v1/audit/logs
Retrieve audit logs with filtering.

**Query Parameters:**
- `start_time`: ISO 8601 timestamp
- `end_time`: ISO 8601 timestamp
- `user_id`: Filter by user
- `action`: Filter by action type
- `status`: `success|failure|blocked`
- `limit`: Number of results
- `offset`: Pagination offset

**Response:**
```json
{
  "logs": [
    {
      "id": "log_123456",
      "timestamp": "2024-01-15T10:30:00Z",
      "user_id": "user_123",
      "action": "llm_request",
      "status": "success",
      "request_id": "req_789",
      "provider": "openai",
      "model": "gpt-4",
      "threat_score": 0.1,
      "tokens_used": 150,
      "cost": 0.003,
      "processing_time": 1200,
      "ip_address": "192.168.1.100",
      "user_agent": "HackAI-Client/1.0"
    }
  ],
  "total": 1000,
  "limit": 50,
  "offset": 0
}
```

### GET /api/v1/audit/logs/{log_id}
Get detailed audit log entry.

### GET /api/v1/audit/export
Export audit logs in various formats.

**Query Parameters:**
- `format`: `json|csv|xlsx`
- `start_time`: Export start time
- `end_time`: Export end time
- `filters`: JSON-encoded filter object

**Response:**
- Returns file download with appropriate Content-Type

### GET /api/v1/audit/summary
Get audit summary for compliance reporting.

**Query Parameters:**
- `period`: `daily|weekly|monthly|quarterly`
- `start_date`: Start date for summary
- `end_date`: End date for summary

## 🔄 Real-time Dashboard

### WebSocket: /api/v1/realtime/dashboard
Real-time dashboard updates via WebSocket.

**Connection:**
```javascript
const ws = new WebSocket('wss://api.hackai.dev/api/v1/realtime/dashboard');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  // Handle real-time updates
};
```

**Message Types:**
- `stats_update`: Real-time statistics
- `threat_alert`: New security threat detected
- `system_status`: System health updates

## ❌ Error Handling

All API endpoints return consistent error responses:

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "The request is invalid",
    "details": "Missing required field: user_id",
    "request_id": "req_123456",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### Common Error Codes
- `UNAUTHORIZED`: Invalid or missing authentication
- `FORBIDDEN`: Insufficient permissions
- `INVALID_REQUEST`: Malformed request
- `RATE_LIMITED`: Rate limit exceeded
- `INTERNAL_ERROR`: Server error
- `SERVICE_UNAVAILABLE`: Service temporarily unavailable

## ⚡ Rate Limiting

Rate limits are applied per user and globally:

**Headers in Response:**
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1642248000
X-RateLimit-Window: 3600
```

**Rate Limit Exceeded Response:**
```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "Rate limit exceeded",
    "retry_after": 60
  }
}
```
