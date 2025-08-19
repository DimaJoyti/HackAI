# 🛡️ LLM Security API Reference

Comprehensive documentation for the LLM Security endpoints that provide the core proxy functionality.

## Overview

The LLM Security API provides secure access to Large Language Models through a comprehensive security layer that includes:

- Real-time threat detection and scoring
- Content filtering and policy enforcement
- Rate limiting and cost management
- Complete audit logging
- Multi-provider support

## Base URL

```
https://api.hackai.dev/api/v1/llm
```

## Authentication

All endpoints require JWT authentication:

```http
Authorization: Bearer <jwt_token>
```

## Endpoints

### POST /proxy

The main LLM proxy endpoint that securely processes LLM requests.

#### Request Headers

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes | JWT Bearer token |
| `Content-Type` | Yes | `application/json` |
| `X-Provider` | Yes | LLM provider (`openai`, `anthropic`, `azure`) |
| `X-Model` | Yes | Model name (e.g., `gpt-4`, `claude-3-sonnet`) |
| `X-User-ID` | No | User identifier for tracking |
| `X-Request-ID` | No | Unique request identifier |

#### Request Body

```json
{
  "messages": [
    {
      "role": "system|user|assistant",
      "content": "string"
    }
  ],
  "max_tokens": 150,
  "temperature": 0.7,
  "top_p": 1.0,
  "frequency_penalty": 0.0,
  "presence_penalty": 0.0,
  "stream": false,
  "stop": ["string"],
  "user": "string"
}
```

#### Response

**Success (200 OK):**
```json
{
  "id": "req_123456789",
  "object": "chat.completion",
  "created": 1642248000,
  "model": "gpt-4",
  "choices": [
    {
      "index": 0,
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
    "risk_level": "low",
    "violations": [],
    "policies_applied": [
      "content_filter",
      "rate_limit",
      "pii_detection"
    ],
    "scan_time_ms": 45
  },
  "metadata": {
    "cost": 0.0003,
    "processing_time_ms": 1250,
    "provider_response_time_ms": 1100,
    "cached": false,
    "request_id": "req_123456789"
  }
}
```

**Blocked Request (403 Forbidden):**
```json
{
  "error": {
    "code": "REQUEST_BLOCKED",
    "message": "Request blocked by security policy",
    "details": "Content contains potential prompt injection",
    "security": {
      "threat_score": 0.95,
      "risk_level": "critical",
      "violations": [
        {
          "type": "prompt_injection",
          "severity": "high",
          "description": "Potential prompt injection detected",
          "matched_pattern": "ignore previous instructions"
        }
      ],
      "policy": "content_filter_strict"
    },
    "request_id": "req_123456789"
  }
}
```

#### Security Features

**Threat Scoring:**
- `0.0 - 0.3`: Low risk (allowed)
- `0.3 - 0.6`: Medium risk (monitored)
- `0.6 - 0.8`: High risk (flagged)
- `0.8 - 1.0`: Critical risk (blocked)

**Content Filtering:**
- Prompt injection detection
- PII (Personally Identifiable Information) detection
- Toxic content filtering
- Malware/phishing URL detection
- Custom pattern matching

**Rate Limiting:**
- Per-user request limits
- Token consumption limits
- Cost-based limiting
- Burst protection

### GET /providers

List available LLM providers and their current status.

#### Response

```json
{
  "providers": [
    {
      "name": "openai",
      "display_name": "OpenAI",
      "status": "active",
      "health": "healthy",
      "models": [
        {
          "name": "gpt-4",
          "display_name": "GPT-4",
          "max_tokens": 8192,
          "cost_per_1k_tokens": {
            "input": 0.03,
            "output": 0.06
          },
          "capabilities": ["chat", "completion"]
        },
        {
          "name": "gpt-3.5-turbo",
          "display_name": "GPT-3.5 Turbo",
          "max_tokens": 4096,
          "cost_per_1k_tokens": {
            "input": 0.001,
            "output": 0.002
          },
          "capabilities": ["chat", "completion"]
        }
      ],
      "rate_limits": {
        "requests_per_minute": 60,
        "tokens_per_minute": 10000,
        "requests_per_day": 1000
      },
      "last_health_check": "2024-01-15T10:30:00Z"
    },
    {
      "name": "anthropic",
      "display_name": "Anthropic",
      "status": "active",
      "health": "healthy",
      "models": [
        {
          "name": "claude-3-sonnet",
          "display_name": "Claude 3 Sonnet",
          "max_tokens": 200000,
          "cost_per_1k_tokens": {
            "input": 0.003,
            "output": 0.015
          },
          "capabilities": ["chat"]
        }
      ],
      "rate_limits": {
        "requests_per_minute": 50,
        "tokens_per_minute": 40000,
        "requests_per_day": 1000
      },
      "last_health_check": "2024-01-15T10:30:00Z"
    }
  ],
  "total_providers": 2,
  "active_providers": 2
}
```

### GET /models

Get detailed information about available models.

#### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `provider` | string | Filter by provider |
| `capability` | string | Filter by capability (`chat`, `completion`, `embedding`) |
| `max_tokens_gte` | integer | Minimum max tokens |

#### Response

```json
{
  "models": [
    {
      "id": "gpt-4",
      "provider": "openai",
      "display_name": "GPT-4",
      "description": "Most capable GPT-4 model",
      "max_tokens": 8192,
      "context_window": 8192,
      "training_data_cutoff": "2023-04-01",
      "capabilities": ["chat", "completion"],
      "pricing": {
        "input_cost_per_1k_tokens": 0.03,
        "output_cost_per_1k_tokens": 0.06,
        "currency": "USD"
      },
      "performance": {
        "average_latency_ms": 1200,
        "success_rate": 0.999,
        "uptime": 0.9995
      },
      "security_features": [
        "content_filtering",
        "safety_classifier",
        "usage_monitoring"
      ]
    }
  ]
}
```

### GET /stats

Get comprehensive LLM usage statistics.

#### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `time_range` | string | `1h`, `24h`, `7d`, `30d` (default: `24h`) |
| `provider` | string | Filter by provider |
| `model` | string | Filter by model |
| `user_id` | string | Filter by user |
| `granularity` | string | `minute`, `hour`, `day` |

#### Response

```json
{
  "summary": {
    "total_requests": 1250,
    "successful_requests": 1200,
    "blocked_requests": 50,
    "error_requests": 0,
    "average_threat_score": 0.15,
    "total_tokens": {
      "input": 75000,
      "output": 50000,
      "total": 125000
    },
    "total_cost": 25.50,
    "average_response_time_ms": 1200,
    "cache_hit_rate": 0.15
  },
  "time_series": [
    {
      "timestamp": "2024-01-15T10:00:00Z",
      "requests": 120,
      "tokens": 12000,
      "cost": 2.40,
      "average_threat_score": 0.12,
      "blocked_requests": 5
    }
  ],
  "top_models": [
    {
      "model": "gpt-4",
      "provider": "openai",
      "requests": 800,
      "tokens": 80000,
      "cost": 20.00,
      "average_threat_score": 0.10
    }
  ],
  "top_users": [
    {
      "user_id": "user_123",
      "requests": 150,
      "tokens": 15000,
      "cost": 3.00,
      "average_threat_score": 0.05
    }
  ],
  "security_summary": {
    "total_violations": 25,
    "violation_types": [
      {
        "type": "pii_detected",
        "count": 15,
        "severity": "medium"
      },
      {
        "type": "prompt_injection",
        "count": 10,
        "severity": "high"
      }
    ],
    "blocked_by_policy": [
      {
        "policy": "content_filter",
        "count": 30
      },
      {
        "policy": "rate_limit",
        "count": 20
      }
    ]
  }
}
```

### POST /analyze

Analyze content for security threats without making an LLM request.

#### Request Body

```json
{
  "content": "string",
  "context": {
    "user_id": "string",
    "provider": "string",
    "model": "string"
  },
  "analysis_types": [
    "threat_detection",
    "pii_detection",
    "toxicity_analysis",
    "prompt_injection"
  ]
}
```

#### Response

```json
{
  "threat_score": 0.75,
  "risk_level": "high",
  "analysis_results": {
    "threat_detection": {
      "score": 0.8,
      "threats": [
        {
          "type": "prompt_injection",
          "confidence": 0.9,
          "description": "Potential attempt to override system instructions"
        }
      ]
    },
    "pii_detection": {
      "found": true,
      "entities": [
        {
          "type": "email",
          "value": "john@example.com",
          "confidence": 0.95,
          "start": 10,
          "end": 25
        }
      ]
    },
    "toxicity_analysis": {
      "score": 0.1,
      "categories": {
        "harassment": 0.05,
        "hate_speech": 0.02,
        "violence": 0.01
      }
    }
  },
  "recommendations": [
    "Block request due to high threat score",
    "Mask detected PII before processing",
    "Apply additional monitoring"
  ],
  "processing_time_ms": 150
}
```

## Error Handling

### Error Response Format

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable error message",
    "details": "Additional error details",
    "request_id": "req_123456789",
    "timestamp": "2024-01-15T10:30:00Z",
    "documentation_url": "https://docs.hackai.dev/errors/ERROR_CODE"
  }
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_PROVIDER` | 400 | Unsupported or invalid provider |
| `INVALID_MODEL` | 400 | Model not available for provider |
| `CONTENT_BLOCKED` | 403 | Request blocked by security policy |
| `RATE_LIMITED` | 429 | Rate limit exceeded |
| `PROVIDER_ERROR` | 502 | Error from LLM provider |
| `PROVIDER_TIMEOUT` | 504 | Provider request timeout |

## Rate Limiting

Rate limits are enforced per user and include:

- **Requests per minute**: Maximum number of requests
- **Tokens per minute**: Maximum token consumption
- **Cost per hour/day**: Maximum spending limits

Rate limit headers are included in all responses:

```http
X-RateLimit-Limit-Requests: 60
X-RateLimit-Remaining-Requests: 59
X-RateLimit-Reset-Requests: 1642248060
X-RateLimit-Limit-Tokens: 10000
X-RateLimit-Remaining-Tokens: 9850
X-RateLimit-Reset-Tokens: 1642248060
```
