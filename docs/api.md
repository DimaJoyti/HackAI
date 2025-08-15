# 🔌 HackAI API Documentation

## 📋 Overview

The HackAI API provides comprehensive access to all platform features including authentication, AI security training, threat detection, and learning analytics. The API follows RESTful principles and uses JSON for data exchange.

## 🔐 Authentication

### JWT Token Authentication

All API requests require authentication using JWT tokens in the Authorization header:

```http
Authorization: Bearer <jwt_token>
```

### OAuth2 Flow

```http
POST /api/v1/auth/oauth/authorize
Content-Type: application/json

{
  "provider": "google",
  "redirect_uri": "https://app.hackai.com/callback"
}
```

## 📚 API Endpoints

### Authentication Endpoints

#### POST /api/v1/auth/login

Authenticate user and receive JWT token.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "securepassword",
  "mfa_code": "123456"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "refresh_token_here",
    "expires_in": 3600,
    "user": {
      "id": "user-123",
      "email": "user@example.com",
      "role": "student",
      "profile": {
        "name": "John Doe",
        "avatar": "https://example.com/avatar.jpg"
      }
    }
  }
}
```

#### POST /api/v1/auth/register

Register new user account.

**Request:**
```json
{
  "email": "newuser@example.com",
  "password": "securepassword",
  "name": "New User",
  "organization": "Example Corp"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "user_id": "user-456",
    "verification_required": true,
    "message": "Verification email sent"
  }
}
```

#### POST /api/v1/auth/refresh

Refresh JWT token using refresh token.

**Request:**
```json
{
  "refresh_token": "refresh_token_here"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "token": "new_jwt_token",
    "expires_in": 3600
  }
}
```

### User Management Endpoints

#### GET /api/v1/users/profile

Get current user profile.

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "user-123",
    "email": "user@example.com",
    "name": "John Doe",
    "role": "student",
    "organization": "Example Corp",
    "created_at": "2024-01-01T00:00:00Z",
    "last_login": "2024-01-15T10:30:00Z",
    "preferences": {
      "theme": "dark",
      "notifications": true,
      "language": "en"
    },
    "progress": {
      "modules_completed": 5,
      "total_modules": 13,
      "completion_percentage": 38.5,
      "current_level": "intermediate"
    }
  }
}
```

#### PUT /api/v1/users/profile

Update user profile.

**Request:**
```json
{
  "name": "John Smith",
  "preferences": {
    "theme": "light",
    "notifications": false
  }
}
```

### Education Endpoints

#### GET /api/v1/education/modules

Get all learning modules.

**Query Parameters:**
- `category` (optional): Filter by category
- `difficulty` (optional): Filter by difficulty level
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 20)

**Response:**
```json
{
  "success": true,
  "data": {
    "modules": [
      {
        "id": "module-1",
        "title": "AI Security Fundamentals",
        "description": "Introduction to AI security landscape",
        "category": "fundamentals",
        "difficulty": "beginner",
        "estimated_duration": "2h 30m",
        "prerequisites": [],
        "learning_objectives": [
          "Understand AI security threats",
          "Identify common vulnerabilities",
          "Apply basic security measures"
        ],
        "progress": {
          "completed": true,
          "completion_date": "2024-01-10T15:30:00Z",
          "score": 95
        }
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 13,
      "total_pages": 1
    }
  }
}
```

#### GET /api/v1/education/modules/{module_id}

Get specific module details.

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "module-1",
    "title": "AI Security Fundamentals",
    "description": "Comprehensive introduction to AI security",
    "content": {
      "sections": [
        {
          "id": "section-1",
          "title": "Introduction to AI Threats",
          "type": "video",
          "duration": "15m",
          "content_url": "https://example.com/video1.mp4"
        },
        {
          "id": "section-2",
          "title": "Common Vulnerabilities",
          "type": "text",
          "content": "Detailed explanation of vulnerabilities..."
        }
      ]
    },
    "assessments": [
      {
        "id": "assessment-1",
        "title": "Knowledge Check",
        "type": "quiz",
        "questions": 10,
        "time_limit": "30m"
      }
    ],
    "labs": [
      {
        "id": "lab-1",
        "title": "Prompt Injection Detection",
        "type": "interactive",
        "environment": "web",
        "estimated_time": "45m"
      }
    ]
  }
}
```

#### POST /api/v1/education/modules/{module_id}/enroll

Enroll in a module.

**Response:**
```json
{
  "success": true,
  "data": {
    "enrollment_id": "enrollment-123",
    "module_id": "module-1",
    "enrolled_at": "2024-01-15T10:30:00Z",
    "status": "active"
  }
}
```

### Assessment Endpoints

#### GET /api/v1/assessments/{assessment_id}

Get assessment details.

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "assessment-1",
    "title": "AI Security Fundamentals Quiz",
    "description": "Test your knowledge of AI security basics",
    "type": "quiz",
    "time_limit": 1800,
    "questions": [
      {
        "id": "q1",
        "type": "multiple_choice",
        "question": "What is prompt injection?",
        "options": [
          "A type of SQL injection",
          "Manipulating AI model inputs",
          "Network attack method",
          "Database vulnerability"
        ],
        "points": 10
      }
    ],
    "passing_score": 70,
    "attempts_allowed": 3
  }
}
```

#### POST /api/v1/assessments/{assessment_id}/submit

Submit assessment answers.

**Request:**
```json
{
  "answers": [
    {
      "question_id": "q1",
      "answer": "Manipulating AI model inputs"
    }
  ],
  "time_taken": 1200
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "submission_id": "submission-123",
    "score": 85,
    "passed": true,
    "feedback": [
      {
        "question_id": "q1",
        "correct": true,
        "explanation": "Correct! Prompt injection involves..."
      }
    ],
    "certificate_earned": true
  }
}
```

### Security Endpoints

#### POST /api/v1/security/scan

Initiate security scan.

**Request:**
```json
{
  "target": "https://example.com",
  "scan_type": "comprehensive",
  "options": {
    "include_ai_tests": true,
    "depth": "medium",
    "timeout": 300
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "scan_id": "scan-123",
    "status": "initiated",
    "estimated_completion": "2024-01-15T11:00:00Z",
    "progress_url": "/api/v1/security/scans/scan-123/progress"
  }
}
```

#### GET /api/v1/security/scans/{scan_id}

Get scan results.

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "scan-123",
    "target": "https://example.com",
    "status": "completed",
    "started_at": "2024-01-15T10:30:00Z",
    "completed_at": "2024-01-15T10:45:00Z",
    "results": {
      "security_score": 85,
      "vulnerabilities": [
        {
          "id": "vuln-1",
          "type": "prompt_injection",
          "severity": "high",
          "title": "Prompt Injection Vulnerability",
          "description": "AI model susceptible to prompt manipulation",
          "location": "/api/chat",
          "evidence": "Payload: 'Ignore previous instructions'",
          "remediation": "Implement input validation and sanitization"
        }
      ],
      "compliance": {
        "owasp_ai_top_10": {
          "score": 8,
          "issues": ["LLM01", "LLM03"]
        },
        "mitre_atlas": {
          "techniques": ["T1040", "T1059"]
        }
      }
    }
  }
}
```

### AI Service Endpoints

#### POST /api/v1/ai/analyze

Analyze content for AI security threats.

**Request:**
```json
{
  "content": "User input to analyze",
  "analysis_type": "prompt_injection",
  "model": "gpt-4"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "analysis_id": "analysis-123",
    "threat_detected": true,
    "confidence": 0.95,
    "threat_type": "prompt_injection",
    "severity": "high",
    "details": {
      "patterns_matched": ["ignore_instructions", "system_override"],
      "risk_score": 8.5,
      "recommendations": [
        "Implement input filtering",
        "Add prompt validation"
      ]
    }
  }
}
```

### Analytics Endpoints

#### GET /api/v1/analytics/progress

Get learning progress analytics.

**Query Parameters:**
- `timeframe` (optional): 7d, 30d, 90d, 1y (default: 30d)
- `granularity` (optional): day, week, month (default: day)

**Response:**
```json
{
  "success": true,
  "data": {
    "timeframe": "30d",
    "summary": {
      "total_study_time": "25h 30m",
      "modules_completed": 5,
      "assessments_passed": 8,
      "labs_completed": 12,
      "average_score": 87.5
    },
    "progress_timeline": [
      {
        "date": "2024-01-01",
        "study_time": 120,
        "modules_completed": 1,
        "score": 85
      }
    ],
    "skill_development": [
      {
        "skill": "Threat Modeling",
        "current_level": 85,
        "target_level": 90,
        "progress": 94.4
      }
    ]
  }
}
```

## 🚨 Error Handling

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input parameters",
    "details": [
      {
        "field": "email",
        "message": "Invalid email format"
      }
    ],
    "request_id": "req-123456"
  }
}
```

### Common Error Codes

- `AUTHENTICATION_REQUIRED` (401): Missing or invalid authentication
- `AUTHORIZATION_FAILED` (403): Insufficient permissions
- `VALIDATION_ERROR` (400): Invalid request parameters
- `RESOURCE_NOT_FOUND` (404): Requested resource not found
- `RATE_LIMIT_EXCEEDED` (429): Too many requests
- `INTERNAL_ERROR` (500): Server error

## 📊 Rate Limiting

### Rate Limits

- **Authentication endpoints**: 5 requests per minute
- **General API**: 100 requests per minute
- **Security scans**: 10 requests per hour
- **File uploads**: 5 requests per minute

### Rate Limit Headers

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642694400
```

## 🔄 Webhooks

### Webhook Events

Configure webhooks to receive real-time notifications:

- `user.registered`: New user registration
- `module.completed`: Module completion
- `assessment.submitted`: Assessment submission
- `security.threat_detected`: Security threat detected
- `scan.completed`: Security scan completed

### Webhook Payload

```json
{
  "event": "module.completed",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "user_id": "user-123",
    "module_id": "module-1",
    "completion_time": "2h 15m",
    "score": 95
  }
}
```

## 📝 SDK and Libraries

### Official SDKs

- **JavaScript/TypeScript**: `@hackai/sdk-js`
- **Python**: `hackai-python`
- **Go**: `github.com/hackai/go-sdk`
- **Java**: `com.hackai:hackai-java-sdk`

### Example Usage (JavaScript)

```javascript
import { HackAI } from '@hackai/sdk-js';

const client = new HackAI({
  apiKey: 'your-api-key',
  baseURL: 'https://api.hackai.com'
});

// Get user profile
const profile = await client.users.getProfile();

// Start security scan
const scan = await client.security.startScan({
  target: 'https://example.com',
  scanType: 'comprehensive'
});

// Get scan results
const results = await client.security.getScanResults(scan.id);
```

This API documentation provides comprehensive coverage of all HackAI platform endpoints with detailed examples and best practices for integration.
