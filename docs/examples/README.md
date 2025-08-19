# 📚 HackAI LLM Security Proxy - Examples

Comprehensive examples and code samples for integrating with the HackAI LLM Security Proxy.

## 📋 Table of Contents

- [Quick Start Examples](#quick-start-examples)
- [Client Libraries](#client-libraries)
- [Authentication Examples](#authentication-examples)
- [LLM Proxy Usage](#llm-proxy-usage)
- [Security Policy Examples](#security-policy-examples)
- [Monitoring & Analytics](#monitoring--analytics)
- [Error Handling](#error-handling)
- [Advanced Use Cases](#advanced-use-cases)

## 🚀 Quick Start Examples

### Basic LLM Request

```bash
curl -X POST https://api.hackai.dev/api/v1/llm/proxy \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Provider: openai" \
  -H "X-Model: gpt-4" \
  -d '{
    "messages": [
      {
        "role": "user",
        "content": "What is the capital of France?"
      }
    ],
    "max_tokens": 150,
    "temperature": 0.7
  }'
```

### Authentication

```bash
# Login to get JWT token
curl -X POST https://api.hackai.dev/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "your_password"
  }'
```

## 📚 Client Libraries

### JavaScript/TypeScript

```typescript
import { HackAIClient } from '@hackai/client';

const client = new HackAIClient({
  apiKey: 'your-api-key',
  baseURL: 'https://api.hackai.dev'
});

// Authenticate
await client.auth.login('user@example.com', 'password');

// Make secure LLM request
const response = await client.llm.chat({
  provider: 'openai',
  model: 'gpt-4',
  messages: [
    { role: 'user', content: 'Hello, world!' }
  ],
  maxTokens: 150
});

console.log(response.choices[0].message.content);
console.log('Threat Score:', response.security.threatScore);
```

### Python

```python
from hackai import HackAIClient

client = HackAIClient(
    api_key="your-api-key",
    base_url="https://api.hackai.dev"
)

# Authenticate
client.auth.login("user@example.com", "password")

# Make secure LLM request
response = client.llm.chat(
    provider="openai",
    model="gpt-4",
    messages=[
        {"role": "user", "content": "Hello, world!"}
    ],
    max_tokens=150
)

print(response.choices[0].message.content)
print(f"Threat Score: {response.security.threat_score}")
```

### Go

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/hackai/go-client"
)

func main() {
    client := hackai.NewClient("your-api-key", "https://api.hackai.dev")
    
    // Authenticate
    err := client.Auth.Login(context.Background(), "user@example.com", "password")
    if err != nil {
        log.Fatal(err)
    }
    
    // Make secure LLM request
    response, err := client.LLM.Chat(context.Background(), &hackai.ChatRequest{
        Provider: "openai",
        Model:    "gpt-4",
        Messages: []hackai.Message{
            {Role: "user", Content: "Hello, world!"},
        },
        MaxTokens: 150,
    })
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Println(response.Choices[0].Message.Content)
    fmt.Printf("Threat Score: %.2f\n", response.Security.ThreatScore)
}
```

## 🔐 Authentication Examples

### JWT Token Management

```javascript
class HackAIAuth {
  constructor(baseURL) {
    this.baseURL = baseURL;
    this.accessToken = localStorage.getItem('hackai_access_token');
    this.refreshToken = localStorage.getItem('hackai_refresh_token');
  }

  async login(email, password) {
    const response = await fetch(`${this.baseURL}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    if (!response.ok) {
      throw new Error('Login failed');
    }

    const data = await response.json();
    this.accessToken = data.access_token;
    this.refreshToken = data.refresh_token;
    
    localStorage.setItem('hackai_access_token', this.accessToken);
    localStorage.setItem('hackai_refresh_token', this.refreshToken);
    
    return data;
  }

  async refreshAccessToken() {
    const response = await fetch(`${this.baseURL}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: this.refreshToken })
    });

    if (!response.ok) {
      throw new Error('Token refresh failed');
    }

    const data = await response.json();
    this.accessToken = data.access_token;
    localStorage.setItem('hackai_access_token', this.accessToken);
    
    return data;
  }

  getAuthHeaders() {
    return {
      'Authorization': `Bearer ${this.accessToken}`,
      'Content-Type': 'application/json'
    };
  }
}
```

## 🛡️ LLM Proxy Usage

### Streaming Responses

```javascript
async function streamLLMResponse(messages) {
  const response = await fetch('/api/v1/llm/proxy', {
    method: 'POST',
    headers: {
      ...auth.getAuthHeaders(),
      'X-Provider': 'openai',
      'X-Model': 'gpt-4'
    },
    body: JSON.stringify({
      messages,
      max_tokens: 500,
      temperature: 0.7,
      stream: true
    })
  });

  const reader = response.body.getReader();
  const decoder = new TextDecoder();

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    const chunk = decoder.decode(value);
    const lines = chunk.split('\n');

    for (const line of lines) {
      if (line.startsWith('data: ')) {
        const data = line.slice(6);
        if (data === '[DONE]') return;

        try {
          const parsed = JSON.parse(data);
          const content = parsed.choices[0]?.delta?.content;
          if (content) {
            console.log(content); // Process streaming content
          }
        } catch (e) {
          // Handle parsing errors
        }
      }
    }
  }
}
```

### Multi-Provider Support

```python
import asyncio
from hackai import HackAIClient

async def compare_providers(prompt):
    client = HackAIClient(api_key="your-api-key")
    
    providers = [
        {"provider": "openai", "model": "gpt-4"},
        {"provider": "anthropic", "model": "claude-3-sonnet"},
        {"provider": "azure", "model": "gpt-35-turbo"}
    ]
    
    tasks = []
    for config in providers:
        task = client.llm.chat(
            provider=config["provider"],
            model=config["model"],
            messages=[{"role": "user", "content": prompt}],
            max_tokens=150
        )
        tasks.append(task)
    
    responses = await asyncio.gather(*tasks, return_exceptions=True)
    
    for i, response in enumerate(responses):
        if isinstance(response, Exception):
            print(f"{providers[i]['provider']}: Error - {response}")
        else:
            print(f"{providers[i]['provider']}: {response.choices[0].message.content}")
            print(f"Threat Score: {response.security.threat_score}")
```

### Content Analysis

```javascript
async function analyzeContent(content) {
  const response = await fetch('/api/v1/llm/analyze', {
    method: 'POST',
    headers: auth.getAuthHeaders(),
    body: JSON.stringify({
      content,
      analysis_types: [
        'threat_detection',
        'pii_detection',
        'toxicity_analysis',
        'prompt_injection'
      ]
    })
  });

  const analysis = await response.json();
  
  if (analysis.threat_score > 0.7) {
    console.warn('High threat content detected!');
    console.log('Threats:', analysis.analysis_results.threat_detection.threats);
  }
  
  if (analysis.analysis_results.pii_detection.found) {
    console.warn('PII detected in content');
    console.log('Entities:', analysis.analysis_results.pii_detection.entities);
  }
  
  return analysis;
}
```

## 📋 Security Policy Examples

### Creating Content Filter Policy

```javascript
async function createContentFilterPolicy() {
  const policy = {
    name: "Strict Content Filter",
    description: "Block harmful content and PII",
    type: "content_filter",
    rules: [
      {
        condition: "contains_pii",
        action: "mask",
        severity: "medium",
        patterns: ["email", "ssn", "phone", "credit_card"]
      },
      {
        condition: "prompt_injection",
        action: "block",
        severity: "high",
        threshold: 0.8
      },
      {
        condition: "toxicity_high",
        action: "block",
        severity: "high",
        threshold: 0.7
      }
    ],
    enabled: true,
    apply_to: {
      users: ["all"],
      providers: ["openai", "anthropic"],
      models: ["gpt-4", "claude-3-sonnet"]
    }
  };

  const response = await fetch('/api/v1/policies', {
    method: 'POST',
    headers: auth.getAuthHeaders(),
    body: JSON.stringify(policy)
  });

  return response.json();
}
```

### Rate Limiting Policy

```python
def create_rate_limit_policy():
    policy = {
        "name": "User Rate Limits",
        "description": "Prevent abuse with rate limiting",
        "type": "rate_limit",
        "rules": [
            {
                "condition": "requests_per_minute",
                "action": "throttle",
                "limit": 60,
                "window": "1m"
            },
            {
                "condition": "tokens_per_hour",
                "action": "block",
                "limit": 100000,
                "window": "1h"
            },
            {
                "condition": "cost_per_day",
                "action": "block",
                "limit": 50.00,
                "window": "24h"
            }
        ],
        "enabled": True,
        "apply_to": {
            "user_tiers": ["free", "basic"],
            "exclude_users": ["admin", "premium"]
        }
    }
    
    response = requests.post(
        f"{base_url}/api/v1/policies",
        headers=auth_headers,
        json=policy
    )
    
    return response.json()
```

### Testing Policies

```javascript
async function testPolicy(policyId, testContent) {
  const response = await fetch(`/api/v1/policies/${policyId}/test`, {
    method: 'POST',
    headers: auth.getAuthHeaders(),
    body: JSON.stringify({
      content: testContent,
      context: {
        user_id: "test_user",
        provider: "openai",
        model: "gpt-4"
      }
    })
  });

  const result = await response.json();
  
  console.log('Policy Test Results:');
  console.log(`Final Action: ${result.final_action}`);
  console.log(`Threat Score: ${result.threat_score}`);
  
  if (result.violations.length > 0) {
    console.log('Violations:');
    result.violations.forEach(violation => {
      console.log(`- ${violation.rule}: ${violation.action} (${violation.severity})`);
    });
  }
  
  return result;
}
```

## 📊 Monitoring & Analytics

### Real-time Dashboard

```javascript
class RealTimeDashboard {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.ws = null;
    this.metrics = {};
  }

  connect() {
    this.ws = new WebSocket(`wss://api.hackai.dev/api/v1/realtime/dashboard?token=${this.apiKey}`);
    
    this.ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      this.handleUpdate(data);
    };

    this.ws.onopen = () => {
      console.log('Connected to real-time dashboard');
    };

    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
  }

  handleUpdate(data) {
    switch (data.type) {
      case 'stats_update':
        this.updateMetrics(data.payload);
        break;
      case 'threat_alert':
        this.handleThreatAlert(data.payload);
        break;
      case 'system_status':
        this.updateSystemStatus(data.payload);
        break;
    }
  }

  updateMetrics(metrics) {
    this.metrics = { ...this.metrics, ...metrics };
    this.renderDashboard();
  }

  handleThreatAlert(alert) {
    console.warn('Threat Alert:', alert);
    this.showNotification(alert);
  }

  renderDashboard() {
    // Update UI with latest metrics
    document.getElementById('total-requests').textContent = this.metrics.total_requests;
    document.getElementById('threat-score').textContent = this.metrics.average_threat_score?.toFixed(2);
    document.getElementById('blocked-requests').textContent = this.metrics.blocked_requests;
  }
}
```

### Usage Analytics

```python
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime, timedelta

def generate_usage_report(days=30):
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    # Fetch usage data
    response = requests.get(
        f"{base_url}/api/v1/llm/stats",
        headers=auth_headers,
        params={
            "time_range": f"{days}d",
            "granularity": "day"
        }
    )
    
    data = response.json()
    
    # Create DataFrame
    df = pd.DataFrame(data['time_series'])
    df['date'] = pd.to_datetime(df['timestamp'])
    
    # Generate plots
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    
    # Requests over time
    axes[0, 0].plot(df['date'], df['requests'])
    axes[0, 0].set_title('Requests Over Time')
    axes[0, 0].set_ylabel('Requests')
    
    # Cost over time
    axes[0, 1].plot(df['date'], df['cost'])
    axes[0, 1].set_title('Cost Over Time')
    axes[0, 1].set_ylabel('Cost ($)')
    
    # Threat score distribution
    axes[1, 0].hist(df['average_threat_score'], bins=20)
    axes[1, 0].set_title('Threat Score Distribution')
    axes[1, 0].set_xlabel('Threat Score')
    
    # Blocked requests
    axes[1, 1].plot(df['date'], df['blocked_requests'], color='red')
    axes[1, 1].set_title('Blocked Requests Over Time')
    axes[1, 1].set_ylabel('Blocked Requests')
    
    plt.tight_layout()
    plt.savefig(f'usage_report_{days}d.png')
    plt.show()
    
    return df
```

## ❌ Error Handling

### Robust Error Handling

```typescript
class HackAIErrorHandler {
  static async handleResponse(response: Response): Promise<any> {
    if (!response.ok) {
      const error = await response.json();
      throw new HackAIError(error, response.status);
    }
    return response.json();
  }

  static async retryRequest(
    requestFn: () => Promise<Response>,
    maxRetries: number = 3,
    backoffMs: number = 1000
  ): Promise<any> {
    let lastError: Error;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const response = await requestFn();
        return await this.handleResponse(response);
      } catch (error) {
        lastError = error as Error;
        
        if (error instanceof HackAIError) {
          // Don't retry client errors (4xx)
          if (error.status >= 400 && error.status < 500) {
            throw error;
          }
        }

        if (attempt < maxRetries) {
          await this.sleep(backoffMs * Math.pow(2, attempt));
        }
      }
    }

    throw lastError!;
  }

  private static sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

class HackAIError extends Error {
  constructor(
    public errorData: any,
    public status: number
  ) {
    super(errorData.error?.message || 'Unknown error');
    this.name = 'HackAIError';
  }

  get code(): string {
    return this.errorData.error?.code || 'UNKNOWN_ERROR';
  }

  get requestId(): string {
    return this.errorData.error?.request_id || '';
  }
}
```

## 🔧 Advanced Use Cases

### Batch Processing

```python
import asyncio
import aiohttp

async def process_batch_requests(requests_batch):
    async with aiohttp.ClientSession() as session:
        tasks = []
        
        for request in requests_batch:
            task = process_single_request(session, request)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        successful = []
        failed = []
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                failed.append({
                    'request': requests_batch[i],
                    'error': str(result)
                })
            else:
                successful.append(result)
        
        return {
            'successful': successful,
            'failed': failed,
            'total': len(requests_batch),
            'success_rate': len(successful) / len(requests_batch)
        }

async def process_single_request(session, request):
    async with session.post(
        'https://api.hackai.dev/api/v1/llm/proxy',
        headers={
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'X-Provider': request['provider'],
            'X-Model': request['model']
        },
        json=request['payload']
    ) as response:
        return await response.json()
```

### Custom Security Integration

```javascript
class CustomSecurityIntegration {
  constructor(hackaiClient, customSecurityAPI) {
    this.hackaiClient = hackaiClient;
    this.customSecurityAPI = customSecurityAPI;
  }

  async secureRequest(request) {
    // Pre-process with custom security
    const customAnalysis = await this.customSecurityAPI.analyze(request.content);
    
    if (customAnalysis.risk_level === 'high') {
      throw new Error('Request blocked by custom security layer');
    }

    // Add custom context to request
    request.metadata = {
      ...request.metadata,
      custom_security_score: customAnalysis.score,
      custom_tags: customAnalysis.tags
    };

    // Process through HackAI
    const response = await this.hackaiClient.llm.chat(request);

    // Post-process response
    const enhancedResponse = await this.enhanceResponse(response, customAnalysis);

    return enhancedResponse;
  }

  async enhanceResponse(response, customAnalysis) {
    return {
      ...response,
      custom_security: {
        pre_analysis: customAnalysis,
        combined_threat_score: (
          response.security.threat_score + customAnalysis.score
        ) / 2,
        recommendations: this.generateRecommendations(response, customAnalysis)
      }
    };
  }

  generateRecommendations(response, customAnalysis) {
    const recommendations = [];
    
    if (response.security.threat_score > 0.5) {
      recommendations.push('Monitor user activity closely');
    }
    
    if (customAnalysis.contains_sensitive_data) {
      recommendations.push('Apply data loss prevention policies');
    }
    
    return recommendations;
  }
}
```
