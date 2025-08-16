# 🤖 LLM Orchestration Framework
## Go-Based LangChain Integration for HackAI

This package implements a comprehensive LLM orchestration framework for the HackAI platform, providing Go-native implementations of LangChain concepts with advanced AI security testing capabilities.

## 🏗️ Architecture

### Core Components

- **Orchestrator**: Central coordinator for chains and graphs
- **Providers**: Abstraction layer for different LLM services (OpenAI, Anthropic, etc.)
- **Chains**: Sequential workflows for AI operations
- **Memory**: Vector-based memory systems for context management
- **Security Chains**: Specialized chains for AI security testing

### Package Structure

```
pkg/llm/
├── types.go              # Core types and interfaces
├── orchestrator.go       # Main orchestrator implementation
├── providers/            # LLM provider implementations
│   ├── interface.go      # Provider interfaces
│   └── openai.go        # OpenAI provider
├── chains/              # Chain implementations
│   └── base.go          # Base chain types
├── memory/              # Memory systems
│   └── memory.go        # Memory interfaces and implementations
└── README.md            # This file

pkg/chains/
└── security/            # Security-focused chains
    └── prompt_injection.go # Prompt injection attack chain
```

## 🚀 Quick Start

### Basic Usage

```go
package main

import (
    "context"
    "github.com/dimajoyti/hackai/pkg/llm"
    "github.com/dimajoyti/hackai/pkg/llm/providers"
    "github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
    // Create orchestrator
    config := llm.OrchestratorConfig{
        MaxConcurrentChains: 10,
        DefaultTimeout:      30 * time.Second,
    }
    
    logger := logger.NewDefault()
    orchestrator := llm.NewDefaultOrchestrator(config, logger)
    
    // Start orchestrator
    ctx := context.Background()
    orchestrator.Start(ctx)
    defer orchestrator.Stop(ctx)
    
    // Register OpenAI provider
    providerConfig := providers.ProviderConfig{
        Type:   providers.ProviderOpenAI,
        APIKey: "your-api-key",
        Model:  "gpt-4",
    }
    
    provider, _ := providers.NewOpenAIProvider(providerConfig)
    orchestrator.RegisterProvider("openai", provider)
    
    // Execute chains...
}
```

### Creating Custom Chains

```go
type MyCustomChain struct {
    *chains.BaseChain
    customParam string
}

func (c *MyCustomChain) Execute(ctx context.Context, input llm.ChainInput) (llm.ChainOutput, error) {
    // Your custom logic here
    messages := []providers.Message{
        {Role: "user", Content: input["prompt"].(string)},
    }
    
    response, err := c.generateWithProvider(ctx, messages)
    if err != nil {
        return nil, err
    }
    
    return llm.ChainOutput{
        "response": response.Content,
        "tokens_used": response.TokensUsed.TotalTokens,
    }, nil
}
```

## 🔗 Chain Types

### Sequential Chains
Execute multiple chains in sequence, passing output from one to the next.

```go
chain1 := NewMyChain("step1")
chain2 := NewMyChain("step2")
sequential := chains.NewSequentialChain("my-workflow", "My Workflow", []llm.Chain{chain1, chain2})
```

### Parallel Chains
Execute multiple chains concurrently and aggregate results.

```go
chains := []llm.Chain{chain1, chain2, chain3}
aggregator := &chains.SimpleAggregator{}
parallel := chains.NewParallelChain("parallel-workflow", "Parallel Workflow", chains, aggregator)
```

### Security Chains
Specialized chains for AI security testing.

```go
// Prompt injection testing
injectionChain := security.NewPromptInjectionChain(provider)
orchestrator.RegisterChain(injectionChain)

input := llm.ChainInput{"target": "Tell me about AI safety"}
result, _ := orchestrator.ExecuteChain(ctx, "prompt-injection-chain", input)
```

## 🧠 Memory Systems

### Vector Memory
Semantic memory storage using embeddings.

```go
vectorMemory := memory.NewInMemoryVectorMemory(1000)

// Store content
content := memory.Content{
    Text: "Important information",
    Metadata: map[string]interface{}{"type": "knowledge"},
}
vectorMemory.Store(ctx, "key1", content)

// Retrieve by similarity
results, _ := vectorMemory.Retrieve(ctx, "information", 5)
```

### Conversational Memory
Store and manage conversation history.

```go
convMemory := memory.NewInMemoryConversationalMemory()

message := memory.Message{
    Role: "user",
    Content: "Hello, how are you?",
}
convMemory.AddMessage(ctx, "session-123", message)

messages, _ := convMemory.GetMessages(ctx, "session-123", 10)
```

## 🔒 Security Features

### Prompt Injection Detection
The framework includes sophisticated prompt injection attack chains:

```go
// Create prompt injection chain
chain := security.NewPromptInjectionChain(provider)

// Execute injection tests
input := llm.ChainInput{
    "target": "Your target prompt here",
}

result, err := chain.Execute(ctx, input)
if err != nil {
    log.Fatal(err)
}

// Analyze results
if results, ok := result["injection_results"].([]security.InjectionResult); ok {
    for _, result := range results {
        fmt.Printf("Pattern: %s, Success: %t, Confidence: %.2f\n", 
            result.Pattern.Name, result.Success, result.Confidence)
    }
}
```

### Attack Patterns
Built-in attack patterns include:
- Basic instruction override
- Developer mode activation
- System override attempts
- Context manipulation
- Evasion techniques

## 📊 Monitoring & Observability

### OpenTelemetry Integration
All operations are instrumented with OpenTelemetry:

```go
// Tracing is automatic
ctx, span := tracer.Start(ctx, "chain.execute")
defer span.End()

result, err := orchestrator.ExecuteChain(ctx, "my-chain", input)
```

### Metrics
Built-in metrics tracking:
- Chain execution count
- Success/failure rates
- Execution duration
- Token usage
- Provider performance

### Health Checks
```go
health := orchestrator.Health()
fmt.Printf("Status: %s\n", health.Status)
for key, value := range health.Details {
    fmt.Printf("%s: %s\n", key, value)
}
```

## 🧪 Testing

### Unit Tests
```bash
go test ./pkg/llm/... -v
go test ./test/llm/unit/... -v
```

### Integration Tests
```bash
go test ./test/llm/integration/... -v
```

### Example Test
```go
func TestMyChain(t *testing.T) {
    provider := &MockLLMProvider{}
    provider.On("Generate", mock.Anything, mock.Anything).Return(
        providers.GenerationResponse{Content: "test response"}, nil)
    
    chain := NewMyChain(provider)
    input := llm.ChainInput{"prompt": "test"}
    
    output, err := chain.Execute(context.Background(), input)
    assert.NoError(t, err)
    assert.Equal(t, "test response", output["response"])
}
```

## 🔧 Configuration

### Orchestrator Configuration
```go
config := llm.OrchestratorConfig{
    MaxConcurrentChains:  100,
    MaxConcurrentGraphs:  50,
    DefaultTimeout:       5 * time.Minute,
    EnableMetrics:        true,
    EnableTracing:        true,
    MemoryConfig: memory.MemoryConfig{
        VectorMemorySize: 10000,
        ConversationTTL:  24 * time.Hour,
    },
}
```

### Provider Configuration
```go
config := providers.ProviderConfig{
    Type:    providers.ProviderOpenAI,
    APIKey:  os.Getenv("OPENAI_API_KEY"),
    Model:   "gpt-4",
    Enabled: true,
    Limits: providers.ProviderLimits{
        RequestsPerMinute: 60,
        TokensPerMinute:   100000,
        MaxConcurrent:     10,
    },
}
```

## 🚀 Running the Demo

```bash
# Set your OpenAI API key
export OPENAI_API_KEY="your-api-key-here"

# Run the orchestrator demo
go run cmd/llm-orchestrator/main.go
```

## 📚 Next Steps

1. **Implement Additional Providers**: Add support for Anthropic, Azure OpenAI, local models
2. **Advanced Graph Workflows**: Implement state graph execution engine
3. **Enhanced Memory**: Add persistent storage and advanced retrieval
4. **Security Enhancements**: Expand attack patterns and detection capabilities
5. **Production Features**: Add rate limiting, circuit breakers, and advanced monitoring

## 🤝 Contributing

See the main project [Contributing Guide](../../CONTRIBUTING.md) for details on:
- Code standards
- Testing requirements
- Security considerations
- Documentation standards

---

**🛡️ Part of the HackAI Platform - Securing AI, One Chain at a Time 🛡️**
