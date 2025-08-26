# 🤖 LangGraph for HackAI
## Advanced AI Agent Framework with State Management

[![Go](https://img.shields.io/badge/Go-1.22+-blue.svg)](https://golang.org)
[![LangGraph](https://img.shields.io/badge/LangGraph-Inspired-green.svg)](https://langgraph.com)
[![AI Agents](https://img.shields.io/badge/AI%20Agents-Multi--Agent-purple.svg)](https://github.com/DimaJoyti/HackAI)

> **Production-ready LangGraph implementation for Go** - Build sophisticated AI agents with state management, checkpointing, parallel execution, and multi-agent collaboration.

## 🌟 Features

### Core Capabilities
- **🔄 Enhanced StateGraph**: Advanced state management with checkpointing and recovery
- **🤖 Agent Types**: ReAct, Plan-and-Execute, Multi-Agent Collaborator patterns
- **🛠️ Tool Integration**: Comprehensive tool system with validation and error handling
- **💾 Checkpointing**: Automatic state persistence and recovery
- **⚡ Parallel Execution**: Multi-branch execution with conflict resolution
- **📡 Event System**: Event-driven architecture for agent communication
- **💬 Message Routing**: Agent-to-agent communication with middleware support
- **🔍 Observability**: Full OpenTelemetry integration with metrics and tracing

### Advanced Features
- **🌿 Branch Management**: Parallel execution with intelligent merging
- **🧠 Memory Systems**: Working, episodic, and semantic memory
- **🔐 Security Integration**: Built-in security testing and vulnerability assessment
- **📊 Analytics**: Real-time performance monitoring and analytics
- **🎯 Conditional Routing**: Advanced decision-making and flow control

## 🏗️ Architecture

```
pkg/langgraph/
├── engine/                 # Enhanced StateGraph engine
│   └── enhanced_state_graph.go
├── storage/                # Checkpointing and persistence
│   └── checkpoint_storage.go
├── parallel/               # Parallel execution engine
│   └── execution.go
├── branching/              # Branch management and merging
│   └── branch_manager.go
├── messaging/              # Event system and message routing
│   └── event_system.go
├── agents/                 # Agent implementations
│   ├── react/             # ReAct agent pattern
│   ├── planexecute/       # Plan-and-Execute pattern
│   └── multiagent/        # Multi-agent collaboration
├── tools/                  # Tool integration system
│   └── registry.go
└── memory/                 # Memory management systems
    └── memory_manager.go
```

## 🚀 Quick Start

### Basic StateGraph with Checkpointing

```go
package main

import (
    "context"
    "github.com/dimajoyti/hackai/pkg/langgraph/engine"
    "github.com/dimajoyti/hackai/pkg/langgraph/storage"
    "github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
    logger := logger.NewDefault()
    
    // Create enhanced state graph
    config := &engine.LangGraphConfig{
        EnableCheckpointing:     true,
        CheckpointInterval:      time.Minute * 5,
        EnableParallelExecution: true,
        MaxParallelBranches:     4,
    }
    
    baseGraph := engine.NewDefaultStateGraph("demo-graph", "Demo Graph")
    langGraph := engine.NewLangGraphStateGraph(baseGraph, config, logger)
    
    // Execute with automatic checkpointing
    ctx := context.Background()
    initialState := llm.GraphState{
        CurrentNode: "start",
        Data: map[string]interface{}{
            "input": "Hello, LangGraph!",
        },
    }
    
    result, err := langGraph.ExecuteWithCheckpointing(ctx, initialState)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Execution completed: %+v\n", result)
}
```

### ReAct Agent Pattern

```go
package main

import (
    "context"
    "github.com/dimajoyti/hackai/pkg/langgraph/agents/react"
    "github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
    logger := logger.NewDefault()
    
    // Create ReAct agent
    agent := react.NewReActAgent("security-agent", logger)
    
    // Register tools
    agent.RegisterTool(NewSecurityScanTool())
    agent.RegisterTool(NewVulnerabilityAnalyzer())
    agent.RegisterTool(NewReportGenerator())
    
    // Execute reasoning and action cycle
    ctx := context.Background()
    input := react.AgentInput{
        Query: "Analyze the security of example.com and generate a report",
        Context: make(map[string]interface{}),
    }
    
    result, err := agent.Execute(ctx, input)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Agent completed in %d iterations: %s\n", 
        result.Iterations, result.Output)
}
```

### Multi-Agent Collaboration

```go
package main

import (
    "context"
    "github.com/dimajoyti/hackai/pkg/langgraph/messaging"
    "github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
    logger := logger.NewDefault()
    
    // Create message router
    router := messaging.NewMessageRouter(logger)
    
    // Create agents
    analyst := NewAnalystAgent("analyst-1", router, logger)
    scanner := NewScannerAgent("scanner-1", router, logger)
    reporter := NewReporterAgent("reporter-1", router, logger)
    
    // Start collaboration
    ctx := context.Background()
    
    // Analyst requests scan
    message := &messaging.AgentMessage{
        From: "analyst-1",
        To:   []string{"scanner-1"},
        Type: messaging.MessageTypeRequest,
        Content: map[string]interface{}{
            "target": "example.com",
            "scan_type": "comprehensive",
        },
    }
    
    err := router.RouteMessage(ctx, message)
    if err != nil {
        log.Fatal(err)
    }
}
```

## 🛠️ Tool Integration

### Creating Custom Tools

```go
type CustomSecurityTool struct {
    name        string
    description string
    scanner     SecurityScanner
}

func (t *CustomSecurityTool) ID() string {
    return "custom_security_tool"
}

func (t *CustomSecurityTool) Execute(ctx context.Context, input ToolInput) (ToolOutput, error) {
    target := input.GetString("target")
    
    // Perform security scan
    results, err := t.scanner.Scan(ctx, target)
    if err != nil {
        return ToolOutput{}, err
    }
    
    return ToolOutput{
        Success: true,
        Data: map[string]interface{}{
            "vulnerabilities": results.Vulnerabilities,
            "risk_score": results.RiskScore,
            "recommendations": results.Recommendations,
        },
    }, nil
}

func (t *CustomSecurityTool) Validate(input ToolInput) error {
    if !input.HasField("target") {
        return fmt.Errorf("target field is required")
    }
    return nil
}
```

### Tool Registry

```go
// Register tools with the registry
registry := tools.NewToolRegistry(logger)

registry.RegisterTool(NewWebSearchTool())
registry.RegisterTool(NewDatabaseTool())
registry.RegisterTool(NewAPITool())
registry.RegisterTool(NewSecurityScanTool())

// Execute tool with validation
result, err := registry.ExecuteTool(ctx, "security_scan", ToolInput{
    "target": "example.com",
    "scan_type": "full",
})
```

## 📊 Event System

### Publishing Events

```go
eventSystem := messaging.NewEventSystem(logger)

// Create event
event := messaging.CreateEvent(
    messaging.EventTypeNodeStarted,
    "security-agent",
    map[string]interface{}{
        "node_id": "vulnerability_scan",
        "target": "example.com",
    },
)

// Publish event
err := eventSystem.PublishEvent(ctx, event)
```

### Event Handlers

```go
// Create custom event handler
handler := messaging.NewDefaultEventHandler(
    []messaging.EventType{messaging.EventTypeNodeCompleted},
    func(ctx context.Context, event *messaging.Event) error {
        fmt.Printf("Node completed: %s\n", event.Data["node_id"])
        return nil
    },
)

// Subscribe to events
eventSystem.Subscribe(messaging.EventTypeNodeCompleted, handler)
```

## 💾 Checkpointing

### Automatic Checkpointing

```go
// Configure automatic checkpointing
config := &engine.LangGraphConfig{
    EnableCheckpointing: true,
    CheckpointInterval:  time.Minute * 5,
    RetentionPolicy: storage.RetentionPolicy{
        MaxCheckpoints: 10,
        MaxAge:        time.Hour * 24,
    },
}

// Checkpoints are created automatically during execution
result, err := langGraph.ExecuteWithCheckpointing(ctx, initialState)
```

### Manual Checkpointing

```go
// Create checkpoint manually
checkpoint, err := langGraph.CreateCheckpoint(ctx, "current_node", currentState)
if err != nil {
    log.Fatal(err)
}

// Restore from checkpoint
restoredState, err := langGraph.RestoreFromCheckpoint(ctx, checkpoint.ID)
if err != nil {
    log.Fatal(err)
}
```

## ⚡ Parallel Execution

### Branch Execution

```go
// Execute multiple branches in parallel
branches := []string{"security_scan", "performance_test", "compliance_check"}

result, err := langGraph.ExecuteParallel(ctx, branches, initialState)
if err != nil {
    log.Fatal(err)
}

// Handle merged results
fmt.Printf("Merged state: %+v\n", result.State)
fmt.Printf("Conflicts resolved: %d\n", len(result.Conflicts))
```

## 🔍 Monitoring and Observability

### OpenTelemetry Integration

```go
// Tracing is automatically enabled
ctx, span := tracer.Start(ctx, "agent_execution")
defer span.End()

// Metrics are collected automatically
span.SetAttributes(
    attribute.String("agent.id", agent.ID),
    attribute.Int("agent.iterations", result.Iterations),
    attribute.Float64("agent.duration", result.Duration.Seconds()),
)
```

### Performance Metrics

```go
// Access agent metrics
metrics := agent.GetMetrics()
fmt.Printf("Execution time: %v\n", metrics.ExecutionTime)
fmt.Printf("Tool usage: %+v\n", metrics.ToolUsage)
fmt.Printf("Success rate: %.2f%%\n", metrics.SuccessRate*100)
```

## 🧪 Testing

### Running Demos

```bash
# Basic LangGraph demo
go run cmd/langgraph-demo/main.go

# ReAct agent demo
go run cmd/react-agent-demo/main.go

# Multi-agent collaboration demo
go run cmd/multiagent-demo/main.go
```

### Unit Tests

```bash
# Run all tests
go test ./pkg/langgraph/...

# Run with coverage
go test -cover ./pkg/langgraph/...

# Run specific test
go test ./pkg/langgraph/engine -v
```

## 📚 Examples

See the `cmd/` directory for comprehensive examples:

- **`langgraph-demo/`**: Basic LangGraph features
- **`react-agent-demo/`**: ReAct agent pattern
- **`multiagent-demo/`**: Multi-agent collaboration
- **`security-agent-demo/`**: Security testing workflows
- **`parallel-execution-demo/`**: Parallel branch execution

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by [LangGraph](https://langgraph.com) by LangChain
- Built on HackAI's existing infrastructure
- Leverages Go's concurrency primitives for performance
