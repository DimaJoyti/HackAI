# 🕸️ LangGraph State Management
## Advanced State Graph Execution Engine for HackAI

This package implements a comprehensive state graph execution engine for the HackAI platform, providing sophisticated workflow orchestration with conditional logic, state persistence, and specialized security testing nodes.

## 🏗️ Architecture

### Core Components

- **State Graph Engine**: Executes complex workflows with conditional branching
- **Node System**: Reusable components for different operations
- **Condition Engine**: Advanced conditional logic evaluation
- **State Persistence**: Save and restore graph execution state
- **Security Nodes**: Specialized nodes for AI security testing

### Package Structure

```
pkg/graph/
├── engine/              # Core state graph execution engine
│   └── state_graph.go   # Main state graph implementation
├── nodes/               # Node implementations
│   ├── base.go          # Base node types and utilities
│   ├── llm/             # LLM-specific nodes
│   │   └── llm_nodes.go # LLM interaction nodes
│   └── security/        # Security testing nodes
│       └── attack_nodes.go # Attack and vulnerability nodes
├── conditions/          # Conditional logic system
│   └── conditions.go    # Condition implementations
├── persistence/         # State persistence backends
│   └── persistence.go   # File and memory persistence
└── README.md           # This file
```

## 🚀 Quick Start

### Basic State Graph

```go
package main

import (
    "context"
    "github.com/dimajoyti/hackai/pkg/graph/engine"
    "github.com/dimajoyti/hackai/pkg/graph/nodes"
    "github.com/dimajoyti/hackai/pkg/graph/conditions"
    "github.com/dimajoyti/hackai/pkg/llm"
)

func main() {
    // Create a new state graph
    graph := engine.NewDefaultStateGraph("my-graph", "My Graph", "A simple workflow")
    
    // Create nodes
    startNode := nodes.NewStartNode("start", "Start Node")
    transformNode := nodes.NewTransformNode("transform", "Transform Data",
        nodes.NewSimpleDataTransformer(map[string]interface{}{
            "processed": true,
            "timestamp": time.Now(),
        }))
    endNode := nodes.NewEndNode("end", "End Node", 0)
    
    // Add nodes to graph
    graph.AddNode(startNode)
    graph.AddNode(transformNode)
    graph.AddNode(endNode)
    
    // Set start and end nodes
    graph.SetStartNode("start")
    graph.AddEndNode("end")
    
    // Add edges
    graph.AddEdge(llm.Edge{
        From: "start",
        To: "transform",
        Condition: &conditions.AlwaysCondition{},
    })
    graph.AddEdge(llm.Edge{
        From: "transform",
        To: "end",
        Condition: &conditions.AlwaysCondition{},
    })
    
    // Execute graph
    initialState := llm.GraphState{
        Data: map[string]interface{}{
            "input": "Hello, World!",
        },
    }
    
    finalState, err := graph.Execute(context.Background(), initialState)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Final state: %+v\n", finalState)
}
```

### Conditional Branching

```go
// Create a condition node
conditionNode := nodes.NewConditionNode("check_value", "Value Check",
    conditions.NewDataCondition("score", "gt", 80))

// Add conditional edges
graph.AddEdge(llm.Edge{
    From: "check_value",
    To: "high_score_path",
    Condition: conditions.NewDataCondition("condition_result", "eq", true),
})
graph.AddEdge(llm.Edge{
    From: "check_value", 
    To: "low_score_path",
    Condition: conditions.NewDataCondition("condition_result", "eq", false),
})
```

## 🧩 Node Types

### Base Nodes

#### StartNode
Initializes graph execution and sets up initial state.

```go
startNode := nodes.NewStartNode("start", "Start Node")
```

#### EndNode
Terminates graph execution with an exit code.

```go
endNode := nodes.NewEndNode("end", "End Node", 0) // Exit code 0 = success
```

#### TransformNode
Applies transformations to state data.

```go
transformer := nodes.NewSimpleDataTransformer(map[string]interface{}{
    "processed": true,
    "category": "important",
})
transformNode := nodes.NewTransformNode("transform", "Data Transform", transformer)
```

#### ConditionNode
Evaluates conditions and stores results in state.

```go
condition := conditions.NewDataCondition("value", "gt", 100)
conditionNode := nodes.NewConditionNode("condition", "Value Check", condition)
```

#### DelayNode
Introduces controlled delays in execution.

```go
delayNode := nodes.NewDelayNode("delay", "Wait 5 seconds", 5*time.Second)
```

#### LogNode
Logs information during graph execution.

```go
logNode := nodes.NewLogNode("log", "Log Progress", "Processing step completed", "info")
```

### LLM Nodes

#### LLMNode
Interacts with Language Models for text generation.

```go
llmNode := llm.NewLLMNode("generate", "Text Generation", provider, 
    "Generate a summary of: {{input_text}}")
llmNode.SetTemperature(0.7)
llmNode.SetMaxTokens(500)
```

#### PromptInjectionTestNode
Tests for prompt injection vulnerabilities.

```go
injectionNode := llm.NewPromptInjectionTestNode("injection_test", "Injection Test", 
    provider, "Tell me about AI safety")
```

#### ModelExtractionNode
Attempts to extract information about the target model.

```go
extractionNode := llm.NewModelExtractionNode("extraction", "Model Extraction", provider)
```

#### EmbeddingNode
Generates embeddings for text data.

```go
embeddingNode := llm.NewEmbeddingNode("embed", "Generate Embeddings", provider, "text_key")
```

### Security Nodes

#### AttackPlannerNode
Plans and coordinates security attack strategies.

```go
plannerNode := security.NewAttackPlannerNode("planner", "Attack Planner",
    []string{"prompt_injection", "jailbreaking", "information_disclosure"})
```

#### VulnerabilityScanner
Scans for vulnerabilities in target systems.

```go
scannerNode := security.NewVulnerabilityScanner("scanner", "Vuln Scanner", provider)
```

#### ExploitExecutorNode
Executes specific exploits against discovered vulnerabilities.

```go
exploitNode := security.NewExploitExecutorNode("exploit", "Exploit Executor", 
    provider, "prompt_injection")
```

#### ReportGeneratorNode
Generates comprehensive attack reports.

```go
reportNode := security.NewReportGeneratorNode("report", "Report Generator", "json")
```

## 🔀 Conditions

### Basic Conditions

```go
// Always true
always := &conditions.AlwaysCondition{}

// Always false  
never := &conditions.NeverCondition{}

// Data-based conditions
dataCondition := conditions.NewDataCondition("score", "gt", 85)
stringCondition := conditions.NewDataCondition("status", "eq", "active")
containsCondition := conditions.NewDataCondition("message", "contains", "error")
```

### Logical Conditions

```go
// AND condition
andCondition := conditions.NewAndCondition(
    conditions.NewDataCondition("score", "gt", 80),
    conditions.NewDataCondition("status", "eq", "active"),
)

// OR condition
orCondition := conditions.NewOrCondition(
    conditions.NewDataCondition("priority", "eq", "high"),
    conditions.NewDataCondition("urgent", "eq", true),
)

// NOT condition
notCondition := conditions.NewNotCondition(
    conditions.NewDataCondition("disabled", "eq", true),
)
```

### Status Conditions

```go
// Success condition
successCondition := conditions.NewSuccessCondition("operation_result")

// Error condition
errorCondition := conditions.NewErrorCondition("last_error")

// Count condition
countCondition := conditions.NewCountCondition("attempts", "lt", 3)
```

## 💾 State Persistence

### File Persistence

```go
persistence, err := persistence.NewFilePersistence("./graph_states")
if err != nil {
    panic(err)
}

graph.SetPersistence(persistence)

// State is automatically saved at checkpoints
// Manual save/load also available
err = persistence.SaveState(ctx, "my-graph-state", state)
loadedState, err := persistence.LoadState(ctx, "my-graph-state")
```

### In-Memory Persistence

```go
persistence := persistence.NewInMemoryPersistence()
graph.SetPersistence(persistence)
```

### Persistence Manager

```go
// Use multiple persistence backends
primary := persistence.NewFilePersistence("./primary")
secondary := persistence.NewInMemoryPersistence()

config := persistence.PersistenceConfig{
    EnableBackup: true,
    BackupInterval: 5 * time.Minute,
}

manager := persistence.NewPersistenceManager(primary, secondary, config)
graph.SetPersistence(manager)
```

## ⚙️ Configuration

### Graph Configuration

```go
config := engine.GraphConfig{
    MaxExecutionTime:   30 * time.Minute,
    MaxSteps:          1000,
    EnablePersistence: true,
    EnableCheckpoints: true,
    CheckpointInterval: 10,
    RetryPolicy: engine.RetryPolicy{
        MaxRetries:    3,
        BackoffFactor: 2.0,
        InitialDelay:  time.Second,
        MaxDelay:      30 * time.Second,
    },
}

graph.SetConfig(config)
```

### Node Configuration

```go
nodeConfig := nodes.NodeConfig{
    Timeout:       30 * time.Second,
    MaxRetries:    3,
    EnableTracing: true,
    Parameters: map[string]interface{}{
        "custom_param": "value",
    },
}

node.SetConfig(nodeConfig)
```

## 🔒 Security Attack Workflows

### Complete Attack Graph

```go
// Create security attack workflow
graph := engine.NewDefaultStateGraph("security-attack", "Security Attack", "AI security testing")

// Attack planning
planner := security.NewAttackPlannerNode("planner", "Attack Planner", 
    []string{"prompt_injection", "jailbreaking"})

// Vulnerability scanning
scanner := security.NewVulnerabilityScanner("scanner", "Vuln Scanner", provider)

// Exploit execution
injectionExploit := security.NewExploitExecutorNode("injection", "Injection Exploit", 
    provider, "prompt_injection")
jailbreakExploit := security.NewExploitExecutorNode("jailbreak", "Jailbreak Exploit", 
    provider, "jailbreaking")

// Report generation
reporter := security.NewReportGeneratorNode("report", "Attack Report", "json")

// Build the graph with conditional execution based on discovered vulnerabilities
// ... add nodes and edges with appropriate conditions
```

## 📊 Monitoring & Observability

### OpenTelemetry Integration

All graph and node executions are automatically instrumented with OpenTelemetry:

```go
// Tracing is automatic - spans are created for:
// - Graph execution
// - Node execution  
// - Condition evaluation
// - State transitions

// Custom attributes are added for:
// - Graph ID and name
// - Node types and IDs
// - Execution duration
// - Success/failure status
// - State data summaries
```

### Execution Statistics

```go
// Graph execution creates detailed history
finalState, err := graph.Execute(ctx, initialState)

// Access execution history
for _, transition := range finalState.History {
    fmt.Printf("Transition: %s -> %s at %s\n", 
        transition.From, transition.To, transition.Timestamp)
}

// Check execution metadata
duration := finalState.UpdateTime.Sub(finalState.StartTime)
fmt.Printf("Total execution time: %s\n", duration)
```

## 🧪 Testing

### Unit Tests

```bash
go test ./pkg/graph/... -v
go test ./test/llm/unit/state_graph_test.go -v
```

### Demo Application

```bash
# Build and run the demo
go build ./cmd/graph-demo
./graph-demo

# With OpenAI API key for security demo
OPENAI_API_KEY=your-key ./graph-demo
```

## 🔧 Advanced Features

### Custom Node Types

```go
// Implement the Node interface
type CustomNode struct {
    *nodes.BaseNode
    customLogic CustomLogic
}

func (n *CustomNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
    // Your custom logic here
    result, err := n.customLogic.Process(state.Data)
    if err != nil {
        return state, err
    }
    
    state.Data["custom_result"] = result
    return state, nil
}
```

### Custom Conditions

```go
// Implement the Condition interface
type CustomCondition struct {
    threshold float64
}

func (c *CustomCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
    // Your custom condition logic
    value, exists := state.Data["custom_metric"]
    if !exists {
        return false, nil
    }
    
    if metric, ok := value.(float64); ok {
        return metric > c.threshold, nil
    }
    
    return false, nil
}

func (c *CustomCondition) String() string {
    return fmt.Sprintf("custom_metric > %f", c.threshold)
}
```

### Error Handling and Recovery

```go
// Graphs automatically handle:
// - Node execution failures with retry logic
// - Timeout management
// - State persistence for recovery
// - Graceful shutdown on context cancellation

// Custom error handling in nodes
func (n *MyNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
    defer func() {
        if r := recover(); r != nil {
            // Handle panics gracefully
            state.Data["error"] = fmt.Sprintf("panic: %v", r)
        }
    }()
    
    // Your node logic with error handling
    return state, nil
}
```

---

**🕸️ Building Complex AI Security Workflows with State Graphs 🕸️**

*This state graph system enables sophisticated AI security testing workflows with conditional logic, state persistence, and comprehensive monitoring capabilities.*
