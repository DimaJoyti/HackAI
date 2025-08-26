# 🎓 LangGraph Tutorial: Building AI Agents with HackAI
## Complete Guide to Advanced Agent Development

[![Tutorial](https://img.shields.io/badge/Tutorial-Complete-green.svg)](https://github.com/DimaJoyti/HackAI)
[![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-orange.svg)](https://github.com/DimaJoyti/HackAI)
[![Time](https://img.shields.io/badge/Time-2--3%20hours-blue.svg)](https://github.com/DimaJoyti/HackAI)

> **Master the art of building sophisticated AI agents** with HackAI's LangGraph implementation. This tutorial covers everything from basic concepts to advanced multi-agent systems.

## 📚 Table of Contents

1. [Introduction to LangGraph](#introduction)
2. [Setting Up Your Environment](#setup)
3. [Basic Concepts](#concepts)
4. [Building Your First Agent](#first-agent)
5. [Advanced Agent Patterns](#advanced-patterns)
6. [Multi-Agent Systems](#multi-agent)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

## 🌟 Introduction to LangGraph {#introduction}

LangGraph is a framework for building stateful, multi-actor applications with LLMs. In HackAI, we've implemented a Go-native version that provides:

- **State Management**: Persistent state across agent interactions
- **Checkpointing**: Automatic state saving and recovery
- **Parallel Execution**: Multi-branch workflows with intelligent merging
- **Tool Integration**: Seamless integration with external tools and APIs
- **Event-Driven Architecture**: Real-time communication between agents

### Why LangGraph?

Traditional chatbots are stateless and limited to single interactions. LangGraph enables:

- **Complex Workflows**: Multi-step processes with decision points
- **Memory**: Agents remember previous interactions and context
- **Collaboration**: Multiple agents working together on complex tasks
- **Reliability**: Fault tolerance with checkpointing and recovery

## 🛠️ Setting Up Your Environment {#setup}

### Prerequisites

- Go 1.22 or later
- Basic understanding of Go programming
- Familiarity with AI/LLM concepts

### Installation

```bash
# Clone the HackAI repository
git clone https://github.com/DimaJoyti/HackAI.git
cd HackAI

# Install dependencies
go mod tidy

# Verify installation
go test ./pkg/langgraph/...
```

### Project Structure

```
your-project/
├── main.go
├── agents/
│   ├── security_agent.go
│   └── analysis_agent.go
├── tools/
│   ├── scanner.go
│   └── reporter.go
└── config/
    └── agent_config.yaml
```

## 🧠 Basic Concepts {#concepts}

### State Management

Every LangGraph execution maintains state that persists across nodes:

```go
type GraphState struct {
    CurrentNode string                 `json:"current_node"`
    StartTime   time.Time              `json:"start_time"`
    Data        map[string]interface{} `json:"data"`
    Metadata    map[string]interface{} `json:"metadata"`
}
```

### Nodes and Edges

- **Nodes**: Individual processing units (agents, tools, decision points)
- **Edges**: Connections between nodes that define workflow flow
- **Conditional Edges**: Dynamic routing based on state or conditions

### Checkpointing

Automatic state persistence enables:
- Recovery from failures
- Resuming long-running processes
- Debugging and analysis
- State inspection and modification

## 🤖 Building Your First Agent {#first-agent}

Let's build a simple security analysis agent step by step.

### Step 1: Define the Agent Structure

```go
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/dimajoyti/hackai/pkg/langgraph/engine"
    "github.com/dimajoyti/hackai/pkg/langgraph/storage"
    "github.com/dimajoyti/hackai/pkg/llm"
    "github.com/dimajoyti/hackai/pkg/logger"
)

type SecurityAgent struct {
    ID       string
    Name     string
    Graph    *engine.LangGraphStateGraph
    Tools    map[string]Tool
    Logger   *logger.Logger
}

func NewSecurityAgent(id, name string, logger *logger.Logger) *SecurityAgent {
    // Create base graph
    baseGraph := engine.NewDefaultStateGraph(id, name)
    
    // Configure LangGraph features
    config := &engine.LangGraphConfig{
        EnableCheckpointing:     true,
        CheckpointInterval:      time.Minute * 2,
        EnableParallelExecution: true,
        MaxParallelBranches:     3,
        EnableEventSystem:       true,
        EnableMessagePassing:    true,
    }
    
    // Create enhanced graph
    langGraph := engine.NewLangGraphStateGraph(baseGraph, config, logger)
    
    return &SecurityAgent{
        ID:     id,
        Name:   name,
        Graph:  langGraph,
        Tools:  make(map[string]Tool),
        Logger: logger,
    }
}
```

### Step 2: Add Tools

```go
// Tool interface
type Tool interface {
    ID() string
    Name() string
    Description() string
    Execute(ctx context.Context, input map[string]interface{}) (interface{}, error)
    Validate(input map[string]interface{}) error
}

// Port scanner tool
type PortScannerTool struct {
    timeout time.Duration
}

func NewPortScannerTool() *PortScannerTool {
    return &PortScannerTool{
        timeout: 30 * time.Second,
    }
}

func (p *PortScannerTool) ID() string { return "port_scanner" }
func (p *PortScannerTool) Name() string { return "Port Scanner" }
func (p *PortScannerTool) Description() string { 
    return "Scans target for open ports and services" 
}

func (p *PortScannerTool) Execute(ctx context.Context, input map[string]interface{}) (interface{}, error) {
    target, ok := input["target"].(string)
    if !ok {
        return nil, fmt.Errorf("target must be a string")
    }
    
    // Simulate port scanning
    time.Sleep(2 * time.Second)
    
    return map[string]interface{}{
        "target": target,
        "open_ports": []int{22, 80, 443, 8080},
        "services": map[int]string{
            22:   "SSH",
            80:   "HTTP",
            443:  "HTTPS",
            8080: "HTTP-Alt",
        },
        "scan_time": time.Now(),
    }, nil
}

func (p *PortScannerTool) Validate(input map[string]interface{}) error {
    if _, ok := input["target"]; !ok {
        return fmt.Errorf("target parameter is required")
    }
    return nil
}

// Register tool with agent
func (sa *SecurityAgent) RegisterTool(tool Tool) {
    sa.Tools[tool.ID()] = tool
    sa.Logger.Info("Tool registered", "agent_id", sa.ID, "tool_id", tool.ID())
}
```

### Step 3: Define the Workflow

```go
func (sa *SecurityAgent) BuildWorkflow() error {
    // Add nodes
    sa.Graph.AddNode(&AnalysisNode{agent: sa})
    sa.Graph.AddNode(&ScanNode{agent: sa})
    sa.Graph.AddNode(&ReportNode{agent: sa})
    
    // Add edges
    sa.Graph.AddEdge(llm.Edge{From: "analysis", To: "scan"})
    sa.Graph.AddEdge(llm.Edge{From: "scan", To: "report"})
    
    // Set entry point
    sa.Graph.SetEntryPoint("analysis")
    
    return nil
}

// Analysis node
type AnalysisNode struct {
    agent *SecurityAgent
}

func (n *AnalysisNode) ID() string { return "analysis" }
func (n *AnalysisNode) Name() string { return "Target Analysis" }

func (n *AnalysisNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
    target := state.Data["target"].(string)
    
    // Analyze target
    analysis := map[string]interface{}{
        "target_type": "web_application",
        "priority": "high",
        "scan_strategy": "comprehensive",
    }
    
    state.Data["analysis"] = analysis
    state.CurrentNode = "scan"
    
    n.agent.Logger.Info("Target analysis completed", "target", target)
    return state, nil
}

func (n *AnalysisNode) Validate() error { return nil }
```

### Step 4: Execute the Agent

```go
func main() {
    logger := logger.NewDefault()
    
    // Create agent
    agent := NewSecurityAgent("sec-agent-1", "Security Analyzer", logger)
    
    // Register tools
    agent.RegisterTool(NewPortScannerTool())
    agent.RegisterTool(NewVulnerabilityScannerTool())
    agent.RegisterTool(NewReportGeneratorTool())
    
    // Build workflow
    if err := agent.BuildWorkflow(); err != nil {
        log.Fatal(err)
    }
    
    // Execute
    ctx := context.Background()
    initialState := llm.GraphState{
        CurrentNode: "analysis",
        StartTime:   time.Now(),
        Data: map[string]interface{}{
            "target": "example.com",
            "scan_type": "comprehensive",
        },
    }
    
    result, err := agent.Graph.ExecuteWithCheckpointing(ctx, initialState)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Security analysis completed: %+v\n", result.Data)
}
```

## 🚀 Advanced Agent Patterns {#advanced-patterns}

### ReAct (Reasoning + Acting) Pattern

The ReAct pattern combines reasoning and acting in iterative cycles:

```go
type ReActAgent struct {
    *SecurityAgent
    maxIterations int
    reasoningEngine *ReasoningEngine
    actionPlanner   *ActionPlanner
}

func (ra *ReActAgent) Execute(ctx context.Context, query string) (*AgentResult, error) {
    thoughts := make([]Thought, 0)
    actions := make([]Action, 0)
    
    for iteration := 1; iteration <= ra.maxIterations; iteration++ {
        // Reasoning phase
        thought, err := ra.reasoningEngine.Think(ctx, query, thoughts, actions)
        if err != nil {
            return nil, err
        }
        thoughts = append(thoughts, thought)
        
        // Action planning
        action, err := ra.actionPlanner.Plan(ctx, thought, ra.Tools)
        if err != nil {
            return nil, err
        }
        
        if action == nil {
            // Agent has reached conclusion
            break
        }
        
        // Execute action
        result, err := ra.executeAction(ctx, action)
        action.Result = result
        action.Error = err
        actions = append(actions, *action)
        
        // Check if we should continue
        if ra.shouldStop(thoughts, actions) {
            break
        }
    }
    
    return &AgentResult{
        Thoughts:   thoughts,
        Actions:    actions,
        Iterations: len(thoughts),
    }, nil
}
```

### Plan-and-Execute Pattern

For complex, multi-step tasks:

```go
type PlanAndExecuteAgent struct {
    *SecurityAgent
    planner   *TaskPlanner
    executor  *TaskExecutor
    monitor   *ExecutionMonitor
}

func (pea *PlanAndExecuteAgent) Execute(ctx context.Context, objective string) (*ExecutionResult, error) {
    // Create high-level plan
    plan, err := pea.planner.CreatePlan(ctx, objective)
    if err != nil {
        return nil, err
    }
    
    // Execute plan with monitoring
    for _, task := range plan.Tasks {
        result, err := pea.executor.ExecuteTask(ctx, task)
        if err != nil {
            // Replan if needed
            newPlan, replanErr := pea.planner.Replan(ctx, plan, task, err)
            if replanErr != nil {
                return nil, fmt.Errorf("execution failed and replanning failed: %w", err)
            }
            plan = newPlan
            continue
        }
        
        // Update plan based on results
        plan = pea.monitor.UpdatePlan(ctx, plan, task, result)
    }
    
    return &ExecutionResult{
        Plan:      plan,
        Completed: true,
    }, nil
}
```

## 🤝 Multi-Agent Systems {#multi-agent}

### Agent Communication

```go
type MultiAgentSystem struct {
    agents        map[string]Agent
    messageRouter *messaging.MessageRouter
    coordinator   *AgentCoordinator
    logger        *logger.Logger
}

func (mas *MultiAgentSystem) StartCollaboration(ctx context.Context, task CollaborativeTask) error {
    // Distribute task among agents
    subtasks, err := mas.coordinator.DistributeTask(ctx, task)
    if err != nil {
        return err
    }
    
    // Start agents
    for agentID, subtask := range subtasks {
        agent := mas.agents[agentID]
        go agent.ExecuteAsync(ctx, subtask)
    }
    
    // Monitor progress and coordinate
    return mas.coordinator.MonitorAndCoordinate(ctx, subtasks)
}
```

### Message Passing

```go
// Send message between agents
message := &messaging.AgentMessage{
    From:    "scanner-agent",
    To:      []string{"analysis-agent"},
    Type:    messaging.MessageTypeData,
    Content: scanResults,
    Priority: messaging.PriorityHigh,
}

err := messageRouter.RouteMessage(ctx, message)
```

## 💡 Best Practices {#best-practices}

### 1. State Management

```go
// ✅ Good: Clear state structure
type SecurityState struct {
    Target      string                 `json:"target"`
    ScanResults map[string]interface{} `json:"scan_results"`
    Findings    []SecurityFinding      `json:"findings"`
    Status      string                 `json:"status"`
}

// ❌ Bad: Unstructured state
state.Data["random_key"] = "random_value"
```

### 2. Error Handling

```go
// ✅ Good: Comprehensive error handling
func (n *ScanNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
    tool, exists := n.agent.Tools["port_scanner"]
    if !exists {
        return state, fmt.Errorf("port_scanner tool not available")
    }
    
    result, err := tool.Execute(ctx, map[string]interface{}{
        "target": state.Data["target"],
    })
    if err != nil {
        // Log error but continue with partial results
        n.agent.Logger.Error("Port scan failed", "error", err)
        state.Data["scan_error"] = err.Error()
        return state, nil
    }
    
    state.Data["scan_results"] = result
    return state, nil
}
```

### 3. Tool Validation

```go
// ✅ Good: Validate inputs before execution
func (t *VulnerabilityScannerTool) Execute(ctx context.Context, input map[string]interface{}) (interface{}, error) {
    if err := t.Validate(input); err != nil {
        return nil, fmt.Errorf("validation failed: %w", err)
    }
    
    // Execute tool logic
    return t.performScan(ctx, input)
}

func (t *VulnerabilityScannerTool) Validate(input map[string]interface{}) error {
    target, ok := input["target"].(string)
    if !ok || target == "" {
        return fmt.Errorf("target must be a non-empty string")
    }
    
    if !isValidTarget(target) {
        return fmt.Errorf("invalid target format: %s", target)
    }
    
    return nil
}
```

### 4. Checkpointing Strategy

```go
// ✅ Good: Strategic checkpointing
config := &engine.LangGraphConfig{
    EnableCheckpointing: true,
    CheckpointInterval:  time.Minute * 5, // Not too frequent
    RetentionPolicy: storage.RetentionPolicy{
        MaxCheckpoints: 10,    // Reasonable limit
        MaxAge:        time.Hour * 24, // Clean up old checkpoints
    },
}
```

### 5. Observability

```go
// ✅ Good: Comprehensive logging and metrics
func (sa *SecurityAgent) Execute(ctx context.Context, input AgentInput) (*AgentResult, error) {
    ctx, span := tracer.Start(ctx, "security_agent.execute")
    defer span.End()
    
    startTime := time.Now()
    
    span.SetAttributes(
        attribute.String("agent.id", sa.ID),
        attribute.String("target", input.Target),
    )
    
    result, err := sa.performAnalysis(ctx, input)
    
    duration := time.Since(startTime)
    span.SetAttributes(
        attribute.Float64("execution.duration", duration.Seconds()),
        attribute.Bool("execution.success", err == nil),
    )
    
    sa.Logger.Info("Agent execution completed",
        "agent_id", sa.ID,
        "duration", duration,
        "success", err == nil)
    
    return result, err
}
```

## 🔧 Troubleshooting {#troubleshooting}

### Common Issues

#### 1. State Not Persisting

**Problem**: State changes are lost between nodes.

**Solution**: Ensure you're returning the modified state:

```go
// ✅ Correct
func (n *ProcessingNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
    state.Data["processed"] = true
    return state, nil // Return modified state
}

// ❌ Incorrect
func (n *ProcessingNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
    state.Data["processed"] = true
    return llm.GraphState{}, nil // Returns empty state
}
```

#### 2. Tool Execution Failures

**Problem**: Tools fail with unclear errors.

**Solution**: Add comprehensive validation and error handling:

```go
func (t *CustomTool) Execute(ctx context.Context, input map[string]interface{}) (interface{}, error) {
    // Validate input
    if err := t.Validate(input); err != nil {
        return nil, fmt.Errorf("input validation failed: %w", err)
    }
    
    // Add timeout
    ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()
    
    // Execute with error handling
    result, err := t.performOperation(ctx, input)
    if err != nil {
        return nil, fmt.Errorf("operation failed: %w", err)
    }
    
    return result, nil
}
```

#### 3. Memory Leaks in Long-Running Agents

**Problem**: Agents consume increasing memory over time.

**Solution**: Implement proper cleanup and resource management:

```go
type Agent struct {
    // ... other fields
    cleanup chan struct{}
    wg      sync.WaitGroup
}

func (a *Agent) Start(ctx context.Context) error {
    a.wg.Add(1)
    go func() {
        defer a.wg.Done()
        ticker := time.NewTicker(time.Minute * 10)
        defer ticker.Stop()
        
        for {
            select {
            case <-ticker.C:
                a.performCleanup()
            case <-a.cleanup:
                return
            case <-ctx.Done():
                return
            }
        }
    }()
    
    return nil
}

func (a *Agent) Stop() error {
    close(a.cleanup)
    a.wg.Wait()
    return nil
}
```

### Performance Optimization

#### 1. Parallel Tool Execution

```go
// Execute multiple tools in parallel
func (sa *SecurityAgent) executeToolsParallel(ctx context.Context, tools []Tool, input map[string]interface{}) (map[string]interface{}, error) {
    results := make(map[string]interface{})
    var mu sync.Mutex
    var wg sync.WaitGroup
    
    for _, tool := range tools {
        wg.Add(1)
        go func(t Tool) {
            defer wg.Done()
            
            result, err := t.Execute(ctx, input)
            
            mu.Lock()
            defer mu.Unlock()
            
            if err != nil {
                results[t.ID()+"_error"] = err.Error()
            } else {
                results[t.ID()] = result
            }
        }(tool)
    }
    
    wg.Wait()
    return results, nil
}
```

#### 2. Efficient State Management

```go
// Use structured state instead of generic maps
type StructuredState struct {
    Target      string            `json:"target"`
    ScanResults []ScanResult      `json:"scan_results"`
    Metadata    map[string]string `json:"metadata"`
}

// Convert to/from GraphState
func (ss *StructuredState) ToGraphState() llm.GraphState {
    data, _ := json.Marshal(ss)
    var genericData map[string]interface{}
    json.Unmarshal(data, &genericData)
    
    return llm.GraphState{
        Data: genericData,
    }
}
```

## 🎯 Next Steps

1. **Explore Advanced Patterns**: Try implementing custom agent patterns for your specific use cases
2. **Build Custom Tools**: Create domain-specific tools for your applications
3. **Implement Multi-Agent Systems**: Design collaborative agent workflows
4. **Add Monitoring**: Integrate comprehensive observability and monitoring
5. **Optimize Performance**: Profile and optimize your agent implementations

## 📚 Additional Resources

- [LangGraph Architecture Guide](LANGGRAPH_AGENT_ARCHITECTURE.md)
- [Implementation Plan](LANGGRAPH_IMPLEMENTATION_PLAN.md)
- [API Documentation](../pkg/langgraph/README.md)
- [Example Applications](../cmd/)

Happy building! 🚀
