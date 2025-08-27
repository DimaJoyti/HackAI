# Multi-Agent Orchestration Integration Guide

## Quick Integration

### 1. Basic Setup

```go
package main

import (
    "context"
    "time"
    
    "github.com/dimajoyti/hackai/pkg/agents/multiagent"
    "github.com/dimajoyti/hackai/pkg/ai"
    "github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
    // Initialize logger
    logger, _ := logger.New(logger.Config{
        Level:  logger.LogLevelInfo,
        Format: "json",
    })

    // Configure orchestrator
    config := &multiagent.OrchestratorConfig{
        MaxConcurrentTasks:     5,
        TaskTimeout:            2 * time.Minute,
        ConflictResolutionMode: "consensus",
        ConsensusThreshold:     0.7,
        EnableLoadBalancing:    true,
        EnableFailover:         true,
        HealthCheckInterval:    30 * time.Second,
        MetricsEnabled:         true,
    }

    // Create orchestrator
    orchestrator := multiagent.NewMultiAgentOrchestrator(config, logger)

    // Register your agents
    orchestrator.RegisterAgent(mySecurityAgent)
    orchestrator.RegisterAgent(myAnalysisAgent)
    orchestrator.RegisterAgent(myStrategyAgent)

    // Start orchestrator
    ctx := context.Background()
    orchestrator.Start(ctx)
    defer orchestrator.Stop()

    // Execute multi-agent task
    task := createMultiAgentTask()
    result, err := orchestrator.ExecuteTask(ctx, task)
    if err != nil {
        logger.Error("Task failed", "error", err)
        return
    }

    logger.Info("Task completed", 
        "success", result.Success,
        "confidence", result.Confidence,
        "execution_time", result.ExecutionTime)
}
```

### 2. Creating Multi-Agent Tasks

```go
func createMultiAgentTask() *multiagent.MultiAgentTask {
    return &multiagent.MultiAgentTask{
        ID:          "analysis-task-001",
        Type:        "comprehensive_analysis",
        Priority:    multiagent.TaskPriorityHigh,
        Description: "Comprehensive analysis of market trends and security risks",
        
        // Specify required agents
        RequiredAgents: []string{
            "security-agent-1",
            "market-analyst-1",
        },
        
        // Optional agents for enhanced analysis
        OptionalAgents: []string{
            "strategy-advisor-1",
        },
        
        // Task constraints
        Constraints: []multiagent.TaskConstraint{
            {
                Type:        "time_limit",
                Value:       "5m",
                Description: "Must complete within 5 minutes",
            },
            {
                Type:        "confidence_threshold",
                Value:       0.8,
                Description: "Minimum 80% confidence required",
            },
        },
        
        // Task parameters
        Parameters: map[string]interface{}{
            "analysis_depth": "comprehensive",
            "include_risks":  true,
            "market_scope":   "global",
        },
        
        // Context information
        Context: map[string]interface{}{
            "industry":     "technology",
            "company_size": "enterprise",
            "urgency":      "high",
        },
        
        // Collaboration mode
        CollaborationMode: "parallel", // "sequential", "parallel", "consensus"
        CreatedAt:         time.Now(),
    }
}
```

### 3. Collaboration Modes

#### Parallel Collaboration
```go
task.CollaborationMode = "parallel"
// Agents work simultaneously, results aggregated
// Best for: Independent analysis tasks
// Execution time: Fastest (limited by slowest agent)
```

#### Sequential Collaboration  
```go
task.CollaborationMode = "sequential"
// Agents work in order, each building on previous results
// Best for: Multi-step workflows, dependent tasks
// Execution time: Sum of all agent execution times
```

#### Consensus Collaboration
```go
task.CollaborationMode = "consensus"
// Agents collaborate to reach agreement
// Best for: Decision making, critical choices
// Execution time: Variable (depends on consensus process)
```

### 4. Agent Implementation

Your agents must implement the `ai.Agent` interface:

```go
type MyCustomAgent struct {
    id          string
    name        string
    description string
    // ... other fields
}

func (a *MyCustomAgent) ID() string {
    return a.id
}

func (a *MyCustomAgent) Name() string {
    return a.name
}

func (a *MyCustomAgent) Description() string {
    return a.description
}

func (a *MyCustomAgent) Execute(ctx context.Context, input ai.AgentInput) (ai.AgentOutput, error) {
    // Your agent logic here
    
    return ai.AgentOutput{
        Response:   "Analysis completed successfully",
        Steps:      []ai.AgentStep{{StepID: "analysis", Action: "analyze", Success: true}},
        Confidence: 0.95,
        Success:    true,
        Metadata:   map[string]interface{}{"agent_type": "custom"},
        Duration:   time.Since(start),
    }, nil
}

// Implement other required methods...
```

### 5. Configuration Options

```go
type OrchestratorConfig struct {
    // Core settings
    MaxConcurrentTasks     int           // Default: 10
    TaskTimeout            time.Duration // Default: 5 minutes
    
    // Conflict resolution
    ConflictResolutionMode string        // "voting", "priority", "consensus"
    ConsensusThreshold     float64       // 0.0-1.0, default: 0.7
    
    // Performance
    EnableLoadBalancing    bool          // Default: true
    EnableFailover         bool          // Default: true
    HealthCheckInterval    time.Duration // Default: 30 seconds
    
    // Observability
    MetricsEnabled         bool          // Default: true
}
```

### 6. Monitoring and Metrics

```go
// Get orchestrator metrics
metrics := orchestrator.GetMetrics()
fmt.Printf("Tasks executed: %d\n", metrics.TasksExecuted)
fmt.Printf("Success rate: %.2f%%\n", metrics.SuccessRate * 100)
fmt.Printf("Average execution time: %v\n", metrics.AvgExecutionTime)
fmt.Printf("Active collaborations: %d\n", metrics.CollaborationsActive)

// Monitor specific task
result, err := orchestrator.ExecuteTask(ctx, task)
if err != nil {
    log.Printf("Task failed: %v", err)
} else {
    log.Printf("Task completed in %v with confidence %.2f", 
        result.ExecutionTime, result.Confidence)
}
```

### 7. Error Handling

```go
result, err := orchestrator.ExecuteTask(ctx, task)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "timeout"):
        log.Printf("Task timed out: %v", err)
        // Handle timeout
        
    case strings.Contains(err.Error(), "consensus"):
        log.Printf("Consensus not reached: %v", err)
        // Handle consensus failure
        
    case strings.Contains(err.Error(), "agent"):
        log.Printf("Agent error: %v", err)
        // Handle agent failure
        
    default:
        log.Printf("Unknown error: %v", err)
        // Handle other errors
    }
    return
}

// Check result quality
if result.Confidence < 0.7 {
    log.Printf("Low confidence result: %.2f", result.Confidence)
    // Handle low confidence
}

if result.ConflictsCount > 0 {
    log.Printf("Conflicts detected and resolved: %d", result.ConflictsCount)
    // Review conflict resolution
}
```

### 8. Custom Collaboration Patterns

```go
// Define custom workflow
pattern := &multiagent.CollaborationPattern{
    Name:        "Security Assessment",
    Description: "Comprehensive security assessment workflow",
    
    AgentRoles: map[string]string{
        "scanner":  "security",
        "analyzer": "analysis", 
        "reporter": "reporting",
    },
    
    Workflow: []multiagent.CollaborationStep{
        {
            ID:        "scan",
            Name:      "Security Scan",
            Type:      "parallel",
            AgentRole: "scanner",
            Action:    "security_scan",
            Required:  true,
        },
        {
            ID:        "analyze",
            Name:      "Analyze Results",
            Type:      "sequential",
            AgentRole: "analyzer",
            Action:    "analyze_scan_results",
            Dependencies: []string{"scan"},
            Required:  true,
        },
        {
            ID:        "report",
            Name:      "Generate Report",
            Type:      "sequential", 
            AgentRole: "reporter",
            Action:    "generate_security_report",
            Dependencies: []string{"analyze"},
            Required:  true,
        },
    },
}

// Register custom pattern
orchestrator.RegisterCollaborationPattern("security_assessment", pattern)
```

### 9. Best Practices

#### Agent Design
- Keep agents focused on specific capabilities
- Implement proper error handling and timeouts
- Return meaningful confidence scores
- Include relevant metadata in outputs

#### Task Design
- Break complex tasks into manageable subtasks
- Set appropriate timeouts and constraints
- Choose the right collaboration mode for your use case
- Provide clear context and parameters

#### Performance Optimization
- Monitor agent performance and adjust configurations
- Use parallel collaboration for independent tasks
- Implement caching for frequently used results
- Set reasonable consensus thresholds

#### Error Handling
- Implement retry logic for transient failures
- Handle agent unavailability gracefully
- Monitor conflict resolution effectiveness
- Log detailed error information for debugging

### 10. Testing

```go
func TestMultiAgentOrchestration(t *testing.T) {
    // Create test orchestrator
    config := &multiagent.OrchestratorConfig{
        MaxConcurrentTasks: 2,
        TaskTimeout:        30 * time.Second,
        MetricsEnabled:     true,
    }
    
    orchestrator := multiagent.NewMultiAgentOrchestrator(config, logger)
    
    // Register mock agents
    orchestrator.RegisterAgent(createMockAgent("test-agent-1"))
    orchestrator.RegisterAgent(createMockAgent("test-agent-2"))
    
    // Start orchestrator
    ctx := context.Background()
    err := orchestrator.Start(ctx)
    require.NoError(t, err)
    defer orchestrator.Stop()
    
    // Create test task
    task := &multiagent.MultiAgentTask{
        ID:             "test-task",
        Type:           "test_analysis",
        RequiredAgents: []string{"test-agent-1", "test-agent-2"},
        CollaborationMode: "parallel",
    }
    
    // Execute task
    result, err := orchestrator.ExecuteTask(ctx, task)
    require.NoError(t, err)
    assert.True(t, result.Success)
    assert.Equal(t, 2, result.ParticipantCount)
}
```

This integration guide provides everything you need to get started with the Multi-Agent Orchestration System. For more detailed examples, see the comprehensive demo in `cmd/multiagent-orchestration-demo/main.go`.
