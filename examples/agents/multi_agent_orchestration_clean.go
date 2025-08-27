// Package: agents
// Description: Multi-agent orchestration example
// Complexity: Intermediate
// Category: AI/Agents

package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// Agent represents a basic agent interface
type Agent interface {
	GetID() string
	GetName() string
	GetType() string
	GetCapabilities() []string
	ExecuteTask(ctx context.Context, task *Task) (*Result, error)
	GetStatus() string
}

// TaskPriority represents task priority levels
type TaskPriority int

const (
	TaskPriorityLow TaskPriority = iota
	TaskPriorityNormal
	TaskPriorityHigh
	TaskPriorityCritical
)

// Task represents a task for agents to execute
type Task struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Priority    TaskPriority               `json:"priority"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	Timeout     time.Duration          `json:"timeout"`
}

// Result represents the result of task execution
type Result struct {
	Success       bool                   `json:"success"`
	Data          map[string]interface{} `json:"data"`
	Error         string                 `json:"error,omitempty"`
	ExecutionTime time.Duration          `json:"execution_time"`
	Confidence    float64                `json:"confidence"`
}

// BaseAgent provides common agent functionality
type BaseAgent struct {
	ID           string
	Name         string
	Type         string
	Capabilities []string
	Priority     TaskPriority
	Status       string
}

// GetID returns the agent ID
func (ba *BaseAgent) GetID() string { return ba.ID }

// GetName returns the agent name
func (ba *BaseAgent) GetName() string { return ba.Name }

// GetType returns the agent type
func (ba *BaseAgent) GetType() string { return ba.Type }

// GetCapabilities returns the agent capabilities
func (ba *BaseAgent) GetCapabilities() []string { return ba.Capabilities }

// GetStatus returns the agent status
func (ba *BaseAgent) GetStatus() string { return ba.Status }

// Orchestrator manages multiple agents and coordinates their tasks
type Orchestrator struct {
	agents map[string]Agent
	logger *logger.Logger
	mutex  sync.RWMutex
}

// NewOrchestrator creates a new agent orchestrator
func NewOrchestrator(logger *logger.Logger) *Orchestrator {
	return &Orchestrator{
		agents: make(map[string]Agent),
		logger: logger,
	}
}

// RegisterAgent registers an agent with the orchestrator
func (o *Orchestrator) RegisterAgent(agent Agent) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	o.agents[agent.GetID()] = agent
}

// Start starts the orchestrator
func (o *Orchestrator) Start(ctx context.Context) error {
	o.logger.Info("Starting orchestrator", "agent_count", len(o.agents))
	return nil
}

// Stop stops the orchestrator
func (o *Orchestrator) Stop() error {
	o.logger.Info("Stopping orchestrator")
	return nil
}

// ExecuteTask executes a task using appropriate agents
func (o *Orchestrator) ExecuteTask(ctx context.Context, task *Task) (*Result, error) {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	// Find suitable agent for the task
	for _, agent := range o.agents {
		capabilities := agent.GetCapabilities()
		for _, capability := range capabilities {
			if capability == task.Type {
				return agent.ExecuteTask(ctx, task)
			}
		}
	}

	return nil, fmt.Errorf("no suitable agent found for task type: %s", task.Type)
}

// SecurityAnalystAgent represents a security analysis agent
type SecurityAnalystAgent struct {
	BaseAgent
	Logger *logger.Logger
}

// ExecuteTask executes a security analysis task
func (sa *SecurityAnalystAgent) ExecuteTask(ctx context.Context, task *Task) (*Result, error) {
	sa.Logger.Info("Executing security analysis task", "task_id", task.ID)

	// Simulate security analysis work
	time.Sleep(100 * time.Millisecond)

	return &Result{
		Success:       true,
		Data:          map[string]interface{}{"analysis": "security_analysis_complete", "threats_found": 0},
		ExecutionTime: 100 * time.Millisecond,
		Confidence:    0.95,
	}, nil
}

// DataAnalystAgent represents a data analysis agent
type DataAnalystAgent struct {
	BaseAgent
	Logger *logger.Logger
}

// ExecuteTask executes a data analysis task
func (da *DataAnalystAgent) ExecuteTask(ctx context.Context, task *Task) (*Result, error) {
	da.Logger.Info("Executing data analysis task", "task_id", task.ID)

	// Simulate data analysis work
	time.Sleep(120 * time.Millisecond)

	return &Result{
		Success:       true,
		Data:          map[string]interface{}{"analysis": "data_analysis_complete", "insights": []string{"trend_up", "anomaly_detected"}},
		ExecutionTime: 120 * time.Millisecond,
		Confidence:    0.90,
	}, nil
}

// createSpecializedAgents creates a set of specialized agents
func createSpecializedAgents(logger *logger.Logger) []Agent {
	return []Agent{
		&SecurityAnalystAgent{
			BaseAgent: BaseAgent{
				ID:           "security-analyst-001",
				Name:         "Security Analyst",
				Type:         "security",
				Capabilities: []string{"threat-analysis", "vulnerability-assessment"},
				Priority:     TaskPriorityHigh,
				Status:       "active",
			},
			Logger: logger,
		},
		&DataAnalystAgent{
			BaseAgent: BaseAgent{
				ID:           "data-analyst-001",
				Name:         "Data Analyst",
				Type:         "business",
				Capabilities: []string{"data-analysis", "statistical-modeling"},
				Priority:     TaskPriorityNormal,
				Status:       "active",
			},
			Logger: logger,
		},
	}
}

// MultiAgentOrchestrationExample demonstrates advanced agent coordination
func main() {
	fmt.Println("🤖 HackAI Multi-Agent Orchestration Example")
	fmt.Println("===========================================")

	// Initialize logger
	logger, err := logger.New(logger.Config{
		Level:  "info",
		Format: "json",
	})
	if err != nil {
		log.Fatal("Failed to initialize logger:", err)
	}

	// Create orchestrator
	orchestrator := NewOrchestrator(logger)

	// Create specialized agents
	agents := createSpecializedAgents(logger)

	// Register agents with orchestrator
	for _, agent := range agents {
		orchestrator.RegisterAgent(agent)
		fmt.Printf("✅ Registered agent: %s (%s)\n", agent.GetName(), agent.GetType())
	}

	// Start orchestrator
	ctx := context.Background()
	if err := orchestrator.Start(ctx); err != nil {
		log.Fatal("Failed to start orchestrator:", err)
	}
	defer orchestrator.Stop()

	fmt.Printf("\n🚀 Orchestrator started with %d agents\n", len(agents))

	// Demonstrate orchestration patterns
	demonstrateOrchestrationPatterns(ctx, orchestrator)

	fmt.Println("\n✅ Multi-Agent Orchestration Example Complete!")
}

// demonstrateOrchestrationPatterns shows different coordination patterns
func demonstrateOrchestrationPatterns(ctx context.Context, orchestrator *Orchestrator) {
	fmt.Println("\n🎭 Demonstrating Orchestration Patterns:")
	fmt.Println("========================================")

	// Pattern 1: Security Analysis Task
	fmt.Println("\n1️⃣ Security Analysis Pattern:")
	securityTask := &Task{
		ID:          "security-task-001",
		Type:        "threat-analysis",
		Priority:    TaskPriorityHigh,
		Description: "Analyze system for security threats",
		Parameters: map[string]interface{}{
			"target": "system_logs",
			"depth":  "comprehensive",
		},
		Timeout: 30 * time.Second,
	}

	result, err := orchestrator.ExecuteTask(ctx, securityTask)
	if err != nil {
		fmt.Printf("❌ Security analysis failed: %v\n", err)
	} else {
		fmt.Printf("✅ Security analysis completed successfully\n")
		fmt.Printf("   Confidence: %.2f, Execution Time: %v\n", result.Confidence, result.ExecutionTime)
	}

	// Pattern 2: Data Analysis Task
	fmt.Println("\n2️⃣ Data Analysis Pattern:")
	dataTask := &Task{
		ID:          "data-task-001",
		Type:        "data-analysis",
		Priority:    TaskPriorityNormal,
		Description: "Analyze business data for insights",
		Parameters: map[string]interface{}{
			"dataset": "sales_data",
			"period":  "last_quarter",
		},
		Timeout: 30 * time.Second,
	}

	result, err = orchestrator.ExecuteTask(ctx, dataTask)
	if err != nil {
		fmt.Printf("❌ Data analysis failed: %v\n", err)
	} else {
		fmt.Printf("✅ Data analysis completed successfully\n")
		fmt.Printf("   Confidence: %.2f, Execution Time: %v\n", result.Confidence, result.ExecutionTime)
	}
}
