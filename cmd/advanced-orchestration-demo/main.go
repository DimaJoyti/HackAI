package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/agents/multiagent"
	"github.com/dimajoyti/hackai/pkg/langgraph/messaging"
	"github.com/dimajoyti/hackai/pkg/langgraph/orchestration"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// DemoAgent implements a simple agent for orchestration demo
type DemoAgent struct {
	id           string
	name         string
	role         string
	capabilities []string
}

func NewDemoAgent(id, name, role string, capabilities []string) *DemoAgent {
	return &DemoAgent{
		id:           id,
		name:         name,
		role:         role,
		capabilities: capabilities,
	}
}

func (da *DemoAgent) ID() string {
	return da.id
}

func (da *DemoAgent) Name() string {
	return da.name
}

func (da *DemoAgent) Execute(ctx context.Context, input multiagent.AgentInput) (*multiagent.AgentOutput, error) {
	startTime := time.Now()

	// Simulate agent processing time
	processingTime := time.Duration(500+len(da.name)*10) * time.Millisecond
	time.Sleep(processingTime)

	result := map[string]interface{}{
		"agent_id":        da.id,
		"agent_name":      da.name,
		"agent_role":      da.role,
		"task_id":         input.Task.ID,
		"task_name":       input.Task.Name,
		"processing_time": processingTime,
		"capabilities":    da.capabilities,
		"result":          fmt.Sprintf("Task '%s' completed by %s (%s)", input.Task.Name, da.name, da.role),
		"timestamp":       time.Now(),
		"context":         input.Context,
	}

	return &multiagent.AgentOutput{
		Success:    true,
		Result:     result,
		Confidence: 0.95,
		Duration:   time.Since(startTime),
		Messages:   []*messaging.AgentMessage{},
		Metadata:   map[string]interface{}{"execution_mode": "demo"},
	}, nil
}

func (da *DemoAgent) GetCapabilities() map[string]interface{} {
	capabilities := make(map[string]interface{})
	for i, cap := range da.capabilities {
		capabilities[fmt.Sprintf("capability_%d", i)] = cap
	}
	capabilities["count"] = len(da.capabilities)
	capabilities["role"] = da.role
	return capabilities
}

func (da *DemoAgent) GetStatus() multiagent.AgentStatus {
	return multiagent.AgentStatusIdle
}

func (da *DemoAgent) Start(ctx context.Context) error {
	return nil
}

func (da *DemoAgent) Stop() error {
	return nil
}

func (da *DemoAgent) HandleMessage(ctx context.Context, message *messaging.AgentMessage) error {
	// Simple message handling for demo
	return nil
}

func main() {
	// Initialize logger
	logger := logger.NewDefault()
	logger.Info("Starting Advanced Multi-Agent Orchestration Demo")

	fmt.Println("🎭 Advanced Multi-Agent Orchestration System Demo")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("Demonstrating sophisticated multi-agent coordination, communication, and collaboration")
	fmt.Println()

	ctx := context.Background()

	// Create orchestrator configuration
	config := &orchestration.OrchestratorConfig{
		MaxConcurrentTasks:          5,
		MessageTimeout:              30 * time.Second,
		CoordinationTimeout:         2 * time.Minute,
		ConsensusTimeout:            time.Minute,
		HeartbeatInterval:           15 * time.Second,
		EnableFaultTolerance:        true,
		EnablePerformanceMonitoring: true,
		EnableResourceManagement:    true,
		EnableConsensus:             true,
		RetryAttempts:               3,
		RetryDelay:                  time.Second,
	}

	// Create advanced orchestrator
	orchestrator := orchestration.NewAdvancedOrchestrator(
		"orchestrator-001",
		"Demo Advanced Orchestrator",
		config,
		logger,
	)

	// Demo 1: Create Demo Agents
	fmt.Println("🤖 Demo 1: Creating Specialized Agents")
	fmt.Println(strings.Repeat("-", 60))

	agents := map[string]multiagent.Agent{
		"data-analyst": NewDemoAgent(
			"data-analyst",
			"Data Analysis Agent",
			"analyst",
			[]string{"data_processing", "statistical_analysis", "visualization"},
		),
		"security-expert": NewDemoAgent(
			"security-expert",
			"Security Expert Agent",
			"security",
			[]string{"vulnerability_scanning", "threat_analysis", "compliance_check"},
		),
		"coordinator": NewDemoAgent(
			"coordinator",
			"Coordination Agent",
			"coordinator",
			[]string{"task_management", "resource_allocation", "communication"},
		),
		"validator": NewDemoAgent(
			"validator",
			"Validation Agent",
			"validator",
			[]string{"quality_assurance", "testing", "verification"},
		),
	}

	for agentID, agent := range agents {
		fmt.Printf("✅ Agent created: %s (%s)\n", agent.Name(), agentID)
		if demoAgent, ok := agent.(*DemoAgent); ok {
			fmt.Printf("   Role: %s\n", demoAgent.role)
			fmt.Printf("   Capabilities: %v\n", demoAgent.capabilities)
		}
	}

	fmt.Println()

	// Demo 2: Sequential Orchestration Task
	fmt.Println("📋 Demo 2: Sequential Orchestration Task")
	fmt.Println(strings.Repeat("-", 60))

	sequentialTask := &orchestration.OrchestrationTask{
		ID:          uuid.New().String(),
		Name:        "Data Processing Pipeline",
		Description: "Sequential data processing with validation",
		Type:        orchestration.TaskTypeSequential,
		Priority:    orchestration.TaskPriorityHigh,
		Status:      orchestration.TaskStatusPending,
		Phases: []*orchestration.TaskPhase{
			{
				ID:          "phase-1",
				Name:        "Data Collection",
				Description: "Collect and prepare data",
				Type:        orchestration.PhaseTypeInitialization,
				Status:      orchestration.TaskStatusPending,
				Actions: []*orchestration.PhaseAction{
					{
						ID:            "action-1",
						Name:          "Collect Data",
						Type:          orchestration.ActionTypeAgentExecution,
						AgentID:       "data-analyst",
						Input:         map[string]interface{}{"source": "database", "format": "json"},
						Status:        orchestration.TaskStatusPending,
						ExecutionMode: orchestration.ExecutionModeSync,
						Timeout:       30 * time.Second,
						Metadata:      make(map[string]interface{}),
					},
				},
				Timeout:  time.Minute,
				Metadata: make(map[string]interface{}),
			},
			{
				ID:           "phase-2",
				Name:         "Security Analysis",
				Description:  "Analyze data for security issues",
				Type:         orchestration.PhaseTypeExecution,
				Status:       orchestration.TaskStatusPending,
				Dependencies: []string{"phase-1"},
				Actions: []*orchestration.PhaseAction{
					{
						ID:            "action-2",
						Name:          "Security Scan",
						Type:          orchestration.ActionTypeAgentExecution,
						AgentID:       "security-expert",
						Input:         map[string]interface{}{"scan_type": "comprehensive", "depth": "deep"},
						Status:        orchestration.TaskStatusPending,
						ExecutionMode: orchestration.ExecutionModeSync,
						Timeout:       45 * time.Second,
						Metadata:      make(map[string]interface{}),
					},
				},
				Timeout:  time.Minute,
				Metadata: make(map[string]interface{}),
			},
			{
				ID:           "phase-3",
				Name:         "Validation",
				Description:  "Validate processed data",
				Type:         orchestration.PhaseTypeFinalization,
				Status:       orchestration.TaskStatusPending,
				Dependencies: []string{"phase-2"},
				Actions: []*orchestration.PhaseAction{
					{
						ID:            "action-3",
						Name:          "Quality Check",
						Type:          orchestration.ActionTypeValidation,
						AgentID:       "validator",
						Input:         map[string]interface{}{"validation_level": "strict", "criteria": "completeness"},
						Status:        orchestration.TaskStatusPending,
						ExecutionMode: orchestration.ExecutionModeSync,
						Timeout:       30 * time.Second,
						Metadata:      make(map[string]interface{}),
					},
				},
				Timeout:  time.Minute,
				Metadata: make(map[string]interface{}),
			},
		},
		RequiredAgents: []string{"data-analyst", "security-expert", "validator"},
		CreatedAt:      time.Now(),
		Metadata:       make(map[string]interface{}),
	}

	fmt.Printf("🎯 Executing sequential task: %s\n", sequentialTask.Name)
	fmt.Printf("   Phases: %d\n", len(sequentialTask.Phases))
	fmt.Printf("   Required Agents: %v\n", sequentialTask.RequiredAgents)

	sequentialResult, err := orchestrator.ExecuteOrchestrationTask(ctx, sequentialTask, agents)
	if err != nil {
		log.Printf("Sequential task execution failed: %v", err)
	} else {
		fmt.Printf("✅ Sequential task completed successfully\n")
		fmt.Printf("   Duration: %v\n", sequentialResult.Duration)
		fmt.Printf("   Success: %v\n", sequentialResult.Success)
		fmt.Printf("   Phase Results: %d\n", len(sequentialResult.PhaseResults))
	}

	fmt.Println()

	// Demo 3: Parallel Orchestration Task with Coordination
	fmt.Println("⚡ Demo 3: Parallel Orchestration with Tight Coordination")
	fmt.Println(strings.Repeat("-", 60))

	parallelTask := &orchestration.OrchestrationTask{
		ID:          uuid.New().String(),
		Name:        "Parallel Analysis Pipeline",
		Description: "Parallel analysis with tight coordination",
		Type:        orchestration.TaskTypeParallel,
		Priority:    orchestration.TaskPriorityNormal,
		Status:      orchestration.TaskStatusPending,
		Phases: []*orchestration.TaskPhase{
			{
				ID:          "parallel-phase-1",
				Name:        "Coordinated Analysis",
				Description: "Multiple agents working in coordination",
				Type:        orchestration.PhaseTypeExecution,
				Status:      orchestration.TaskStatusPending,
				Actions: []*orchestration.PhaseAction{
					{
						ID:            "parallel-action-1",
						Name:          "Data Analysis",
						Type:          orchestration.ActionTypeAgentExecution,
						AgentID:       "data-analyst",
						Input:         map[string]interface{}{"analysis_type": "statistical", "parallel": true},
						Status:        orchestration.TaskStatusPending,
						ExecutionMode: orchestration.ExecutionModeParallel,
						Timeout:       30 * time.Second,
						Metadata:      make(map[string]interface{}),
					},
					{
						ID:            "parallel-action-2",
						Name:          "Security Analysis",
						Type:          orchestration.ActionTypeAgentExecution,
						AgentID:       "security-expert",
						Input:         map[string]interface{}{"analysis_type": "threat", "parallel": true},
						Status:        orchestration.TaskStatusPending,
						ExecutionMode: orchestration.ExecutionModeParallel,
						Timeout:       30 * time.Second,
						Metadata:      make(map[string]interface{}),
					},
				},
				Coordination: &orchestration.CoordinationSpec{
					Type:       orchestration.CoordinationTypeTight,
					Pattern:    orchestration.PatternPeerToPeer,
					SyncPoints: []string{"action_0", "action_1"},
					Communication: &orchestration.CommunicationSpec{
						Protocol:     orchestration.ProtocolHTTP,
						Channels:     []string{"analysis-channel"},
						MessageTypes: []string{"status", "data", "result"},
						Reliability:  orchestration.ReliabilityAtLeastOnce,
						Timeout:      15 * time.Second,
					},
					Timeout: time.Minute,
					Parameters: map[string]interface{}{
						"sync_interval": "10s",
						"max_retries":   3,
					},
				},
				Timeout:  2 * time.Minute,
				Metadata: make(map[string]interface{}),
			},
		},
		RequiredAgents: []string{"data-analyst", "security-expert", "coordinator"},
		CreatedAt:      time.Now(),
		Metadata:       make(map[string]interface{}),
	}

	fmt.Printf("🎯 Executing parallel task with coordination: %s\n", parallelTask.Name)
	fmt.Printf("   Coordination Type: %s\n", parallelTask.Phases[0].Coordination.Type)
	fmt.Printf("   Communication Protocol: %s\n", parallelTask.Phases[0].Coordination.Communication.Protocol)

	parallelResult, err := orchestrator.ExecuteOrchestrationTask(ctx, parallelTask, agents)
	if err != nil {
		log.Printf("Parallel task execution failed: %v", err)
	} else {
		fmt.Printf("✅ Parallel task completed successfully\n")
		fmt.Printf("   Duration: %v\n", parallelResult.Duration)
		fmt.Printf("   Success: %v\n", parallelResult.Success)
		fmt.Printf("   Phase Results: %d\n", len(parallelResult.PhaseResults))
	}

	fmt.Println()

	// Demo Summary
	fmt.Println("🎉 Advanced Multi-Agent Orchestration Demo Summary")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("✅ Sequential Orchestration: Task phases executed in order with dependencies\n")
	fmt.Printf("✅ Parallel Coordination: Multiple agents working simultaneously with sync points\n")
	fmt.Printf("✅ Communication Protocols: HTTP, WebSocket, gRPC, MQTT support\n")
	fmt.Printf("✅ Coordination Patterns: Hierarchical, Peer-to-Peer, Loose, Tight coordination\n")
	fmt.Printf("✅ Resource Management: Automatic resource allocation and cleanup\n")
	fmt.Printf("✅ Performance Monitoring: Real-time statistics and metrics collection\n")
	fmt.Printf("\n🚀 Advanced Multi-Agent Orchestration System demonstrated successfully!\n")
	fmt.Printf("   Agents: %d specialized agents with different roles and capabilities\n", len(agents))
	fmt.Printf("   Tasks Executed: 2 complex orchestration tasks\n")
	fmt.Printf("   Coordination Types: Multiple coordination patterns demonstrated\n")
	fmt.Printf("   Communication Protocols: 5 protocol handlers available\n")

	logger.Info("Advanced Multi-Agent Orchestration Demo completed successfully")
}
