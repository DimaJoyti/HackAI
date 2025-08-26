package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/agents/multiagent"
	"github.com/dimajoyti/hackai/pkg/langgraph/messaging"
	"github.com/dimajoyti/hackai/pkg/langgraph/tools"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// DemoAgent implements the Agent interface for demonstration
type DemoAgent struct {
	id           string
	name         string
	agentType    string
	capabilities map[string]interface{}
	status       multiagent.AgentStatus
	logger       *logger.Logger
}

// NewDemoAgent creates a new demo agent
func NewDemoAgent(id, name, agentType string, logger *logger.Logger) *DemoAgent {
	capabilities := map[string]interface{}{
		"agent_type":        agentType,
		"available_tools":   []string{"demo_tool", "analysis_tool"},
		"parallel_execution": true,
		"self_reflection":   true,
	}

	return &DemoAgent{
		id:           id,
		name:         name,
		agentType:    agentType,
		capabilities: capabilities,
		status:       multiagent.AgentStatusIdle,
		logger:       logger,
	}
}

func (da *DemoAgent) ID() string                                    { return da.id }
func (da *DemoAgent) Name() string                                  { return da.name }
func (da *DemoAgent) GetCapabilities() map[string]interface{}       { return da.capabilities }
func (da *DemoAgent) GetStatus() multiagent.AgentStatus             { return da.status }

func (da *DemoAgent) Execute(ctx context.Context, input multiagent.AgentInput) (*multiagent.AgentOutput, error) {
	da.status = multiagent.AgentStatusBusy
	defer func() { da.status = multiagent.AgentStatusIdle }()

	da.logger.Info("Demo agent executing task",
		"agent_id", da.id,
		"task_id", input.Task.ID,
		"task_name", input.Task.Name)

	// Simulate work
	time.Sleep(2 * time.Second)

	// Generate result based on agent type
	var result interface{}
	confidence := 0.85

	switch da.agentType {
	case "security":
		result = map[string]interface{}{
			"scan_completed":      true,
			"vulnerabilities":     []string{"CVE-2023-1234", "CVE-2023-5678"},
			"risk_score":          7.5,
			"recommendations":     []string{"Update software", "Enable firewall"},
			"agent_id":           da.id,
		}
	case "analysis":
		result = map[string]interface{}{
			"analysis_completed":  true,
			"patterns_found":      3,
			"anomalies":          []string{"unusual_traffic", "failed_logins"},
			"confidence_score":    confidence,
			"agent_id":           da.id,
		}
	case "reporting":
		result = map[string]interface{}{
			"report_generated":   true,
			"format":            "comprehensive",
			"sections":          []string{"executive_summary", "findings", "recommendations"},
			"page_count":        15,
			"agent_id":          da.id,
		}
	default:
		result = map[string]interface{}{
			"task_completed": true,
			"agent_type":     da.agentType,
			"agent_id":       da.id,
		}
	}

	return &multiagent.AgentOutput{
		Success:    true,
		Result:     result,
		Confidence: confidence,
		Duration:   2 * time.Second,
		Messages:   make([]*messaging.AgentMessage, 0),
		Metadata: map[string]interface{}{
			"agent_type": da.agentType,
			"execution_mode": "demo",
		},
	}, nil
}

func (da *DemoAgent) HandleMessage(ctx context.Context, message *messaging.AgentMessage) error {
	da.logger.Info("Demo agent received message",
		"agent_id", da.id,
		"from", message.From,
		"type", message.Type)
	return nil
}

func (da *DemoAgent) Start(ctx context.Context) error {
	da.status = multiagent.AgentStatusIdle
	da.logger.Info("Demo agent started", "agent_id", da.id)
	return nil
}

func (da *DemoAgent) Stop() error {
	da.status = multiagent.AgentStatusOffline
	da.logger.Info("Demo agent stopped", "agent_id", da.id)
	return nil
}

// DemoTool implements a simple tool for demonstration
type DemoTool struct {
	*tools.BaseTool
}

func NewDemoTool() *DemoTool {
	base := tools.NewBaseTool("demo_tool", "Demo Tool", "A demonstration tool", tools.CategoryUtility)
	return &DemoTool{BaseTool: base}
}

func (dt *DemoTool) Execute(ctx context.Context, input map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"tool_executed": true,
		"input_received": input,
		"timestamp": time.Now(),
	}, nil
}

func main() {
	// Initialize logger
	logger := logger.NewDefault()
	logger.Info("Starting Multi-Agent System Demo")

	// Create multi-agent system
	system := multiagent.NewMultiAgentSystem("demo-system", "Demo Multi-Agent System", logger)

	// Create demo agents
	securityAgent := NewDemoAgent("security-agent-1", "Security Analyzer", "security", logger)
	analysisAgent := NewDemoAgent("analysis-agent-1", "Data Analyzer", "analysis", logger)
	reportingAgent := NewDemoAgent("reporting-agent-1", "Report Generator", "reporting", logger)

	// Register agents
	if err := system.RegisterAgent(securityAgent); err != nil {
		log.Fatal("Failed to register security agent:", err)
	}
	if err := system.RegisterAgent(analysisAgent); err != nil {
		log.Fatal("Failed to register analysis agent:", err)
	}
	if err := system.RegisterAgent(reportingAgent); err != nil {
		log.Fatal("Failed to register reporting agent:", err)
	}

	// Start the system
	ctx := context.Background()
	if err := system.StartSystem(ctx); err != nil {
		log.Fatal("Failed to start multi-agent system:", err)
	}
	defer system.StopSystem()

	// Demo 1: Security Assessment Collaborative Task
	fmt.Println("\n🔒 Demo 1: Security Assessment Collaborative Task")
	fmt.Println(strings.Repeat("=", 60))

	securityTask := multiagent.CollaborativeTask{
		ID:          "security-assessment-001",
		Name:        "Comprehensive Security Assessment",
		Description: "Perform a comprehensive security assessment of the target system",
		Type:        multiagent.TaskTypeSecurityAssessment,
		Objective:   "Identify vulnerabilities and assess security posture",
		RequiredAgents: []string{"security-agent-1"},
		OptionalAgents: []string{"analysis-agent-1", "reporting-agent-1"},
		Priority:    multiagent.PriorityHigh,
		Status:      multiagent.TaskStatusPending,
		Metadata: map[string]interface{}{
			"target": "example.com",
			"scope":  "comprehensive",
		},
	}

	result1, err := system.ExecuteCollaborativeTask(ctx, securityTask)
	if err != nil {
		log.Printf("Security assessment failed: %v", err)
	} else {
		fmt.Printf("✅ Security Assessment Completed!\n")
		fmt.Printf("   Duration: %v\n", result1.Duration)
		fmt.Printf("   Participating Agents: %d\n", len(result1.ParticipatingAgents))
		fmt.Printf("   Success: %v\n", result1.Success)
	}

	// Demo 2: Data Analysis Collaborative Task
	fmt.Println("\n📊 Demo 2: Data Analysis Collaborative Task")
	fmt.Println(strings.Repeat("=", 60))

	dataTask := multiagent.CollaborativeTask{
		ID:          "data-analysis-001",
		Name:        "Multi-Source Data Analysis",
		Description: "Analyze data from multiple sources and generate insights",
		Type:        multiagent.TaskTypeDataAnalysis,
		Objective:   "Extract patterns and insights from collected data",
		RequiredAgents: []string{"analysis-agent-1"},
		OptionalAgents: []string{"reporting-agent-1"},
		Priority:    multiagent.PriorityNormal,
		Status:      multiagent.TaskStatusPending,
		Metadata: map[string]interface{}{
			"data_sources": []string{"logs", "metrics", "events"},
			"analysis_type": "pattern_recognition",
		},
	}

	result2, err := system.ExecuteCollaborativeTask(ctx, dataTask)
	if err != nil {
		log.Printf("Data analysis failed: %v", err)
	} else {
		fmt.Printf("✅ Data Analysis Completed!\n")
		fmt.Printf("   Duration: %v\n", result2.Duration)
		fmt.Printf("   Participating Agents: %d\n", len(result2.ParticipatingAgents))
		fmt.Printf("   Success: %v\n", result2.Success)
	}

	// Demo 3: Investigation Collaborative Task
	fmt.Println("\n🔍 Demo 3: Investigation Collaborative Task")
	fmt.Println(strings.Repeat("=", 60))

	investigationTask := multiagent.CollaborativeTask{
		ID:          "investigation-001",
		Name:        "Security Incident Investigation",
		Description: "Investigate a security incident and gather evidence",
		Type:        multiagent.TaskTypeInvestigation,
		Objective:   "Determine the scope and impact of the security incident",
		RequiredAgents: []string{"security-agent-1", "analysis-agent-1"},
		OptionalAgents: []string{"reporting-agent-1"},
		Priority:    multiagent.PriorityCritical,
		Status:      multiagent.TaskStatusPending,
		Metadata: map[string]interface{}{
			"incident_id": "INC-2024-001",
			"severity": "high",
			"affected_systems": []string{"web-server", "database"},
		},
	}

	result3, err := system.ExecuteCollaborativeTask(ctx, investigationTask)
	if err != nil {
		log.Printf("Investigation failed: %v", err)
	} else {
		fmt.Printf("✅ Investigation Completed!\n")
		fmt.Printf("   Duration: %v\n", result3.Duration)
		fmt.Printf("   Participating Agents: %d\n", len(result3.ParticipatingAgents))
		fmt.Printf("   Success: %v\n", result3.Success)
	}

	// Demo 4: System Status and Capabilities
	fmt.Println("\n📋 Demo 4: System Status and Agent Capabilities")
	fmt.Println(strings.Repeat("=", 60))

	status := system.GetSystemStatus()
	fmt.Printf("System ID: %s\n", status.SystemID)
	fmt.Printf("Total Agents: %d\n", status.TotalAgents)
	fmt.Printf("Agent Statuses:\n")
	for agentID, agentStatus := range status.AgentStatuses {
		fmt.Printf("  - %s: %s\n", agentID, agentStatus)
	}

	fmt.Printf("\nAgent Capabilities:\n")
	for agentID, agent := range map[string]multiagent.Agent{
		"security-agent-1": securityAgent,
		"analysis-agent-1": analysisAgent,
		"reporting-agent-1": reportingAgent,
	} {
		capabilities := agent.GetCapabilities()
		fmt.Printf("  %s (%s):\n", agentID, agent.Name())
		for key, value := range capabilities {
			fmt.Printf("    - %s: %v\n", key, value)
		}
	}

	// Demo 5: Workflow Engine Integration
	fmt.Println("\n🔄 Demo 5: Workflow Engine Integration")
	fmt.Println(strings.Repeat("=", 60))

	// Create a workflow from template
	workflowEngine := system.WorkflowEngine
	workflow, err := workflowEngine.CreateWorkflowFromTemplate("security_assessment_workflow", map[string]interface{}{
		"target": "demo.example.com",
		"scan_depth": "comprehensive",
	})

	if err != nil {
		log.Printf("Failed to create workflow: %v", err)
	} else {
		fmt.Printf("✅ Workflow Created!\n")
		fmt.Printf("   Workflow ID: %s\n", workflow.ID)
		fmt.Printf("   Steps: %d\n", len(workflow.Steps))
		fmt.Printf("   Status: %s\n", workflow.Status)

		// Execute the workflow
		agents := map[string]multiagent.Agent{
			"security-agent-1": securityAgent,
			"analysis-agent-1": analysisAgent,
			"reporting-agent-1": reportingAgent,
		}

		workflowResult, err := workflowEngine.ExecuteWorkflow(ctx, workflow.ID, agents)
		if err != nil {
			log.Printf("Workflow execution failed: %v", err)
		} else {
			fmt.Printf("✅ Workflow Executed!\n")
			fmt.Printf("   Duration: %v\n", workflowResult.Duration)
			fmt.Printf("   Success: %v\n", workflowResult.Success)
			fmt.Printf("   Steps Completed: %d\n", len(workflowResult.StepResults))
		}
	}

	// Demo Summary
	fmt.Println("\n🎉 Multi-Agent System Demo Summary")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("✅ Security Assessment: Completed\n")
	fmt.Printf("✅ Data Analysis: Completed\n")
	fmt.Printf("✅ Investigation: Completed\n")
	fmt.Printf("✅ System Status: Retrieved\n")
	fmt.Printf("✅ Workflow Execution: Completed\n")
	fmt.Printf("\n🚀 Multi-Agent System Demo completed successfully!\n")
	fmt.Printf("   Total Agents: %d\n", len(status.AgentStatuses))
	fmt.Printf("   Tasks Executed: 3\n")
	fmt.Printf("   Workflows Executed: 1\n")

	logger.Info("Multi-Agent System Demo completed successfully")
}
