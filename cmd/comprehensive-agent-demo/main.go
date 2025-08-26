package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/agents/multiagent"
	"github.com/dimajoyti/hackai/pkg/langgraph/agents/planexecute"
	"github.com/dimajoyti/hackai/pkg/langgraph/agents/react"
	"github.com/dimajoyti/hackai/pkg/langgraph/messaging"
	"github.com/dimajoyti/hackai/pkg/langgraph/tools"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// SecurityScanTool demonstrates a security scanning tool
type SecurityScanTool struct {
	*tools.BaseTool
}

func NewSecurityScanTool() *SecurityScanTool {
	base := tools.NewBaseTool("security_scanner", "Security Scanner", "Performs comprehensive security scans", tools.CategorySecurity)
	return &SecurityScanTool{BaseTool: base}
}

func (sst *SecurityScanTool) Execute(ctx context.Context, input map[string]interface{}) (interface{}, error) {
	target := "unknown"
	if t, exists := input["target"]; exists {
		target = t.(string)
	}

	// Simulate security scan
	time.Sleep(3 * time.Second)

	return map[string]interface{}{
		"scan_completed":  true,
		"target":          target,
		"vulnerabilities": []string{"CVE-2023-1234", "CVE-2023-5678", "CVE-2023-9012"},
		"critical_count":  1,
		"high_count":      2,
		"medium_count":    5,
		"low_count":       8,
		"risk_score":      8.5,
		"scan_duration":   "3 minutes",
		"recommendations": []string{
			"Update web server to latest version",
			"Enable WAF protection",
			"Implement rate limiting",
			"Review access controls",
		},
		"compliance_status": map[string]bool{
			"OWASP_Top_10": false,
			"PCI_DSS":      true,
			"ISO_27001":    false,
		},
	}, nil
}

func (sst *SecurityScanTool) Validate(input map[string]interface{}) error {
	if _, exists := input["target"]; !exists {
		return fmt.Errorf("target parameter is required")
	}
	return nil
}

// VulnerabilityAnalyzer demonstrates a vulnerability analysis tool
type VulnerabilityAnalyzer struct {
	*tools.BaseTool
}

func NewVulnerabilityAnalyzer() *VulnerabilityAnalyzer {
	base := tools.NewBaseTool("vuln_analyzer", "Vulnerability Analyzer", "Analyzes and prioritizes vulnerabilities", tools.CategorySecurity)
	return &VulnerabilityAnalyzer{BaseTool: base}
}

func (va *VulnerabilityAnalyzer) Execute(ctx context.Context, input map[string]interface{}) (interface{}, error) {
	// Simulate vulnerability analysis
	time.Sleep(2 * time.Second)

	return map[string]interface{}{
		"analysis_completed":    true,
		"total_vulnerabilities": 16,
		"prioritized_list": []map[string]interface{}{
			{
				"cve_id":          "CVE-2023-1234",
				"severity":        "CRITICAL",
				"cvss_score":      9.8,
				"exploitable":     true,
				"patch_available": true,
				"priority":        1,
			},
			{
				"cve_id":          "CVE-2023-5678",
				"severity":        "HIGH",
				"cvss_score":      7.5,
				"exploitable":     false,
				"patch_available": true,
				"priority":        2,
			},
		},
		"remediation_timeline": map[string]string{
			"immediate": "1 vulnerability",
			"30_days":   "2 vulnerabilities",
			"90_days":   "13 vulnerabilities",
		},
		"business_impact": "HIGH",
		"recommended_actions": []string{
			"Patch CVE-2023-1234 immediately",
			"Schedule maintenance window for remaining patches",
			"Implement monitoring for exploitation attempts",
		},
	}, nil
}

// DataCollectorTool demonstrates a data collection tool
type DataCollectorTool struct {
	*tools.BaseTool
}

func NewDataCollectorTool() *DataCollectorTool {
	base := tools.NewBaseTool("data_collector", "Data Collector", "Collects data from various sources", tools.CategoryData)
	return &DataCollectorTool{BaseTool: base}
}

func (dct *DataCollectorTool) Execute(ctx context.Context, input map[string]interface{}) (interface{}, error) {
	// Simulate data collection
	time.Sleep(1 * time.Second)

	return map[string]interface{}{
		"collection_completed": true,
		"sources_accessed":     []string{"system_logs", "network_traffic", "user_activity", "security_events"},
		"records_collected":    15420,
		"time_range":           "last_24_hours",
		"data_quality":         "high",
		"anomalies_detected": []string{
			"unusual_login_pattern",
			"elevated_privilege_usage",
			"suspicious_network_traffic",
		},
		"collection_stats": map[string]interface{}{
			"success_rate":    0.98,
			"error_count":     12,
			"processing_time": "45 seconds",
		},
	}, nil
}

// ReportGeneratorTool demonstrates a report generation tool
type ReportGeneratorTool struct {
	*tools.BaseTool
}

func NewReportGeneratorTool() *ReportGeneratorTool {
	base := tools.NewBaseTool("report_generator", "Report Generator", "Generates comprehensive reports", tools.CategoryReporting)
	return &ReportGeneratorTool{BaseTool: base}
}

func (rgt *ReportGeneratorTool) Execute(ctx context.Context, input map[string]interface{}) (interface{}, error) {
	// Simulate report generation
	time.Sleep(2 * time.Second)

	return map[string]interface{}{
		"report_generated": true,
		"report_id":        fmt.Sprintf("RPT-%d", time.Now().Unix()),
		"format":           "comprehensive_security_assessment",
		"sections": []string{
			"executive_summary",
			"methodology",
			"findings_overview",
			"vulnerability_details",
			"risk_assessment",
			"recommendations",
			"remediation_roadmap",
			"compliance_status",
			"appendices",
		},
		"page_count":      42,
		"charts_included": 8,
		"tables_included": 12,
		"export_formats":  []string{"PDF", "HTML", "JSON", "CSV"},
		"distribution_list": []string{
			"security_team@company.com",
			"it_management@company.com",
			"compliance@company.com",
		},
		"next_review_date": time.Now().AddDate(0, 3, 0).Format("2006-01-02"),
	}, nil
}

func main() {
	// Initialize logger
	logger := logger.NewDefault()
	logger.Info("Starting Comprehensive Agent Demo")

	fmt.Println("🤖 HackAI LangGraph Comprehensive Agent Demo")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("Demonstrating ReAct, Plan-and-Execute, and Multi-Agent collaboration")
	fmt.Println()

	ctx := context.Background()

	// Create tools
	securityTool := NewSecurityScanTool()
	vulnAnalyzer := NewVulnerabilityAnalyzer()
	dataCollector := NewDataCollectorTool()
	reportGenerator := NewReportGeneratorTool()

	// Demo 1: ReAct Agent
	fmt.Println("🧠 Demo 1: ReAct Agent (Reasoning + Acting)")
	fmt.Println(strings.Repeat("-", 50))

	reactAgent := react.NewReActAgent("react-security-agent", "ReAct Security Analyst", logger)

	// Register tools with ReAct agent
	reactAgent.RegisterTool(securityTool)
	reactAgent.RegisterTool(vulnAnalyzer)

	reactInput := react.AgentInput{
		Query: "Analyze the security of example.com and provide a detailed assessment with vulnerability prioritization",
		Context: map[string]interface{}{
			"target": "example.com",
			"scope":  "comprehensive",
		},
		Goals: []string{
			"Identify security vulnerabilities",
			"Assess risk levels",
			"Provide actionable recommendations",
		},
	}

	fmt.Printf("🎯 Task: %s\n", reactInput.Query)
	fmt.Printf("🎯 Target: %s\n", reactInput.Context["target"])

	reactResult, err := reactAgent.Execute(ctx, reactInput)
	if err != nil {
		log.Printf("ReAct agent failed: %v", err)
	} else {
		fmt.Printf("✅ ReAct Agent Completed!\n")
		fmt.Printf("   Iterations: %d\n", reactResult.Iterations)
		fmt.Printf("   Duration: %v\n", reactResult.Duration)
		fmt.Printf("   Confidence: %.2f\n", reactResult.Confidence)
		fmt.Printf("   Tools Used: %d\n", len(reactResult.Actions))
		fmt.Printf("   Success: %v\n", reactResult.Success)
		if reactResult.Success {
			fmt.Printf("   Final Answer: %s\n", reactResult.Answer[:min(100, len(reactResult.Answer))]+"...")
		}
	}

	fmt.Println()

	// Demo 2: Plan-and-Execute Agent
	fmt.Println("📋 Demo 2: Plan-and-Execute Agent")
	fmt.Println(strings.Repeat("-", 50))

	planExecuteAgent := planexecute.NewPlanAndExecuteAgent("plan-exec-agent", "Security Assessment Planner", logger)

	// Register tools with Plan-and-Execute agent
	planExecuteAgent.RegisterTool(securityTool)
	planExecuteAgent.RegisterTool(vulnAnalyzer)
	planExecuteAgent.RegisterTool(dataCollector)
	planExecuteAgent.RegisterTool(reportGenerator)

	planInput := planexecute.AgentInput{
		Objective: "Conduct a comprehensive security assessment and generate a detailed report",
		Context: map[string]interface{}{
			"target":                  "example.com",
			"assessment_type":         "full_security_audit",
			"compliance_requirements": []string{"OWASP", "PCI_DSS"},
		},
		Constraints: []string{
			"Complete within 30 minutes",
			"Include executive summary",
			"Provide remediation timeline",
		},
	}

	fmt.Printf("🎯 Objective: %s\n", planInput.Objective)
	fmt.Printf("🎯 Target: %s\n", planInput.Context["target"])

	planResult, err := planExecuteAgent.Execute(ctx, planInput)
	if err != nil {
		log.Printf("Plan-and-Execute agent failed: %v", err)
	} else {
		fmt.Printf("✅ Plan-and-Execute Agent Completed!\n")
		fmt.Printf("   Duration: %v\n", planResult.Duration)
		fmt.Printf("   Tasks Completed: %d\n", planResult.TasksCompleted)
		fmt.Printf("   Tasks Failed: %d\n", planResult.TasksFailed)
		fmt.Printf("   Success: %v\n", planResult.Success)
		fmt.Printf("   Plan ID: %s\n", planResult.Plan.ID)
		fmt.Printf("   Total Tasks: %d\n", len(planResult.Plan.Tasks))
	}

	fmt.Println()

	// Demo 3: Multi-Agent System
	fmt.Println("🤝 Demo 3: Multi-Agent Collaboration")
	fmt.Println(strings.Repeat("-", 50))

	// Create multi-agent system
	multiAgentSystem := multiagent.NewMultiAgentSystem("comprehensive-security-system", "Comprehensive Security Assessment System", logger)

	// Create specialized agents that implement the Agent interface
	securityAgent := &AgentWrapper{
		id:         "security-specialist",
		name:       "Security Specialist",
		agentType:  "security",
		reactAgent: reactAgent,
		logger:     logger,
	}

	planningAgent := &AgentWrapper{
		id:               "planning-specialist",
		name:             "Planning Specialist",
		agentType:        "planning",
		planExecuteAgent: planExecuteAgent,
		logger:           logger,
	}

	// Register agents with multi-agent system
	multiAgentSystem.RegisterAgent(securityAgent)
	multiAgentSystem.RegisterAgent(planningAgent)

	// Start the multi-agent system
	multiAgentSystem.StartSystem(ctx)
	defer multiAgentSystem.StopSystem()

	// Create a collaborative task
	collaborativeTask := multiagent.CollaborativeTask{
		ID:             "comprehensive-security-assessment",
		Name:           "Comprehensive Security Assessment",
		Description:    "Multi-agent collaborative security assessment with detailed reporting",
		Type:           multiagent.TaskTypeSecurityAssessment,
		Objective:      "Perform thorough security assessment using multiple specialized agents",
		RequiredAgents: []string{"security-specialist", "planning-specialist"},
		Priority:       multiagent.PriorityHigh,
		Status:         multiagent.TaskStatusPending,
		Metadata: map[string]interface{}{
			"target":           "example.com",
			"assessment_depth": "comprehensive",
			"deliverables":     []string{"vulnerability_report", "risk_assessment", "remediation_plan"},
		},
	}

	fmt.Printf("🎯 Collaborative Task: %s\n", collaborativeTask.Name)
	fmt.Printf("🎯 Required Agents: %v\n", collaborativeTask.RequiredAgents)

	collaborativeResult, err := multiAgentSystem.ExecuteCollaborativeTask(ctx, collaborativeTask)
	if err != nil {
		log.Printf("Multi-agent collaboration failed: %v", err)
	} else {
		fmt.Printf("✅ Multi-Agent Collaboration Completed!\n")
		fmt.Printf("   Duration: %v\n", collaborativeResult.Duration)
		fmt.Printf("   Participating Agents: %d\n", len(collaborativeResult.ParticipatingAgents))
		fmt.Printf("   Subtask Results: %d\n", len(collaborativeResult.SubtaskResults))
		fmt.Printf("   Success: %v\n", collaborativeResult.Success)
	}

	fmt.Println()

	// Demo 4: System Capabilities Summary
	fmt.Println("📊 Demo 4: System Capabilities Summary")
	fmt.Println(strings.Repeat("-", 50))

	fmt.Printf("ReAct Agent Capabilities:\n")
	reactCaps := reactAgent.GetCapabilities()
	for key, value := range reactCaps {
		fmt.Printf("  - %s: %v\n", key, value)
	}

	fmt.Printf("\nPlan-and-Execute Agent Capabilities:\n")
	planCaps := planExecuteAgent.GetCapabilities()
	for key, value := range planCaps {
		fmt.Printf("  - %s: %v\n", key, value)
	}

	fmt.Printf("\nMulti-Agent System Status:\n")
	systemStatus := multiAgentSystem.GetSystemStatus()
	fmt.Printf("  - System ID: %s\n", systemStatus.SystemID)
	fmt.Printf("  - Total Agents: %d\n", systemStatus.TotalAgents)
	fmt.Printf("  - Agent Statuses:\n")
	for agentID, status := range systemStatus.AgentStatuses {
		fmt.Printf("    * %s: %s\n", agentID, status)
	}

	// Final Summary
	fmt.Println()
	fmt.Println("🎉 Comprehensive Agent Demo Summary")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("✅ ReAct Agent: Reasoning + Acting cycles with tool integration\n")
	fmt.Printf("✅ Plan-and-Execute Agent: Strategic planning with parallel execution\n")
	fmt.Printf("✅ Multi-Agent System: Collaborative task execution with conflict resolution\n")
	fmt.Printf("✅ Tool Integration: Security scanning, analysis, and reporting tools\n")
	fmt.Printf("✅ Observability: Comprehensive logging and metrics collection\n")
	fmt.Printf("\n🚀 All agent types demonstrated successfully!\n")
	fmt.Printf("   Total Execution Time: ~15-20 seconds\n")
	fmt.Printf("   Tools Demonstrated: 4\n")
	fmt.Printf("   Agent Types: 3\n")
	fmt.Printf("   Collaboration Patterns: Multiple\n")

	logger.Info("Comprehensive Agent Demo completed successfully")
}

// AgentWrapper wraps our agents to implement the multiagent.Agent interface
type AgentWrapper struct {
	id               string
	name             string
	agentType        string
	reactAgent       *react.ReActAgent
	planExecuteAgent *planexecute.PlanAndExecuteAgent
	logger           *logger.Logger
	status           multiagent.AgentStatus
}

func (aw *AgentWrapper) ID() string                        { return aw.id }
func (aw *AgentWrapper) Name() string                      { return aw.name }
func (aw *AgentWrapper) GetStatus() multiagent.AgentStatus { return aw.status }

func (aw *AgentWrapper) GetCapabilities() map[string]interface{} {
	if aw.reactAgent != nil {
		return aw.reactAgent.GetCapabilities()
	}
	if aw.planExecuteAgent != nil {
		return aw.planExecuteAgent.GetCapabilities()
	}
	return map[string]interface{}{
		"agent_type": aw.agentType,
	}
}

func (aw *AgentWrapper) Execute(ctx context.Context, input multiagent.AgentInput) (*multiagent.AgentOutput, error) {
	aw.status = multiagent.AgentStatusBusy
	defer func() { aw.status = multiagent.AgentStatusIdle }()

	if aw.reactAgent != nil {
		reactInput := react.AgentInput{
			Query:   input.Task.Objective,
			Context: input.Context,
		}
		result, err := aw.reactAgent.Execute(ctx, reactInput)
		if err != nil {
			return nil, err
		}
		return &multiagent.AgentOutput{
			Success:    result.Success,
			Result:     result.Answer,
			Confidence: result.Confidence,
			Duration:   result.Duration,
		}, nil
	}

	if aw.planExecuteAgent != nil {
		planInput := planexecute.AgentInput{
			Objective: input.Task.Objective,
			Context:   input.Context,
		}
		result, err := aw.planExecuteAgent.Execute(ctx, planInput)
		if err != nil {
			return nil, err
		}
		return &multiagent.AgentOutput{
			Success:  result.Success,
			Result:   result.Result,
			Duration: result.Duration,
		}, nil
	}

	return nil, fmt.Errorf("no agent implementation available")
}

func (aw *AgentWrapper) HandleMessage(ctx context.Context, message *messaging.AgentMessage) error {
	aw.logger.Info("Agent received message", "agent_id", aw.id, "from", message.From)
	return nil
}

func (aw *AgentWrapper) Start(ctx context.Context) error {
	aw.status = multiagent.AgentStatusIdle
	aw.logger.Info("Agent started", "agent_id", aw.id)
	return nil
}

func (aw *AgentWrapper) Stop() error {
	aw.status = multiagent.AgentStatusOffline
	aw.logger.Info("Agent stopped", "agent_id", aw.id)
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
