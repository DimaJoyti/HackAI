package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
	fmt.Println("🧠 HackAI ReAct Agent Demo")
	fmt.Println("===========================")

	// Initialize logger
	appLogger := logger.NewDefault()

	// Run ReAct agent demo
	if err := runReActAgentDemo(appLogger); err != nil {
		log.Fatalf("ReAct agent demo failed: %v", err)
	}

	fmt.Println("\n✅ ReAct agent demo completed successfully!")
}

// runReActAgentDemo demonstrates a ReAct (Reasoning + Acting) agent
func runReActAgentDemo(logger *logger.Logger) error {
	fmt.Println("\n🤖 ReAct Agent Demo")
	fmt.Println("-------------------")

	ctx := context.Background()

	// Create ReAct agent
	agent := NewReActAgent("react-agent-1", "Security Analysis Agent", logger)

	// Create tools for the agent
	tools := []Tool{
		NewCalculatorTool(),
		NewWebSearchTool(),
		NewSecurityScanTool(),
		NewReportGeneratorTool(),
	}

	// Register tools with agent
	for _, tool := range tools {
		agent.RegisterTool(tool)
	}

	// Test scenarios
	scenarios := []string{
		"Calculate the risk score for a system with 5 critical vulnerabilities, 10 high vulnerabilities, and 20 medium vulnerabilities",
		"Search for recent security vulnerabilities in Node.js applications",
		"Perform a security scan on the domain example.com",
		"Generate a security report for the findings",
	}

	for i, scenario := range scenarios {
		fmt.Printf("\n📋 Scenario %d: %s\n", i+1, scenario)

		result, err := agent.Execute(ctx, AgentInput{
			Query:   scenario,
			Context: make(map[string]interface{}),
		})

		if err != nil {
			return fmt.Errorf("scenario %d failed: %w", i+1, err)
		}

		fmt.Printf("✅ Result: %s\n", result.Output)
		fmt.Printf("🔄 Iterations: %d\n", result.Iterations)
		fmt.Printf("⏱️  Duration: %v\n", result.Duration)
	}

	return nil
}

// ReActAgent implements the ReAct (Reasoning + Acting) pattern
type ReActAgent struct {
	ID              string
	Name            string
	Tools           map[string]Tool
	MaxIterations   int
	Logger          *logger.Logger
	ReasoningEngine *ReasoningEngine
	ActionPlanner   *ActionPlanner
	SelfReflector   *SelfReflector
}

// AgentInput represents input to the agent
type AgentInput struct {
	Query   string                 `json:"query"`
	Context map[string]interface{} `json:"context"`
}

// AgentOutput represents output from the agent
type AgentOutput struct {
	Output     string        `json:"output"`
	Iterations int           `json:"iterations"`
	Duration   time.Duration `json:"duration"`
	Thoughts   []Thought     `json:"thoughts"`
	Actions    []Action      `json:"actions"`
}

// Thought represents a reasoning step
type Thought struct {
	Step       int       `json:"step"`
	Content    string    `json:"content"`
	Confidence float64   `json:"confidence"`
	Timestamp  time.Time `json:"timestamp"`
}

// Action represents an action taken by the agent
type Action struct {
	Step      int                    `json:"step"`
	Tool      string                 `json:"tool"`
	Input     map[string]interface{} `json:"input"`
	Output    interface{}            `json:"output"`
	Success   bool                   `json:"success"`
	Error     string                 `json:"error,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// Tool interface for agent tools
type Tool interface {
	ID() string
	Name() string
	Description() string
	Execute(ctx context.Context, input map[string]interface{}) (interface{}, error)
	CanHandle(query string) bool
}

// NewReActAgent creates a new ReAct agent
func NewReActAgent(id, name string, logger *logger.Logger) *ReActAgent {
	return &ReActAgent{
		ID:              id,
		Name:            name,
		Tools:           make(map[string]Tool),
		MaxIterations:   5,
		Logger:          logger,
		ReasoningEngine: NewReasoningEngine(),
		ActionPlanner:   NewActionPlanner(),
		SelfReflector:   NewSelfReflector(),
	}
}

// RegisterTool registers a tool with the agent
func (a *ReActAgent) RegisterTool(tool Tool) {
	a.Tools[tool.ID()] = tool
	a.Logger.Info("Tool registered", "agent_id", a.ID, "tool_id", tool.ID(), "tool_name", tool.Name())
}

// Execute executes the ReAct workflow
func (a *ReActAgent) Execute(ctx context.Context, input AgentInput) (*AgentOutput, error) {
	startTime := time.Now()

	output := &AgentOutput{
		Thoughts: make([]Thought, 0),
		Actions:  make([]Action, 0),
	}

	for iteration := 1; iteration <= a.MaxIterations; iteration++ {
		// Reasoning phase
		thought, err := a.ReasoningEngine.Think(ctx, input.Query, output.Thoughts, output.Actions)
		if err != nil {
			return nil, fmt.Errorf("reasoning failed at iteration %d: %w", iteration, err)
		}

		output.Thoughts = append(output.Thoughts, thought)
		a.Logger.Info("Agent thought", "agent_id", a.ID, "iteration", iteration, "thought", thought.Content)

		// Action planning
		action, err := a.ActionPlanner.Plan(ctx, thought, a.Tools)
		if err != nil {
			return nil, fmt.Errorf("action planning failed at iteration %d: %w", iteration, err)
		}

		if action == nil {
			// No action needed, agent has reached conclusion
			output.Output = thought.Content
			break
		}

		// Execute action
		tool, exists := a.Tools[action.Tool]
		if !exists {
			return nil, fmt.Errorf("tool %s not found", action.Tool)
		}

		actionResult, err := tool.Execute(ctx, action.Input)
		if err != nil {
			action.Success = false
			action.Error = err.Error()
			a.Logger.Error("Tool execution failed", "agent_id", a.ID, "tool", action.Tool, "error", err)
		} else {
			action.Success = true
			action.Output = actionResult
			a.Logger.Info("Tool executed", "agent_id", a.ID, "tool", action.Tool, "result", actionResult)
		}

		output.Actions = append(output.Actions, *action)

		// Self-reflection
		shouldContinue, finalAnswer := a.SelfReflector.Reflect(ctx, thought, action, output.Thoughts, output.Actions)
		if !shouldContinue {
			output.Output = finalAnswer
			break
		}

		// Update input context with action results
		if action.Success {
			input.Context[fmt.Sprintf("action_%d_result", iteration)] = action.Output
		}
	}

	output.Iterations = len(output.Thoughts)
	output.Duration = time.Since(startTime)

	return output, nil
}

// ReasoningEngine handles the reasoning phase
type ReasoningEngine struct{}

func NewReasoningEngine() *ReasoningEngine {
	return &ReasoningEngine{}
}

func (re *ReasoningEngine) Think(ctx context.Context, query string, previousThoughts []Thought, previousActions []Action) (Thought, error) {
	step := len(previousThoughts) + 1

	// Simple reasoning logic based on query analysis
	var content string
	var confidence float64

	if step == 1 {
		content = fmt.Sprintf("I need to analyze the query: '%s'. Let me break this down and determine what actions are needed.", query)
		confidence = 0.8
	} else {
		// Analyze previous actions and plan next steps
		if len(previousActions) > 0 {
			lastAction := previousActions[len(previousActions)-1]
			if lastAction.Success {
				content = fmt.Sprintf("The previous action using %s was successful. Let me analyze the results and determine next steps.", lastAction.Tool)
				confidence = 0.9
			} else {
				content = "The previous action failed. Let me try a different approach."
				confidence = 0.6
			}
		} else {
			content = "I need to select an appropriate tool to help with this task."
			confidence = 0.7
		}
	}

	return Thought{
		Step:       step,
		Content:    content,
		Confidence: confidence,
		Timestamp:  time.Now(),
	}, nil
}

// ActionPlanner handles action planning
type ActionPlanner struct{}

func NewActionPlanner() *ActionPlanner {
	return &ActionPlanner{}
}

func (ap *ActionPlanner) Plan(ctx context.Context, thought Thought, tools map[string]Tool) (*Action, error) {
	// Simple action planning logic
	for _, tool := range tools {
		if tool.CanHandle(thought.Content) {
			return &Action{
				Step:      thought.Step,
				Tool:      tool.ID(),
				Input:     map[string]interface{}{"query": thought.Content},
				Timestamp: time.Now(),
			}, nil
		}
	}

	// No suitable tool found, agent should conclude
	return nil, nil
}

// SelfReflector handles self-reflection
type SelfReflector struct{}

func NewSelfReflector() *SelfReflector {
	return &SelfReflector{}
}

func (sr *SelfReflector) Reflect(ctx context.Context, thought Thought, action *Action, allThoughts []Thought, allActions []Action) (bool, string) {
	// Simple reflection logic
	if action != nil && action.Success {
		// Check if we have enough information to provide a final answer
		if len(allActions) >= 2 {
			return false, fmt.Sprintf("Based on my analysis and the results from %d actions, I can conclude: %v", len(allActions), action.Output)
		}
	}

	// Continue if we haven't reached a conclusion
	return len(allThoughts) < 3, ""
}

// Tool implementations

// CalculatorTool performs mathematical calculations
type CalculatorTool struct{}

func NewCalculatorTool() *CalculatorTool {
	return &CalculatorTool{}
}

func (ct *CalculatorTool) ID() string   { return "calculator" }
func (ct *CalculatorTool) Name() string { return "Calculator" }
func (ct *CalculatorTool) Description() string {
	return "Performs mathematical calculations and risk scoring"
}

func (ct *CalculatorTool) CanHandle(query string) bool {
	keywords := []string{"calculate", "risk score", "vulnerabilities", "math", "score"}
	queryLower := strings.ToLower(query)
	for _, keyword := range keywords {
		if strings.Contains(queryLower, keyword) {
			return true
		}
	}
	return false
}

func (ct *CalculatorTool) Execute(ctx context.Context, input map[string]interface{}) (interface{}, error) {
	// Simple risk calculation: Critical * 10 + High * 5 + Medium * 2
	result := "Risk Score Calculation: Assuming 5 critical (50 points), 10 high (50 points), 20 medium (40 points) = Total Risk Score: 140"
	return result, nil
}

// WebSearchTool simulates web search functionality
type WebSearchTool struct{}

func NewWebSearchTool() *WebSearchTool {
	return &WebSearchTool{}
}

func (wst *WebSearchTool) ID() string          { return "web_search" }
func (wst *WebSearchTool) Name() string        { return "Web Search" }
func (wst *WebSearchTool) Description() string { return "Searches the web for information" }

func (wst *WebSearchTool) CanHandle(query string) bool {
	keywords := []string{"search", "find", "recent", "vulnerabilities", "CVE"}
	queryLower := strings.ToLower(query)
	for _, keyword := range keywords {
		if strings.Contains(queryLower, keyword) {
			return true
		}
	}
	return false
}

func (wst *WebSearchTool) Execute(ctx context.Context, input map[string]interface{}) (interface{}, error) {
	result := "Found 3 recent Node.js vulnerabilities: CVE-2023-1234 (Critical), CVE-2023-5678 (High), CVE-2023-9012 (Medium)"
	return result, nil
}

// SecurityScanTool simulates security scanning
type SecurityScanTool struct{}

func NewSecurityScanTool() *SecurityScanTool {
	return &SecurityScanTool{}
}

func (sst *SecurityScanTool) ID() string   { return "security_scan" }
func (sst *SecurityScanTool) Name() string { return "Security Scanner" }
func (sst *SecurityScanTool) Description() string {
	return "Performs security scans on domains and applications"
}

func (sst *SecurityScanTool) CanHandle(query string) bool {
	keywords := []string{"scan", "security", "domain", "vulnerability"}
	queryLower := strings.ToLower(query)
	for _, keyword := range keywords {
		if strings.Contains(queryLower, keyword) {
			return true
		}
	}
	return false
}

func (sst *SecurityScanTool) Execute(ctx context.Context, input map[string]interface{}) (interface{}, error) {
	result := "Security scan completed for example.com: 2 medium vulnerabilities found (outdated SSL certificate, missing security headers)"
	return result, nil
}

// ReportGeneratorTool generates reports
type ReportGeneratorTool struct{}

func NewReportGeneratorTool() *ReportGeneratorTool {
	return &ReportGeneratorTool{}
}

func (rgt *ReportGeneratorTool) ID() string   { return "report_generator" }
func (rgt *ReportGeneratorTool) Name() string { return "Report Generator" }
func (rgt *ReportGeneratorTool) Description() string {
	return "Generates security reports and summaries"
}

func (rgt *ReportGeneratorTool) CanHandle(query string) bool {
	keywords := []string{"report", "generate", "summary", "findings"}
	queryLower := strings.ToLower(query)
	for _, keyword := range keywords {
		if strings.Contains(queryLower, keyword) {
			return true
		}
	}
	return false
}

func (rgt *ReportGeneratorTool) Execute(ctx context.Context, input map[string]interface{}) (interface{}, error) {
	result := "Security Report Generated: Executive Summary with risk scores, vulnerability details, and remediation recommendations"
	return result, nil
}
