package react

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/tools"
	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var reactTracer = otel.Tracer("hackai/langgraph/agents/react")

// ReActAgent implements the ReAct (Reasoning + Acting) pattern
type ReActAgent struct {
	ID               string
	Name             string
	Description      string
	Tools            map[string]tools.Tool
	MaxIterations    int
	ConfidenceThreshold float64
	Logger           *logger.Logger
	ReasoningEngine  *ReasoningEngine
	ActionPlanner    *ActionPlanner
	SelfReflector    *SelfReflector
	ToolExecutor     *ToolExecutor
	config           *ReActConfig
}

// ReActConfig holds configuration for the ReAct agent
type ReActConfig struct {
	MaxIterations       int           `json:"max_iterations"`
	ConfidenceThreshold float64       `json:"confidence_threshold"`
	ToolTimeout         time.Duration `json:"tool_timeout"`
	EnableSelfReflection bool         `json:"enable_self_reflection"`
	EnableMemory        bool          `json:"enable_memory"`
	MaxMemorySize       int           `json:"max_memory_size"`
}

// AgentInput represents input to the ReAct agent
type AgentInput struct {
	Query     string                 `json:"query"`
	Context   map[string]interface{} `json:"context"`
	Goals     []string               `json:"goals"`
	Constraints []string             `json:"constraints"`
}

// AgentOutput represents output from the ReAct agent
type AgentOutput struct {
	Answer      string        `json:"answer"`
	Confidence  float64       `json:"confidence"`
	Iterations  int           `json:"iterations"`
	Duration    time.Duration `json:"duration"`
	Thoughts    []Thought     `json:"thoughts"`
	Actions     []Action      `json:"actions"`
	Success     bool          `json:"success"`
	Error       string        `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Thought represents a reasoning step
type Thought struct {
	Step        int                    `json:"step"`
	Content     string                 `json:"content"`
	Reasoning   string                 `json:"reasoning"`
	Confidence  float64                `json:"confidence"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Action represents an action taken by the agent
type Action struct {
	Step        int                    `json:"step"`
	Tool        string                 `json:"tool"`
	Input       map[string]interface{} `json:"input"`
	Output      interface{}            `json:"output"`
	Success     bool                   `json:"success"`
	Error       string                 `json:"error,omitempty"`
	Duration    time.Duration          `json:"duration"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewReActAgent creates a new ReAct agent
func NewReActAgent(id, name string, logger *logger.Logger) *ReActAgent {
	config := &ReActConfig{
		MaxIterations:       10,
		ConfidenceThreshold: 0.8,
		ToolTimeout:         30 * time.Second,
		EnableSelfReflection: true,
		EnableMemory:        true,
		MaxMemorySize:       100,
	}

	return &ReActAgent{
		ID:                  id,
		Name:                name,
		Description:         "ReAct agent using reasoning and acting cycles",
		Tools:               make(map[string]tools.Tool),
		MaxIterations:       config.MaxIterations,
		ConfidenceThreshold: config.ConfidenceThreshold,
		Logger:              logger,
		ReasoningEngine:     NewReasoningEngine(logger),
		ActionPlanner:       NewActionPlanner(logger),
		SelfReflector:       NewSelfReflector(logger),
		ToolExecutor:        NewToolExecutor(config.ToolTimeout, logger),
		config:              config,
	}
}

// RegisterTool registers a tool with the agent
func (ra *ReActAgent) RegisterTool(tool tools.Tool) error {
	if tool == nil {
		return fmt.Errorf("tool cannot be nil")
	}

	ra.Tools[tool.ID()] = tool
	ra.Logger.Info("Tool registered with ReAct agent",
		"agent_id", ra.ID,
		"tool_id", tool.ID(),
		"tool_name", tool.Name())

	return nil
}

// Execute executes the ReAct workflow
func (ra *ReActAgent) Execute(ctx context.Context, input AgentInput) (*AgentOutput, error) {
	ctx, span := reactTracer.Start(ctx, "react_agent.execute",
		trace.WithAttributes(
			attribute.String("agent.id", ra.ID),
			attribute.String("agent.name", ra.Name),
			attribute.String("query", input.Query),
		),
	)
	defer span.End()

	startTime := time.Now()
	
	output := &AgentOutput{
		Thoughts: make([]Thought, 0),
		Actions:  make([]Action, 0),
		Metadata: make(map[string]interface{}),
	}

	ra.Logger.Info("Starting ReAct agent execution",
		"agent_id", ra.ID,
		"query", input.Query,
		"max_iterations", ra.MaxIterations)

	// Main ReAct loop
	for iteration := 1; iteration <= ra.MaxIterations; iteration++ {
		// Reasoning phase
		thought, err := ra.ReasoningEngine.Think(ctx, input, output.Thoughts, output.Actions)
		if err != nil {
			output.Success = false
			output.Error = fmt.Sprintf("reasoning failed at iteration %d: %v", iteration, err)
			span.RecordError(err)
			return output, err
		}
		
		output.Thoughts = append(output.Thoughts, thought)
		ra.Logger.Debug("Agent reasoning step",
			"agent_id", ra.ID,
			"iteration", iteration,
			"thought", thought.Content,
			"confidence", thought.Confidence)

		// Check if reasoning confidence is high enough to conclude
		if thought.Confidence >= ra.ConfidenceThreshold && ra.shouldConclude(thought, output) {
			output.Answer = thought.Content
			output.Confidence = thought.Confidence
			output.Success = true
			break
		}

		// Action planning phase
		action, err := ra.ActionPlanner.Plan(ctx, thought, ra.Tools, input)
		if err != nil {
			output.Success = false
			output.Error = fmt.Sprintf("action planning failed at iteration %d: %v", iteration, err)
			span.RecordError(err)
			return output, err
		}

		// If no action is planned, agent has reached conclusion
		if action == nil {
			output.Answer = thought.Content
			output.Confidence = thought.Confidence
			output.Success = true
			break
		}

		// Execute action
		actionResult, err := ra.ToolExecutor.Execute(ctx, action, ra.Tools)
		if err != nil {
			action.Success = false
			action.Error = err.Error()
			ra.Logger.Error("Tool execution failed",
				"agent_id", ra.ID,
				"tool", action.Tool,
				"error", err)
		} else {
			action.Success = true
			action.Output = actionResult
			ra.Logger.Debug("Tool executed successfully",
				"agent_id", ra.ID,
				"tool", action.Tool,
				"duration", action.Duration)
		}

		output.Actions = append(output.Actions, *action)

		// Self-reflection phase (if enabled)
		if ra.config.EnableSelfReflection {
			shouldContinue, finalAnswer, confidence := ra.SelfReflector.Reflect(ctx, thought, action, output)
			if !shouldContinue {
				output.Answer = finalAnswer
				output.Confidence = confidence
				output.Success = true
				break
			}
		}

		// Update context with action results for next iteration
		if action.Success {
			input.Context[fmt.Sprintf("action_%d_result", iteration)] = action.Output
		}
	}

	// Finalize output
	output.Iterations = len(output.Thoughts)
	output.Duration = time.Since(startTime)

	// If no answer was set, use the last thought
	if output.Answer == "" && len(output.Thoughts) > 0 {
		lastThought := output.Thoughts[len(output.Thoughts)-1]
		output.Answer = lastThought.Content
		output.Confidence = lastThought.Confidence
		output.Success = true
	}

	// Set metadata
	output.Metadata["total_tools_used"] = len(output.Actions)
	output.Metadata["successful_actions"] = ra.countSuccessfulActions(output.Actions)
	output.Metadata["average_confidence"] = ra.calculateAverageConfidence(output.Thoughts)

	span.SetAttributes(
		attribute.Int("execution.iterations", output.Iterations),
		attribute.Float64("execution.duration", output.Duration.Seconds()),
		attribute.Bool("execution.success", output.Success),
		attribute.Float64("execution.confidence", output.Confidence),
	)

	ra.Logger.Info("ReAct agent execution completed",
		"agent_id", ra.ID,
		"iterations", output.Iterations,
		"duration", output.Duration,
		"success", output.Success,
		"confidence", output.Confidence)

	return output, nil
}

// shouldConclude determines if the agent should conclude based on the current thought
func (ra *ReActAgent) shouldConclude(thought Thought, output *AgentOutput) bool {
	// Check if the thought indicates a conclusion
	conclusionKeywords := []string{"conclusion", "answer", "result", "final", "therefore"}
	thoughtLower := strings.ToLower(thought.Content)
	
	for _, keyword := range conclusionKeywords {
		if strings.Contains(thoughtLower, keyword) {
			return true
		}
	}

	// Check if we have enough information
	if len(output.Actions) >= 3 && thought.Confidence > 0.7 {
		return true
	}

	return false
}

// countSuccessfulActions counts the number of successful actions
func (ra *ReActAgent) countSuccessfulActions(actions []Action) int {
	count := 0
	for _, action := range actions {
		if action.Success {
			count++
		}
	}
	return count
}

// calculateAverageConfidence calculates the average confidence across all thoughts
func (ra *ReActAgent) calculateAverageConfidence(thoughts []Thought) float64 {
	if len(thoughts) == 0 {
		return 0.0
	}

	total := 0.0
	for _, thought := range thoughts {
		total += thought.Confidence
	}

	return total / float64(len(thoughts))
}

// GetCapabilities returns the agent's capabilities
func (ra *ReActAgent) GetCapabilities() map[string]interface{} {
	toolNames := make([]string, 0, len(ra.Tools))
	for _, tool := range ra.Tools {
		toolNames = append(toolNames, tool.Name())
	}

	return map[string]interface{}{
		"agent_type":           "react",
		"max_iterations":       ra.MaxIterations,
		"confidence_threshold": ra.ConfidenceThreshold,
		"available_tools":      toolNames,
		"self_reflection":      ra.config.EnableSelfReflection,
		"memory_enabled":       ra.config.EnableMemory,
	}
}

// UpdateConfig updates the agent configuration
func (ra *ReActAgent) UpdateConfig(config *ReActConfig) {
	if config.MaxIterations > 0 {
		ra.MaxIterations = config.MaxIterations
		ra.config.MaxIterations = config.MaxIterations
	}
	
	if config.ConfidenceThreshold > 0 && config.ConfidenceThreshold <= 1.0 {
		ra.ConfidenceThreshold = config.ConfidenceThreshold
		ra.config.ConfidenceThreshold = config.ConfidenceThreshold
	}

	if config.ToolTimeout > 0 {
		ra.config.ToolTimeout = config.ToolTimeout
		ra.ToolExecutor.UpdateTimeout(config.ToolTimeout)
	}

	ra.config.EnableSelfReflection = config.EnableSelfReflection
	ra.config.EnableMemory = config.EnableMemory

	ra.Logger.Info("ReAct agent configuration updated",
		"agent_id", ra.ID,
		"max_iterations", ra.MaxIterations,
		"confidence_threshold", ra.ConfidenceThreshold)
}
