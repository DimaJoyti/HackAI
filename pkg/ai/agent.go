package ai

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var agentTracer = otel.Tracer("hackai/ai/agent")

// BaseAgent provides common functionality for all agents
type BaseAgent struct {
	id             string
	name           string
	description    string
	tools          map[string]Tool
	decisionEngine DecisionEngine
	metrics        AgentMetrics
	logger         *logger.Logger
	tracer         trace.Tracer
	mutex          sync.RWMutex
}

// NewBaseAgent creates a new base agent
func NewBaseAgent(id, name, description string, logger *logger.Logger) *BaseAgent {
	return &BaseAgent{
		id:          id,
		name:        name,
		description: description,
		tools:       make(map[string]Tool),
		logger:      logger,
		tracer:      agentTracer,
		metrics: AgentMetrics{
			ToolUsageStats:    make(map[string]int64),
			LastExecutionTime: time.Now(),
		},
	}
}

// ID returns the agent ID
func (a *BaseAgent) ID() string {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.id
}

// Name returns the agent name
func (a *BaseAgent) Name() string {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.name
}

// Description returns the agent description
func (a *BaseAgent) Description() string {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.description
}

// AddTool adds a tool to the agent
func (a *BaseAgent) AddTool(tool Tool) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if tool == nil {
		return fmt.Errorf("tool cannot be nil")
	}

	toolName := tool.Name()
	if toolName == "" {
		return fmt.Errorf("tool name cannot be empty")
	}

	if _, exists := a.tools[toolName]; exists {
		return fmt.Errorf("tool %s already exists", toolName)
	}

	a.tools[toolName] = tool
	a.metrics.ToolUsageStats[toolName] = 0

	a.logger.Debug("Tool added to agent",
		"agent_id", a.id,
		"tool_name", toolName)

	return nil
}

// RemoveTool removes a tool from the agent
func (a *BaseAgent) RemoveTool(toolName string) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if _, exists := a.tools[toolName]; !exists {
		return fmt.Errorf("tool %s not found", toolName)
	}

	delete(a.tools, toolName)
	delete(a.metrics.ToolUsageStats, toolName)

	a.logger.Debug("Tool removed from agent",
		"agent_id", a.id,
		"tool_name", toolName)

	return nil
}

// GetAvailableTools returns all available tools
func (a *BaseAgent) GetAvailableTools() []Tool {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	tools := make([]Tool, 0, len(a.tools))
	for _, tool := range a.tools {
		tools = append(tools, tool)
	}
	return tools
}

// SetDecisionEngine sets the decision engine for the agent
func (a *BaseAgent) SetDecisionEngine(engine DecisionEngine) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if engine == nil {
		return fmt.Errorf("decision engine cannot be nil")
	}

	a.decisionEngine = engine

	a.logger.Debug("Decision engine set for agent",
		"agent_id", a.id)

	return nil
}

// GetMetrics returns the agent metrics
func (a *BaseAgent) GetMetrics() AgentMetrics {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.metrics
}

// Execute executes the agent with the given input
func (a *BaseAgent) Execute(ctx context.Context, input AgentInput) (AgentOutput, error) {
	startTime := time.Now()

	// Create span for tracing
	ctx, span := a.tracer.Start(ctx, "agent.execute",
		trace.WithAttributes(
			attribute.String("agent.id", a.id),
			attribute.String("agent.name", a.name),
			attribute.String("query", input.Query),
			attribute.Int("max_steps", input.MaxSteps),
		),
	)
	defer span.End()

	// Update metrics
	a.updateExecutionStart()

	// Validate input
	if err := a.validateInput(input); err != nil {
		span.RecordError(err)
		return AgentOutput{}, fmt.Errorf("input validation failed: %w", err)
	}

	// Initialize output
	output := AgentOutput{
		Steps:     make([]AgentStep, 0),
		ToolsUsed: make([]string, 0),
		Metadata:  make(map[string]interface{}),
		Success:   false,
	}

	// Execute agent steps
	for step := 0; step < input.MaxSteps; step++ {
		stepResult, shouldContinue, err := a.executeStep(ctx, input, output.Steps, step)
		if err != nil {
			output.Steps = append(output.Steps, stepResult)
			a.updateExecutionEnd(time.Since(startTime), false)
			span.RecordError(err)
			return output, fmt.Errorf("step %d failed: %w", step, err)
		}

		output.Steps = append(output.Steps, stepResult)

		// Update tools used
		if stepResult.Tool != "" {
			found := false
			for _, tool := range output.ToolsUsed {
				if tool == stepResult.Tool {
					found = true
					break
				}
			}
			if !found {
				output.ToolsUsed = append(output.ToolsUsed, stepResult.Tool)
			}
		}

		// Check if we should continue
		if !shouldContinue {
			if stepResult.Action == "respond" {
				output.Response = stepResult.Output["response"].(string)
				output.Success = true
			}
			break
		}
	}

	// Calculate final metrics
	duration := time.Since(startTime)
	output.Duration = duration
	output.Confidence = a.calculateConfidence(output.Steps)

	// Update metrics
	a.updateExecutionEnd(duration, output.Success)
	a.updateToolUsageStats(output.ToolsUsed)

	if !output.Success && output.Response == "" {
		output.Response = "Maximum steps reached without completion"
	}

	span.SetAttributes(
		attribute.String("execution.duration", duration.String()),
		attribute.Bool("execution.success", output.Success),
		attribute.Int("steps.count", len(output.Steps)),
		attribute.Float64("confidence", output.Confidence),
	)

	a.logger.Info("Agent execution completed",
		"agent_id", a.id,
		"success", output.Success,
		"steps", len(output.Steps),
		"duration", duration)

	return output, nil
}

// executeStep executes a single step of the agent
func (a *BaseAgent) executeStep(ctx context.Context, input AgentInput, history []AgentStep, stepIndex int) (AgentStep, bool, error) {
	stepStartTime := time.Now()

	// Create step
	step := AgentStep{
		StepID:    fmt.Sprintf("step_%d", stepIndex),
		Timestamp: stepStartTime,
		Input:     make(map[string]interface{}),
		Output:    make(map[string]interface{}),
	}

	// Get decision from decision engine
	if a.decisionEngine == nil {
		return step, false, fmt.Errorf("no decision engine set")
	}

	action, err := a.decisionEngine.DecideNextAction(ctx, input, history)
	if err != nil {
		step.Error = err.Error()
		step.Success = false
		step.Duration = time.Since(stepStartTime)
		return step, false, fmt.Errorf("decision engine failed: %w", err)
	}

	step.Action = action.Type
	step.Reasoning = action.Reasoning

	// Execute based on action type
	switch action.Type {
	case "tool_use":
		return a.executeToolAction(ctx, action, step, stepStartTime)
	case "respond":
		step.Output["response"] = action.Response
		step.Success = true
		step.Duration = time.Since(stepStartTime)
		return step, false, nil // Don't continue after responding
	case "continue":
		step.Success = true
		step.Duration = time.Since(stepStartTime)
		return step, true, nil
	case "stop":
		step.Success = true
		step.Duration = time.Since(stepStartTime)
		return step, false, nil
	default:
		step.Error = fmt.Sprintf("unknown action type: %s", action.Type)
		step.Success = false
		step.Duration = time.Since(stepStartTime)
		return step, false, fmt.Errorf("unknown action type: %s", action.Type)
	}
}

// executeToolAction executes a tool action
func (a *BaseAgent) executeToolAction(ctx context.Context, action AgentAction, step AgentStep, startTime time.Time) (AgentStep, bool, error) {
	// Get the tool
	a.mutex.RLock()
	tool, exists := a.tools[action.ToolName]
	a.mutex.RUnlock()

	if !exists {
		step.Error = fmt.Sprintf("tool %s not found", action.ToolName)
		step.Success = false
		step.Duration = time.Since(startTime)
		return step, false, fmt.Errorf("tool %s not found", action.ToolName)
	}

	step.Tool = action.ToolName
	step.Input = action.ToolInput

	// Execute the tool
	toolOutput, err := tool.Execute(ctx, action.ToolInput)
	if err != nil {
		step.Error = err.Error()
		step.Success = false
		step.Duration = time.Since(startTime)
		return step, false, fmt.Errorf("tool execution failed: %w", err)
	}

	step.Output = toolOutput
	step.Success = true
	step.Duration = time.Since(startTime)

	return step, true, nil // Continue after tool execution
}

// validateInput validates the agent input
func (a *BaseAgent) validateInput(input AgentInput) error {
	if input.Query == "" {
		return fmt.Errorf("query cannot be empty")
	}
	if input.MaxSteps <= 0 {
		return fmt.Errorf("max steps must be positive")
	}
	if input.MaxSteps > 100 {
		return fmt.Errorf("max steps cannot exceed 100")
	}
	return nil
}

// calculateConfidence calculates the confidence score based on execution steps
func (a *BaseAgent) calculateConfidence(steps []AgentStep) float64 {
	if len(steps) == 0 {
		return 0.0
	}

	successCount := 0
	for _, step := range steps {
		if step.Success {
			successCount++
		}
	}

	return float64(successCount) / float64(len(steps))
}

// Validate validates the agent configuration
func (a *BaseAgent) Validate() error {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	if a.id == "" {
		return fmt.Errorf("agent ID cannot be empty")
	}
	if a.name == "" {
		return fmt.Errorf("agent name cannot be empty")
	}

	// Validate all tools
	for toolName, tool := range a.tools {
		if !tool.IsHealthy(context.Background()) {
			return fmt.Errorf("tool %s is not healthy", toolName)
		}
	}

	return nil
}

// updateExecutionStart updates metrics at the start of execution
func (a *BaseAgent) updateExecutionStart() {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.metrics.TotalExecutions++
}

// updateExecutionEnd updates metrics at the end of execution
func (a *BaseAgent) updateExecutionEnd(duration time.Duration, success bool) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if success {
		a.metrics.SuccessfulRuns++
	} else {
		a.metrics.FailedRuns++
	}

	// Update average latency
	if a.metrics.TotalExecutions == 1 {
		a.metrics.AverageLatency = duration
	} else {
		total := time.Duration(a.metrics.TotalExecutions-1) * a.metrics.AverageLatency
		a.metrics.AverageLatency = (total + duration) / time.Duration(a.metrics.TotalExecutions)
	}

	a.metrics.LastExecutionTime = time.Now()
}

// updateToolUsageStats updates tool usage statistics
func (a *BaseAgent) updateToolUsageStats(toolsUsed []string) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	for _, toolName := range toolsUsed {
		a.metrics.ToolUsageStats[toolName]++
	}
}
