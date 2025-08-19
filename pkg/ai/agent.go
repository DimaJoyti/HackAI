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

// EnhancedAgent extends the basic Agent interface with sophisticated decision-making
type EnhancedAgent interface {
	Agent
	ExecuteWithContext(ctx context.Context, execCtx AgentExecutionContext, input AgentInput) (*AgentExecutionResult, error)
	ExecuteAsync(ctx context.Context, execCtx AgentExecutionContext, input AgentInput) (<-chan *AgentExecutionResult, error)
	AddToolValidator(validator ToolValidator) error
	RemoveToolValidator(validatorID string) error
	GetExecutionHistory() []AgentExecutionResult
	UpdateStrategy(strategy AgentStrategy) error
	GetRecommendations(ctx context.Context, input AgentInput) ([]ActionRecommendation, error)
}

// AgentExecutionContext provides enhanced context for agent execution
type AgentExecutionContext struct {
	RequestID        string                 `json:"request_id"`
	UserID           string                 `json:"user_id"`
	SessionID        string                 `json:"session_id"`
	SecurityLevel    SecurityLevel          `json:"security_level"`
	MaxExecutionTime time.Duration          `json:"max_execution_time"`
	Priority         AgentPriority          `json:"priority"`
	Metadata         map[string]interface{} `json:"metadata"`
	StartTime        time.Time              `json:"start_time"`
}

// AgentExecutionResult provides detailed execution results
type AgentExecutionResult struct {
	Success            bool                    `json:"success"`
	Output             AgentOutput             `json:"output"`
	Error              error                   `json:"error,omitempty"`
	ExecutionTime      time.Duration           `json:"execution_time"`
	StepsExecuted      int                     `json:"steps_executed"`
	ToolsUsed          []string                `json:"tools_used"`
	DecisionPoints     []DecisionPoint         `json:"decision_points"`
	PerformanceMetrics AgentPerformanceMetrics `json:"performance_metrics"`
	Metadata           map[string]interface{}  `json:"metadata"`
}

// DecisionPoint represents a decision made during execution
type DecisionPoint struct {
	StepNumber     int                    `json:"step_number"`
	DecisionType   string                 `json:"decision_type"`
	Options        []ActionRecommendation `json:"options"`
	SelectedAction AgentAction            `json:"selected_action"`
	Confidence     float64                `json:"confidence"`
	Reasoning      string                 `json:"reasoning"`
	Timestamp      time.Time              `json:"timestamp"`
}

// ActionRecommendation represents a recommended action
type ActionRecommendation struct {
	Action        AgentAction `json:"action"`
	Confidence    float64     `json:"confidence"`
	Reasoning     string      `json:"reasoning"`
	Risk          RiskLevel   `json:"risk"`
	EstimatedCost float64     `json:"estimated_cost"`
}

// AgentPerformanceMetrics tracks detailed performance metrics
type AgentPerformanceMetrics struct {
	TotalExecutionTime time.Duration `json:"total_execution_time"`
	DecisionTime       time.Duration `json:"decision_time"`
	ToolExecutionTime  time.Duration `json:"tool_execution_time"`
	MemoryUsage        int64         `json:"memory_usage"`
	TokensConsumed     int           `json:"tokens_consumed"`
	APICallsCount      int           `json:"api_calls_count"`
	CacheHitRate       float64       `json:"cache_hit_rate"`
}

// AgentPriority defines execution priority levels
type AgentPriority int

const (
	PriorityLow AgentPriority = iota
	PriorityNormal
	PriorityHigh
	PriorityCritical
)

// RiskLevel defines risk levels for actions
type RiskLevel int

const (
	RiskLow RiskLevel = iota
	RiskMedium
	RiskHigh
	RiskCritical
)

// AgentStrategy defines the strategy for agent execution
type AgentStrategy struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	DecisionThreshold float64                `json:"decision_threshold"`
	RiskTolerance     RiskLevel              `json:"risk_tolerance"`
	MaxRetries        int                    `json:"max_retries"`
	TimeoutStrategy   string                 `json:"timeout_strategy"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// ToolValidator validates tool usage and security
type ToolValidator interface {
	ID() string
	ValidateTool(ctx context.Context, tool Tool, input map[string]interface{}) error
	ValidateOutput(ctx context.Context, tool Tool, output map[string]interface{}) error
}

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

	if a.logger != nil {
		a.logger.Debug("Tool added to agent",
			"agent_id", a.id,
			"tool_name", toolName)
	}

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

	if a.logger != nil {
		a.logger.Debug("Tool removed from agent",
			"agent_id", a.id,
			"tool_name", toolName)
	}

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

	if a.logger != nil {
		a.logger.Debug("Decision engine set for agent",
			"agent_id", a.id)
	}

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

	if a.logger != nil {
		a.logger.Info("Agent execution completed",
			"agent_id", a.id,
			"success", output.Success,
			"steps", len(output.Steps),
			"duration", duration)
	}

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

// AdvancedAgent implements the EnhancedAgent interface with sophisticated decision-making
type AdvancedAgent struct {
	*BaseAgent
	strategy         AgentStrategy
	toolValidators   []ToolValidator
	executionHistory []AgentExecutionResult
	maxHistorySize   int
	mlDecisionEngine *MLDecisionEngine
	mutex            sync.RWMutex
}

// NewAdvancedAgent creates a new advanced agent with enhanced capabilities
func NewAdvancedAgent(id, name, description string, logger *logger.Logger) *AdvancedAgent {
	baseAgent := NewBaseAgent(id, name, description, logger)

	return &AdvancedAgent{
		BaseAgent:        baseAgent,
		strategy:         getDefaultStrategy(),
		toolValidators:   make([]ToolValidator, 0),
		executionHistory: make([]AgentExecutionResult, 0),
		maxHistorySize:   100,
		mlDecisionEngine: NewMLDecisionEngine(fmt.Sprintf("%s-decision-engine", id), logger),
	}
}

// getDefaultStrategy returns a default agent strategy
func getDefaultStrategy() AgentStrategy {
	return AgentStrategy{
		ID:                "default",
		Name:              "Default Strategy",
		Description:       "Default agent execution strategy",
		DecisionThreshold: 0.7,
		RiskTolerance:     RiskMedium,
		MaxRetries:        3,
		TimeoutStrategy:   "exponential_backoff",
		Metadata:          make(map[string]interface{}),
	}
}

// ExecuteWithContext executes the agent with enhanced context and detailed results
func (a *AdvancedAgent) ExecuteWithContext(ctx context.Context, execCtx AgentExecutionContext, input AgentInput) (*AgentExecutionResult, error) {
	ctx, span := a.tracer.Start(ctx, "advanced_agent.execute_with_context",
		trace.WithAttributes(
			attribute.String("agent.id", a.id),
			attribute.String("agent.name", a.name),
			attribute.String("request.id", execCtx.RequestID),
			attribute.String("user.id", execCtx.UserID),
			attribute.String("priority", string(rune(execCtx.Priority))),
		),
	)
	defer span.End()

	startTime := time.Now()
	result := &AgentExecutionResult{
		DecisionPoints:     make([]DecisionPoint, 0),
		ToolsUsed:          make([]string, 0),
		Metadata:           make(map[string]interface{}),
		PerformanceMetrics: AgentPerformanceMetrics{},
	}

	// Validate input
	if err := a.validateInput(input); err != nil {
		result.Success = false
		result.Error = fmt.Errorf("input validation failed: %w", err)
		result.ExecutionTime = time.Since(startTime)
		span.RecordError(result.Error)
		return result, result.Error
	}

	// Execute with enhanced decision-making
	output, err := a.executeWithDecisionEngine(ctx, execCtx, input, result)
	if err != nil {
		result.Success = false
		result.Error = err
		result.Output = AgentOutput{}
	} else {
		result.Success = true
		result.Output = output
		result.ToolsUsed = output.ToolsUsed
	}

	result.ExecutionTime = time.Since(startTime)
	result.StepsExecuted = len(result.Output.Steps)

	// Update performance metrics
	a.updatePerformanceMetrics(result)

	// Store execution history
	a.addToHistory(*result)

	span.SetAttributes(
		attribute.Bool("execution.success", result.Success),
		attribute.String("execution.duration", result.ExecutionTime.String()),
		attribute.Int("steps.executed", result.StepsExecuted),
	)

	return result, nil
}

// ExecuteAsync executes the agent asynchronously
func (a *AdvancedAgent) ExecuteAsync(ctx context.Context, execCtx AgentExecutionContext, input AgentInput) (<-chan *AgentExecutionResult, error) {
	resultChan := make(chan *AgentExecutionResult, 1)

	go func() {
		defer close(resultChan)
		result, _ := a.ExecuteWithContext(ctx, execCtx, input)
		resultChan <- result
	}()

	return resultChan, nil
}

// executeWithDecisionEngine executes the agent using the ML decision engine
func (a *AdvancedAgent) executeWithDecisionEngine(ctx context.Context, execCtx AgentExecutionContext, input AgentInput, result *AgentExecutionResult) (AgentOutput, error) {
	output := AgentOutput{
		Steps:     make([]AgentStep, 0),
		ToolsUsed: make([]string, 0),
		Metadata:  make(map[string]interface{}),
		Success:   false,
	}

	// Execute steps with decision engine
	for step := 0; step < input.MaxSteps; step++ {
		decisionStartTime := time.Now()

		// Get recommendations from decision engine
		recommendations, err := a.GetRecommendations(ctx, input)
		if err != nil {
			return output, fmt.Errorf("failed to get recommendations for step %d: %w", step, err)
		}

		// Select best action based on strategy
		selectedAction, confidence, reasoning := a.selectBestAction(recommendations)

		// Record decision point
		decisionPoint := DecisionPoint{
			StepNumber:     step,
			DecisionType:   "action_selection",
			Options:        recommendations,
			SelectedAction: selectedAction,
			Confidence:     confidence,
			Reasoning:      reasoning,
			Timestamp:      time.Now(),
		}
		result.DecisionPoints = append(result.DecisionPoints, decisionPoint)
		result.PerformanceMetrics.DecisionTime += time.Since(decisionStartTime)

		// Execute the selected action
		stepResult, shouldContinue, err := a.executeActionWithValidation(ctx, selectedAction, input, output.Steps, step)
		if err != nil {
			output.Steps = append(output.Steps, stepResult)
			return output, fmt.Errorf("step %d execution failed: %w", step, err)
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
			break
		}
	}

	output.Success = true
	return output, nil
}

// GetRecommendations gets action recommendations from the decision engine
func (a *AdvancedAgent) GetRecommendations(ctx context.Context, input AgentInput) ([]ActionRecommendation, error) {
	// Convert agent input to decision engine format
	agentInput := AgentInput{
		Query:       input.Query,
		Context:     input.Context,
		MaxSteps:    input.MaxSteps,
		Tools:       input.Tools,
		Constraints: input.Constraints,
		Goals:       input.Goals,
	}

	// Get current execution history for context
	history := a.getRecentExecutionSteps()

	// Get decision from ML engine
	action, err := a.mlDecisionEngine.DecideNextAction(ctx, agentInput, history)
	if err != nil {
		return nil, fmt.Errorf("decision engine failed: %w", err)
	}

	// Convert to recommendations format
	recommendations := []ActionRecommendation{
		{
			Action:        action,
			Confidence:    0.8, // Default confidence
			Reasoning:     action.Reasoning,
			Risk:          a.assessActionRisk(action),
			EstimatedCost: a.estimateActionCost(action),
		},
	}

	// Add alternative actions based on available tools
	alternatives := a.generateAlternativeActions(ctx, input)
	recommendations = append(recommendations, alternatives...)

	return recommendations, nil
}

// selectBestAction selects the best action based on strategy and confidence
func (a *AdvancedAgent) selectBestAction(recommendations []ActionRecommendation) (AgentAction, float64, string) {
	if len(recommendations) == 0 {
		return AgentAction{
			Type:      "respond",
			Response:  "No suitable actions available",
			Reasoning: "No recommendations provided",
		}, 0.1, "No recommendations available"
	}

	// Filter by risk tolerance
	filtered := make([]ActionRecommendation, 0)
	for _, rec := range recommendations {
		if rec.Risk <= a.strategy.RiskTolerance {
			filtered = append(filtered, rec)
		}
	}

	if len(filtered) == 0 {
		// If no actions meet risk tolerance, use the lowest risk option
		lowestRisk := recommendations[0]
		for _, rec := range recommendations {
			if rec.Risk < lowestRisk.Risk {
				lowestRisk = rec
			}
		}
		return lowestRisk.Action, lowestRisk.Confidence,
			fmt.Sprintf("Selected lowest risk option: %s", lowestRisk.Reasoning)
	}

	// Select highest confidence action that meets threshold
	best := filtered[0]
	for _, rec := range filtered {
		if rec.Confidence > best.Confidence && rec.Confidence >= a.strategy.DecisionThreshold {
			best = rec
		}
	}

	return best.Action, best.Confidence, best.Reasoning
}

// executeActionWithValidation executes an action with tool validation
func (a *AdvancedAgent) executeActionWithValidation(ctx context.Context, action AgentAction, input AgentInput, history []AgentStep, stepNumber int) (AgentStep, bool, error) {
	stepStartTime := time.Now()

	step := AgentStep{
		StepID:    fmt.Sprintf("step_%d", stepNumber),
		Action:    action.Type,
		Timestamp: stepStartTime,
		Success:   false,
		Reasoning: action.Reasoning,
	}

	// Validate action if it uses a tool
	if action.Type == "tool_use" && action.ToolName != "" {
		tool, exists := a.tools[action.ToolName]
		if !exists {
			err := fmt.Errorf("tool %s not found", action.ToolName)
			step.Error = err.Error()
			step.Duration = time.Since(stepStartTime)
			return step, false, err
		}

		// Run tool validators
		for _, validator := range a.toolValidators {
			if err := validator.ValidateTool(ctx, tool, action.ToolInput); err != nil {
				validationErr := fmt.Errorf("tool validation failed: %w", err)
				step.Error = validationErr.Error()
				step.Duration = time.Since(stepStartTime)
				return step, false, validationErr
			}
		}

		// Execute tool
		toolOutput, err := tool.Execute(ctx, action.ToolInput)
		if err != nil {
			execErr := fmt.Errorf("tool execution failed: %w", err)
			step.Error = execErr.Error()
			step.Duration = time.Since(stepStartTime)
			return step, false, execErr
		}

		// Validate tool output
		for _, validator := range a.toolValidators {
			if err := validator.ValidateOutput(ctx, tool, toolOutput); err != nil {
				outputErr := fmt.Errorf("tool output validation failed: %w", err)
				step.Error = outputErr.Error()
				step.Duration = time.Since(stepStartTime)
				return step, false, outputErr
			}
		}

		step.Tool = action.ToolName
		step.Input = action.ToolInput
		step.Output = toolOutput
		step.Success = true
	} else if action.Type == "respond" {
		// Handle response action
		step.Output = map[string]interface{}{
			"response": action.Response,
		}
		step.Success = true
	} else {
		err := fmt.Errorf("unknown action type: %s", action.Type)
		step.Error = err.Error()
		step.Duration = time.Since(stepStartTime)
		return step, false, err
	}

	step.Duration = time.Since(stepStartTime)

	// Determine if execution should continue
	shouldContinue := a.shouldContinueExecution(action, step, history)

	return step, shouldContinue, nil
}

// Helper methods for AdvancedAgent

// getRecentExecutionSteps gets recent execution steps for context
func (a *AdvancedAgent) getRecentExecutionSteps() []AgentStep {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	if len(a.executionHistory) == 0 {
		return []AgentStep{}
	}

	// Get steps from the most recent execution
	recent := a.executionHistory[len(a.executionHistory)-1]
	return recent.Output.Steps
}

// assessActionRisk assesses the risk level of an action
func (a *AdvancedAgent) assessActionRisk(action AgentAction) RiskLevel {
	switch action.Type {
	case "respond":
		return RiskLow
	case "tool_use":
		// Assess risk based on tool type
		if action.ToolName == "" {
			return RiskMedium
		}

		// Security-related tools have higher risk
		securityTools := []string{"security_scanner", "penetration_tester", "vulnerability_scanner"}
		for _, tool := range securityTools {
			if action.ToolName == tool {
				return RiskHigh
			}
		}

		return RiskMedium
	default:
		return RiskMedium
	}
}

// estimateActionCost estimates the cost of an action
func (a *AdvancedAgent) estimateActionCost(action AgentAction) float64 {
	switch action.Type {
	case "respond":
		return 0.001 // Low cost for simple responses
	case "tool_use":
		// Estimate based on tool complexity
		if action.ToolName == "" {
			return 0.01
		}

		// Different tools have different costs
		toolCosts := map[string]float64{
			"security_scanner":      0.05,
			"penetration_tester":    0.10,
			"vulnerability_scanner": 0.08,
			"general_analyzer":      0.02,
			"basic_analyzer":        0.01,
		}

		if cost, exists := toolCosts[action.ToolName]; exists {
			return cost
		}

		return 0.03 // Default tool cost
	default:
		return 0.02
	}
}

// generateAlternativeActions generates alternative actions based on available tools
func (a *AdvancedAgent) generateAlternativeActions(ctx context.Context, input AgentInput) []ActionRecommendation {
	alternatives := make([]ActionRecommendation, 0)

	// Generate alternatives based on available tools
	for _, tool := range a.GetAvailableTools() {
		action := AgentAction{
			Type:     "tool_use",
			ToolName: tool.Name(),
			ToolInput: map[string]interface{}{
				"query": input.Query,
			},
			Reasoning: fmt.Sprintf("Using %s to analyze the query", tool.Name()),
		}

		alternative := ActionRecommendation{
			Action:        action,
			Confidence:    0.6, // Lower confidence for alternatives
			Reasoning:     action.Reasoning,
			Risk:          a.assessActionRisk(action),
			EstimatedCost: a.estimateActionCost(action),
		}

		alternatives = append(alternatives, alternative)
	}

	// Add a simple response alternative
	responseAction := AgentAction{
		Type:      "respond",
		Response:  "I need more information to provide a specific analysis.",
		Reasoning: "Fallback response when no specific action is clear",
	}

	alternatives = append(alternatives, ActionRecommendation{
		Action:        responseAction,
		Confidence:    0.4,
		Reasoning:     responseAction.Reasoning,
		Risk:          RiskLow,
		EstimatedCost: 0.001,
	})

	return alternatives
}

// shouldContinueExecution determines if execution should continue
func (a *AdvancedAgent) shouldContinueExecution(action AgentAction, step AgentStep, history []AgentStep) bool {
	// Don't continue if the step failed
	if !step.Success {
		return false
	}

	// Don't continue if it's a response action (final action)
	if action.Type == "respond" {
		return false
	}

	// Continue if it's a tool use that succeeded
	return true
}

// updatePerformanceMetrics updates performance metrics
func (a *AdvancedAgent) updatePerformanceMetrics(result *AgentExecutionResult) {
	// Update basic metrics
	result.PerformanceMetrics.TotalExecutionTime = result.ExecutionTime

	// Calculate tool execution time
	toolTime := time.Duration(0)
	for _, step := range result.Output.Steps {
		toolTime += step.Duration
	}
	result.PerformanceMetrics.ToolExecutionTime = toolTime

	// Estimate other metrics (in a real implementation, these would be measured)
	result.PerformanceMetrics.MemoryUsage = int64(len(result.Output.Steps) * 1024) // Rough estimate
	result.PerformanceMetrics.TokensConsumed = len(result.Output.Response) / 4     // Rough token estimate
	result.PerformanceMetrics.APICallsCount = len(result.ToolsUsed)
	result.PerformanceMetrics.CacheHitRate = 0.0 // Would be calculated from actual cache usage
}

// addToHistory adds an execution result to the history
func (a *AdvancedAgent) addToHistory(result AgentExecutionResult) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.executionHistory = append(a.executionHistory, result)

	// Maintain history size limit
	if len(a.executionHistory) > a.maxHistorySize {
		a.executionHistory = a.executionHistory[1:]
	}
}

// Interface implementation methods for AdvancedAgent

// AddToolValidator adds a tool validator to the agent
func (a *AdvancedAgent) AddToolValidator(validator ToolValidator) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if validator == nil {
		return fmt.Errorf("validator cannot be nil")
	}

	// Check if validator with same ID already exists
	for _, existing := range a.toolValidators {
		if existing.ID() == validator.ID() {
			return fmt.Errorf("validator with ID %s already exists", validator.ID())
		}
	}

	a.toolValidators = append(a.toolValidators, validator)
	return nil
}

// RemoveToolValidator removes a tool validator from the agent
func (a *AdvancedAgent) RemoveToolValidator(validatorID string) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	for i, validator := range a.toolValidators {
		if validator.ID() == validatorID {
			a.toolValidators = append(a.toolValidators[:i], a.toolValidators[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("validator with ID %s not found", validatorID)
}

// GetExecutionHistory returns the execution history
func (a *AdvancedAgent) GetExecutionHistory() []AgentExecutionResult {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	// Return a copy to prevent external modification
	history := make([]AgentExecutionResult, len(a.executionHistory))
	copy(history, a.executionHistory)
	return history
}

// UpdateStrategy updates the agent's execution strategy
func (a *AdvancedAgent) UpdateStrategy(strategy AgentStrategy) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Validate strategy
	if strategy.DecisionThreshold < 0 || strategy.DecisionThreshold > 1 {
		return fmt.Errorf("decision threshold must be between 0 and 1")
	}

	if strategy.MaxRetries < 0 {
		return fmt.Errorf("max retries cannot be negative")
	}

	a.strategy = strategy

	if a.logger != nil {
		a.logger.Debug("Agent strategy updated",
			"agent_id", a.id,
			"strategy_id", strategy.ID,
			"strategy_name", strategy.Name)
	}

	return nil
}
