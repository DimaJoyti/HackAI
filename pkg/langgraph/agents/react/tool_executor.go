package react

import (
	"context"
	"fmt"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/tools"
	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var toolTracer = otel.Tracer("hackai/langgraph/agents/react/tools")

// ToolExecutor handles tool execution with error handling and retries
type ToolExecutor struct {
	timeout       time.Duration
	maxRetries    int
	retryDelay    time.Duration
	logger        *logger.Logger
	validator     *InputValidator
	errorHandler  *ErrorHandler
	metrics       *ExecutionMetrics
}

// ExecutionMetrics tracks tool execution metrics
type ExecutionMetrics struct {
	TotalExecutions   int64                    `json:"total_executions"`
	SuccessfulExecutions int64                 `json:"successful_executions"`
	FailedExecutions  int64                    `json:"failed_executions"`
	AverageLatency    time.Duration            `json:"average_latency"`
	ToolUsageCount    map[string]int64         `json:"tool_usage_count"`
	ToolSuccessRate   map[string]float64       `json:"tool_success_rate"`
	LastUpdated       time.Time                `json:"last_updated"`
}

// InputValidator validates tool inputs
type InputValidator struct {
	logger *logger.Logger
}

// ErrorHandler handles tool execution errors
type ErrorHandler struct {
	logger        *logger.Logger
	retryStrategies map[string]RetryStrategy
}

// RetryStrategy defines how to handle retries for different error types
type RetryStrategy struct {
	MaxRetries    int           `json:"max_retries"`
	RetryDelay    time.Duration `json:"retry_delay"`
	BackoffFactor float64       `json:"backoff_factor"`
	RetryableErrors []string    `json:"retryable_errors"`
}

// ExecutionResult holds the result of tool execution
type ExecutionResult struct {
	Output    interface{} `json:"output"`
	Success   bool        `json:"success"`
	Error     error       `json:"error,omitempty"`
	Duration  time.Duration `json:"duration"`
	Retries   int         `json:"retries"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// NewToolExecutor creates a new tool executor
func NewToolExecutor(timeout time.Duration, logger *logger.Logger) *ToolExecutor {
	return &ToolExecutor{
		timeout:      timeout,
		maxRetries:   3,
		retryDelay:   time.Second,
		logger:       logger,
		validator:    &InputValidator{logger: logger},
		errorHandler: NewErrorHandler(logger),
		metrics:      &ExecutionMetrics{
			ToolUsageCount:  make(map[string]int64),
			ToolSuccessRate: make(map[string]float64),
			LastUpdated:     time.Now(),
		},
	}
}

// NewErrorHandler creates a new error handler
func NewErrorHandler(logger *logger.Logger) *ErrorHandler {
	eh := &ErrorHandler{
		logger:          logger,
		retryStrategies: make(map[string]RetryStrategy),
	}

	// Initialize default retry strategies
	eh.initializeRetryStrategies()

	return eh
}

// initializeRetryStrategies sets up default retry strategies
func (eh *ErrorHandler) initializeRetryStrategies() {
	strategies := map[string]RetryStrategy{
		"network": {
			MaxRetries:      3,
			RetryDelay:      time.Second * 2,
			BackoffFactor:   2.0,
			RetryableErrors: []string{"timeout", "connection", "network"},
		},
		"rate_limit": {
			MaxRetries:      5,
			RetryDelay:      time.Second * 5,
			BackoffFactor:   1.5,
			RetryableErrors: []string{"rate limit", "too many requests", "429"},
		},
		"temporary": {
			MaxRetries:      2,
			RetryDelay:      time.Second,
			BackoffFactor:   1.0,
			RetryableErrors: []string{"temporary", "unavailable", "busy"},
		},
	}

	eh.retryStrategies = strategies
}

// Execute executes a tool with error handling and retries
func (te *ToolExecutor) Execute(ctx context.Context, action *Action, availableTools map[string]tools.Tool) (interface{}, error) {
	ctx, span := toolTracer.Start(ctx, "tool_executor.execute",
		trace.WithAttributes(
			attribute.String("tool.id", action.Tool),
			attribute.Int("action.step", action.Step),
		),
	)
	defer span.End()

	startTime := time.Now()
	
	// Get the tool
	tool, exists := availableTools[action.Tool]
	if !exists {
		err := fmt.Errorf("tool %s not found", action.Tool)
		span.RecordError(err)
		te.updateMetrics(action.Tool, false, time.Since(startTime), 0)
		return nil, err
	}

	// Validate input
	if err := te.validator.ValidateInput(tool, action.Input); err != nil {
		span.RecordError(err)
		te.updateMetrics(action.Tool, false, time.Since(startTime), 0)
		return nil, fmt.Errorf("input validation failed: %w", err)
	}

	// Execute with retries
	result := te.executeWithRetries(ctx, tool, action.Input)
	
	// Update action with execution details
	action.Duration = result.Duration
	action.Success = result.Success
	if result.Error != nil {
		action.Error = result.Error.Error()
	}

	// Update metrics
	te.updateMetrics(action.Tool, result.Success, result.Duration, result.Retries)

	// Set span attributes
	span.SetAttributes(
		attribute.Bool("execution.success", result.Success),
		attribute.Float64("execution.duration", result.Duration.Seconds()),
		attribute.Int("execution.retries", result.Retries),
	)

	if result.Error != nil {
		span.RecordError(result.Error)
		te.logger.Error("Tool execution failed",
			"tool", action.Tool,
			"step", action.Step,
			"error", result.Error,
			"retries", result.Retries,
			"duration", result.Duration)
		return nil, result.Error
	}

	te.logger.Debug("Tool execution successful",
		"tool", action.Tool,
		"step", action.Step,
		"duration", result.Duration,
		"retries", result.Retries)

	return result.Output, nil
}

// executeWithRetries executes a tool with retry logic
func (te *ToolExecutor) executeWithRetries(ctx context.Context, tool tools.Tool, input map[string]interface{}) ExecutionResult {
	var lastError error
	retries := 0
	startTime := time.Now()

	for attempt := 0; attempt <= te.maxRetries; attempt++ {
		// Create timeout context for this attempt
		attemptCtx, cancel := context.WithTimeout(ctx, te.timeout)
		
		// Execute tool
		output, err := tool.Execute(attemptCtx, input)
		cancel()

		if err == nil {
			// Success
			return ExecutionResult{
				Output:   output,
				Success:  true,
				Duration: time.Since(startTime),
				Retries:  retries,
				Metadata: map[string]interface{}{
					"attempts": attempt + 1,
				},
			}
		}

		lastError = err
		retries++

		// Check if error is retryable
		if attempt < te.maxRetries && te.errorHandler.IsRetryable(err) {
			delay := te.calculateRetryDelay(attempt, err)
			te.logger.Debug("Tool execution failed, retrying",
				"tool", tool.ID(),
				"attempt", attempt+1,
				"error", err,
				"retry_delay", delay)

			// Wait before retry
			select {
			case <-time.After(delay):
				continue
			case <-ctx.Done():
				return ExecutionResult{
					Success:  false,
					Error:    ctx.Err(),
					Duration: time.Since(startTime),
					Retries:  retries,
				}
			}
		} else {
			break
		}
	}

	// All retries exhausted
	return ExecutionResult{
		Success:  false,
		Error:    lastError,
		Duration: time.Since(startTime),
		Retries:  retries,
		Metadata: map[string]interface{}{
			"max_retries_reached": true,
		},
	}
}

// calculateRetryDelay calculates the delay before the next retry
func (te *ToolExecutor) calculateRetryDelay(attempt int, err error) time.Duration {
	strategy := te.errorHandler.GetRetryStrategy(err)
	
	delay := strategy.RetryDelay
	for i := 0; i < attempt; i++ {
		delay = time.Duration(float64(delay) * strategy.BackoffFactor)
	}

	// Cap the delay at 30 seconds
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}

	return delay
}

// updateMetrics updates execution metrics
func (te *ToolExecutor) updateMetrics(toolID string, success bool, duration time.Duration, retries int) {
	te.metrics.TotalExecutions++
	te.metrics.ToolUsageCount[toolID]++

	if success {
		te.metrics.SuccessfulExecutions++
	} else {
		te.metrics.FailedExecutions++
	}

	// Update average latency (simple moving average)
	if te.metrics.TotalExecutions == 1 {
		te.metrics.AverageLatency = duration
	} else {
		te.metrics.AverageLatency = time.Duration(
			(int64(te.metrics.AverageLatency)*te.metrics.TotalExecutions + int64(duration)) / (te.metrics.TotalExecutions + 1),
		)
	}

	// Update tool success rate
	toolUsage := te.metrics.ToolUsageCount[toolID]
	toolSuccesses := int64(0)
	if success {
		if rate, exists := te.metrics.ToolSuccessRate[toolID]; exists {
			toolSuccesses = int64(rate * float64(toolUsage-1)) + 1
		} else {
			toolSuccesses = 1
		}
	} else {
		if rate, exists := te.metrics.ToolSuccessRate[toolID]; exists {
			toolSuccesses = int64(rate * float64(toolUsage-1))
		}
	}
	te.metrics.ToolSuccessRate[toolID] = float64(toolSuccesses) / float64(toolUsage)

	te.metrics.LastUpdated = time.Now()
}

// ValidateInput validates tool input
func (iv *InputValidator) ValidateInput(tool tools.Tool, input map[string]interface{}) error {
	// Basic validation - check if tool has a Validate method
	if validator, ok := tool.(interface{ Validate(map[string]interface{}) error }); ok {
		return validator.Validate(input)
	}

	// Default validation - ensure input is not nil
	if input == nil {
		return fmt.Errorf("input cannot be nil")
	}

	return nil
}

// IsRetryable checks if an error is retryable
func (eh *ErrorHandler) IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	errorStr := err.Error()
	
	for _, strategy := range eh.retryStrategies {
		for _, retryableError := range strategy.RetryableErrors {
			if contains(errorStr, retryableError) {
				return true
			}
		}
	}

	return false
}

// GetRetryStrategy gets the appropriate retry strategy for an error
func (eh *ErrorHandler) GetRetryStrategy(err error) RetryStrategy {
	if err == nil {
		return RetryStrategy{MaxRetries: 0}
	}

	errorStr := err.Error()
	
	for strategyName, strategy := range eh.retryStrategies {
		for _, retryableError := range strategy.RetryableErrors {
			if contains(errorStr, retryableError) {
				eh.logger.Debug("Selected retry strategy",
					"strategy", strategyName,
					"error", errorStr)
				return strategy
			}
		}
	}

	// Default strategy
	return RetryStrategy{
		MaxRetries:    1,
		RetryDelay:    time.Second,
		BackoffFactor: 1.0,
	}
}

// UpdateTimeout updates the execution timeout
func (te *ToolExecutor) UpdateTimeout(timeout time.Duration) {
	te.timeout = timeout
	te.logger.Info("Tool executor timeout updated", "timeout", timeout)
}

// GetMetrics returns current execution metrics
func (te *ToolExecutor) GetMetrics() ExecutionMetrics {
	return *te.metrics
}

// ResetMetrics resets execution metrics
func (te *ToolExecutor) ResetMetrics() {
	te.metrics = &ExecutionMetrics{
		ToolUsageCount:  make(map[string]int64),
		ToolSuccessRate: make(map[string]float64),
		LastUpdated:     time.Now(),
	}
	te.logger.Info("Tool executor metrics reset")
}

// GetToolStatistics returns statistics for a specific tool
func (te *ToolExecutor) GetToolStatistics(toolID string) map[string]interface{} {
	stats := make(map[string]interface{})
	
	if usage, exists := te.metrics.ToolUsageCount[toolID]; exists {
		stats["usage_count"] = usage
	} else {
		stats["usage_count"] = 0
	}

	if rate, exists := te.metrics.ToolSuccessRate[toolID]; exists {
		stats["success_rate"] = rate
	} else {
		stats["success_rate"] = 0.0
	}

	return stats
}

// contains checks if a string contains a substring (case-insensitive)
func contains(str, substr string) bool {
	return len(str) >= len(substr) && 
		   (str == substr || 
		    (len(str) > len(substr) && 
		     (str[:len(substr)] == substr || 
		      str[len(str)-len(substr):] == substr ||
		      containsSubstring(str, substr))))
}

// containsSubstring checks if str contains substr anywhere
func containsSubstring(str, substr string) bool {
	for i := 0; i <= len(str)-len(substr); i++ {
		if str[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// AddRetryStrategy adds a custom retry strategy
func (eh *ErrorHandler) AddRetryStrategy(name string, strategy RetryStrategy) {
	eh.retryStrategies[name] = strategy
	eh.logger.Info("Retry strategy added", "name", name, "max_retries", strategy.MaxRetries)
}

// RemoveRetryStrategy removes a retry strategy
func (eh *ErrorHandler) RemoveRetryStrategy(name string) {
	delete(eh.retryStrategies, name)
	eh.logger.Info("Retry strategy removed", "name", name)
}

// GetRetryStrategies returns all configured retry strategies
func (eh *ErrorHandler) GetRetryStrategies() map[string]RetryStrategy {
	strategies := make(map[string]RetryStrategy)
	for name, strategy := range eh.retryStrategies {
		strategies[name] = strategy
	}
	return strategies
}
