package ai

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var chainTracer = otel.Tracer("hackai/ai/chain")

// ChainExecutionContext provides enhanced context for chain execution
type ChainExecutionContext struct {
	RequestID     string                 `json:"request_id"`
	UserID        string                 `json:"user_id"`
	SessionID     string                 `json:"session_id"`
	SecurityLevel SecurityLevel          `json:"security_level"`
	Metadata      map[string]interface{} `json:"metadata"`
	StartTime     time.Time              `json:"start_time"`
	Timeout       time.Duration          `json:"timeout"`
}

// ChainExecutionResult provides detailed execution results
type ChainExecutionResult struct {
	Success       bool                   `json:"success"`
	Output        map[string]interface{} `json:"output"`
	Error         error                  `json:"error,omitempty"`
	ExecutionTime time.Duration          `json:"execution_time"`
	TokensUsed    int                    `json:"tokens_used"`
	Cost          float64                `json:"cost"`
	Steps         []ChainExecutionStep   `json:"steps"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ChainExecutionStep represents a single step in chain execution tracking
type ChainExecutionStep struct {
	StepID        string                 `json:"step_id"`
	StepType      string                 `json:"step_type"`
	Input         map[string]interface{} `json:"input"`
	Output        map[string]interface{} `json:"output"`
	Error         error                  `json:"error,omitempty"`
	ExecutionTime time.Duration          `json:"execution_time"`
	Timestamp     time.Time              `json:"timestamp"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// EnhancedChain extends the basic Chain interface with advanced capabilities
type EnhancedChain interface {
	Chain
	ExecuteWithContext(ctx context.Context, execCtx ChainExecutionContext, input map[string]interface{}) (*ChainExecutionResult, error)
	ExecuteAsync(ctx context.Context, execCtx ChainExecutionContext, input map[string]interface{}) (<-chan *ChainExecutionResult, error)
	ValidateInput(input map[string]interface{}) error
	GetExecutionHistory() []ChainExecutionResult
	AddMiddleware(middleware ChainMiddleware) error
	RemoveMiddleware(middlewareID string) error
}

// ChainMiddleware allows for pre/post processing of chain execution
type ChainMiddleware interface {
	ID() string
	PreExecute(ctx context.Context, execCtx ChainExecutionContext, input map[string]interface{}) error
	PostExecute(ctx context.Context, execCtx ChainExecutionContext, result *ChainExecutionResult) error
}

// BaseChain provides common functionality for all chains
type BaseChain struct {
	config  ChainConfig
	memory  llm.Memory
	metrics ChainMetrics
	logger  *logger.Logger
	tracer  trace.Tracer
	mutex   sync.RWMutex
}

// NewBaseChain creates a new base chain
func NewBaseChain(config ChainConfig, logger *logger.Logger) *BaseChain {
	if config.CreatedAt.IsZero() {
		config.CreatedAt = time.Now()
	}
	config.UpdatedAt = time.Now()

	return &BaseChain{
		config: config,
		logger: logger,
		tracer: chainTracer,
		metrics: ChainMetrics{
			LastExecutionTime: time.Now(),
		},
	}
}

// ID returns the chain ID
func (c *BaseChain) ID() string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.config.ID
}

// Name returns the chain name
func (c *BaseChain) Name() string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.config.Name
}

// Description returns the chain description
func (c *BaseChain) Description() string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.config.Description
}

// GetConfig returns the chain configuration
func (c *BaseChain) GetConfig() ChainConfig {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.config
}

// SetConfig updates the chain configuration
func (c *BaseChain) SetConfig(config ChainConfig) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if config.ID != c.config.ID {
		return fmt.Errorf("cannot change chain ID")
	}

	config.UpdatedAt = time.Now()
	c.config = config
	return nil
}

// GetMemory returns the chain memory
func (c *BaseChain) GetMemory() llm.Memory {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.memory
}

// SetMemory sets the chain memory
func (c *BaseChain) SetMemory(memory llm.Memory) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.memory = memory
}

// GetMetrics returns the chain metrics
func (c *BaseChain) GetMetrics() ChainMetrics {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.metrics
}

// Validate validates the chain configuration
func (c *BaseChain) Validate() error {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if c.config.ID == "" {
		return fmt.Errorf("chain ID cannot be empty")
	}
	if c.config.Name == "" {
		return fmt.Errorf("chain name cannot be empty")
	}
	if c.config.Timeout <= 0 {
		return fmt.Errorf("chain timeout must be positive")
	}
	if c.config.MaxRetries < 0 {
		return fmt.Errorf("chain max retries cannot be negative")
	}

	return nil
}

// Execute provides base execution functionality with metrics and tracing
func (c *BaseChain) Execute(ctx context.Context, input llm.ChainInput) (llm.ChainOutput, error) {
	startTime := time.Now()

	// Create span for tracing
	ctx, span := c.tracer.Start(ctx, "chain.execute",
		trace.WithAttributes(
			attribute.String("chain.id", c.config.ID),
			attribute.String("chain.name", c.config.Name),
			attribute.String("chain.type", string(c.config.Type)),
		),
	)
	defer span.End()

	// Update metrics
	c.updateExecutionStart()

	// Apply timeout
	if c.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.config.Timeout)
		defer cancel()
	}

	// Execute the actual chain logic (to be implemented by concrete chains)
	output, err := c.executeInternal(ctx, input)

	// Update metrics and tracing
	duration := time.Since(startTime)
	c.updateExecutionEnd(duration, err == nil)

	if err != nil {
		span.RecordError(err)
		c.logger.Error("Chain execution failed",
			"chain_id", c.config.ID,
			"error", err,
			"duration", duration)
		return nil, err
	}

	span.SetAttributes(
		attribute.String("execution.duration", duration.String()),
		attribute.Bool("execution.success", true),
	)

	c.logger.Info("Chain executed successfully",
		"chain_id", c.config.ID,
		"duration", duration)

	return output, nil
}

// executeInternal is meant to be overridden by concrete chain implementations
func (c *BaseChain) executeInternal(ctx context.Context, input llm.ChainInput) (llm.ChainOutput, error) {
	return nil, fmt.Errorf("executeInternal not implemented")
}

// Clone creates a copy of the chain
func (c *BaseChain) Clone() Chain {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	clonedConfig := c.config
	clonedConfig.ID = c.config.ID + "_clone"
	clonedConfig.CreatedAt = time.Now()
	clonedConfig.UpdatedAt = time.Now()

	return NewBaseChain(clonedConfig, c.logger)
}

// updateExecutionStart updates metrics at the start of execution
func (c *BaseChain) updateExecutionStart() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.metrics.TotalExecutions++
}

// updateExecutionEnd updates metrics at the end of execution
func (c *BaseChain) updateExecutionEnd(duration time.Duration, success bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if success {
		c.metrics.SuccessfulRuns++
	} else {
		c.metrics.FailedRuns++
	}

	// Update average latency
	if c.metrics.TotalExecutions == 1 {
		c.metrics.AverageLatency = duration
	} else {
		total := time.Duration(c.metrics.TotalExecutions-1) * c.metrics.AverageLatency
		c.metrics.AverageLatency = (total + duration) / time.Duration(c.metrics.TotalExecutions)
	}

	c.metrics.LastExecutionTime = time.Now()
}

// AdvancedChain implements the EnhancedChain interface with sophisticated execution capabilities
type AdvancedChain struct {
	*BaseChain
	middlewares      []ChainMiddleware
	executionHistory []ChainExecutionResult
	maxHistorySize   int
	validator        ChainInputValidator
	mutex            sync.RWMutex
}

// ChainInputValidator validates chain input
type ChainInputValidator interface {
	Validate(input map[string]interface{}) error
}

// NewAdvancedChain creates a new advanced chain with enhanced capabilities
func NewAdvancedChain(config ChainConfig, logger *logger.Logger) *AdvancedChain {
	baseChain := NewBaseChain(config, logger)

	return &AdvancedChain{
		BaseChain:        baseChain,
		middlewares:      make([]ChainMiddleware, 0),
		executionHistory: make([]ChainExecutionResult, 0),
		maxHistorySize:   100, // Default history size
	}
}

// ExecuteWithContext executes the chain with enhanced context and detailed results
func (c *AdvancedChain) ExecuteWithContext(ctx context.Context, execCtx ChainExecutionContext, input map[string]interface{}) (*ChainExecutionResult, error) {
	ctx, span := c.tracer.Start(ctx, "advanced_chain.execute_with_context",
		trace.WithAttributes(
			attribute.String("chain.id", c.config.ID),
			attribute.String("chain.name", c.config.Name),
			attribute.String("request.id", execCtx.RequestID),
			attribute.String("user.id", execCtx.UserID),
			attribute.String("security.level", string(execCtx.SecurityLevel)),
		),
	)
	defer span.End()

	startTime := time.Now()
	result := &ChainExecutionResult{
		Steps:    make([]ChainExecutionStep, 0),
		Metadata: make(map[string]interface{}),
	}

	// Update execution start metrics
	c.updateExecutionStart()

	// Validate input
	if c.validator != nil {
		if err := c.validator.Validate(input); err != nil {
			result.Success = false
			result.Error = fmt.Errorf("input validation failed: %w", err)
			result.ExecutionTime = time.Since(startTime)
			span.RecordError(result.Error)
			return result, result.Error
		}
	}

	// Execute pre-middleware
	for _, middleware := range c.middlewares {
		if err := middleware.PreExecute(ctx, execCtx, input); err != nil {
			result.Success = false
			result.Error = fmt.Errorf("middleware %s pre-execute failed: %w", middleware.ID(), err)
			result.ExecutionTime = time.Since(startTime)
			span.RecordError(result.Error)
			return result, result.Error
		}
	}

	// Execute the actual chain logic (to be implemented by specific chain types)
	output, err := c.executeInternal(ctx, input)
	if err != nil {
		result.Success = false
		result.Error = err
	} else {
		result.Success = true
		result.Output = output
	}

	result.ExecutionTime = time.Since(startTime)

	// Execute post-middleware
	for _, middleware := range c.middlewares {
		if err := middleware.PostExecute(ctx, execCtx, result); err != nil {
			c.logger.Error("Middleware post-execute failed",
				"middleware_id", middleware.ID(),
				"error", err)
		}
	}

	// Update metrics
	c.updateExecutionEnd(result.ExecutionTime, result.Success)

	// Store execution history
	c.addToHistory(*result)

	span.SetAttributes(
		attribute.Bool("execution.success", result.Success),
		attribute.String("execution.duration", result.ExecutionTime.String()),
	)

	return result, nil
}

// ExecuteAsync executes the chain asynchronously
func (c *AdvancedChain) ExecuteAsync(ctx context.Context, execCtx ChainExecutionContext, input map[string]interface{}) (<-chan *ChainExecutionResult, error) {
	resultChan := make(chan *ChainExecutionResult, 1)

	go func() {
		defer close(resultChan)
		result, _ := c.ExecuteWithContext(ctx, execCtx, input)
		resultChan <- result
	}()

	return resultChan, nil
}

// ValidateInput validates the input for the chain
func (c *AdvancedChain) ValidateInput(input map[string]interface{}) error {
	if c.validator != nil {
		return c.validator.Validate(input)
	}
	return nil
}

// GetExecutionHistory returns the execution history
func (c *AdvancedChain) GetExecutionHistory() []ChainExecutionResult {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Return a copy to prevent external modification
	history := make([]ChainExecutionResult, len(c.executionHistory))
	copy(history, c.executionHistory)
	return history
}

// AddMiddleware adds a middleware to the chain
func (c *AdvancedChain) AddMiddleware(middleware ChainMiddleware) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if middleware with same ID already exists
	for _, existing := range c.middlewares {
		if existing.ID() == middleware.ID() {
			return fmt.Errorf("middleware with ID %s already exists", middleware.ID())
		}
	}

	c.middlewares = append(c.middlewares, middleware)
	return nil
}

// RemoveMiddleware removes a middleware from the chain
func (c *AdvancedChain) RemoveMiddleware(middlewareID string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for i, middleware := range c.middlewares {
		if middleware.ID() == middlewareID {
			c.middlewares = append(c.middlewares[:i], c.middlewares[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("middleware with ID %s not found", middlewareID)
}

// executeInternal is a placeholder for actual chain execution logic
// This should be implemented by specific chain types
func (c *AdvancedChain) executeInternal(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	// This is a base implementation - specific chain types should override this
	return input, nil
}

// addToHistory adds an execution result to the history
func (c *AdvancedChain) addToHistory(result ChainExecutionResult) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.executionHistory = append(c.executionHistory, result)

	// Maintain history size limit
	if len(c.executionHistory) > c.maxHistorySize {
		c.executionHistory = c.executionHistory[1:]
	}
}

// SequentialChain implements a sequential chain that executes steps in order
type SequentialChain struct {
	*BaseChain
	steps []ChainStep
}

// ChainStep represents a single step in a sequential chain
type ChainStep struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Handler     ChainStepHandler       `json:"-"`
	Config      map[string]interface{} `json:"config"`
}

// ChainStepHandler defines the function signature for chain step handlers
type ChainStepHandler func(ctx context.Context, input llm.ChainInput, stepConfig map[string]interface{}) (llm.ChainOutput, error)

// NewSequentialChain creates a new sequential chain
func NewSequentialChain(config ChainConfig, steps []ChainStep, logger *logger.Logger) *SequentialChain {
	config.Type = ChainTypeSequential
	baseChain := NewBaseChain(config, logger)

	return &SequentialChain{
		BaseChain: baseChain,
		steps:     steps,
	}
}

// executeInternal implements the sequential execution logic
func (c *SequentialChain) executeInternal(ctx context.Context, input llm.ChainInput) (llm.ChainOutput, error) {
	currentInput := input
	var finalOutput llm.ChainOutput

	for i, step := range c.steps {
		stepCtx, stepSpan := c.tracer.Start(ctx, fmt.Sprintf("chain.step.%s", step.ID),
			trace.WithAttributes(
				attribute.String("step.id", step.ID),
				attribute.String("step.name", step.Name),
				attribute.Int("step.index", i),
			),
		)

		stepOutput, err := step.Handler(stepCtx, currentInput, step.Config)
		stepSpan.End()

		if err != nil {
			stepSpan.RecordError(err)
			return nil, fmt.Errorf("step %s failed: %w", step.ID, err)
		}

		// Use step output as input for next step
		currentInput = map[string]interface{}(stepOutput)
		finalOutput = stepOutput

		c.logger.Debug("Chain step completed",
			"chain_id", c.config.ID,
			"step_id", step.ID,
			"step_index", i)
	}

	return finalOutput, nil
}

// AddStep adds a new step to the sequential chain
func (c *SequentialChain) AddStep(step ChainStep) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Validate step
	if step.ID == "" {
		return fmt.Errorf("step ID cannot be empty")
	}
	if step.Handler == nil {
		return fmt.Errorf("step handler cannot be nil")
	}

	// Check for duplicate step IDs
	for _, existingStep := range c.steps {
		if existingStep.ID == step.ID {
			return fmt.Errorf("step with ID %s already exists", step.ID)
		}
	}

	c.steps = append(c.steps, step)
	return nil
}

// GetSteps returns the chain steps
func (c *SequentialChain) GetSteps() []ChainStep {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.steps
}

// Clone creates a copy of the sequential chain
func (c *SequentialChain) Clone() Chain {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	clonedConfig := c.config
	clonedConfig.ID = c.config.ID + "_clone"
	clonedConfig.CreatedAt = time.Now()
	clonedConfig.UpdatedAt = time.Now()

	// Deep copy steps
	clonedSteps := make([]ChainStep, len(c.steps))
	copy(clonedSteps, c.steps)

	return NewSequentialChain(clonedConfig, clonedSteps, c.logger)
}
