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
