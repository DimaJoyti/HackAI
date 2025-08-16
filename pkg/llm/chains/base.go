package chains

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/llm/providers"
)

var tracer = otel.Tracer("hackai/llm/chains")

// BaseChain provides common functionality for all chains
type BaseChain struct {
	id          string
	name        string
	description string
	chainType   llm.ChainType
	provider    providers.LLMProvider
	memory      llm.Memory
	config      ChainConfig
	createdAt   time.Time
	updatedAt   time.Time
}

// ChainConfig represents configuration for a chain
type ChainConfig struct {
	MaxRetries    int                    `json:"max_retries"`
	Timeout       time.Duration          `json:"timeout"`
	Temperature   float64                `json:"temperature"`
	MaxTokens     int                    `json:"max_tokens"`
	EnableMemory  bool                   `json:"enable_memory"`
	EnableTracing bool                   `json:"enable_tracing"`
	Parameters    map[string]interface{} `json:"parameters"`
}

// NewBaseChain creates a new base chain
func NewBaseChain(id, name, description string, chainType llm.ChainType, provider providers.LLMProvider) *BaseChain {
	if id == "" {
		id = uuid.New().String()
	}

	return &BaseChain{
		id:          id,
		name:        name,
		description: description,
		chainType:   chainType,
		provider:    provider,
		config: ChainConfig{
			MaxRetries:    3,
			Timeout:       30 * time.Second,
			Temperature:   0.7,
			MaxTokens:     1000,
			EnableMemory:  true,
			EnableTracing: true,
			Parameters:    make(map[string]interface{}),
		},
		createdAt: time.Now(),
		updatedAt: time.Now(),
	}
}

// ID returns the chain ID
func (c *BaseChain) ID() string {
	return c.id
}

// Name returns the chain name
func (c *BaseChain) Name() string {
	return c.name
}

// Description returns the chain description
func (c *BaseChain) Description() string {
	return c.description
}

// GetMemory returns the chain memory
func (c *BaseChain) GetMemory() llm.Memory {
	return c.memory
}

// SetMemory sets the chain memory
func (c *BaseChain) SetMemory(memory llm.Memory) {
	c.memory = memory
	c.updatedAt = time.Now()
}

// Validate validates the chain configuration
func (c *BaseChain) Validate() error {
	if c.id == "" {
		return fmt.Errorf("chain ID is required")
	}
	if c.name == "" {
		return fmt.Errorf("chain name is required")
	}
	if c.provider == nil {
		return fmt.Errorf("LLM provider is required")
	}
	return nil
}

// SetConfig updates the chain configuration
func (c *BaseChain) SetConfig(config ChainConfig) {
	c.config = config
	c.updatedAt = time.Now()
}

// GetConfig returns the chain configuration
func (c *BaseChain) GetConfig() ChainConfig {
	return c.config
}

// GetProvider returns the LLM provider
func (c *BaseChain) GetProvider() providers.LLMProvider {
	return c.provider
}

// executeWithRetry executes a function with retry logic
func (c *BaseChain) executeWithRetry(ctx context.Context, fn func() error) error {
	var lastErr error

	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			backoff := time.Duration(attempt*attempt) * time.Second
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}

		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if providerErr, ok := err.(*providers.ProviderError); ok && !providerErr.IsRetryable() {
			break
		}
	}

	return fmt.Errorf("failed after %d attempts: %w", c.config.MaxRetries+1, lastErr)
}

// generateWithProvider generates text using the configured provider
func (c *BaseChain) generateWithProvider(ctx context.Context, messages []providers.Message) (providers.GenerationResponse, error) {
	request := providers.GenerationRequest{
		Messages:    messages,
		Temperature: c.config.Temperature,
		MaxTokens:   c.config.MaxTokens,
	}

	var response providers.GenerationResponse
	err := c.executeWithRetry(ctx, func() error {
		var err error
		response, err = c.provider.Generate(ctx, request)
		return err
	})

	return response, err
}

// storeInMemory stores data in memory if enabled
func (c *BaseChain) storeInMemory(ctx context.Context, key string, value interface{}) error {
	if !c.config.EnableMemory || c.memory == nil {
		return nil
	}

	return c.memory.Store(ctx, key, value)
}

// retrieveFromMemory retrieves data from memory if enabled
func (c *BaseChain) retrieveFromMemory(ctx context.Context, key string) (interface{}, error) {
	if !c.config.EnableMemory || c.memory == nil {
		return nil, nil
	}

	return c.memory.Retrieve(ctx, key)
}

// SequentialChain executes multiple chains in sequence
type SequentialChain struct {
	*BaseChain
	chains []llm.Chain
}

// NewSequentialChain creates a new sequential chain
func NewSequentialChain(id, name string, chains []llm.Chain) *SequentialChain {
	base := NewBaseChain(id, name, "Sequential execution of multiple chains", llm.ChainTypeSequential, nil)

	return &SequentialChain{
		BaseChain: base,
		chains:    chains,
	}
}

// Execute executes the sequential chain
func (c *SequentialChain) Execute(ctx context.Context, input llm.ChainInput) (llm.ChainOutput, error) {
	ctx, span := tracer.Start(ctx, "sequential_chain.execute",
		trace.WithAttributes(
			attribute.String("chain.id", c.ID()),
			attribute.String("chain.name", c.Name()),
			attribute.Int("chain.count", len(c.chains)),
		),
	)
	defer span.End()

	// Apply timeout
	if c.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.config.Timeout)
		defer cancel()
	}

	var output llm.ChainOutput = llm.ChainOutput(input)

	for i, chain := range c.chains {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			chainSpan := trace.SpanFromContext(ctx)
			chainSpan.SetAttributes(
				attribute.Int("chain.step", i),
				attribute.String("chain.step.id", chain.ID()),
			)

			result, err := chain.Execute(ctx, llm.ChainInput(output))
			if err != nil {
				span.RecordError(err)
				return nil, fmt.Errorf("chain %d (%s) failed: %w", i, chain.ID(), err)
			}

			output = result

			// Store intermediate result in memory
			if err := c.storeInMemory(ctx, fmt.Sprintf("step_%d_result", i), result); err != nil {
				// Log error but don't fail the execution
				span.AddEvent("memory_store_failed", trace.WithAttributes(
					attribute.String("error", err.Error()),
				))
			}
		}
	}

	span.SetAttributes(attribute.Bool("success", true))
	return output, nil
}

// Validate validates the sequential chain
func (c *SequentialChain) Validate() error {
	if err := c.BaseChain.Validate(); err != nil {
		return err
	}

	if len(c.chains) == 0 {
		return fmt.Errorf("sequential chain must have at least one chain")
	}

	for i, chain := range c.chains {
		if err := chain.Validate(); err != nil {
			return fmt.Errorf("chain %d validation failed: %w", i, err)
		}
	}

	return nil
}

// ParallelChain executes multiple chains in parallel
type ParallelChain struct {
	*BaseChain
	chains     []llm.Chain
	aggregator OutputAggregator
}

// OutputAggregator defines how to aggregate parallel chain outputs
type OutputAggregator interface {
	Aggregate(outputs []llm.ChainOutput) llm.ChainOutput
}

// SimpleAggregator simply combines all outputs into a single map
type SimpleAggregator struct{}

// Aggregate implements OutputAggregator
func (a *SimpleAggregator) Aggregate(outputs []llm.ChainOutput) llm.ChainOutput {
	result := make(llm.ChainOutput)

	for i, output := range outputs {
		result[fmt.Sprintf("chain_%d_output", i)] = output
	}

	return result
}

// NewParallelChain creates a new parallel chain
func NewParallelChain(id, name string, chains []llm.Chain, aggregator OutputAggregator) *ParallelChain {
	base := NewBaseChain(id, name, "Parallel execution of multiple chains", llm.ChainTypeParallel, nil)

	if aggregator == nil {
		aggregator = &SimpleAggregator{}
	}

	return &ParallelChain{
		BaseChain:  base,
		chains:     chains,
		aggregator: aggregator,
	}
}

// Execute executes the parallel chain
func (c *ParallelChain) Execute(ctx context.Context, input llm.ChainInput) (llm.ChainOutput, error) {
	ctx, span := tracer.Start(ctx, "parallel_chain.execute",
		trace.WithAttributes(
			attribute.String("chain.id", c.ID()),
			attribute.String("chain.name", c.Name()),
			attribute.Int("chain.count", len(c.chains)),
		),
	)
	defer span.End()

	// Apply timeout
	if c.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.config.Timeout)
		defer cancel()
	}

	// Execute chains in parallel
	type result struct {
		index  int
		output llm.ChainOutput
		err    error
	}

	results := make(chan result, len(c.chains))

	for i, chain := range c.chains {
		go func(idx int, ch llm.Chain) {
			output, err := ch.Execute(ctx, input)
			results <- result{index: idx, output: output, err: err}
		}(i, chain)
	}

	// Collect results
	outputs := make([]llm.ChainOutput, len(c.chains))
	var errors []error

	for i := 0; i < len(c.chains); i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res := <-results:
			if res.err != nil {
				errors = append(errors, fmt.Errorf("chain %d failed: %w", res.index, res.err))
			} else {
				outputs[res.index] = res.output
			}
		}
	}

	// Check for errors
	if len(errors) > 0 {
		span.RecordError(fmt.Errorf("parallel execution had %d errors", len(errors)))
		return nil, fmt.Errorf("parallel execution failed with %d errors: %v", len(errors), errors)
	}

	// Aggregate results
	aggregatedOutput := c.aggregator.Aggregate(outputs)

	span.SetAttributes(attribute.Bool("success", true))
	return aggregatedOutput, nil
}

// Validate validates the parallel chain
func (c *ParallelChain) Validate() error {
	if err := c.BaseChain.Validate(); err != nil {
		return err
	}

	if len(c.chains) == 0 {
		return fmt.Errorf("parallel chain must have at least one chain")
	}

	for i, chain := range c.chains {
		if err := chain.Validate(); err != nil {
			return fmt.Errorf("chain %d validation failed: %w", i, err)
		}
	}

	return nil
}
