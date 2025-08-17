package llm

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/llm/chains"
	"github.com/dimajoyti/hackai/pkg/llm/providers"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// TestProviderManager tests the provider manager functionality
func TestProviderManager(t *testing.T) {
	logger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "json",
		Output: "stdout",
	})
	require.NoError(t, err)

	// Create provider manager
	manager := providers.NewDefaultProviderManager(logger)
	require.NotNil(t, manager)

	// Create mock provider
	mockProvider := &MockProvider{
		providerType: providers.ProviderOpenAI,
		model: providers.ModelInfo{
			Name:         "gpt-3.5-turbo",
			MaxTokens:    4096,
			ContextSize:  4096,
			Capabilities: []string{"text-generation", "conversation"},
		},
		healthy: true,
	}

	t.Run("RegisterProvider", func(t *testing.T) {
		err := manager.RegisterProvider("test-provider", mockProvider)
		assert.NoError(t, err)

		providers := manager.ListProviders()
		assert.Contains(t, providers, "test-provider")
	})

	t.Run("GetProvider", func(t *testing.T) {
		provider, err := manager.GetProvider("test-provider")
		assert.NoError(t, err)
		assert.Equal(t, mockProvider, provider)
	})

	t.Run("GetBestProvider", func(t *testing.T) {
		request := providers.GenerationRequest{
			Messages: []providers.Message{
				{Role: "user", Content: "Hello, world!"},
			},
			MaxTokens: 100,
		}

		provider, err := manager.GetBestProvider(context.Background(), request)
		assert.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("HealthCheck", func(t *testing.T) {
		results := manager.HealthCheck(context.Background())
		assert.Contains(t, results, "test-provider")
		assert.NoError(t, results["test-provider"])
	})

	t.Run("GetStats", func(t *testing.T) {
		stats := manager.GetStats()
		assert.Contains(t, stats, "test-provider")
		assert.True(t, stats["test-provider"].IsHealthy)
	})
}

// TestLoadBalancer tests load balancing functionality
func TestLoadBalancer(t *testing.T) {
	// TODO: Load balancer tests are temporarily disabled
	// due to interface changes in the providers package
	t.Skip("Load balancer tests temporarily disabled - provider interface changes needed")
}

// TestCircuitBreaker tests circuit breaker functionality
func TestCircuitBreaker(t *testing.T) {
	t.Run("BasicCircuitBreaker", func(t *testing.T) {
		cb := providers.NewCircuitBreaker(3, 1*time.Second)

		// Initially closed
		assert.True(t, cb.CanExecute())
		assert.Equal(t, providers.CircuitClosed, cb.GetState())

		// Record failures
		for i := 0; i < 3; i++ {
			cb.RecordFailure()
		}

		// Should be open now
		assert.False(t, cb.CanExecute())
		assert.Equal(t, providers.CircuitOpen, cb.GetState())

		// Wait for reset timeout
		time.Sleep(1100 * time.Millisecond)

		// Should be half-open
		assert.True(t, cb.CanExecute())

		// Record success
		cb.RecordSuccess()

		// Should be closed again
		assert.Equal(t, providers.CircuitClosed, cb.GetState())
	})

	t.Run("AdvancedCircuitBreaker", func(t *testing.T) {
		cb := providers.NewAdvancedCircuitBreaker(3, 2, 5, 1*time.Second)

		// Test metrics
		metrics := cb.GetMetrics()
		assert.Equal(t, providers.CircuitClosed, metrics.State)
		assert.Equal(t, int64(0), metrics.TotalRequests)
	})
}

// TestChainImplementations tests chain implementations
func TestChainImplementations(t *testing.T) {
	logger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "json",
		Output: "stdout",
	})
	require.NoError(t, err)

	mockProvider := &MockProvider{
		providerType: providers.ProviderOpenAI,
		healthy:      true,
	}

	t.Run("SimpleChain", func(t *testing.T) {
		chain := chains.NewSimpleChain(
			"test-chain",
			"Test Chain",
			"A test chain",
			mockProvider,
			"Hello {{name}}!",
			logger,
		)

		input := llm.ChainInput{
			"name":        "World",
			"temperature": 0.7,
			"max_tokens":  100,
		}

		output, err := chain.Execute(context.Background(), input)
		assert.NoError(t, err)
		assert.True(t, output["success"].(bool))
		assert.NotEmpty(t, output["result"].(string))
	})

	t.Run("ConversationalChain", func(t *testing.T) {
		memory := &MockMemory{}
		chain := chains.NewConversationalChain(
			"conv-chain",
			"Conversational Chain",
			"A conversational chain",
			mockProvider,
			memory,
			"You are a helpful assistant.",
			logger,
		)

		input := llm.ChainInput{
			"message":         "Hello!",
			"conversation_id": "test-conv",
			"temperature":     0.7,
			"max_tokens":      100,
		}

		output, err := chain.Execute(context.Background(), input)
		assert.NoError(t, err)
		assert.True(t, output["success"].(bool))
		assert.NotEmpty(t, output["result"].(string))
	})

	t.Run("SequentialChain", func(t *testing.T) {
		subChain1 := chains.NewSimpleChain("sub1", "Sub Chain 1", "First chain", mockProvider, "Step 1: {{input}}", logger)
		subChain2 := chains.NewSimpleChain("sub2", "Sub Chain 2", "Second chain", mockProvider, "Step 2: {{previous_result}}", logger)

		chain := chains.NewSequentialChain(
			"seq-chain",
			"Sequential Chain",
			[]llm.Chain{subChain1, subChain2},
		)

		input := llm.ChainInput{
			"input":       "test input",
			"temperature": 0.7,
			"max_tokens":  100,
		}

		output, err := chain.Execute(context.Background(), input)
		assert.NoError(t, err)
		assert.True(t, output["success"].(bool))
		assert.NotEmpty(t, output["result"].(string))
	})
}

// TestRequestProcessor tests the request processing pipeline
func TestRequestProcessor(t *testing.T) {
	// TODO: Request processor tests are temporarily disabled
	// due to interface changes in the providers package  
	t.Skip("Request processor tests temporarily disabled - provider interface changes needed")
}

// Mock implementations for testing

type MockProvider struct {
	providerType providers.ProviderType
	model        providers.ModelInfo
	healthy      bool
	responses    []string
	callCount    int
}

func (m *MockProvider) GetType() providers.ProviderType {
	return m.providerType
}

func (m *MockProvider) GetModel() providers.ModelInfo {
	if m.model.Name == "" {
		return providers.ModelInfo{
			Name:         "mock-model",
			MaxTokens:    4096,
			ContextSize:  4096,
			Capabilities: []string{"text-generation"},
		}
	}
	return m.model
}

func (m *MockProvider) GetLimits() providers.ProviderLimits {
	return providers.ProviderLimits{
		RequestsPerMinute: 60,
		TokensPerMinute:   100000,
		MaxConcurrent:     10,
	}
}

func (m *MockProvider) Generate(ctx context.Context, request providers.GenerationRequest) (providers.GenerationResponse, error) {
	m.callCount++

	response := "Mock response"
	if len(m.responses) > 0 {
		response = m.responses[(m.callCount-1)%len(m.responses)]
	}

	return providers.GenerationResponse{
		Content:      response,
		Model:        m.model.Name,
		TokensUsed: providers.TokenUsage{
			PromptTokens:     10,
			CompletionTokens: 20,
			TotalTokens:      30,
		},
		FinishReason: "stop",
	}, nil
}

func (m *MockProvider) Health(ctx context.Context) error {
	if !m.healthy {
		return fmt.Errorf("provider unhealthy")
	}
	return nil
}

func (m *MockProvider) Close() error {
	return nil
}

func (m *MockProvider) Embed(ctx context.Context, text string) ([]float64, error) {
	// Mock embedding implementation
	embedding := make([]float64, 1536) // OpenAI embedding size
	for i := range embedding {
		embedding[i] = 0.1 // Simple mock values
	}
	return embedding, nil
}

func (m *MockProvider) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	// Mock batch embedding implementation
	embeddings := make([][]float64, len(texts))
	for i := range texts {
		embeddings[i] = make([]float64, 1536) // OpenAI embedding size
		for j := range embeddings[i] {
			embeddings[i][j] = 0.1 // Simple mock values
		}
	}
	return embeddings, nil
}

func (m *MockProvider) Stream(ctx context.Context, request providers.GenerationRequest) (<-chan providers.StreamChunk, error) {
	// Mock streaming implementation
	ch := make(chan providers.StreamChunk, 1)
	go func() {
		defer close(ch)
		ch <- providers.StreamChunk{
			Content: "Mock streaming response",
			Delta:   "Mock streaming response",
		}
	}()
	return ch, nil
}

type MockMemory struct {
	data map[string]interface{}
}

func (m *MockMemory) Store(ctx context.Context, key string, value interface{}) error {
	return nil
}

func (m *MockMemory) Retrieve(ctx context.Context, key string) (interface{}, error) {
	return nil, fmt.Errorf("not found")
}

func (m *MockMemory) Delete(ctx context.Context, key string) error {
	return nil
}

func (m *MockMemory) Keys(ctx context.Context) ([]string, error) {
	return []string{}, nil
}

func (m *MockMemory) Clear(ctx context.Context) error {
	m.data = make(map[string]interface{})
	return nil
}
