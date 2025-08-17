package llm

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/llm/chains"
	"github.com/dimajoyti/hackai/pkg/llm/providers"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// TestBasicOrchestration tests basic orchestration functionality
func TestBasicOrchestration(t *testing.T) {
	logger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "json",
		Output: "stdout",
	})
	require.NoError(t, err)

	// Create orchestrator config
	config := llm.OrchestratorConfig{
		MaxConcurrentChains: 10,
		MaxConcurrentGraphs: 10,
		DefaultTimeout:      30000000000, // 30 seconds in nanoseconds
		EnableMetrics:       true,
		EnableTracing:       true,
	}

	// Create orchestrator
	orchestrator := llm.NewDefaultOrchestrator(config, logger)
	require.NotNil(t, orchestrator)

	// Create mock provider
	mockProvider := &TestMockProvider{
		providerType: providers.ProviderOpenAI,
		model: providers.ModelInfo{
			Name:         "gpt-3.5-turbo",
			MaxTokens:    4096,
			ContextSize:  4096,
			Capabilities: []string{"text-generation", "conversation"},
		},
		healthy: true,
	}

	// Create simple chain
	simpleChain := chains.NewSimpleChain(
		"test-chain",
		"Test Chain",
		"A test chain",
		mockProvider,
		"Hello {{name}}!",
		logger,
	)

	t.Run("RegisterChain", func(t *testing.T) {
		err := orchestrator.RegisterChain(simpleChain)
		assert.NoError(t, err)

		chains := orchestrator.ListChains()
		assert.Len(t, chains, 1)
		assert.Equal(t, "test-chain", chains[0].ID)
	})

	t.Run("ExecuteChain", func(t *testing.T) {
		input := llm.ChainInput{
			"name":        "World",
			"temperature": 0.7,
			"max_tokens":  100,
		}

		output, err := orchestrator.ExecuteChain(context.Background(), "test-chain", input)
		assert.NoError(t, err)
		assert.NotNil(t, output)

		// Check that we got some result
		result, ok := output["result"].(string)
		assert.True(t, ok)
		assert.NotEmpty(t, result)

		// Check success flag
		success, ok := output["success"].(bool)
		assert.True(t, ok)
		assert.True(t, success)
	})

	t.Run("ListChains", func(t *testing.T) {
		chains := orchestrator.ListChains()
		assert.Len(t, chains, 1)
		assert.Equal(t, "test-chain", chains[0].ID)
		assert.Equal(t, "Test Chain", chains[0].Name)
	})
}

// TestBasicProviderManager tests basic provider manager functionality
func TestBasicProviderManager(t *testing.T) {
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
	mockProvider := &TestMockProvider{
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

		providerList := manager.ListProviders()
		assert.Contains(t, providerList, "test-provider")
	})

	t.Run("GetProvider", func(t *testing.T) {
		provider, err := manager.GetProvider("test-provider")
		assert.NoError(t, err)
		assert.Equal(t, mockProvider, provider)
	})

	t.Run("HealthCheck", func(t *testing.T) {
		results := manager.HealthCheck(context.Background())
		assert.Contains(t, results, "test-provider")
		assert.NoError(t, results["test-provider"])
	})
}

// TestSimpleChain tests the simple chain implementation
func TestSimpleChain(t *testing.T) {
	logger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "json",
		Output: "stdout",
	})
	require.NoError(t, err)

	mockProvider := &TestMockProvider{
		providerType: providers.ProviderOpenAI,
		healthy:      true,
	}

	chain := chains.NewSimpleChain(
		"test-chain",
		"Test Chain",
		"A test chain",
		mockProvider,
		"Hello {{name}}!",
		logger,
	)

	t.Run("BasicExecution", func(t *testing.T) {
		input := llm.ChainInput{
			"name":        "World",
			"temperature": 0.7,
			"max_tokens":  100,
		}

		output, err := chain.Execute(context.Background(), input)
		assert.NoError(t, err)
		assert.NotNil(t, output)

		// Check that we got some result
		result, ok := output["result"].(string)
		assert.True(t, ok)
		assert.NotEmpty(t, result)
	})

	t.Run("ChainInfo", func(t *testing.T) {
		assert.Equal(t, "test-chain", chain.ID())
		assert.Equal(t, "Test Chain", chain.Name())
		assert.Equal(t, "A test chain", chain.Description())
	})

	t.Run("Validation", func(t *testing.T) {
		err := chain.Validate()
		assert.NoError(t, err)
	})
}

// TestMockProvider for simple testing
type TestMockProvider struct {
	providerType providers.ProviderType
	model        providers.ModelInfo
	healthy      bool
	responses    []string
	callCount    int
}

func (m *TestMockProvider) GetType() providers.ProviderType {
	return m.providerType
}

func (m *TestMockProvider) GetModel() providers.ModelInfo {
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

func (m *TestMockProvider) GetLimits() providers.ProviderLimits {
	return providers.ProviderLimits{
		RequestsPerMinute: 60,
		TokensPerMinute:   100000,
		MaxConcurrent:     10,
	}
}

func (m *TestMockProvider) Generate(ctx context.Context, request providers.GenerationRequest) (providers.GenerationResponse, error) {
	m.callCount++

	response := "Mock response"
	if len(m.responses) > 0 {
		response = m.responses[(m.callCount-1)%len(m.responses)]
	}

	return providers.GenerationResponse{
		Content: response,
		Model:   m.model.Name,
		TokensUsed: providers.TokenUsage{
			PromptTokens:     10,
			CompletionTokens: 20,
			TotalTokens:      30,
		},
		FinishReason: "stop",
	}, nil
}

func (m *TestMockProvider) Stream(ctx context.Context, request providers.GenerationRequest) (<-chan providers.StreamChunk, error) {
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

func (m *TestMockProvider) Embed(ctx context.Context, text string) ([]float64, error) {
	embedding := make([]float64, 1536)
	for i := range embedding {
		embedding[i] = 0.1
	}
	return embedding, nil
}

func (m *TestMockProvider) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	embeddings := make([][]float64, len(texts))
	for i := range texts {
		embeddings[i] = make([]float64, 1536)
		for j := range embeddings[i] {
			embeddings[i][j] = 0.1
		}
	}
	return embeddings, nil
}

func (m *TestMockProvider) Health(ctx context.Context) error {
	if !m.healthy {
		return fmt.Errorf("provider unhealthy")
	}
	return nil
}

func (m *TestMockProvider) Close() error {
	return nil
}
