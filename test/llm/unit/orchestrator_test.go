package unit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/llm/memory"
	"github.com/dimajoyti/hackai/pkg/llm/providers"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// MockLLMProvider for testing
type MockLLMProvider struct {
	mock.Mock
}

func (m *MockLLMProvider) Generate(ctx context.Context, req providers.GenerationRequest) (providers.GenerationResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(providers.GenerationResponse), args.Error(1)
}

func (m *MockLLMProvider) Stream(ctx context.Context, req providers.GenerationRequest) (<-chan providers.StreamChunk, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(<-chan providers.StreamChunk), args.Error(1)
}

func (m *MockLLMProvider) Embed(ctx context.Context, text string) ([]float64, error) {
	args := m.Called(ctx, text)
	return args.Get(0).([]float64), args.Error(1)
}

func (m *MockLLMProvider) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	args := m.Called(ctx, texts)
	return args.Get(0).([][]float64), args.Error(1)
}

func (m *MockLLMProvider) GetModel() providers.ModelInfo {
	args := m.Called()
	return args.Get(0).(providers.ModelInfo)
}

func (m *MockLLMProvider) GetLimits() providers.ProviderLimits {
	args := m.Called()
	return args.Get(0).(providers.ProviderLimits)
}

func (m *MockLLMProvider) GetType() providers.ProviderType {
	args := m.Called()
	return args.Get(0).(providers.ProviderType)
}

func (m *MockLLMProvider) Health(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockLLMProvider) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockChain for testing
type MockChain struct {
	mock.Mock
	id          string
	name        string
	description string
}

func NewMockChain(id, name, description string) *MockChain {
	return &MockChain{
		id:          id,
		name:        name,
		description: description,
	}
}

func (m *MockChain) ID() string {
	return m.id
}

func (m *MockChain) Name() string {
	return m.name
}

func (m *MockChain) Description() string {
	return m.description
}

func (m *MockChain) Execute(ctx context.Context, input llm.ChainInput) (llm.ChainOutput, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(llm.ChainOutput), args.Error(1)
}

func (m *MockChain) GetMemory() llm.Memory {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(llm.Memory)
}

func (m *MockChain) SetMemory(memory llm.Memory) {
	m.Called(memory)
}

func (m *MockChain) Validate() error {
	args := m.Called()
	return args.Error(0)
}

// TestOrchestratorBasicOperations tests basic orchestrator operations
func TestOrchestratorBasicOperations(t *testing.T) {
	// Setup
	config := llm.OrchestratorConfig{
		MaxConcurrentChains: 10,
		MaxConcurrentGraphs: 5,
		DefaultTimeout:      30 * time.Second,
		EnableMetrics:       true,
		EnableTracing:       true,
		MemoryConfig: memory.MemoryConfig{
			VectorMemorySize: 1000,
		},
	}

	testLogger := getTestLogger()
	orchestrator := llm.NewDefaultOrchestrator(config, testLogger)

	// Test starting the orchestrator
	err := orchestrator.Start(context.Background())
	assert.NoError(t, err)

	// Test health check
	health := orchestrator.Health()
	assert.Equal(t, "healthy", health.Status)
	assert.NotEmpty(t, health.Details)

	// Test stopping the orchestrator
	err = orchestrator.Stop(context.Background())
	assert.NoError(t, err)
}

// TestChainRegistrationAndExecution tests chain registration and execution
func TestChainRegistrationAndExecution(t *testing.T) {
	// Setup
	config := llm.OrchestratorConfig{
		MaxConcurrentChains: 10,
		DefaultTimeout:      30 * time.Second,
		MemoryConfig: memory.MemoryConfig{
			VectorMemorySize: 1000,
		},
	}

	testLogger := getTestLogger()
	orchestrator := llm.NewDefaultOrchestrator(config, testLogger)

	// Create mock chain
	mockChain := NewMockChain("test-chain", "Test Chain", "A test chain")
	mockChain.On("Validate").Return(nil)
	mockChain.On("GetMemory").Return(nil)
	mockChain.On("SetMemory", mock.Anything).Return()

	expectedOutput := llm.ChainOutput{
		"result": "test output",
		"status": "success",
	}
	mockChain.On("Execute", mock.Anything, mock.Anything).Return(expectedOutput, nil)

	// Test chain registration
	err := orchestrator.RegisterChain(mockChain)
	require.NoError(t, err)

	// Test listing chains
	chains := orchestrator.ListChains()
	assert.Len(t, chains, 1)
	assert.Equal(t, "test-chain", chains[0].ID)
	assert.Equal(t, "Test Chain", chains[0].Name)

	// Test chain execution
	input := llm.ChainInput{
		"prompt": "test prompt",
	}

	output, err := orchestrator.ExecuteChain(context.Background(), "test-chain", input)
	require.NoError(t, err)
	assert.Equal(t, expectedOutput, output)

	// Test chain unregistration
	err = orchestrator.UnregisterChain("test-chain")
	assert.NoError(t, err)

	// Verify chain is removed
	chains = orchestrator.ListChains()
	assert.Len(t, chains, 0)

	// Verify mock expectations
	mockChain.AssertExpectations(t)
}

// TestProviderRegistration tests provider registration
func TestProviderRegistration(t *testing.T) {
	// Setup
	config := llm.OrchestratorConfig{
		MemoryConfig: memory.MemoryConfig{
			VectorMemorySize: 1000,
		},
	}

	testLogger := getTestLogger()
	orchestrator := llm.NewDefaultOrchestrator(config, testLogger)

	// Create mock provider
	mockProvider := &MockLLMProvider{}
	mockProvider.On("GetType").Return(providers.ProviderOpenAI)
	mockProvider.On("Health", mock.Anything).Return(nil)
	mockProvider.On("Close").Return(nil)

	// Start orchestrator
	err := orchestrator.Start(context.Background())
	assert.NoError(t, err)

	// Test provider registration
	err = orchestrator.RegisterProvider("test-provider", mockProvider)
	assert.NoError(t, err)

	// Test getting provider
	provider, err := orchestrator.GetProvider("test-provider")
	require.NoError(t, err)
	assert.Equal(t, mockProvider, provider)

	// Test health check includes provider
	health := orchestrator.Health()
	assert.Contains(t, health.Details, "provider_test-provider")
	assert.Equal(t, "healthy", health.Details["provider_test-provider"])

	// Test getting non-existent provider
	_, err = orchestrator.GetProvider("non-existent")
	assert.Error(t, err)

	// Stop orchestrator to trigger Close() on providers
	err = orchestrator.Stop(context.Background())
	assert.NoError(t, err)

	mockProvider.AssertExpectations(t)
}

// TestExecutionStats tests execution statistics tracking
func TestExecutionStats(t *testing.T) {
	// Setup
	config := llm.OrchestratorConfig{
		MemoryConfig: memory.MemoryConfig{
			VectorMemorySize: 1000,
		},
	}

	testLogger := getTestLogger()
	orchestrator := llm.NewDefaultOrchestrator(config, testLogger)

	// Create mock chain
	mockChain := NewMockChain("test-chain", "Test Chain", "A test chain")
	mockChain.On("Validate").Return(nil)
	mockChain.On("GetMemory").Return(nil)
	mockChain.On("SetMemory", mock.Anything).Return()

	expectedOutput := llm.ChainOutput{"result": "success"}
	mockChain.On("Execute", mock.Anything, mock.Anything).Return(expectedOutput, nil)

	// Register chain
	err := orchestrator.RegisterChain(mockChain)
	require.NoError(t, err)

	// Execute chain multiple times
	input := llm.ChainInput{"prompt": "test"}

	for i := 0; i < 3; i++ {
		_, err := orchestrator.ExecuteChain(context.Background(), "test-chain", input)
		require.NoError(t, err)
	}

	// Check statistics
	stats := orchestrator.GetStats()
	assert.Equal(t, int64(3), stats.TotalChainExecutions)
	assert.Equal(t, int64(3), stats.SuccessfulExecutions)
	assert.Equal(t, int64(0), stats.FailedExecutions)
	assert.True(t, stats.AverageExecutionTime > 0)
	assert.False(t, stats.LastExecutionTime.IsZero())

	mockChain.AssertExpectations(t)
}

// Use the default logger for testing
func getTestLogger() *logger.Logger {
	return logger.NewDefault()
}
