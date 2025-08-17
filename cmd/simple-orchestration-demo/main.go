package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/llm/chains"
	"github.com/dimajoyti/hackai/pkg/llm/providers"
	"github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
	// Initialize logger
	appLogger, err := logger.New(logger.Config{
		Level:      logger.LevelInfo,
		Format:     "json",
		Output:     "stdout",
		AddSource:  true,
		TimeFormat: time.RFC3339,
	})
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	appLogger.Info("🤖 Starting LLM Orchestration Demo")

	// Create orchestrator config
	config := llm.OrchestratorConfig{
		MaxConcurrentChains: 10,
		MaxConcurrentGraphs: 10,
		DefaultTimeout:      30 * time.Second,
		EnableMetrics:       true,
		EnableTracing:       true,
	}

	// Create orchestrator
	orchestrator := llm.NewDefaultOrchestrator(config, appLogger)

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

	// Register demo chains
	if err := registerDemoChains(orchestrator, mockProvider, appLogger); err != nil {
		appLogger.Fatal("Failed to register chains", "error", err)
	}

	// Run orchestration demos
	demoOrchestration(orchestrator, appLogger)

	appLogger.Info("✅ LLM Orchestration Demo completed successfully!")
}

func registerDemoChains(orchestrator *llm.DefaultOrchestrator, provider *MockProvider, logger *logger.Logger) error {
	// Simple completion chain
	simpleChain := chains.NewSimpleChain(
		"simple-completion",
		"Simple Completion",
		"A simple text completion chain",
		provider,
		"Complete this text: {{input}}",
		logger,
	)

	if err := orchestrator.RegisterChain(simpleChain); err != nil {
		return err
	}

	// Conversational chain
	memory := &SimpleMemory{}
	conversationalChain := chains.NewConversationalChain(
		"conversation",
		"Conversational Chain",
		"A conversational AI chain",
		provider,
		memory,
		"You are a helpful AI assistant. Be concise and friendly.",
		logger,
	)

	if err := orchestrator.RegisterChain(conversationalChain); err != nil {
		return err
	}

	// Analysis chain
	analysisChain := chains.NewSimpleChain(
		"analysis",
		"Analysis Chain",
		"Analyze the input text",
		provider,
		"Analyze this text and provide insights: {{input}}",
		logger,
	)

	if err := orchestrator.RegisterChain(analysisChain); err != nil {
		return err
	}

	return nil
}

func demoOrchestration(orchestrator *llm.DefaultOrchestrator, logger *logger.Logger) {
	logger.Info("=== 🚀 LLM Orchestration Demo ===")

	ctx := context.Background()

	// Demo 1: Simple Chain Execution
	logger.Info("📝 Demo 1: Simple Chain Execution")
	input := llm.ChainInput{
		"input":       "The future of artificial intelligence is",
		"temperature": 0.7,
		"max_tokens":  100,
	}

	output, err := orchestrator.ExecuteChain(ctx, "simple-completion", input)
	if err != nil {
		logger.Error("Simple chain execution failed", "error", err)
	} else {
		result, _ := output["result"].(string)
		tokensUsed, _ := output["tokens_used"].(int)
		success, _ := output["success"].(bool)

		logger.Info("✅ Simple chain completed",
			"result", result,
			"tokens_used", tokensUsed,
			"success", success,
		)
	}

	// Demo 2: Conversational Chain
	logger.Info("💬 Demo 2: Conversational Chain")
	convInput := llm.ChainInput{
		"message":         "Hello! Can you help me understand machine learning?",
		"conversation_id": "demo-conversation",
		"temperature":     0.8,
		"max_tokens":      150,
	}

	convOutput, err := orchestrator.ExecuteChain(ctx, "conversation", convInput)
	if err != nil {
		logger.Error("Conversational chain execution failed", "error", err)
	} else {
		result, _ := convOutput["result"].(string)
		tokensUsed, _ := convOutput["tokens_used"].(int)

		logger.Info("✅ Conversational chain completed",
			"result", result,
			"tokens_used", tokensUsed,
		)
	}

	// Demo 3: Analysis Chain
	logger.Info("🔍 Demo 3: Analysis Chain")
	analysisInput := llm.ChainInput{
		"input":       "Large language models are transforming how we interact with AI systems.",
		"temperature": 0.6,
		"max_tokens":  200,
	}

	analysisOutput, err := orchestrator.ExecuteChain(ctx, "analysis", analysisInput)
	if err != nil {
		logger.Error("Analysis chain execution failed", "error", err)
	} else {
		result, _ := analysisOutput["result"].(string)
		tokensUsed, _ := analysisOutput["tokens_used"].(int)

		logger.Info("✅ Analysis chain completed",
			"result", result,
			"tokens_used", tokensUsed,
		)
	}

	// Demo 4: List all registered chains
	logger.Info("📋 Demo 4: List Registered Chains")
	chains := orchestrator.ListChains()
	logger.Info("Registered chains", "count", len(chains))
	for _, chain := range chains {
		logger.Info("Chain info",
			"id", chain.ID,
			"name", chain.Name,
			"description", chain.Description,
			"status", chain.Status,
		)
	}

	logger.Info("🎉 All orchestration demos completed successfully!")
}

// MockProvider for demonstration purposes
type MockProvider struct {
	providerType providers.ProviderType
	model        providers.ModelInfo
	healthy      bool
	callCount    int
}

func (m *MockProvider) GetType() providers.ProviderType {
	return m.providerType
}

func (m *MockProvider) GetModel() providers.ModelInfo {
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

	// Simulate processing time
	time.Sleep(100 * time.Millisecond)

	// Generate mock response based on input
	var response string
	if len(request.Messages) > 0 {
		lastMessage := request.Messages[len(request.Messages)-1]
		response = fmt.Sprintf("🤖 Mock AI Response to: '%s' (Call #%d)", lastMessage.Content, m.callCount)
	} else {
		response = fmt.Sprintf("🤖 Mock AI Response (Call #%d)", m.callCount)
	}

	return providers.GenerationResponse{
		Content: response,
		Model:   m.model.Name,
		TokensUsed: providers.TokenUsage{
			PromptTokens:     len(request.Messages) * 10,
			CompletionTokens: len(response) / 4,
			TotalTokens:      len(request.Messages)*10 + len(response)/4,
		},
		FinishReason: "stop",
	}, nil
}

func (m *MockProvider) Stream(ctx context.Context, request providers.GenerationRequest) (<-chan providers.StreamChunk, error) {
	ch := make(chan providers.StreamChunk, 1)
	go func() {
		defer close(ch)
		ch <- providers.StreamChunk{
			Content: "🤖 Mock streaming response",
			Delta:   "🤖 Mock streaming response",
		}
	}()
	return ch, nil
}

func (m *MockProvider) Embed(ctx context.Context, text string) ([]float64, error) {
	embedding := make([]float64, 1536)
	for i := range embedding {
		embedding[i] = 0.1
	}
	return embedding, nil
}

func (m *MockProvider) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	embeddings := make([][]float64, len(texts))
	for i := range texts {
		embeddings[i] = make([]float64, 1536)
		for j := range embeddings[i] {
			embeddings[i][j] = 0.1
		}
	}
	return embeddings, nil
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

// SimpleMemory implements a simple in-memory storage for Memory interface
type SimpleMemory struct {
	data map[string]interface{}
}

func (m *SimpleMemory) Store(ctx context.Context, key string, value interface{}) error {
	if m.data == nil {
		m.data = make(map[string]interface{})
	}
	m.data[key] = value
	return nil
}

func (m *SimpleMemory) Retrieve(ctx context.Context, key string) (interface{}, error) {
	if m.data == nil {
		return nil, fmt.Errorf("key %s not found", key)
	}
	value, exists := m.data[key]
	if !exists {
		return nil, fmt.Errorf("key %s not found", key)
	}
	return value, nil
}

func (m *SimpleMemory) Delete(ctx context.Context, key string) error {
	if m.data == nil {
		return nil
	}
	delete(m.data, key)
	return nil
}

func (m *SimpleMemory) Clear(ctx context.Context) error {
	m.data = make(map[string]interface{})
	return nil
}

func (m *SimpleMemory) Keys(ctx context.Context) ([]string, error) {
	if m.data == nil {
		return []string{}, nil
	}
	keys := make([]string, 0, len(m.data))
	for key := range m.data {
		keys = append(keys, key)
	}
	return keys, nil
}
