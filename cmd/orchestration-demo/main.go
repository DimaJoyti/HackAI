package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/infrastructure"
	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/llm/chains"
	"github.com/dimajoyti/hackai/pkg/llm/providers"
	"github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
	// Initialize logger
	loggerConfig := logger.Config{
		Level:      logger.LevelInfo,
		Format:     "json",
		Output:     "stdout",
		AddSource:  true,
		TimeFormat: time.RFC3339,
	}

	appLogger, err := logger.New(loggerConfig)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	appLogger.Info("Starting LLM Orchestration Demo")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		appLogger.Fatal("Failed to load configuration", "error", err)
	}

	// Create infrastructure manager
	infraManager, err := infrastructure.NewInfrastructureManager(cfg, appLogger)
	if err != nil {
		appLogger.Fatal("Failed to create infrastructure manager", "error", err)
	}

	// Initialize and start infrastructure
	ctx := context.Background()
	if err := infraManager.Initialize(ctx); err != nil {
		appLogger.Fatal("Failed to initialize infrastructure", "error", err)
	}

	if err := infraManager.Start(ctx); err != nil {
		appLogger.Fatal("Failed to start infrastructure", "error", err)
	}

	// Create orchestration components
	orchestrator, err := setupOrchestration(infraManager, appLogger)
	if err != nil {
		appLogger.Fatal("Failed to setup orchestration", "error", err)
	}

	// Create HTTP server
	server := createHTTPServer(orchestrator, infraManager, appLogger)

	// Start server in background
	go func() {
		appLogger.Info("Starting HTTP server", "port", cfg.Server.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			appLogger.Error("HTTP server error", "error", err)
		}
	}()

	// Demo orchestration features
	demoOrchestration(orchestrator, appLogger)

	// Wait for shutdown signal
	infraManager.WaitForShutdown()

	// Graceful shutdown
	appLogger.Info("Shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop HTTP server
	if err := server.Shutdown(shutdownCtx); err != nil {
		appLogger.Error("HTTP server shutdown error", "error", err)
	}

	// Stop orchestrator
	if err := orchestrator.StopWorkerPool(); err != nil {
		appLogger.Error("Orchestrator shutdown error", "error", err)
	}

	// Stop infrastructure
	if err := infraManager.Stop(shutdownCtx); err != nil {
		appLogger.Error("Infrastructure shutdown error", "error", err)
	}

	appLogger.Info("Orchestration Demo completed")
}

func setupOrchestration(infraManager *infrastructure.InfrastructureManager, logger *logger.Logger) (*llm.DefaultOrchestrator, error) {
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

	// Create provider manager
	providerManager := providers.NewDefaultProviderManager(logger)

	// Register mock provider for demo (in production, use real providers)
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

	if err := providerManager.RegisterProvider("demo-provider", mockProvider); err != nil {
		return nil, fmt.Errorf("failed to register provider: %w", err)
	}

	// Note: Provider manager integration would be added here in a full implementation

	// Start worker pool
	if err := orchestrator.StartWorkerPool(context.Background(), 5); err != nil {
		return nil, fmt.Errorf("failed to start worker pool: %w", err)
	}

	// Register demo chains
	if err := registerDemoChains(orchestrator, mockProvider, logger); err != nil {
		return nil, fmt.Errorf("failed to register chains: %w", err)
	}

	return orchestrator, nil
}

func registerDemoChains(orchestrator *llm.DefaultOrchestrator, provider providers.LLMProvider, logger *logger.Logger) error {
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

	// Sequential chain for complex tasks
	step1 := chains.NewSimpleChain("step1", "Analysis", "Analyze the input", provider, "Analyze this: {{input}}", logger)
	step2 := chains.NewSimpleChain("step2", "Summary", "Summarize the analysis", provider, "Summarize: {{previous_result}}", logger)

	sequentialChain := chains.NewSequentialChain(
		"analysis-summary",
		"Analysis and Summary",
		[]llm.Chain{step1, step2},
	)

	if err := orchestrator.RegisterChain(sequentialChain); err != nil {
		return err
	}

	return nil
}

func createHTTPServer(orchestrator *llm.DefaultOrchestrator, infraManager *infrastructure.InfrastructureManager, logger *logger.Logger) *http.Server {
	mux := http.NewServeMux()

	// Health check endpoint
	if healthManager := infraManager.GetHealthManager(); healthManager != nil {
		mux.Handle("/health", healthManager.HTTPHandler())
	}

	// Orchestration endpoints
	mux.HandleFunc("/api/chains", createChainsHandler(orchestrator, logger))
	mux.HandleFunc("/api/chains/execute", createChainExecuteHandler(orchestrator, logger))
	mux.HandleFunc("/api/orchestrator/stats", createStatsHandler(orchestrator, logger))

	// Apply middleware
	var handler http.Handler = mux
	for _, middleware := range infraManager.GetMiddleware() {
		handler = middleware(handler)
	}

	return &http.Server{
		Addr:    ":8080",
		Handler: handler,
	}
}

func createChainsHandler(orchestrator *llm.DefaultOrchestrator, logger *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		chains := orchestrator.ListChains()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"chains": chains,
			"count":  len(chains),
		})
	}
}

func createChainExecuteHandler(orchestrator *llm.DefaultOrchestrator, logger *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var request struct {
			ChainID    string                 `json:"chain_id"`
			Variables  map[string]interface{} `json:"variables"`
			Parameters struct {
				Temperature float64 `json:"temperature"`
				MaxTokens   int     `json:"max_tokens"`
			} `json:"parameters"`
		}

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		input := llm.ChainInput(request.Variables)
		input["temperature"] = request.Parameters.Temperature
		input["max_tokens"] = request.Parameters.MaxTokens

		output, err := orchestrator.ExecuteChain(r.Context(), request.ChainID, input)
		if err != nil {
			logger.Error("Chain execution failed", "error", err)
			http.Error(w, "Chain execution failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(output)
	}
}

func createStatsHandler(orchestrator *llm.DefaultOrchestrator, logger *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		stats := map[string]interface{}{
			"queue_depth":       orchestrator.GetQueueDepth(),
			"active_executions": orchestrator.GetActiveExecutions(),
			"registered_chains": len(orchestrator.ListChains()),
			"registered_graphs": len(orchestrator.ListGraphs()),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	}
}

func demoOrchestration(orchestrator *llm.DefaultOrchestrator, logger *logger.Logger) {
	logger.Info("=== LLM Orchestration Demo ===")

	ctx := context.Background()

	// Demo 1: Simple Chain Execution
	logger.Info("Demo 1: Simple Chain Execution")
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

		logger.Info("Simple chain completed",
			"result", result,
			"tokens_used", tokensUsed,
			"success", success,
		)
	}

	// Demo 2: Conversational Chain
	logger.Info("Demo 2: Conversational Chain")
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

		logger.Info("Conversational chain completed",
			"result", result,
			"tokens_used", tokensUsed,
		)
	}

	// Demo 3: Sequential Chain
	logger.Info("Demo 3: Sequential Chain")
	seqInput := llm.ChainInput{
		"input":       "Large language models are transforming how we interact with AI systems.",
		"temperature": 0.6,
		"max_tokens":  200,
	}

	seqOutput, err := orchestrator.ExecuteChain(ctx, "analysis-summary", seqInput)
	if err != nil {
		logger.Error("Sequential chain execution failed", "error", err)
	} else {
		result, _ := seqOutput["result"].(string)
		tokensUsed, _ := seqOutput["tokens_used"].(int)

		logger.Info("Sequential chain completed",
			"result", result,
			"tokens_used", tokensUsed,
		)
	}

	// Demo 4: Async Execution
	logger.Info("Demo 4: Async Chain Execution")
	resultChan, err := orchestrator.ExecuteChainAsync(ctx, "simple-completion", input)
	if err != nil {
		logger.Error("Async chain execution failed", "error", err)
	} else {
		select {
		case result := <-resultChan:
			if result.Error != nil {
				logger.Error("Async chain failed", "error", result.Error)
			} else {
				logger.Info("Async chain completed",
					"duration", result.Duration,
					"success", true,
				)
			}
		case <-time.After(30 * time.Second):
			logger.Error("Async chain timed out")
		}
	}

	logger.Info("Orchestration demo completed")
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
		response = fmt.Sprintf("Mock response to: %s (Call #%d)", lastMessage.Content, m.callCount)
	} else {
		response = fmt.Sprintf("Mock response (Call #%d)", m.callCount)
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

func (m *MockProvider) Stream(ctx context.Context, request providers.GenerationRequest) (<-chan providers.StreamChunk, error) {
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
