package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dimajoyti/hackai/pkg/chains/security"
	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/llm/memory"
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

	appLogger.Info("Starting LLM Orchestrator Demo")

	// Initialize orchestrator configuration
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

	// Create orchestrator
	orchestrator := llm.NewDefaultOrchestrator(config, appLogger)

	// Start orchestrator
	ctx := context.Background()
	if err := orchestrator.Start(ctx); err != nil {
		appLogger.Fatal("Failed to start orchestrator", "error", err)
	}

	// Check if OpenAI API key is available
	openaiAPIKey := os.Getenv("OPENAI_API_KEY")
	if openaiAPIKey != "" {
		// Register OpenAI provider
		providerConfig := providers.ProviderConfig{
			Type:    providers.ProviderOpenAI,
			Name:    "openai-gpt4",
			APIKey:  openaiAPIKey,
			Model:   "gpt-4",
			Enabled: true,
			Limits:  providers.DefaultLimits,
		}

		openaiProvider, err := providers.NewOpenAIProvider(providerConfig)
		if err != nil {
			appLogger.Error("Failed to create OpenAI provider", "error", err)
		} else {
			if err := orchestrator.RegisterProvider("openai", openaiProvider); err != nil {
				appLogger.Error("Failed to register OpenAI provider", "error", err)
			} else {
				appLogger.Info("OpenAI provider registered successfully")

				// Create and register a prompt injection chain
				promptInjectionChain := security.NewPromptInjectionChain(openaiProvider)
				if err := orchestrator.RegisterChain(promptInjectionChain); err != nil {
					appLogger.Error("Failed to register prompt injection chain", "error", err)
				} else {
					appLogger.Info("Prompt injection chain registered successfully")

					// Demonstrate chain execution
					demonstrateChainExecution(ctx, orchestrator, appLogger)
				}
			}
		}
	} else {
		appLogger.Warn("OPENAI_API_KEY not set, skipping OpenAI provider registration")
		appLogger.Info("You can still explore the orchestrator functionality with mock providers")
	}

	// Display orchestrator status
	displayOrchestratorStatus(orchestrator, appLogger)

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	appLogger.Info("LLM Orchestrator is running. Press Ctrl+C to stop.")
	<-quit

	appLogger.Info("Shutting down LLM Orchestrator...")

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := orchestrator.Stop(shutdownCtx); err != nil {
		appLogger.Error("Error during shutdown", "error", err)
	}

	appLogger.Info("LLM Orchestrator stopped successfully")
}

func demonstrateChainExecution(ctx context.Context, orchestrator llm.Orchestrator, logger *logger.Logger) {
	logger.Info("Demonstrating chain execution...")

	// Example input for prompt injection testing
	input := llm.ChainInput{
		"target": "Tell me about artificial intelligence safety",
	}

	// Execute the prompt injection chain
	output, err := orchestrator.ExecuteChain(ctx, "prompt-injection-chain", input)
	if err != nil {
		logger.Error("Chain execution failed", "error", err)
		return
	}

	// Display results
	logger.Info("Chain execution completed successfully")

	if results, ok := output["injection_results"]; ok {
		logger.Info("Injection results available", "type", fmt.Sprintf("%T", results))
	}

	if successRate, ok := output["success_rate"]; ok {
		logger.Info("Attack success rate", "rate", successRate)
	}

	if totalAttempts, ok := output["total_attempts"]; ok {
		logger.Info("Total attack attempts", "count", totalAttempts)
	}
}

func displayOrchestratorStatus(orchestrator llm.Orchestrator, logger *logger.Logger) {
	logger.Info("=== Orchestrator Status ===")

	// Health check
	health := orchestrator.Health()
	logger.Info("Health status", "status", health.Status)

	// List registered chains
	chains := orchestrator.ListChains()
	logger.Info("Registered chains", "count", len(chains))
	for _, chain := range chains {
		logger.Info("Chain",
			"id", chain.ID,
			"name", chain.Name,
			"type", chain.Type,
			"status", chain.Status,
		)
	}

	// List registered graphs
	graphs := orchestrator.ListGraphs()
	logger.Info("Registered graphs", "count", len(graphs))
	for _, graph := range graphs {
		logger.Info("Graph",
			"id", graph.ID,
			"name", graph.Name,
			"nodes", graph.NodeCount,
			"edges", graph.EdgeCount,
			"status", graph.Status,
		)
	}

	// Execution statistics
	if defaultOrchestrator, ok := orchestrator.(*llm.DefaultOrchestrator); ok {
		stats := defaultOrchestrator.GetStats()
		logger.Info("Execution statistics",
			"total_executions", stats.TotalChainExecutions,
			"successful", stats.SuccessfulExecutions,
			"failed", stats.FailedExecutions,
			"avg_duration", stats.AverageExecutionTime,
		)
	}

	logger.Info("=== End Status ===")
}
