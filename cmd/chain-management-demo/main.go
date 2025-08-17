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

	appLogger.Info("🔗 Starting Chain Management System Demo")

	// Create Chain Management System
	chainManager, err := setupChainManager(appLogger)
	if err != nil {
		appLogger.Fatal("Failed to setup chain manager", "error", err)
	}

	// Run comprehensive demo
	if err := runChainManagementDemo(chainManager, appLogger); err != nil {
		appLogger.Fatal("Demo failed", "error", err)
	}

	appLogger.Info("✅ Chain Management System Demo completed successfully!")
}

func setupChainManager(logger *logger.Logger) (*chains.DefaultChainManager, error) {
	// Create registry
	registry := chains.NewDefaultChainRegistry(logger)

	// Create validator with comprehensive configuration
	validatorConfig := chains.ValidatorConfig{
		MaxNameLength:        100,
		MaxDescriptionLength: 1000,
		AllowedTags:          []string{"demo", "test", "production", "ai", "nlp", "analysis"},
		RequiredTags:         []string{},
		MaxDependencies:      10,
		MaxExecutionTime:     60 * time.Second,
		MaxMemoryUsage:       1024 * 1024 * 1024, // 1GB
		SecurityChecks: chains.SecurityChecks{
			CheckPromptInjection: true,
			CheckDataLeakage:     true,
			CheckMaliciousCode:   true,
			CheckResourceLimits:  true,
		},
	}
	validator := chains.NewDefaultChainValidator(validatorConfig, logger)

	// Create monitor
	monitor, err := chains.NewDefaultChainMonitor(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create monitor: %w", err)
	}

	// Create security manager
	security := chains.NewDefaultChainSecurity(logger)

	// Create template manager
	templates := chains.NewDefaultTemplateManager(logger)

	// Create chain manager
	chainManager := chains.NewDefaultChainManager(registry, validator, monitor, security, templates, logger)

	return chainManager, nil
}

func runChainManagementDemo(manager *chains.DefaultChainManager, logger *logger.Logger) error {
	ctx := context.Background()

	logger.Info("=== 🚀 Chain Management System Demo ===")

	// Demo 1: Chain Registration and Lifecycle Management
	if err := demoChainLifecycle(ctx, manager, logger); err != nil {
		return fmt.Errorf("chain lifecycle demo failed: %w", err)
	}

	// Demo 2: Chain Templates and Instantiation
	if err := demoChainTemplates(ctx, manager, logger); err != nil {
		return fmt.Errorf("chain templates demo failed: %w", err)
	}

	// Demo 3: Security and Access Control
	if err := demoChainSecurity(ctx, manager, logger); err != nil {
		return fmt.Errorf("chain security demo failed: %w", err)
	}

	// Demo 4: Monitoring and Health Checks
	if err := demoChainMonitoring(ctx, manager, logger); err != nil {
		return fmt.Errorf("chain monitoring demo failed: %w", err)
	}

	// Demo 5: Chain Discovery and Search
	if err := demoChainDiscovery(ctx, manager, logger); err != nil {
		return fmt.Errorf("chain discovery demo failed: %w", err)
	}

	return nil
}

func demoChainLifecycle(ctx context.Context, manager *chains.DefaultChainManager, logger *logger.Logger) error {
	logger.Info("📋 Demo 1: Chain Registration and Lifecycle Management")

	// Create a demo chain
	demoChain := &DemoChain{
		id:          "demo-text-analyzer",
		name:        "Text Analyzer Chain",
		description: "Analyzes text for sentiment, entities, and key topics",
	}

	// Create metadata
	metadata := chains.ChainMetadata{
		Version:      "1.0.0",
		Author:       "demo-system",
		Tags:         []string{"demo", "ai", "nlp", "analysis"},
		Category:     "text-processing",
		Description:  "A comprehensive text analysis chain for demonstration",
		Dependencies: []string{},
		Parameters: map[string]interface{}{
			"model_type":   "advanced",
			"confidence":   0.8,
			"max_entities": 10,
		},
	}

	// Register the chain
	if err := manager.RegisterChain(ctx, demoChain, metadata); err != nil {
		return fmt.Errorf("failed to register chain: %w", err)
	}
	logger.Info("✅ Chain registered successfully", "chain_id", demoChain.ID())

	// List all chains
	filter := chains.ChainFilter{
		Tags:  []string{"demo"},
		Limit: 10,
	}
	chainList, err := manager.ListChains(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to list chains: %w", err)
	}
	logger.Info("📋 Listed chains", "count", len(chainList))

	// Update the chain
	demoChain.description = "Updated: Advanced text analysis with enhanced features"
	if err := manager.UpdateChain(ctx, demoChain.ID(), demoChain); err != nil {
		return fmt.Errorf("failed to update chain: %w", err)
	}
	logger.Info("🔄 Chain updated successfully")

	// Enable/disable chain
	if err := manager.DisableChain(ctx, demoChain.ID()); err != nil {
		return fmt.Errorf("failed to disable chain: %w", err)
	}
	logger.Info("⏸️ Chain disabled")

	if err := manager.EnableChain(ctx, demoChain.ID()); err != nil {
		return fmt.Errorf("failed to enable chain: %w", err)
	}
	logger.Info("▶️ Chain enabled")

	return nil
}

func demoChainTemplates(ctx context.Context, manager *chains.DefaultChainManager, logger *logger.Logger) error {
	logger.Info("📝 Demo 2: Chain Templates and Instantiation")

	// Create a chain template
	template := chains.ChainTemplate{
		ID:             "text-summarizer-template",
		Name:           "Text Summarizer Template",
		Description:    "A reusable template for creating text summarization chains",
		Version:        "1.0.0",
		Author:         "demo-system",
		Category:       "text-processing",
		Tags:           []string{"demo", "template", "summarization"},
		Type:           llm.ChainTypeSequential,
		PromptTemplate: "Summarize the following text in {{max_sentences}} sentences:\n\n{{text}}\n\nSummary:",
		Parameters: []chains.TemplateParameter{
			{
				Name:        "text",
				Type:        "string",
				Description: "The text to summarize",
				Required:    true,
				Examples:    []interface{}{"This is a sample text to summarize..."},
			},
			{
				Name:         "max_sentences",
				Type:         "number",
				Description:  "Maximum number of sentences in summary",
				Required:     false,
				DefaultValue: 3,
				Examples:     []interface{}{2, 3, 5},
			},
		},
		Configuration: chains.TemplateConfiguration{
			ProviderType: providers.ProviderOpenAI,
			ModelName:    "gpt-3.5-turbo",
			Temperature:  0.7,
			MaxTokens:    200,
		},
		Visibility: "public",
		License:    "MIT",
	}

	// Create the template
	if err := manager.CreateTemplate(ctx, template); err != nil {
		return fmt.Errorf("failed to create template: %w", err)
	}
	logger.Info("✅ Template created successfully", "template_id", template.ID)

	// Instantiate a chain from the template
	config := chains.TemplateConfig{
		ChainID:     "my-summarizer-chain",
		Name:        "My Text Summarizer",
		Description: "A customized text summarizer based on template",
		Parameters: map[string]interface{}{
			"text":          "Artificial Intelligence is transforming industries across the globe. From healthcare to finance, AI technologies are enabling new capabilities and improving efficiency. Machine learning algorithms can now process vast amounts of data to identify patterns and make predictions that were previously impossible.",
			"max_sentences": 2,
		},
	}

	chain, err := manager.InstantiateFromTemplate(ctx, template.ID, config)
	if err != nil {
		return fmt.Errorf("failed to instantiate chain from template: %w", err)
	}
	logger.Info("✅ Chain instantiated from template", "chain_id", config.ChainID)

	// Execute the instantiated chain
	input := llm.ChainInput{
		"text":          config.Parameters["text"],
		"max_sentences": config.Parameters["max_sentences"],
	}

	output, err := chain.Execute(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to execute template chain: %w", err)
	}
	logger.Info("✅ Template chain executed", "result", output["result"])

	return nil
}

func demoChainSecurity(ctx context.Context, manager *chains.DefaultChainManager, logger *logger.Logger) error {
	logger.Info("🔒 Demo 3: Security and Access Control")

	chainID := "demo-text-analyzer"

	// Set up permissions
	permissions := chains.ChainPermissions{
		ChainID:   chainID,
		Owners:    []string{"admin", "chain-owner"},
		Readers:   []string{"data-scientist", "analyst"},
		Executors: []string{"api-user", "service-account"},
		Admins:    []string{"admin"},
		Groups: map[string][]string{
			"ml-team":   {"ml-engineer-1", "ml-engineer-2"},
			"data-team": {"data-analyst-1", "data-analyst-2"},
		},
		PublicRead:    false,
		PublicExecute: false,
	}

	if err := manager.SetChainPermissions(ctx, chainID, permissions); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}
	logger.Info("✅ Permissions configured")

	// Test access control
	testCases := []struct {
		userID        string
		action        string
		shouldSucceed bool
	}{
		{"admin", "admin", true},
		{"chain-owner", "admin", true},
		{"data-scientist", "read", true},
		{"api-user", "execute", true},
		{"unauthorized-user", "read", false},
		{"unauthorized-user", "execute", false},
	}

	for _, tc := range testCases {
		err := manager.CheckAccess(ctx, chainID, tc.userID, tc.action)
		if tc.shouldSucceed {
			if err != nil {
				logger.Warn("Expected access to succeed but failed",
					"user", tc.userID, "action", tc.action, "error", err)
			} else {
				logger.Info("✅ Access granted", "user", tc.userID, "action", tc.action)
			}
		} else {
			if err == nil {
				logger.Warn("Expected access to fail but succeeded",
					"user", tc.userID, "action", tc.action)
			} else {
				logger.Info("🚫 Access denied (expected)", "user", tc.userID, "action", tc.action)
			}
		}
	}

	// Execute chain with proper permissions
	input := llm.ChainInput{
		"text": "This is a test input for security demonstration",
	}

	options := chains.ExecutionOptions{
		UserID:  "api-user",
		Timeout: 30 * time.Second,
	}

	output, err := manager.ExecuteChain(ctx, chainID, input, options)
	if err != nil {
		return fmt.Errorf("failed to execute chain with permissions: %w", err)
	}
	logger.Info("✅ Chain executed with proper permissions", "result", output["result"])

	return nil
}

func demoChainMonitoring(ctx context.Context, manager *chains.DefaultChainManager, logger *logger.Logger) error {
	logger.Info("📊 Demo 4: Monitoring and Health Checks")

	chainID := "demo-text-analyzer"

	// Get chain metrics
	metrics, err := manager.GetChainMetrics(ctx, chainID)
	if err != nil {
		return fmt.Errorf("failed to get metrics: %w", err)
	}

	logger.Info("📈 Chain Metrics",
		"chain_id", metrics.ChainID,
		"total_executions", metrics.TotalExecutions,
		"successful_executions", metrics.SuccessfulExecutions,
		"failed_executions", metrics.FailedExecutions,
		"average_latency", metrics.AverageLatency,
		"error_rate", fmt.Sprintf("%.2f%%", metrics.ErrorRate*100),
		"throughput_per_min", fmt.Sprintf("%.2f", metrics.ThroughputPerMin),
	)

	// Get chain health
	health, err := manager.GetChainHealth(ctx, chainID)
	if err != nil {
		return fmt.Errorf("failed to get health: %w", err)
	}

	logger.Info("🏥 Chain Health",
		"chain_id", health.ChainID,
		"status", health.Status,
		"last_check", health.LastCheck,
		"issues_count", len(health.Issues),
	)

	if len(health.Issues) > 0 {
		for _, issue := range health.Issues {
			logger.Info("⚠️ Health Issue",
				"type", issue.Type,
				"severity", issue.Severity,
				"message", issue.Message,
			)
		}
	}

	return nil
}

func demoChainDiscovery(ctx context.Context, manager *chains.DefaultChainManager, logger *logger.Logger) error {
	logger.Info("🔍 Demo 5: Chain Discovery and Search")

	// Search for chains
	searchResults, err := manager.SearchChains(ctx, "text")
	if err != nil {
		return fmt.Errorf("failed to search chains: %w", err)
	}

	logger.Info("🔍 Search Results", "query", "text", "results", len(searchResults))
	for _, result := range searchResults {
		logger.Info("📋 Found Chain",
			"id", result.ID,
			"name", result.Name,
			"category", result.Category,
			"tags", result.Tags,
			"author", result.Author,
		)
	}

	// Filter chains by category
	filter := chains.ChainFilter{
		Category: "text-processing",
		Tags:     []string{"demo"},
		Limit:    10,
	}

	filteredChains, err := manager.ListChains(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to filter chains: %w", err)
	}

	logger.Info("🏷️ Filtered Chains", "category", "text-processing", "results", len(filteredChains))
	for _, chain := range filteredChains {
		logger.Info("📋 Filtered Chain",
			"id", chain.ID,
			"name", chain.Name,
			"version", chain.Version,
			"execution_count", chain.ExecutionCount,
		)
	}

	return nil
}

// DemoChain implements a simple chain for demonstration
type DemoChain struct {
	id          string
	name        string
	description string
	memory      llm.Memory
}

func (dc *DemoChain) ID() string          { return dc.id }
func (dc *DemoChain) Name() string        { return dc.name }
func (dc *DemoChain) Description() string { return dc.description }

func (dc *DemoChain) Execute(ctx context.Context, input llm.ChainInput) (llm.ChainOutput, error) {
	// Simulate processing time
	time.Sleep(100 * time.Millisecond)

	// Extract input text
	text, ok := input["text"].(string)
	if !ok {
		text = "No text provided"
	}

	// Generate mock analysis result
	result := fmt.Sprintf("Analysis of '%s': Sentiment: Positive, Entities: [AI, Technology], Topics: [Innovation, Efficiency]", text)

	return llm.ChainOutput{
		"result":     result,
		"sentiment":  "positive",
		"entities":   []string{"AI", "Technology"},
		"topics":     []string{"Innovation", "Efficiency"},
		"confidence": 0.95,
		"success":    true,
	}, nil
}

func (dc *DemoChain) GetMemory() llm.Memory       { return dc.memory }
func (dc *DemoChain) SetMemory(memory llm.Memory) { dc.memory = memory }
func (dc *DemoChain) Validate() error             { return nil }
