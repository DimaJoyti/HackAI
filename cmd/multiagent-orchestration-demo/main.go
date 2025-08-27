package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/dimajoyti/hackai/pkg/agents/multiagent"
	"github.com/dimajoyti/hackai/pkg/ai"
	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/llm/providers"
	"github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
	fmt.Println("🚀 HackAI Multi-Agent Orchestration System Demo")
	fmt.Println("================================================")
	fmt.Println("Demonstrating: Agent Coordination, Conflict Resolution, Collaborative Workflows")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	logger, err := logger.New(logger.Config{
		Level:      logger.LogLevel(cfg.Observability.Logging.Level),
		Format:     cfg.Observability.Logging.Format,
		Output:     cfg.Observability.Logging.Output,
		AddSource:  true,
		TimeFormat: time.RFC3339,
	})
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	ctx := context.Background()

	// Skip database initialization for demo
	logger.Info("Skipping database initialization for demo")

	// Run the multi-agent orchestration demo
	if err := runMultiAgentOrchestrationDemo(ctx, cfg, logger); err != nil {
		logger.Fatal("Demo failed", "error", err)
	}

	fmt.Println("\n✅ Multi-Agent Orchestration Demo completed successfully!")
}

func runMultiAgentOrchestrationDemo(ctx context.Context, cfg *config.Config, logger *logger.Logger) error {
	fmt.Println("\n🏗️ Phase 1: Multi-Agent Orchestrator Setup")
	fmt.Println("==========================================")

	// Initialize multi-agent orchestrator
	orchestratorConfig := &multiagent.OrchestratorConfig{
		MaxConcurrentTasks:     10,
		TaskTimeout:            5 * time.Minute,
		ConflictResolutionMode: "consensus",
		ConsensusThreshold:     0.7,
		EnableLoadBalancing:    true,
		EnableFailover:         true,
		HealthCheckInterval:    30 * time.Second,
		MetricsEnabled:         true,
	}

	orchestrator := multiagent.NewMultiAgentOrchestrator(orchestratorConfig, logger)

	fmt.Println("✅ Multi-agent orchestrator initialized")
	fmt.Printf("   • Max concurrent tasks: %d\n", orchestratorConfig.MaxConcurrentTasks)
	fmt.Printf("   • Conflict resolution: %s\n", orchestratorConfig.ConflictResolutionMode)
	fmt.Printf("   • Consensus threshold: %.1f\n", orchestratorConfig.ConsensusThreshold)

	fmt.Println("\n🤖 Phase 2: Agent Registration")
	fmt.Println("==============================")

	// Create mock agents for demo
	securityAgent1 := createMockAgent("security-agent-1", "Threat Detector", logger)
	securityAgent2 := createMockAgent("security-agent-2", "Vulnerability Scanner", logger)
	securityAgent3 := createMockAgent("security-agent-3", "Incident Analyzer", logger)
	businessAgent1 := createMockAgent("business-agent-1", "Market Researcher", logger)
	businessAgent2 := createMockAgent("business-agent-2", "Data Analyst", logger)
	businessAgent3 := createMockAgent("business-agent-3", "Strategy Advisor", logger)

	// Register all agents
	agents := []ai.Agent{
		securityAgent1, securityAgent2, securityAgent3,
		businessAgent1, businessAgent2, businessAgent3,
	}

	for _, agent := range agents {
		if err := orchestrator.RegisterAgent(agent); err != nil {
			return fmt.Errorf("failed to register agent %s: %w", agent.ID(), err)
		}
	}

	fmt.Printf("✅ Registered %d agents with orchestrator\n", len(agents))
	for _, agent := range agents {
		fmt.Printf("   • %s (%s)\n", agent.ID(), agent.Name())
	}

	fmt.Println("\n🚀 Phase 3: Start Orchestrator")
	fmt.Println("==============================")

	// Start the orchestrator
	if err := orchestrator.Start(ctx); err != nil {
		return fmt.Errorf("failed to start orchestrator: %w", err)
	}
	defer orchestrator.Stop()

	fmt.Println("✅ Multi-agent orchestrator started")

	// Wait for initialization
	time.Sleep(2 * time.Second)

	fmt.Println("\n🔒 Phase 4: Security Analysis Collaboration")
	fmt.Println("==========================================")

	// Create a security analysis task
	securityTask := &multiagent.MultiAgentTask{
		ID:          "security-analysis-001",
		Type:        "security_analysis",
		Priority:    multiagent.TaskPriorityHigh,
		Description: "Comprehensive security analysis of suspicious network activity",
		RequiredAgents: []string{
			"security-agent-1", // Threat detector
			"security-agent-2", // Vulnerability scanner
			"security-agent-3", // Incident analyzer
		},
		OptionalAgents: []string{},
		Constraints: []multiagent.TaskConstraint{
			{
				Type:        "time_limit",
				Value:       "5m",
				Description: "Must complete within 5 minutes",
			},
			{
				Type:        "confidence_threshold",
				Value:       0.8,
				Description: "Minimum confidence threshold of 80%",
			},
		},
		Dependencies: []string{},
		Parameters: map[string]interface{}{
			"target_system":  "production_web_server",
			"suspicious_ips": []string{"203.0.113.42", "198.51.100.23"},
			"alert_severity": "high",
			"analysis_depth": "comprehensive",
		},
		Context: map[string]interface{}{
			"industry":     "technology",
			"company_size": "enterprise",
			"region":       "global",
			"urgency":      "high",
		},
		CollaborationMode: "parallel",
		CreatedAt:         time.Now(),
	}

	fmt.Println("🔍 Executing security analysis collaboration...")
	fmt.Printf("   • Task ID: %s\n", securityTask.ID)
	fmt.Printf("   • Collaboration mode: %s\n", securityTask.CollaborationMode)
	fmt.Printf("   • Required agents: %d\n", len(securityTask.RequiredAgents))

	securityResult, err := orchestrator.ExecuteTask(ctx, securityTask)
	if err != nil {
		return fmt.Errorf("security analysis task failed: %w", err)
	}

	fmt.Println("\n📊 Security Analysis Results:")
	fmt.Printf("   • Success: %v\n", securityResult.Success)
	fmt.Printf("   • Execution time: %v\n", securityResult.ExecutionTime)
	fmt.Printf("   • Participants: %d\n", securityResult.ParticipantCount)
	fmt.Printf("   • Conflicts: %d\n", securityResult.ConflictsCount)
	fmt.Printf("   • Confidence: %.2f\n", securityResult.Confidence)
	fmt.Printf("   • Consensus score: %.2f\n", securityResult.ConsensusScore)

	fmt.Println("\n💼 Phase 5: Business Analysis Collaboration")
	fmt.Println("==========================================")

	// Create a business analysis task
	businessTask := &multiagent.MultiAgentTask{
		ID:          "business-analysis-001",
		Type:        "business_analysis",
		Priority:    multiagent.TaskPriorityMedium,
		Description: "Market analysis for new AI product launch",
		RequiredAgents: []string{
			"business-agent-1", // Market researcher
			"business-agent-2", // Data analyst
		},
		OptionalAgents: []string{
			"business-agent-3", // Strategy advisor
		},
		Constraints: []multiagent.TaskConstraint{
			{
				Type:        "budget_limit",
				Value:       100000,
				Description: "Analysis budget limit of $100,000",
			},
		},
		Dependencies: []string{},
		Parameters: map[string]interface{}{
			"product_category": "ai_assistant",
			"target_market":    "enterprise",
			"launch_timeline":  "Q2_2024",
			"competitors":      []string{"OpenAI", "Anthropic", "Google"},
		},
		Context: map[string]interface{}{
			"industry":     "artificial_intelligence",
			"company_size": "startup",
			"region":       "north_america",
			"urgency":      "medium",
		},
		CollaborationMode: "sequential",
		CreatedAt:         time.Now(),
	}

	fmt.Println("📈 Executing business analysis collaboration...")
	fmt.Printf("   • Task ID: %s\n", businessTask.ID)
	fmt.Printf("   • Collaboration mode: %s\n", businessTask.CollaborationMode)
	fmt.Printf("   • Required agents: %d\n", len(businessTask.RequiredAgents))
	fmt.Printf("   • Optional agents: %d\n", len(businessTask.OptionalAgents))

	businessResult, err := orchestrator.ExecuteTask(ctx, businessTask)
	if err != nil {
		return fmt.Errorf("business analysis task failed: %w", err)
	}

	fmt.Println("\n📊 Business Analysis Results:")
	fmt.Printf("   • Success: %v\n", businessResult.Success)
	fmt.Printf("   • Execution time: %v\n", businessResult.ExecutionTime)
	fmt.Printf("   • Participants: %d\n", businessResult.ParticipantCount)
	fmt.Printf("   • Conflicts: %d\n", businessResult.ConflictsCount)
	fmt.Printf("   • Confidence: %.2f\n", businessResult.Confidence)
	fmt.Printf("   • Consensus score: %.2f\n", businessResult.ConsensusScore)

	fmt.Println("\n🤝 Phase 6: Consensus-Based Collaboration")
	fmt.Println("=========================================")

	// Create a consensus task involving multiple agent types
	consensusTask := &multiagent.MultiAgentTask{
		ID:          "consensus-decision-001",
		Type:        "strategic_decision",
		Priority:    multiagent.TaskPriorityHigh,
		Description: "Strategic decision on AI security investment priorities",
		RequiredAgents: []string{
			"security-agent-1",
			"business-agent-2",
			"business-agent-3",
		},
		OptionalAgents: []string{
			"security-agent-2",
		},
		Constraints: []multiagent.TaskConstraint{
			{
				Type:        "consensus_threshold",
				Value:       0.8,
				Description: "Requires 80% consensus among participants",
			},
		},
		Dependencies: []string{},
		Parameters: map[string]interface{}{
			"investment_budget": 5000000,
			"time_horizon":      "12_months",
			"risk_tolerance":    "medium",
			"strategic_goals":   []string{"security", "growth", "innovation"},
		},
		Context: map[string]interface{}{
			"industry":     "technology",
			"company_size": "enterprise",
			"region":       "global",
			"urgency":      "high",
		},
		CollaborationMode: "consensus",
		CreatedAt:         time.Now(),
	}

	fmt.Println("🎯 Executing consensus-based collaboration...")
	fmt.Printf("   • Task ID: %s\n", consensusTask.ID)
	fmt.Printf("   • Collaboration mode: %s\n", consensusTask.CollaborationMode)
	fmt.Printf("   • Required agents: %d\n", len(consensusTask.RequiredAgents))

	consensusResult, err := orchestrator.ExecuteTask(ctx, consensusTask)
	if err != nil {
		return fmt.Errorf("consensus task failed: %w", err)
	}

	fmt.Println("\n📊 Consensus Decision Results:")
	fmt.Printf("   • Success: %v\n", consensusResult.Success)
	fmt.Printf("   • Execution time: %v\n", consensusResult.ExecutionTime)
	fmt.Printf("   • Participants: %d\n", consensusResult.ParticipantCount)
	fmt.Printf("   • Conflicts: %d\n", consensusResult.ConflictsCount)
	fmt.Printf("   • Confidence: %.2f\n", consensusResult.Confidence)
	fmt.Printf("   • Consensus score: %.2f\n", consensusResult.ConsensusScore)

	fmt.Println("\n📈 Phase 7: Orchestrator Performance Metrics")
	fmt.Println("============================================")

	// Get orchestrator metrics
	fmt.Println("📊 Multi-Agent Orchestrator Performance:")
	fmt.Printf("   • Total tasks executed: 3\n")
	fmt.Printf("   • Security analysis: %v (%.0fms)\n", securityResult.Success, float64(securityResult.ExecutionTime.Milliseconds()))
	fmt.Printf("   • Business analysis: %v (%.0fms)\n", businessResult.Success, float64(businessResult.ExecutionTime.Milliseconds()))
	fmt.Printf("   • Consensus decision: %v (%.0fms)\n", consensusResult.Success, float64(consensusResult.ExecutionTime.Milliseconds()))

	avgExecutionTime := (securityResult.ExecutionTime + businessResult.ExecutionTime + consensusResult.ExecutionTime) / 3
	fmt.Printf("   • Average execution time: %v\n", avgExecutionTime)

	successCount := 0
	if securityResult.Success {
		successCount++
	}
	if businessResult.Success {
		successCount++
	}
	if consensusResult.Success {
		successCount++
	}
	successRate := float64(successCount) / 3.0 * 100
	fmt.Printf("   • Success rate: %.1f%%\n", successRate)

	totalConflicts := securityResult.ConflictsCount + businessResult.ConflictsCount + consensusResult.ConflictsCount
	fmt.Printf("   • Total conflicts resolved: %d\n", totalConflicts)

	avgConsensus := (securityResult.ConsensusScore + businessResult.ConsensusScore + consensusResult.ConsensusScore) / 3
	fmt.Printf("   • Average consensus score: %.2f\n", avgConsensus)

	fmt.Println("\n🎉 Demo Summary")
	fmt.Println("===============")
	fmt.Println("✅ Successfully demonstrated:")
	fmt.Println("   • Multi-agent orchestration with sophisticated coordination")
	fmt.Println("   • Parallel collaboration for security analysis")
	fmt.Println("   • Sequential collaboration for business analysis")
	fmt.Println("   • Consensus-based decision making across agent types")
	fmt.Println("   • Conflict detection and resolution strategies")
	fmt.Println("   • Load balancing and failover mechanisms")
	fmt.Println("   • Real-time performance monitoring and metrics")
	fmt.Println("   • Cross-domain agent collaboration (security + business)")

	return nil
}

// MockLLMProvider provides a mock LLM provider for demo purposes
type MockLLMProvider struct{}

func (m *MockLLMProvider) Generate(ctx context.Context, request providers.GenerationRequest) (providers.GenerationResponse, error) {
	return providers.GenerationResponse{
		Content:      "Mock analysis result: High confidence security assessment completed.",
		TokensUsed:   providers.TokenUsage{PromptTokens: 50, CompletionTokens: 50, TotalTokens: 100},
		FinishReason: "completed",
		Model:        "mock-gpt-4",
		ID:           "mock-response-123",
		Created:      time.Now(),
	}, nil
}

func (m *MockLLMProvider) Stream(ctx context.Context, request providers.GenerationRequest) (<-chan providers.StreamChunk, error) {
	ch := make(chan providers.StreamChunk, 1)
	go func() {
		defer close(ch)
		ch <- providers.StreamChunk{
			Content:      "Mock streaming response",
			Delta:        "Mock streaming response",
			FinishReason: "completed",
		}
	}()
	return ch, nil
}

func (m *MockLLMProvider) Embed(ctx context.Context, text string) ([]float64, error) {
	return []float64{0.1, 0.2, 0.3, 0.4, 0.5}, nil
}

func (m *MockLLMProvider) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	embeddings := make([][]float64, len(texts))
	for i := range texts {
		embeddings[i] = []float64{0.1, 0.2, 0.3, 0.4, 0.5}
	}
	return embeddings, nil
}

func (m *MockLLMProvider) GetModel() providers.ModelInfo {
	return providers.ModelInfo{
		Name:         "mock-gpt-4",
		Provider:     "mock",
		MaxTokens:    4096,
		ContextSize:  8192,
		Capabilities: []string{"text-generation", "embedding"},
	}
}

func (m *MockLLMProvider) GetLimits() providers.ProviderLimits {
	return providers.ProviderLimits{
		RequestsPerMinute: 1000,
		TokensPerMinute:   100000,
		MaxConcurrent:     10,
		MaxRetries:        3,
	}
}

func (m *MockLLMProvider) GetType() providers.ProviderType {
	return providers.ProviderType("mock")
}

func (m *MockLLMProvider) Health(ctx context.Context) error {
	return nil
}

func (m *MockLLMProvider) Close() error {
	return nil
}

// createMockAgent creates a mock agent for demo purposes
func createMockAgent(id, name string, logger *logger.Logger) ai.Agent {
	return &MockAIAgent{
		id:     id,
		name:   name,
		desc:   fmt.Sprintf("Mock agent: %s", name),
		logger: logger,
	}
}

// Removed unused business agent code - using MockAgent instead

// MockAIAgent implements ai.Agent interface for demo purposes
type MockAIAgent struct {
	id     string
	name   string
	desc   string
	logger *logger.Logger
}

func (m *MockAIAgent) ID() string {
	return m.id
}

func (m *MockAIAgent) Name() string {
	return m.name
}

func (m *MockAIAgent) Description() string {
	return m.desc
}

func (m *MockAIAgent) Execute(ctx context.Context, input ai.AgentInput) (ai.AgentOutput, error) {
	// Simulate work
	time.Sleep(50 * time.Millisecond)

	return ai.AgentOutput{
		Response:   fmt.Sprintf("Mock result from %s", m.name),
		Confidence: 0.85,
		Success:    true,
		Metadata:   map[string]interface{}{"agent_id": m.id},
		Duration:   50 * time.Millisecond,
	}, nil
}

func (m *MockAIAgent) AddTool(tool ai.Tool) error {
	return nil
}

func (m *MockAIAgent) RemoveTool(toolName string) error {
	return nil
}

func (m *MockAIAgent) GetAvailableTools() []ai.Tool {
	return []ai.Tool{}
}

func (m *MockAIAgent) SetDecisionEngine(engine ai.DecisionEngine) error {
	return nil
}

func (m *MockAIAgent) GetMetrics() ai.AgentMetrics {
	return ai.AgentMetrics{
		TotalExecutions:   100,
		SuccessfulRuns:    95,
		FailedRuns:        5,
		AverageLatency:    200 * time.Millisecond,
		LastExecutionTime: time.Now(),
	}
}

func (m *MockAIAgent) Validate() error {
	return nil
}
