package fraud

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/dimajoyti/hackai/pkg/ai"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// StubOrchestrator provides a stub AI orchestrator for testing
type StubOrchestrator struct{}

// Chain operations
func (so *StubOrchestrator) RegisterChain(chain ai.Chain) error   { return nil }
func (so *StubOrchestrator) UnregisterChain(chainID string) error { return nil }
func (so *StubOrchestrator) ExecuteChain(ctx context.Context, chainID string, input map[string]interface{}) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}
func (so *StubOrchestrator) ExecuteChainAsync(ctx context.Context, chainID string, input map[string]interface{}) (<-chan ai.OrchestratorResult, error) {
	ch := make(chan ai.OrchestratorResult, 1)
	close(ch)
	return ch, nil
}
func (so *StubOrchestrator) ExecuteChainWithPriority(ctx context.Context, chainID string, input map[string]interface{}, priority ai.OrchestratorExecutionPriority) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}
func (so *StubOrchestrator) ListChains() []ai.ChainInfo { return []ai.ChainInfo{} }

// Graph operations
func (so *StubOrchestrator) RegisterGraph(graph ai.Graph) error   { return nil }
func (so *StubOrchestrator) UnregisterGraph(graphID string) error { return nil }
func (so *StubOrchestrator) ExecuteGraph(ctx context.Context, graphID string, state ai.GraphState) (ai.GraphState, error) {
	return ai.GraphState{}, nil
}
func (so *StubOrchestrator) ExecuteGraphAsync(ctx context.Context, graphID string, state ai.GraphState) (<-chan ai.OrchestratorResult, error) {
	ch := make(chan ai.OrchestratorResult, 1)
	close(ch)
	return ch, nil
}
func (so *StubOrchestrator) ExecuteGraphWithPriority(ctx context.Context, graphID string, state ai.GraphState, priority ai.OrchestratorExecutionPriority) (ai.GraphState, error) {
	return ai.GraphState{}, nil
}
func (so *StubOrchestrator) ListGraphs() []ai.GraphInfo { return []ai.GraphInfo{} }

// Agent operations
func (so *StubOrchestrator) RegisterAgent(agent ai.Agent) error   { return nil }
func (so *StubOrchestrator) UnregisterAgent(agentID string) error { return nil }
func (so *StubOrchestrator) ExecuteAgent(ctx context.Context, agentID string, input ai.AgentInput) (ai.AgentOutput, error) {
	return ai.AgentOutput{}, nil
}
func (so *StubOrchestrator) ExecuteAgentAsync(ctx context.Context, agentID string, input ai.AgentInput) (<-chan ai.OrchestratorResult, error) {
	ch := make(chan ai.OrchestratorResult, 1)
	close(ch)
	return ch, nil
}
func (so *StubOrchestrator) ExecuteAgentWithPriority(ctx context.Context, agentID string, input ai.AgentInput, priority ai.OrchestratorExecutionPriority) (ai.AgentOutput, error) {
	return ai.AgentOutput{}, nil
}
func (so *StubOrchestrator) ListAgents() []ai.AgentInfo { return []ai.AgentInfo{} }

// Tool operations
func (so *StubOrchestrator) RegisterTool(tool ai.Tool) error          { return nil }
func (so *StubOrchestrator) UnregisterTool(toolName string) error     { return nil }
func (so *StubOrchestrator) GetTool(toolName string) (ai.Tool, error) { return nil, nil }
func (so *StubOrchestrator) ListTools() []string                      { return []string{} }

// Advanced execution management
func (so *StubOrchestrator) ExecuteBatch(ctx context.Context, requests []ai.BatchRequest) ([]ai.BatchResult, error) {
	return []ai.BatchResult{}, nil
}
func (so *StubOrchestrator) ScheduleExecution(ctx context.Context, request ai.ScheduledRequest) (string, error) {
	return "stub-execution-id", nil
}
func (so *StubOrchestrator) CancelExecution(executionID string) error { return nil }
func (so *StubOrchestrator) GetExecutionStatus(executionID string) (ai.ExecutionStatus, error) {
	return ai.ExecutionStatus{}, nil
}

// Load balancing and scaling
func (so *StubOrchestrator) ScaleWorkers(newSize int) error { return nil }
func (so *StubOrchestrator) GetLoadMetrics() ai.LoadMetrics { return ai.LoadMetrics{} }
func (so *StubOrchestrator) SetLoadBalancingStrategy(strategy ai.LoadBalancingStrategy) error {
	return nil
}

// Lifecycle management
func (so *StubOrchestrator) Start(ctx context.Context) error        { return nil }
func (so *StubOrchestrator) Stop() error                            { return nil }
func (so *StubOrchestrator) Health() ai.HealthStatus                { return ai.HealthStatus{} }
func (so *StubOrchestrator) GetStats() ai.OrchestratorStats         { return ai.OrchestratorStats{} }
func (so *StubOrchestrator) GetDetailedMetrics() ai.DetailedMetrics { return ai.DetailedMetrics{} }

func TestHackAIIntegrationComplete(t *testing.T) {
	// Create logger
	testLogger, _ := logger.New(logger.Config{
		Level:  logger.LevelDebug,
		Format: "text",
		Output: "stdout",
	})

	// Create fraud detection engine
	config := DefaultEngineConfig()
	engine, err := NewFraudDetectionEngine("integration-test-engine", "Integration Test Engine", config, testLogger)
	if err != nil {
		t.Fatalf("Failed to create fraud detection engine: %v", err)
	}

	// Start the engine
	ctx := context.Background()
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("Failed to start engine: %v", err)
	}
	defer engine.Stop()

	// Create stub components
	aiOrchestrator := &StubOrchestrator{}
	securityFramework := NewStubSecurityFramework(testLogger)

	// Create HackAI integration
	integration := NewHackAIIntegration(engine, aiOrchestrator, securityFramework, testLogger)

	// Create test request
	request := &FraudDetectionRequest{
		ID:        "integration-test-001",
		UserID:    "user-integration-test",
		SessionID: "session-integration-test",
		TransactionData: map[string]interface{}{
			"amount":   1000.00,
			"currency": "USD",
			"merchant": "Suspicious Merchant",
		},
		UserContext: map[string]interface{}{
			"user_age_days": 1.0, // New account
			"account_type":  "unverified",
		},
		DeviceFingerprint: map[string]interface{}{
			"ip_address": "10.0.0.1",
			"user_agent": "Bot/1.0",
		},
		Timestamp: time.Now(),
		Priority:  PriorityHigh,
	}

	// Test fraud detection with threat intelligence
	response, err := integration.ProcessFraudDetectionWithIntelligence(ctx, request)
	if err != nil {
		t.Fatalf("Integration fraud detection failed: %v", err)
	}

	// Validate response
	if response == nil {
		t.Fatal("Response is nil")
	}

	if response.RequestID != request.ID {
		t.Errorf("Expected request ID %s, got %s", request.ID, response.RequestID)
	}

	// Check that threat intelligence was integrated
	if response.Metadata == nil {
		t.Error("Response metadata is nil")
	} else {
		if _, exists := response.Metadata["threat_intelligence"]; !exists {
			t.Error("Threat intelligence not found in response metadata")
		}
	}

	// Validate performance
	if response.ProcessingTime <= 0 {
		t.Error("Invalid processing time")
	}

	if response.ProcessingTime > 100*time.Millisecond {
		t.Errorf("Processing time too slow: %v", response.ProcessingTime)
	}

	t.Logf("Integration test completed successfully:")
	t.Logf("  Request ID: %s", response.RequestID)
	t.Logf("  Fraud Score: %.3f", response.FraudScore)
	t.Logf("  Risk Level: %s", response.RiskLevel)
	t.Logf("  Decision: %s", response.Decision)
	t.Logf("  Processing Time: %v", response.ProcessingTime)
	t.Logf("  Threat Intelligence: %v", response.Metadata["threat_intelligence"] != nil)
}

func TestEnhancedCacheManager(t *testing.T) {
	// Create logger
	testLogger, _ := logger.New(logger.Config{
		Level:  logger.LevelDebug,
		Format: "text",
		Output: "stdout",
	})

	// Create stub Redis cache
	redis := NewStubRedisCache()
	config := DefaultEngineConfig()
	cacheManager := NewEnhancedCacheManager(redis, config, testLogger)

	ctx := context.Background()

	// Test caching fraud response
	response := &FraudDetectionResponse{
		RequestID:  "cache-test-001",
		FraudScore: 0.75,
		Confidence: 0.85,
		RiskLevel:  RiskLevelHigh,
		Decision:   DecisionReview,
		Timestamp:  time.Now(),
	}

	// Set cache
	err := cacheManager.SetFraudResponse(ctx, "cache-test-001", response, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to set cache: %v", err)
	}

	// Get from cache
	cachedResponse, err := cacheManager.GetFraudResponse(ctx, "cache-test-001")
	if err != nil {
		t.Fatalf("Failed to get from cache: %v", err)
	}

	if cachedResponse == nil {
		t.Fatal("Cached response is nil")
	}

	if cachedResponse.RequestID != response.RequestID {
		t.Errorf("Expected request ID %s, got %s", response.RequestID, cachedResponse.RequestID)
	}

	if cachedResponse.FraudScore != response.FraudScore {
		t.Errorf("Expected fraud score %.3f, got %.3f", response.FraudScore, cachedResponse.FraudScore)
	}

	// Test cache stats
	stats := cacheManager.GetStats()
	if stats.Hits != 1 {
		t.Errorf("Expected 1 cache hit, got %d", stats.Hits)
	}

	if stats.Sets != 1 {
		t.Errorf("Expected 1 cache set, got %d", stats.Sets)
	}

	if stats.HitRate != 1.0 {
		t.Errorf("Expected hit rate 1.0, got %.3f", stats.HitRate)
	}

	t.Logf("Cache test completed successfully:")
	t.Logf("  Cache Hits: %d", stats.Hits)
	t.Logf("  Cache Sets: %d", stats.Sets)
	t.Logf("  Hit Rate: %.3f", stats.HitRate)
}

func TestFraudStorage(t *testing.T) {
	// Create logger
	testLogger, _ := logger.New(logger.Config{
		Level:  logger.LevelDebug,
		Format: "text",
		Output: "stdout",
	})

	// Create fraud storage (stub implementation)
	storage, err := NewFraudStorage("", testLogger)
	if err != nil {
		t.Fatalf("Failed to create fraud storage: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()

	// Test storing fraud request
	request := &FraudDetectionRequest{
		ID:        "storage-test-001",
		UserID:    "user-storage-test",
		SessionID: "session-storage-test",
		TransactionData: map[string]interface{}{
			"amount": 100.0,
		},
		Timestamp: time.Now(),
	}

	err = storage.StoreFraudRequest(ctx, request)
	if err != nil {
		t.Fatalf("Failed to store fraud request: %v", err)
	}

	// Test storing fraud response
	response := &FraudDetectionResponse{
		RequestID:  "storage-test-001",
		FraudScore: 0.5,
		Decision:   DecisionAllow,
		Timestamp:  time.Now(),
	}

	err = storage.StoreFraudResponse(ctx, response)
	if err != nil {
		t.Fatalf("Failed to store fraud response: %v", err)
	}

	// Test getting user behavior history
	history, err := storage.GetUserBehaviorHistory(ctx, "user-storage-test", 10)
	if err != nil {
		t.Fatalf("Failed to get user behavior history: %v", err)
	}

	// Should return empty history for stub implementation
	if len(history) != 0 {
		t.Errorf("Expected empty history, got %d items", len(history))
	}

	t.Log("Storage test completed successfully")
}

func BenchmarkIntegratedFraudDetection(b *testing.B) {
	// Create logger
	testLogger, _ := logger.New(logger.Config{
		Level:  logger.LevelError, // Reduce logging for benchmark
		Format: "text",
		Output: "stdout",
	})

	// Create fraud detection engine
	config := DefaultEngineConfig()
	engine, err := NewFraudDetectionEngine("bench-integration-engine", "Benchmark Integration Engine", config, testLogger)
	if err != nil {
		b.Fatalf("Failed to create fraud detection engine: %v", err)
	}

	ctx := context.Background()
	engine.Start(ctx)
	defer engine.Stop()

	// Create integration
	aiOrchestrator := &StubOrchestrator{}
	securityFramework := NewStubSecurityFramework(testLogger)
	integration := NewHackAIIntegration(engine, aiOrchestrator, securityFramework, testLogger)

	request := &FraudDetectionRequest{
		ID:        "bench-integration",
		UserID:    "user-bench",
		SessionID: "session-bench",
		TransactionData: map[string]interface{}{
			"amount": 100.0,
		},
		UserContext: map[string]interface{}{
			"user_age_days": 365.0,
		},
		DeviceFingerprint: map[string]interface{}{
			"ip_address": "192.168.1.1",
		},
		Timestamp: time.Now(),
		Priority:  PriorityNormal,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request.ID = fmt.Sprintf("bench-integration-%d", i)
		_, err := integration.ProcessFraudDetectionWithIntelligence(ctx, request)
		if err != nil {
			b.Fatalf("Integration fraud detection failed: %v", err)
		}
	}
}
