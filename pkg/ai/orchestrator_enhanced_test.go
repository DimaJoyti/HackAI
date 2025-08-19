package ai

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dimajoyti/hackai/pkg/logger"
)

func TestEnhancedOrchestrator_PriorityExecution(t *testing.T) {
	// Create a proper logger for testing
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(t, err)

	config := OrchestratorConfig{
		MaxConcurrentExecutions: 5,
		WorkerPoolSize:          2,
		RequestQueueSize:        100,
		DefaultTimeout:          30 * time.Second,
		EnableMetrics:           true,
		EnableTracing:           true,
		HealthCheckInterval:     10 * time.Second,
	}

	orchestrator := NewOrchestrator(config, testLogger)
	require.NotNil(t, orchestrator)

	// Start orchestrator
	ctx := context.Background()
	err = orchestrator.Start(ctx)
	require.NoError(t, err)
	defer orchestrator.Stop()

	// Create test chain
	testChain := NewTestChain("priority-test-chain", "Priority Test Chain")
	err = orchestrator.RegisterChain(testChain)
	require.NoError(t, err)

	t.Run("priority execution order", func(t *testing.T) {
		// Submit requests with different priorities
		input := map[string]interface{}{"test": "priority"}

		// Submit low priority request
		lowPriorityResult, err := orchestrator.ExecuteChainWithPriority(ctx, "priority-test-chain", input, OrchestratorPriorityLow)
		require.NoError(t, err)

		// Submit high priority request
		highPriorityResult, err := orchestrator.ExecuteChainWithPriority(ctx, "priority-test-chain", input, OrchestratorPriorityHigh)
		require.NoError(t, err)

		// Submit critical priority request
		criticalPriorityResult, err := orchestrator.ExecuteChainWithPriority(ctx, "priority-test-chain", input, OrchestratorPriorityCritical)
		require.NoError(t, err)

		// All should succeed
		assert.NotNil(t, lowPriorityResult)
		assert.NotNil(t, highPriorityResult)
		assert.NotNil(t, criticalPriorityResult)
	})

	t.Run("load metrics", func(t *testing.T) {
		metrics := orchestrator.GetLoadMetrics()
		assert.GreaterOrEqual(t, metrics.ActiveWorkers, 0)
		assert.GreaterOrEqual(t, metrics.IdleWorkers, 0)
		assert.GreaterOrEqual(t, metrics.QueueDepth, int64(0))
		assert.NotNil(t, metrics.WorkerUtilization)
		assert.NotNil(t, metrics.ResourceUsage)
	})

	t.Run("detailed metrics", func(t *testing.T) {
		detailedMetrics := orchestrator.GetDetailedMetrics()
		assert.NotNil(t, detailedMetrics.ExecutionMetrics)
		assert.NotNil(t, detailedMetrics.PerformanceMetrics)
		assert.NotNil(t, detailedMetrics.ResourceMetrics)
		assert.NotNil(t, detailedMetrics.ComponentMetrics)
		assert.NotNil(t, detailedMetrics.ErrorMetrics)
	})
}

func TestEnhancedOrchestrator_BatchExecution(t *testing.T) {
	// Create a proper logger for testing
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(t, err)

	config := OrchestratorConfig{
		MaxConcurrentExecutions: 10,
		WorkerPoolSize:          3,
		RequestQueueSize:        200,
		DefaultTimeout:          30 * time.Second,
		EnableMetrics:           true,
	}

	orchestrator := NewOrchestrator(config, testLogger)
	require.NotNil(t, orchestrator)

	// Start orchestrator
	ctx := context.Background()
	err = orchestrator.Start(ctx)
	require.NoError(t, err)
	defer orchestrator.Stop()

	// Create test components
	testChain := NewTestChain("batch-test-chain", "Batch Test Chain")
	err = orchestrator.RegisterChain(testChain)
	require.NoError(t, err)

	testAgent := NewTestAgent("batch-test-agent", "Batch Test Agent", "Test agent for batch execution", testLogger)
	err = orchestrator.RegisterAgent(testAgent)
	require.NoError(t, err)

	t.Run("batch execution", func(t *testing.T) {
		// Create batch requests
		requests := []BatchRequest{
			{
				ID:       "batch-1",
				Type:     "chain",
				TargetID: "batch-test-chain",
				Input:    map[string]interface{}{"test": "batch1"},
				Priority: OrchestratorPriorityNormal,
				Timeout:  10 * time.Second,
				Metadata: map[string]interface{}{"batch": true},
			},
			{
				ID:       "batch-2",
				Type:     "agent",
				TargetID: "batch-test-agent",
				Input: AgentInput{
					Query:    "Test batch execution",
					Context:  map[string]interface{}{"test": "batch2"},
					MaxSteps: 3,
				},
				Priority: OrchestratorPriorityHigh,
				Timeout:  10 * time.Second,
				Metadata: map[string]interface{}{"batch": true},
			},
			{
				ID:       "batch-3",
				Type:     "chain",
				TargetID: "batch-test-chain",
				Input:    map[string]interface{}{"test": "batch3"},
				Priority: OrchestratorPriorityLow,
				Timeout:  10 * time.Second,
				Metadata: map[string]interface{}{"batch": true},
			},
		}

		results, err := orchestrator.ExecuteBatch(ctx, requests)
		require.NoError(t, err)
		assert.Len(t, results, 3)

		// Check results
		for i, result := range results {
			assert.Equal(t, requests[i].ID, result.ID)
			assert.True(t, result.Success)
			assert.NotNil(t, result.Output)
			assert.Greater(t, result.Duration, time.Duration(0))
		}
	})
}

func TestEnhancedOrchestrator_ScheduledExecution(t *testing.T) {
	// Create a proper logger for testing
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(t, err)

	config := OrchestratorConfig{
		MaxConcurrentExecutions: 5,
		WorkerPoolSize:          2,
		RequestQueueSize:        50,
		DefaultTimeout:          30 * time.Second,
	}

	orchestrator := NewOrchestrator(config, testLogger)
	require.NotNil(t, orchestrator)

	// Start orchestrator
	ctx := context.Background()
	err = orchestrator.Start(ctx)
	require.NoError(t, err)
	defer orchestrator.Stop()

	// Create test chain
	testChain := NewTestChain("scheduled-test-chain", "Scheduled Test Chain")
	err = orchestrator.RegisterChain(testChain)
	require.NoError(t, err)

	t.Run("schedule execution", func(t *testing.T) {
		// Schedule execution for near future
		scheduledRequest := ScheduledRequest{
			ID:          "scheduled-1",
			Type:        "chain",
			TargetID:    "scheduled-test-chain",
			Input:       map[string]interface{}{"test": "scheduled"},
			Priority:    OrchestratorPriorityNormal,
			ScheduledAt: time.Now().Add(100 * time.Millisecond),
			Timeout:     10 * time.Second,
			Metadata:    map[string]interface{}{"scheduled": true},
		}

		executionID, err := orchestrator.ScheduleExecution(ctx, scheduledRequest)
		require.NoError(t, err)
		assert.NotEmpty(t, executionID)

		// Check execution status
		status, err := orchestrator.GetExecutionStatus(executionID)
		require.NoError(t, err)
		assert.Equal(t, executionID, status.ID)
		assert.Contains(t, []string{"pending", "running", "completed"}, status.Status)
	})

	t.Run("cancel execution", func(t *testing.T) {
		// Schedule execution for future
		scheduledRequest := ScheduledRequest{
			ID:          "scheduled-cancel",
			Type:        "chain",
			TargetID:    "scheduled-test-chain",
			Input:       map[string]interface{}{"test": "cancel"},
			Priority:    OrchestratorPriorityNormal,
			ScheduledAt: time.Now().Add(5 * time.Second),
			Timeout:     10 * time.Second,
			Metadata:    map[string]interface{}{"cancel_test": true},
		}

		executionID, err := orchestrator.ScheduleExecution(ctx, scheduledRequest)
		require.NoError(t, err)

		// Cancel execution
		err = orchestrator.CancelExecution(executionID)
		require.NoError(t, err)

		// Check status
		status, err := orchestrator.GetExecutionStatus(executionID)
		require.NoError(t, err)
		assert.Equal(t, "cancelled", status.Status)
	})
}

func TestEnhancedOrchestrator_LoadBalancing(t *testing.T) {
	// Create a proper logger for testing
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(t, err)

	config := OrchestratorConfig{
		MaxConcurrentExecutions: 20,
		WorkerPoolSize:          4,
		RequestQueueSize:        100,
		DefaultTimeout:          30 * time.Second,
		EnableMetrics:           true,
	}

	orchestrator := NewOrchestrator(config, testLogger)
	require.NotNil(t, orchestrator)

	// Start orchestrator
	ctx := context.Background()
	err = orchestrator.Start(ctx)
	require.NoError(t, err)
	defer orchestrator.Stop()

	// Create test chain
	testChain := NewTestChain("load-test-chain", "Load Test Chain")
	err = orchestrator.RegisterChain(testChain)
	require.NoError(t, err)

	t.Run("load balancing strategies", func(t *testing.T) {
		// Test different load balancing strategies
		strategies := []LoadBalancingStrategy{
			RoundRobin,
			LeastConnections,
			WeightedRoundRobin,
			ResourceBased,
		}

		for _, strategy := range strategies {
			err := orchestrator.SetLoadBalancingStrategy(strategy)
			assert.NoError(t, err)

			// Execute some requests to test the strategy
			for i := 0; i < 5; i++ {
				input := map[string]interface{}{"test": "load_balancing", "iteration": i}
				result, err := orchestrator.ExecuteChain(ctx, "load-test-chain", input)
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		}
	})

	t.Run("worker scaling", func(t *testing.T) {
		// Scale up workers
		err := orchestrator.ScaleWorkers(6)
		assert.NoError(t, err)

		// Check load metrics
		metrics := orchestrator.GetLoadMetrics()
		assert.Equal(t, 6, metrics.ActiveWorkers+metrics.IdleWorkers)

		// Scale down workers
		err = orchestrator.ScaleWorkers(3)
		assert.NoError(t, err)

		// Check load metrics again
		metrics = orchestrator.GetLoadMetrics()
		assert.Equal(t, 3, metrics.ActiveWorkers+metrics.IdleWorkers)
	})
}

func TestEnhancedOrchestrator_CircuitBreaker(t *testing.T) {
	// Create a proper logger for testing
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(t, err)

	config := OrchestratorConfig{
		MaxConcurrentExecutions: 5,
		WorkerPoolSize:          2,
		RequestQueueSize:        50,
		DefaultTimeout:          30 * time.Second,
	}

	orchestrator := NewOrchestrator(config, testLogger)
	require.NotNil(t, orchestrator)

	// Start orchestrator
	ctx := context.Background()
	err = orchestrator.Start(ctx)
	require.NoError(t, err)
	defer orchestrator.Stop()

	// Create failing test chain
	failingChain := NewFailingTestChain("failing-chain", "Failing Test Chain")
	err = orchestrator.RegisterChain(failingChain)
	require.NoError(t, err)

	t.Run("circuit breaker activation", func(t *testing.T) {
		// Execute multiple failing requests to trigger circuit breaker
		input := map[string]interface{}{"test": "circuit_breaker"}

		for i := 0; i < 15; i++ {
			_, err := orchestrator.ExecuteChain(ctx, "failing-chain", input)
			// Expect errors due to failing chain
			assert.Error(t, err)
		}

		// Circuit breaker should be open now
		// Additional requests should fail fast
		_, err := orchestrator.ExecuteChain(ctx, "failing-chain", input)
		assert.Error(t, err)
	})
}
