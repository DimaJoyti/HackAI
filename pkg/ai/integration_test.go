package ai

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// TestFullWorkflow tests the complete AI framework workflow
func TestFullWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create a proper logger for testing
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(t, err)

	// Create orchestrator
	config := OrchestratorConfig{
		WorkerPoolSize:          2,
		MaxConcurrentExecutions: 5,
		DefaultTimeout:          30 * time.Second,
		EnableMetrics:           true,
		EnableTracing:           true,
	}

	orchestrator := NewOrchestrator(config, testLogger)
	require.NotNil(t, orchestrator)

	// Start orchestrator
	ctx := context.Background()
	err = orchestrator.Start(ctx)
	require.NoError(t, err)
	defer orchestrator.Stop()

	t.Run("end_to_end_chain_execution", func(t *testing.T) {
		// Create and register a test chain
		mockChain := NewMockChain("integration-chain", "Integration Chain", "Chain for integration testing")
		mockChain.On("Execute", mock.Anything, mock.Anything).Return(
			llm.ChainOutput{
				"result":    "Integration test successful",
				"processed": true,
				"timestamp": time.Now().Unix(),
			},
			nil,
		)

		err := orchestrator.RegisterChain(mockChain)
		require.NoError(t, err)

		// Execute the chain
		input := llm.ChainInput{
			"message": "Integration test message",
			"context": map[string]interface{}{
				"test_type": "integration",
				"priority":  "high",
			},
		}

		output, err := orchestrator.ExecuteChain(ctx, "integration-chain", input)
		require.NoError(t, err)
		require.NotNil(t, output)

		assert.Equal(t, "Integration test successful", output["result"])
		assert.Equal(t, true, output["processed"])
		assert.NotNil(t, output["timestamp"])

		// Verify mock expectations
		mockChain.AssertExpectations(t)
	})

	t.Run("end_to_end_agent_execution", func(t *testing.T) {
		// Create and register a test agent
		mockAgent := NewMockAgent("integration-agent", "Integration Agent", "Agent for integration testing")
		mockAgent.On("Execute", mock.Anything, mock.Anything).Return(
			AgentOutput{
				Response:   "Agent integration test completed successfully",
				Success:    true,
				Confidence: 0.95,
				Steps: []AgentStep{
					{
						StepID:    "step1",
						Action:    "analyze_input",
						Input:     map[string]interface{}{"message": "Integration test message"},
						Output:    map[string]interface{}{"analysis": "completed"},
						Success:   true,
						Duration:  50 * time.Millisecond,
						Timestamp: time.Now(),
					},
					{
						StepID:    "step2",
						Action:    "generate_response",
						Input:     map[string]interface{}{"analysis": "completed"},
						Output:    map[string]interface{}{"response": "Agent integration test completed successfully"},
						Success:   true,
						Duration:  30 * time.Millisecond,
						Timestamp: time.Now(),
					},
				},
				ToolsUsed: []string{"analyzer", "generator"},
				Duration:  80 * time.Millisecond,
				Metadata: map[string]interface{}{
					"test_type": "integration",
					"version":   "1.0",
				},
			},
			nil,
		)

		err := orchestrator.RegisterAgent(mockAgent)
		require.NoError(t, err)

		// Execute the agent
		input := AgentInput{
			Query: "Integration test query",
			Context: map[string]interface{}{
				"test_type": "integration",
				"priority":  "high",
			},
			MaxSteps: 5,
			Tools:    []string{"analyzer", "generator"},
		}

		output, err := orchestrator.ExecuteAgent(ctx, "integration-agent", input)
		require.NoError(t, err)
		require.NotNil(t, output)

		assert.Equal(t, "Agent integration test completed successfully", output.Response)
		assert.True(t, output.Success)
		assert.Equal(t, 0.95, output.Confidence)
		assert.Len(t, output.Steps, 2)
		assert.Contains(t, output.ToolsUsed, "analyzer")
		assert.Contains(t, output.ToolsUsed, "generator")

		// Verify mock expectations
		mockAgent.AssertExpectations(t)
	})

	t.Run("end_to_end_graph_execution", func(t *testing.T) {
		// Create and register a test graph
		mockGraph := NewMockGraph("integration-graph", "Integration Graph", "Graph for integration testing")
		mockGraph.On("Execute", mock.Anything, mock.Anything).Return(
			GraphState{
				"result":          "Graph integration test successful",
				"nodes_processed": 3,
				"final_state":     "completed",
			},
			nil,
		)

		err := orchestrator.RegisterGraph(mockGraph)
		require.NoError(t, err)

		// Execute the graph
		initialState := GraphState{
			"input": "Integration test input",
			"config": map[string]interface{}{
				"test_type": "integration",
				"max_depth": 5,
			},
		}

		finalState, err := orchestrator.ExecuteGraph(ctx, "integration-graph", initialState)
		require.NoError(t, err)
		require.NotNil(t, finalState)

		assert.Equal(t, "Graph integration test successful", finalState["result"])
		assert.Equal(t, 3, finalState["nodes_processed"])
		assert.Equal(t, "completed", finalState["final_state"])

		// Verify mock expectations
		mockGraph.AssertExpectations(t)
	})

	t.Run("concurrent_execution_stress_test", func(t *testing.T) {
		// Create multiple chains for concurrent testing
		chains := make([]*MockChain, 5)
		for i := 0; i < 5; i++ {
			chainID := fmt.Sprintf("stress-chain-%d", i)
			chain := NewMockChain(chainID, fmt.Sprintf("Stress Chain %d", i), "Chain for stress testing")
			chain.On("Execute", mock.Anything, mock.Anything).Return(
				llm.ChainOutput{
					"chain_id": chainID,
					"result":   fmt.Sprintf("Stress test result %d", i),
					"success":  true,
				},
				nil,
			)
			chains[i] = chain

			err := orchestrator.RegisterChain(chain)
			require.NoError(t, err)
		}

		// Execute all chains concurrently
		results := make(chan llm.ChainOutput, 5)
		errors := make(chan error, 5)

		for i := 0; i < 5; i++ {
			go func(chainIndex int) {
				chainID := fmt.Sprintf("stress-chain-%d", chainIndex)
				input := llm.ChainInput{
					"message": fmt.Sprintf("Stress test message %d", chainIndex),
					"index":   chainIndex,
				}

				output, err := orchestrator.ExecuteChain(ctx, chainID, input)
				if err != nil {
					errors <- err
					return
				}
				results <- output
			}(i)
		}

		// Collect results
		successCount := 0
		for i := 0; i < 5; i++ {
			select {
			case output := <-results:
				assert.True(t, output["success"].(bool))
				successCount++
			case err := <-errors:
				t.Errorf("Concurrent execution failed: %v", err)
			case <-time.After(10 * time.Second):
				t.Error("Timeout waiting for concurrent execution")
			}
		}

		assert.Equal(t, 5, successCount, "All concurrent executions should succeed")

		// Verify all mock expectations
		for _, chain := range chains {
			chain.AssertExpectations(t)
		}
	})

	t.Run("orchestrator_health_and_metrics", func(t *testing.T) {
		// Check orchestrator statistics
		stats := orchestrator.GetStats()
		assert.GreaterOrEqual(t, stats.TotalExecutions, int64(0))
		assert.GreaterOrEqual(t, stats.UptimeSeconds, int64(0))
	})
}

// TestToolIntegration tests the integration of tools with the framework
func TestToolIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(t, err)

	// Create orchestrator
	config := OrchestratorConfig{
		WorkerPoolSize:          2,
		MaxConcurrentExecutions: 5,
		DefaultTimeout:          30 * time.Second,
		EnableMetrics:           true,
	}

	orchestrator := NewOrchestrator(config, testLogger)
	require.NotNil(t, orchestrator)

	ctx := context.Background()
	err = orchestrator.Start(ctx)
	require.NoError(t, err)
	defer orchestrator.Stop()

	t.Run("security_tools_standalone", func(t *testing.T) {
		// Test security tools directly
		securityScanner := NewSecurityScannerTool(testLogger)
		penetrationTester := NewPenetrationTesterTool(testLogger)

		// Test security scanner
		scanInput := ToolInput{
			"target":    "localhost",
			"scan_type": "quick",
		}

		scanOutput, err := securityScanner.Execute(context.Background(), scanInput)
		require.NoError(t, err)
		require.NotNil(t, scanOutput)

		assert.Contains(t, scanOutput, "vulnerabilities")
		assert.Contains(t, scanOutput, "scan_summary")

		// Test penetration tester
		penTestInput := ToolInput{
			"target":      "localhost",
			"attack_type": "web_app",
			"intensity":   "low",
		}

		penTestOutput, err := penetrationTester.Execute(context.Background(), penTestInput)
		require.NoError(t, err)
		require.NotNil(t, penTestOutput)

		assert.Contains(t, penTestOutput, "exploits_found")
		assert.Contains(t, penTestOutput, "attack_vectors")
		assert.Contains(t, penTestOutput, "recommendations")
	})

	t.Run("tool_validation_standalone", func(t *testing.T) {
		// Test tool validation
		validator := NewSecurityToolValidator("test-validator", testLogger)

		// Create mock tools for validation
		securityScanner := NewSecurityScannerTool(testLogger)

		// Valid input
		validInput := ToolInput{
			"target":    "example.com",
			"scan_type": "quick",
		}

		err := validator.ValidateTool(context.Background(), securityScanner, validInput)
		assert.NoError(t, err)

		// Invalid input
		invalidInput := ToolInput{
			"target":    "192.168.1.1", // Private IP should be rejected
			"scan_type": "quick",
		}

		err = validator.ValidateTool(context.Background(), securityScanner, invalidInput)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private IP")
	})
}

// TestMemoryIntegration tests memory system integration
func TestMemoryIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	_, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(t, err)

	t.Run("memory_backend_integration", func(t *testing.T) {
		// Test in-memory backend
		backend := NewInMemoryBackend()
		require.NotNil(t, backend)

		// Test basic operations
		sessionID := "test-session-1"
		memory := Memory{
			SessionID: sessionID,
			UserID:    "test-user",
			Messages: []Message{
				{
					Role:      "user",
					Content:   "This is a test memory for integration testing",
					Timestamp: time.Now(),
				},
			},
			Context:   map[string]interface{}{"test": true},
			Metadata:  map[string]interface{}{"priority": "high"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Version:   1,
		}

		err := backend.Store(context.Background(), sessionID, memory)
		require.NoError(t, err)

		// Retrieve memory
		retrieved, err := backend.Retrieve(context.Background(), sessionID)
		require.NoError(t, err)
		require.NotNil(t, retrieved)

		assert.Equal(t, memory.SessionID, retrieved.SessionID)
		assert.Equal(t, memory.UserID, retrieved.UserID)
		assert.Len(t, retrieved.Messages, 1)

		// Search memories
		results, err := backend.Search(context.Background(), "integration testing", 10)
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, memory.SessionID, results[0].SessionID)

		// Test health check
		healthy := backend.IsHealthy(context.Background())
		assert.True(t, healthy)

		// Test statistics
		stats := backend.GetStats()
		assert.GreaterOrEqual(t, stats.TotalMemories, int64(1))
		assert.Greater(t, stats.AverageSize, int64(0))
	})

	// Note: Compression and encryption integration tests removed as those types are not yet implemented
}
