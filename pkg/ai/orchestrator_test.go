package ai

import (
	"context"
	"testing"
	"time"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestOrchestratorBasicOperations(t *testing.T) {
	// Create test suite
	ts := NewTestSuite(t)
	require.NoError(t, ts.Setup())
	defer ts.Teardown()

	t.Run("RegisterAndListChains", func(t *testing.T) {
		// Register a mock chain
		mockChain := ts.RegisterMockChain("test-chain", "Test Chain", "A test chain")

		// List chains
		chains := ts.orchestrator.ListChains()
		assert.Len(t, chains, 1)
		assert.Equal(t, "test-chain", chains[0].ID)
		assert.Equal(t, "Test Chain", chains[0].Name)

		// Verify mock expectations
		mockChain.AssertExpectations(t)
	})

	t.Run("RegisterAndListTools", func(t *testing.T) {
		// Register a mock tool
		mockTool := ts.RegisterMockTool("test-tool", "A test tool")

		// List tools
		tools := ts.orchestrator.ListTools()
		assert.Contains(t, tools, "test-tool")

		// Get tool
		tool, err := ts.orchestrator.GetTool("test-tool")
		assert.NoError(t, err)
		assert.Equal(t, "test-tool", tool.Name())

		// Verify mock expectations
		mockTool.AssertExpectations(t)
	})

	t.Run("RegisterAndListGraphs", func(t *testing.T) {
		// Register a mock graph
		mockGraph := ts.RegisterMockGraph("test-graph", "Test Graph", "A test graph")

		// List graphs
		graphs := ts.orchestrator.ListGraphs()
		assert.Len(t, graphs, 1)
		assert.Equal(t, "test-graph", graphs[0].ID)
		assert.Equal(t, "Test Graph", graphs[0].Name)

		// Verify mock expectations
		mockGraph.AssertExpectations(t)
	})

	t.Run("RegisterAndListAgents", func(t *testing.T) {
		// Register a mock agent
		mockAgent := ts.RegisterMockAgent("test-agent", "Test Agent", "A test agent")

		// List agents
		agents := ts.orchestrator.ListAgents()
		assert.Len(t, agents, 1)
		assert.Equal(t, "test-agent", agents[0].ID)
		assert.Equal(t, "Test Agent", agents[0].Name)

		// Verify mock expectations
		mockAgent.AssertExpectations(t)
	})
}

func TestChainExecution(t *testing.T) {
	ts := NewTestSuite(t)
	require.NoError(t, ts.Setup())
	defer ts.Teardown()

	// Register a test chain first
	ts.RegisterMockChain("test-chain", "Test Chain", "A test chain")

	testCases := []ChainTestCase{
		{
			Name: "SuccessfulExecution",
			Input: map[string]interface{}{
				"message": "test message",
			},
			ExpectedOutput: map[string]interface{}{
				"result": "processed: test message",
			},
			ExpectError: false,
			Timeout:     30 * time.Second,
			SetupMocks: func(mockChain *MockChain) {
				mockChain.On("Execute", mock.Anything, llm.ChainInput{
					"message": "test message",
				}).Return(llm.ChainOutput{
					"result": "processed: test message",
				}, nil)
			},
		},
		{
			Name: "ExecutionWithError",
			Input: map[string]interface{}{
				"invalid": "input",
			},
			ExpectError:      true,
			ExpectedErrorMsg: "invalid input",
			Timeout:          30 * time.Second,
			SetupMocks: func(mockChain *MockChain) {
				mockChain.On("Execute", mock.Anything, llm.ChainInput{
					"invalid": "input",
				}).Return(llm.ChainOutput{}, assert.AnError)
			},
		},
	}

	ts.TestChainExecution("test-chain", testCases)
}

func TestGraphExecution(t *testing.T) {
	ts := NewTestSuite(t)
	require.NoError(t, ts.Setup())
	defer ts.Teardown()

	// Register a mock graph
	mockGraph := ts.RegisterMockGraph("test-graph", "Test Graph", "A test graph")

	// Setup mock expectations
	mockGraph.On("Execute", mock.Anything, GraphState{
		"input": "test input",
	}).Return(GraphState{
		"output": "processed output",
		"step":   "complete",
	}, nil)

	// Execute graph
	ctx := context.Background()
	initialState := GraphState{
		"input": "test input",
	}

	finalState, err := ts.orchestrator.ExecuteGraph(ctx, "test-graph", initialState)
	assert.NoError(t, err)
	assert.Equal(t, "processed output", finalState["output"])
	assert.Equal(t, "complete", finalState["step"])

	// Verify mock expectations
	mockGraph.AssertExpectations(t)
}

func TestAgentExecution(t *testing.T) {
	ts := NewTestSuite(t)
	require.NoError(t, ts.Setup())
	defer ts.Teardown()

	// Register a mock agent
	mockAgent := ts.RegisterMockAgent("test-agent", "Test Agent", "A test agent")

	// Setup mock expectations
	expectedInput := AgentInput{
		Query:    "test query",
		MaxSteps: 5,
	}

	expectedOutput := AgentOutput{
		Response:   "test response",
		Success:    true,
		Confidence: 0.9,
		Steps: []AgentStep{
			{
				StepID:    "step_1",
				Action:    "respond",
				Success:   true,
				Reasoning: "Generated response",
			},
		},
	}

	mockAgent.On("Execute", mock.Anything, expectedInput).Return(expectedOutput, nil)

	// Execute agent
	ctx := context.Background()
	output, err := ts.orchestrator.ExecuteAgent(ctx, "test-agent", expectedInput)
	assert.NoError(t, err)
	assert.Equal(t, "test response", output.Response)
	assert.True(t, output.Success)
	assert.Equal(t, 0.9, output.Confidence)

	// Verify mock expectations
	mockAgent.AssertExpectations(t)
}

func TestAsyncExecution(t *testing.T) {
	ts := NewTestSuite(t)
	require.NoError(t, ts.Setup())
	defer ts.Teardown()

	// Register a mock chain
	mockChain := ts.RegisterMockChain("async-chain", "Async Chain", "An async test chain")

	// Setup mock expectations
	mockChain.On("Execute", mock.Anything, llm.ChainInput{
		"message": "async test",
	}).Return(llm.ChainOutput{
		"result": "async result",
	}, nil)

	// Execute chain asynchronously
	ctx := context.Background()
	input := map[string]interface{}{
		"message": "async test",
	}

	resultChan, err := ts.orchestrator.ExecuteChainAsync(ctx, "async-chain", input)
	assert.NoError(t, err)

	// Wait for result
	select {
	case result := <-resultChan:
		assert.NoError(t, result.Error)
		// Handle both map and ChainOutput types
		switch output := result.Output.(type) {
		case map[string]interface{}:
			assert.Equal(t, "async result", output["result"])
		case llm.ChainOutput:
			assert.Equal(t, "async result", output["result"])
		default:
			t.Fatalf("Unexpected result type: %T", result.Output)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Async execution timed out")
	}

	// Verify mock expectations
	mockChain.AssertExpectations(t)
}

func TestOrchestratorHealth(t *testing.T) {
	ts := NewTestSuite(t)
	require.NoError(t, ts.Setup())
	defer ts.Teardown()

	// Check health
	ts.AssertOrchestratorHealth()

	// Check stats
	stats := ts.orchestrator.GetStats()
	assert.GreaterOrEqual(t, stats.UptimeSeconds, int64(0))
	assert.Equal(t, int64(0), stats.TotalExecutions) // No executions yet
}

func TestConcurrentExecution(t *testing.T) {
	ts := NewTestSuite(t)
	require.NoError(t, ts.Setup())
	defer ts.Teardown()

	// Register a mock chain
	mockChain := ts.RegisterMockChain("concurrent-chain", "Concurrent Chain", "A concurrent test chain")

	// Setup mock expectations for multiple calls
	for i := 0; i < 10; i++ {
		mockChain.On("Execute", mock.Anything, llm.ChainInput{
			"id": i,
		}).Return(llm.ChainOutput{
			"result": i * 2,
		}, nil)
	}

	// Execute multiple chains concurrently
	ctx := context.Background()
	results := make(chan map[string]interface{}, 10)
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			input := map[string]interface{}{
				"id": id,
			}
			output, err := ts.orchestrator.ExecuteChain(ctx, "concurrent-chain", input)
			if err != nil {
				errors <- err
			} else {
				results <- output
			}
		}(i)
	}

	// Collect results
	successCount := 0
	errorCount := 0

	for i := 0; i < 10; i++ {
		select {
		case <-results:
			successCount++
		case <-errors:
			errorCount++
		case <-time.After(30 * time.Second):
			t.Fatal("Concurrent execution timed out")
		}
	}

	assert.Equal(t, 10, successCount)
	assert.Equal(t, 0, errorCount)

	// Verify mock expectations
	mockChain.AssertExpectations(t)
}

func BenchmarkChainExecution(b *testing.B) {
	ts := NewTestSuite(&testing.T{})
	ts.Setup()
	defer ts.Teardown()

	// Register a mock chain
	mockChain := ts.RegisterMockChain("bench-chain", "Benchmark Chain", "A benchmark test chain")

	input := map[string]interface{}{
		"message": "benchmark test",
	}

	// Setup mock expectations
	mockChain.On("Execute", mock.Anything, llm.ChainInput(input)).Return(
		llm.ChainOutput{"result": "benchmark result"}, nil)

	ts.BenchmarkChainExecution(b, "bench-chain", input)
}

func TestErrorHandling(t *testing.T) {
	ts := NewTestSuite(t)
	require.NoError(t, ts.Setup())
	defer ts.Teardown()

	t.Run("NonExistentChain", func(t *testing.T) {
		ctx := context.Background()
		input := map[string]interface{}{"test": "input"}

		_, err := ts.orchestrator.ExecuteChain(ctx, "non-existent", input)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("NonExistentGraph", func(t *testing.T) {
		ctx := context.Background()
		state := GraphState{"test": "state"}

		_, err := ts.orchestrator.ExecuteGraph(ctx, "non-existent", state)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("NonExistentAgent", func(t *testing.T) {
		ctx := context.Background()
		input := AgentInput{Query: "test", MaxSteps: 1}

		_, err := ts.orchestrator.ExecuteAgent(ctx, "non-existent", input)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("NonExistentTool", func(t *testing.T) {
		_, err := ts.orchestrator.GetTool("non-existent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}
