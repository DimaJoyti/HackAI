package ai

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// BenchmarkChainExecutionPerformance benchmarks chain execution performance
func BenchmarkChainExecutionPerformance(b *testing.B) {
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelError, // Reduce logging for benchmarks
		Format: "text",
		Output: "stdout",
	})
	require.NoError(b, err)

	config := OrchestratorConfig{
		WorkerPoolSize:          4,
		MaxConcurrentExecutions: 10,
		DefaultTimeout:          30 * time.Second,
		EnableMetrics:           false, // Disable metrics for pure performance
		EnableTracing:           false,
	}

	orchestrator := NewOrchestrator(config, testLogger)
	require.NotNil(b, orchestrator)

	ctx := context.Background()
	err = orchestrator.Start(ctx)
	require.NoError(b, err)
	defer orchestrator.Stop()

	// Create a fast mock chain
	mockChain := NewMockChain("benchmark-chain", "Benchmark Chain", "Chain for benchmarking")
	mockChain.On("Execute", mock.Anything, mock.Anything).Return(
		llm.ChainOutput{
			"result": "benchmark result",
			"status": "success",
		},
		nil,
	)

	err = orchestrator.RegisterChain(mockChain)
	require.NoError(b, err)

	input := llm.ChainInput{
		"message": "benchmark message",
		"data":    "test data",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := orchestrator.ExecuteChain(ctx, "benchmark-chain", input)
			if err != nil {
				b.Errorf("Chain execution failed: %v", err)
			}
		}
	})
}

// BenchmarkAgentExecution benchmarks agent execution performance
func BenchmarkAgentExecution(b *testing.B) {
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelError,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(b, err)

	config := OrchestratorConfig{
		WorkerPoolSize:          4,
		MaxConcurrentExecutions: 10,
		DefaultTimeout:          30 * time.Second,
		EnableMetrics:           false,
		EnableTracing:           false,
	}

	orchestrator := NewOrchestrator(config, testLogger)
	require.NotNil(b, orchestrator)

	ctx := context.Background()
	err = orchestrator.Start(ctx)
	require.NoError(b, err)
	defer orchestrator.Stop()

	// Create a fast mock agent
	mockAgent := NewMockAgent("benchmark-agent", "Benchmark Agent", "Agent for benchmarking")
	mockAgent.On("Execute", mock.Anything, mock.Anything).Return(
		AgentOutput{
			Response:   "Benchmark response",
			Success:    true,
			Confidence: 0.9,
			Steps: []AgentStep{
				{
					StepID:    "step1",
					Action:    "process",
					Success:   true,
					Duration:  1 * time.Microsecond,
					Timestamp: time.Now(),
				},
			},
			ToolsUsed: []string{"benchmark_tool"},
			Duration:  10 * time.Microsecond,
		},
		nil,
	)

	err = orchestrator.RegisterAgent(mockAgent)
	require.NoError(b, err)

	input := AgentInput{
		Query:    "benchmark query",
		MaxSteps: 3,
		Tools:    []string{"benchmark_tool"},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := orchestrator.ExecuteAgent(ctx, "benchmark-agent", input)
			if err != nil {
				b.Errorf("Agent execution failed: %v", err)
			}
		}
	})
}

// BenchmarkGraphExecution benchmarks graph execution performance
func BenchmarkGraphExecution(b *testing.B) {
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelError,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(b, err)

	config := OrchestratorConfig{
		WorkerPoolSize:          4,
		MaxConcurrentExecutions: 10,
		DefaultTimeout:          30 * time.Second,
		EnableMetrics:           false,
		EnableTracing:           false,
	}

	orchestrator := NewOrchestrator(config, testLogger)
	require.NotNil(b, orchestrator)

	ctx := context.Background()
	err = orchestrator.Start(ctx)
	require.NoError(b, err)
	defer orchestrator.Stop()

	// Create a fast mock graph
	mockGraph := NewMockGraph("benchmark-graph", "Benchmark Graph", "Graph for benchmarking")
	mockGraph.On("Execute", mock.Anything, mock.Anything).Return(
		GraphState{
			"result": "benchmark result",
			"status": "completed",
		},
		nil,
	)

	err = orchestrator.RegisterGraph(mockGraph)
	require.NoError(b, err)

	initialState := GraphState{
		"input": "benchmark input",
		"data":  "test data",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := orchestrator.ExecuteGraph(ctx, "benchmark-graph", initialState)
			if err != nil {
				b.Errorf("Graph execution failed: %v", err)
			}
		}
	})
}

// BenchmarkMemoryOperations benchmarks memory system performance
func BenchmarkMemoryOperations(b *testing.B) {
	backend := NewInMemoryBackend()
	ctx := context.Background()

	b.Run("Store", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				sessionID := fmt.Sprintf("benchmark-session-%d", i)
				memory := Memory{
					SessionID: sessionID,
					UserID:    "benchmark-user",
					Messages: []Message{
						{
							Role:      "user",
							Content:   fmt.Sprintf("Benchmark message %d", i),
							Timestamp: time.Now(),
						},
					},
					Context:   map[string]interface{}{"benchmark": true},
					Metadata:  map[string]interface{}{"test": i},
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
					Version:   1,
				}
				err := backend.Store(ctx, sessionID, memory)
				if err != nil {
					b.Errorf("Memory store failed: %v", err)
				}
				i++
			}
		})
	})

	// Store some memories for retrieval benchmarks
	for i := 0; i < 1000; i++ {
		sessionID := fmt.Sprintf("retrieve-benchmark-%d", i)
		memory := Memory{
			SessionID: sessionID,
			UserID:    "benchmark-user",
			Messages: []Message{
				{
					Role:      "user",
					Content:   fmt.Sprintf("Retrieve benchmark content %d", i),
					Timestamp: time.Now(),
				},
			},
			Context:   map[string]interface{}{"benchmark": true},
			Metadata:  map[string]interface{}{"test": i},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Version:   1,
		}
		backend.Store(ctx, sessionID, memory)
	}

	b.Run("Retrieve", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				id := fmt.Sprintf("retrieve-benchmark-%d", i%1000)
				_, err := backend.Retrieve(ctx, id)
				if err != nil {
					b.Errorf("Memory retrieve failed: %v", err)
				}
				i++
			}
		})
	})

	b.Run("Search", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := backend.Search(ctx, "benchmark", 10)
				if err != nil {
					b.Errorf("Memory search failed: %v", err)
				}
			}
		})
	})
}

// Note: Compression and encryption benchmarks removed as those types are not yet implemented

// BenchmarkDecisionEngine benchmarks ML decision engine performance
func BenchmarkDecisionEngine(b *testing.B) {
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelError,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(b, err)

	engine := NewMLDecisionEngine("benchmark-engine", testLogger)
	ctx := context.Background()

	input := AgentInput{
		Query:    "Benchmark decision making query with various keywords for analysis",
		Context:  map[string]interface{}{"priority": "high", "type": "benchmark"},
		MaxSteps: 5,
		Tools:    []string{"tool1", "tool2", "tool3"},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := engine.DecideNextAction(ctx, input, []AgentStep{})
			if err != nil {
				b.Errorf("Decision making failed: %v", err)
			}
		}
	})
}

// BenchmarkConcurrentExecution benchmarks concurrent execution performance
func BenchmarkConcurrentExecution(b *testing.B) {
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelError,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(b, err)

	config := OrchestratorConfig{
		WorkerPoolSize:          8,
		MaxConcurrentExecutions: 20,
		DefaultTimeout:          30 * time.Second,
		EnableMetrics:           false,
		EnableTracing:           false,
	}

	orchestrator := NewOrchestrator(config, testLogger)
	require.NotNil(b, orchestrator)

	ctx := context.Background()
	err = orchestrator.Start(ctx)
	require.NoError(b, err)
	defer orchestrator.Stop()

	// Register multiple chains
	for i := 0; i < 10; i++ {
		chainID := fmt.Sprintf("concurrent-chain-%d", i)
		mockChain := NewMockChain(chainID, fmt.Sprintf("Concurrent Chain %d", i), "Chain for concurrent benchmarking")
		mockChain.On("Execute", mock.Anything, mock.Anything).Return(
			llm.ChainOutput{
				"result":   fmt.Sprintf("concurrent result %d", i),
				"chain_id": chainID,
			},
			nil,
		)
		err = orchestrator.RegisterChain(mockChain)
		require.NoError(b, err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			chainID := fmt.Sprintf("concurrent-chain-%d", i%10)
			input := llm.ChainInput{
				"message": fmt.Sprintf("concurrent message %d", i),
				"index":   i,
			}
			_, err := orchestrator.ExecuteChain(ctx, chainID, input)
			if err != nil {
				b.Errorf("Concurrent execution failed: %v", err)
			}
			i++
		}
	})
}

// BenchmarkPriorityExecution benchmarks priority-based execution
func BenchmarkPriorityExecution(b *testing.B) {
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelError,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(b, err)

	config := OrchestratorConfig{
		WorkerPoolSize:          4,
		MaxConcurrentExecutions: 10,
		DefaultTimeout:          30 * time.Second,
		EnableMetrics:           false,
		EnableTracing:           false,
	}

	orchestrator := NewOrchestrator(config, testLogger)
	require.NotNil(b, orchestrator)

	ctx := context.Background()
	err = orchestrator.Start(ctx)
	require.NoError(b, err)
	defer orchestrator.Stop()

	// Create a mock chain for priority testing
	mockChain := NewMockChain("priority-chain", "Priority Chain", "Chain for priority benchmarking")
	mockChain.On("Execute", mock.Anything, mock.Anything).Return(
		llm.ChainOutput{
			"result": "priority result",
			"status": "success",
		},
		nil,
	)

	err = orchestrator.RegisterChain(mockChain)
	require.NoError(b, err)

	priorities := []OrchestratorExecutionPriority{
		OrchestratorPriorityLow,
		OrchestratorPriorityNormal,
		OrchestratorPriorityHigh,
		OrchestratorPriorityCritical,
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			priority := priorities[i%len(priorities)]
			input := llm.ChainInput{
				"message":  fmt.Sprintf("priority message %d", i),
				"priority": int(priority),
			}
			_, err := orchestrator.ExecuteChainWithPriority(ctx, "priority-chain", input, priority)
			if err != nil {
				b.Errorf("Priority execution failed: %v", err)
			}
			i++
		}
	})
}
