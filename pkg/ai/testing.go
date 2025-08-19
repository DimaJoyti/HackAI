package ai

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// TestSuite provides comprehensive testing utilities for AI components
type TestSuite struct {
	orchestrator *DefaultOrchestrator
	mockTools    map[string]*MockTool
	mockChains   map[string]*MockChain
	mockGraphs   map[string]*MockGraph
	mockAgents   map[string]*MockAgent
	testMemory   *MockMemoryManager
	logger       *logger.Logger
	t            *testing.T
}

// NewTestSuite creates a new test suite
func NewTestSuite(t *testing.T) *TestSuite {
	// Create a proper logger for testing
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelDebug,
		Format: "text",
		Output: "stdout",
	})
	if err != nil {
		panic(err)
	}

	config := OrchestratorConfig{
		MaxConcurrentExecutions: 10,
		WorkerPoolSize:          2,
		RequestQueueSize:        100,
		DefaultTimeout:          30 * time.Second,
		EnableMetrics:           true,
		EnableTracing:           false, // Disable tracing in tests
		HealthCheckInterval:     10 * time.Second,
	}

	orchestrator := NewOrchestrator(config, testLogger)

	return &TestSuite{
		orchestrator: orchestrator,
		mockTools:    make(map[string]*MockTool),
		mockChains:   make(map[string]*MockChain),
		mockGraphs:   make(map[string]*MockGraph),
		mockAgents:   make(map[string]*MockAgent),
		testMemory:   NewMockMemoryManager(),
		logger:       testLogger,
		t:            t,
	}
}

// Setup initializes the test suite
func (ts *TestSuite) Setup() error {
	ctx := context.Background()
	return ts.orchestrator.Start(ctx)
}

// Teardown cleans up the test suite
func (ts *TestSuite) Teardown() error {
	return ts.orchestrator.Stop()
}

// Mock implementations

// MockTool implements Tool interface for testing
type MockTool struct {
	mock.Mock
	name        string
	description string
	schema      ToolSchema
	healthy     bool
}

func NewMockTool(name, description string) *MockTool {
	mockTool := &MockTool{
		name:        name,
		description: description,
		healthy:     true,
		schema: ToolSchema{
			Name:         name,
			Description:  description,
			InputSchema:  make(map[string]ParameterSchema),
			OutputSchema: make(map[string]ParameterSchema),
		},
	}

	// Set up default mock expectations
	mockTool.On("Validate", mock.Anything).Return(nil).Maybe()
	mockTool.On("GetMetrics").Return(ToolMetrics{}).Maybe()

	return mockTool
}

func (m *MockTool) Name() string          { return m.name }
func (m *MockTool) Description() string   { return m.description }
func (m *MockTool) GetSchema() ToolSchema { return m.schema }

func (m *MockTool) Execute(ctx context.Context, input ToolInput) (ToolOutput, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(ToolOutput), args.Error(1)
}

func (m *MockTool) Validate(input ToolInput) error {
	args := m.Called(input)
	return args.Error(0)
}

func (m *MockTool) GetMetrics() ToolMetrics {
	args := m.Called()
	return args.Get(0).(ToolMetrics)
}

func (m *MockTool) IsHealthy(ctx context.Context) bool {
	return m.healthy
}

func (m *MockTool) SetHealthy(healthy bool) {
	m.healthy = healthy
}

// MockChain implements Chain interface for testing
type MockChain struct {
	mock.Mock
	id          string
	name        string
	description string
	config      ChainConfig
}

func NewMockChain(id, name, description string) *MockChain {
	mockChain := &MockChain{
		id:          id,
		name:        name,
		description: description,
		config: ChainConfig{
			ID:          id,
			Name:        name,
			Description: description,
			Type:        ChainTypeSequential,
			Enabled:     true,
			MaxRetries:  3,
			Timeout:     30 * time.Second,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	// Set up default mock expectations
	mockChain.On("Validate").Return(nil)
	mockChain.On("GetMetrics").Return(ChainMetrics{}).Maybe()
	mockChain.On("Clone").Return(mockChain).Maybe()
	mockChain.On("GetMemory").Return(nil).Maybe()
	mockChain.On("SetMemory", mock.Anything).Maybe()

	return mockChain
}

func (m *MockChain) ID() string          { return m.id }
func (m *MockChain) Name() string        { return m.name }
func (m *MockChain) Description() string { return m.description }

func (m *MockChain) Execute(ctx context.Context, input llm.ChainInput) (llm.ChainOutput, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(llm.ChainOutput), args.Error(1)
}

func (m *MockChain) GetMemory() llm.Memory {
	args := m.Called()
	return args.Get(0).(llm.Memory)
}

func (m *MockChain) SetMemory(memory llm.Memory) {
	m.Called(memory)
}

func (m *MockChain) GetConfig() ChainConfig {
	return m.config
}

func (m *MockChain) SetConfig(config ChainConfig) error {
	m.config = config
	return nil
}

func (m *MockChain) GetMetrics() ChainMetrics {
	args := m.Called()
	return args.Get(0).(ChainMetrics)
}

func (m *MockChain) Validate() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockChain) Clone() Chain {
	args := m.Called()
	return args.Get(0).(Chain)
}

// MockGraph implements Graph interface for testing
type MockGraph struct {
	mock.Mock
	id          string
	name        string
	description string
	nodes       map[string]GraphNode
	edges       map[string][]string
}

func NewMockGraph(id, name, description string) *MockGraph {
	mockGraph := &MockGraph{
		id:          id,
		name:        name,
		description: description,
		nodes:       make(map[string]GraphNode),
		edges:       make(map[string][]string),
	}

	// Set up default mock expectations (excluding Execute to allow custom setup)
	mockGraph.On("Validate").Return(nil)
	mockGraph.On("GetMetrics").Return(GraphMetrics{}).Maybe()
	mockGraph.On("Clone").Return(mockGraph).Maybe()
	mockGraph.On("AddNode", mock.Anything).Return(nil).Maybe()
	mockGraph.On("AddEdge", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockGraph.On("SetEntryPoint", mock.Anything).Return(nil).Maybe()
	// Note: Execute expectation should be set up in individual tests

	return mockGraph
}

func (m *MockGraph) ID() string          { return m.id }
func (m *MockGraph) Name() string        { return m.name }
func (m *MockGraph) Description() string { return m.description }

func (m *MockGraph) Execute(ctx context.Context, initialState GraphState) (GraphState, error) {
	args := m.Called(ctx, initialState)
	return args.Get(0).(GraphState), args.Error(1)
}

func (m *MockGraph) AddNode(node GraphNode) error {
	args := m.Called(node)
	if args.Error(0) == nil {
		m.nodes[node.ID()] = node
	}
	return args.Error(0)
}

func (m *MockGraph) AddEdge(from, to string) error {
	args := m.Called(from, to)
	if args.Error(0) == nil {
		m.edges[from] = append(m.edges[from], to)
	}
	return args.Error(0)
}

func (m *MockGraph) AddConditionalEdge(from string, condition EdgeCondition, edges map[string]string) error {
	args := m.Called(from, condition, edges)
	return args.Error(0)
}

func (m *MockGraph) SetEntryPoint(nodeID string) error {
	args := m.Called(nodeID)
	return args.Error(0)
}

func (m *MockGraph) GetNodes() map[string]GraphNode {
	return m.nodes
}

func (m *MockGraph) GetEdges() map[string][]string {
	return m.edges
}

func (m *MockGraph) GetMetrics() GraphMetrics {
	args := m.Called()
	return args.Get(0).(GraphMetrics)
}

func (m *MockGraph) Validate() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockGraph) Clone() Graph {
	args := m.Called()
	return args.Get(0).(Graph)
}

// MockAgent implements Agent interface for testing
type MockAgent struct {
	mock.Mock
	id          string
	name        string
	description string
	tools       []Tool
}

func NewMockAgent(id, name, description string) *MockAgent {
	mockAgent := &MockAgent{
		id:          id,
		name:        name,
		description: description,
		tools:       make([]Tool, 0),
	}

	// Set up default mock expectations
	mockAgent.On("Validate").Return(nil)
	mockAgent.On("GetMetrics").Return(AgentMetrics{}).Maybe()
	mockAgent.On("AddTool", mock.Anything).Return(nil).Maybe()
	mockAgent.On("SetDecisionEngine", mock.Anything).Return(nil).Maybe()

	return mockAgent
}

func (m *MockAgent) ID() string          { return m.id }
func (m *MockAgent) Name() string        { return m.name }
func (m *MockAgent) Description() string { return m.description }

func (m *MockAgent) Execute(ctx context.Context, input AgentInput) (AgentOutput, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(AgentOutput), args.Error(1)
}

func (m *MockAgent) AddTool(tool Tool) error {
	args := m.Called(tool)
	if args.Error(0) == nil {
		m.tools = append(m.tools, tool)
	}
	return args.Error(0)
}

func (m *MockAgent) RemoveTool(toolName string) error {
	args := m.Called(toolName)
	return args.Error(0)
}

func (m *MockAgent) GetAvailableTools() []Tool {
	return m.tools
}

func (m *MockAgent) SetDecisionEngine(engine DecisionEngine) error {
	args := m.Called(engine)
	return args.Error(0)
}

func (m *MockAgent) GetMetrics() AgentMetrics {
	args := m.Called()
	return args.Get(0).(AgentMetrics)
}

func (m *MockAgent) Validate() error {
	args := m.Called()
	return args.Error(0)
}

// MockMemoryManager implements MemoryManager interface for testing
type MockMemoryManager struct {
	mock.Mock
	memories map[string]Memory
	mutex    sync.RWMutex
}

func NewMockMemoryManager() *MockMemoryManager {
	return &MockMemoryManager{
		memories: make(map[string]Memory),
	}
}

func (m *MockMemoryManager) Store(ctx context.Context, sessionID string, memory Memory) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	args := m.Called(ctx, sessionID, memory)
	if args.Error(0) == nil {
		m.memories[sessionID] = memory
	}
	return args.Error(0)
}

func (m *MockMemoryManager) Retrieve(ctx context.Context, sessionID string) (Memory, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	args := m.Called(ctx, sessionID)
	if memory, exists := m.memories[sessionID]; exists && args.Error(1) == nil {
		return memory, nil
	}
	return Memory{}, args.Error(1)
}

func (m *MockMemoryManager) Search(ctx context.Context, query string, limit int) ([]Memory, error) {
	args := m.Called(ctx, query, limit)
	return args.Get(0).([]Memory), args.Error(1)
}

func (m *MockMemoryManager) Clear(ctx context.Context, sessionID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	args := m.Called(ctx, sessionID)
	if args.Error(0) == nil {
		delete(m.memories, sessionID)
	}
	return args.Error(0)
}

func (m *MockMemoryManager) GetStats() MemoryStats {
	args := m.Called()
	return args.Get(0).(MemoryStats)
}

func (m *MockMemoryManager) IsHealthy(ctx context.Context) bool {
	args := m.Called(ctx)
	return args.Bool(0)
}

// Test helper methods

// RegisterMockTool adds a mock tool for testing
func (ts *TestSuite) RegisterMockTool(name, description string) *MockTool {
	mockTool := NewMockTool(name, description)
	ts.mockTools[name] = mockTool

	err := ts.orchestrator.RegisterTool(mockTool)
	require.NoError(ts.t, err, "Failed to register mock tool")

	return mockTool
}

// RegisterMockChain adds a mock chain for testing
func (ts *TestSuite) RegisterMockChain(id, name, description string) *MockChain {
	mockChain := NewMockChain(id, name, description)
	ts.mockChains[id] = mockChain

	err := ts.orchestrator.RegisterChain(mockChain)
	require.NoError(ts.t, err, "Failed to register mock chain")

	return mockChain
}

// RegisterMockGraph adds a mock graph for testing
func (ts *TestSuite) RegisterMockGraph(id, name, description string) *MockGraph {
	mockGraph := NewMockGraph(id, name, description)
	ts.mockGraphs[id] = mockGraph

	err := ts.orchestrator.RegisterGraph(mockGraph)
	require.NoError(ts.t, err, "Failed to register mock graph")

	return mockGraph
}

// RegisterMockAgent adds a mock agent for testing
func (ts *TestSuite) RegisterMockAgent(id, name, description string) *MockAgent {
	mockAgent := NewMockAgent(id, name, description)
	ts.mockAgents[id] = mockAgent

	err := ts.orchestrator.RegisterAgent(mockAgent)
	require.NoError(ts.t, err, "Failed to register mock agent")

	return mockAgent
}

// Test case structures

// ChainTestCase represents a test case for chain execution
type ChainTestCase struct {
	Name             string
	Input            map[string]interface{}
	ExpectedOutput   map[string]interface{}
	ExpectError      bool
	ExpectedErrorMsg string
	Timeout          time.Duration
	SetupMocks       func(*MockChain)
}

// GraphTestCase represents a test case for graph execution
type GraphTestCase struct {
	Name             string
	InitialState     GraphState
	ExpectedState    GraphState
	ExpectError      bool
	ExpectedErrorMsg string
	Timeout          time.Duration
	SetupMocks       func(*MockGraph)
}

// AgentTestCase represents a test case for agent execution
type AgentTestCase struct {
	Name             string
	Input            AgentInput
	ExpectedOutput   AgentOutput
	ExpectError      bool
	ExpectedErrorMsg string
	Timeout          time.Duration
	SetupMocks       func(*MockAgent)
}

// Test execution methods

// TestChainExecution tests chain execution with various scenarios
func (ts *TestSuite) TestChainExecution(chainID string, testCases []ChainTestCase) {
	mockChain, exists := ts.mockChains[chainID]
	require.True(ts.t, exists, "Mock chain not found: %s", chainID)

	for _, tc := range testCases {
		ts.t.Run(tc.Name, func(t *testing.T) {
			// Setup mocks
			if tc.SetupMocks != nil {
				tc.SetupMocks(mockChain)
			}

			// Set timeout
			timeout := tc.Timeout
			if timeout == 0 {
				timeout = 30 * time.Second
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			// Execute chain
			output, err := ts.orchestrator.ExecuteChain(ctx, chainID, tc.Input)

			// Validate results
			if tc.ExpectError {
				assert.Error(t, err)
				if tc.ExpectedErrorMsg != "" {
					assert.Contains(t, err.Error(), tc.ExpectedErrorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, output)

				// Validate output
				for key, expectedValue := range tc.ExpectedOutput {
					actualValue, exists := output[key]
					assert.True(t, exists, "Expected key %s not found in output", key)
					assert.Equal(t, expectedValue, actualValue)
				}
			}

			// Verify mock expectations
			mockChain.AssertExpectations(t)
		})
	}
}

// BenchmarkChainExecution benchmarks chain execution performance
func (ts *TestSuite) BenchmarkChainExecution(b *testing.B, chainID string, input map[string]interface{}) {
	mockChain, exists := ts.mockChains[chainID]
	require.True(ts.t, exists, "Mock chain not found: %s", chainID)

	// Setup mock to return success
	mockChain.On("Execute", mock.Anything, input).Return(
		map[string]interface{}{"result": "success"}, nil)

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := ts.orchestrator.ExecuteChain(ctx, chainID, input)
			if err != nil {
				b.Fatalf("Chain execution failed: %v", err)
			}
		}
	})
}

// AssertOrchestratorHealth asserts that the orchestrator is healthy
func (ts *TestSuite) AssertOrchestratorHealth() {
	health := ts.orchestrator.Health()
	assert.Equal(ts.t, "healthy", health.Status)
	assert.True(ts.t, health.Uptime > 0)
}

// AssertStats asserts orchestrator statistics
func (ts *TestSuite) AssertStats(expectedExecutions int64) {
	stats := ts.orchestrator.GetStats()
	assert.Equal(ts.t, expectedExecutions, stats.TotalExecutions)
	assert.True(ts.t, stats.UptimeSeconds > 0)
}

// NewFailingTestChain creates a test chain that always fails
func NewFailingTestChain(id, name string) Chain {
	// Create a mock chain that always fails
	mockChain := NewMockChain(id, name, "A test chain that always fails")

	// Set up the mock to always return an error
	mockChain.On("Execute", mock.Anything, mock.Anything).Return(
		llm.ChainOutput{},
		fmt.Errorf("test chain failure"),
	)

	return mockChain
}

// NewTestChain creates a simple test chain
func NewTestChain(id, name string) Chain {
	// Create a mock chain that succeeds
	mockChain := NewMockChain(id, name, "A test chain")

	// Set up the mock to return success
	mockChain.On("Execute", mock.Anything, mock.Anything).Return(
		llm.ChainOutput{
			"result": "test_success",
			"status": "completed",
		},
		nil,
	)

	return mockChain
}

// NewTestAgent creates a simple test agent
func NewTestAgent(id, name, description string, logger *logger.Logger) Agent {
	// Create a mock agent that succeeds
	mockAgent := NewMockAgent(id, name, description)

	// Set up the mock to return success
	mockAgent.On("Execute", mock.Anything, mock.Anything).Return(
		AgentOutput{
			Response:   "Agent executed successfully",
			Success:    true,
			Confidence: 0.95,
			Steps: []AgentStep{
				{
					StepID:    "test_step",
					Action:    "test_action",
					Input:     map[string]interface{}{"test": "input"},
					Output:    map[string]interface{}{"result": "success"},
					Success:   true,
					Duration:  100 * time.Millisecond,
					Timestamp: time.Now(),
				},
			},
			ToolsUsed: []string{"test_tool"},
			Duration:  100 * time.Millisecond,
			Metadata: map[string]interface{}{
				"test": "metadata",
			},
		},
		nil,
	)

	return mockAgent
}
