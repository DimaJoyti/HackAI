package graph

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var engineTracer = otel.Tracer("hackai/llm/graph/engine")

// ExecutionEngine provides graph execution capabilities
type ExecutionEngine interface {
	// Core execution
	Execute(ctx context.Context, graph llm.StateGraph, initialState llm.GraphState) (llm.GraphState, error)
	ExecuteAsync(ctx context.Context, graph llm.StateGraph, initialState llm.GraphState) (<-chan ExecutionUpdate, error)

	// Execution control
	Pause(ctx context.Context, executionID string) error
	Resume(ctx context.Context, executionID string) error
	Cancel(ctx context.Context, executionID string) error

	// Execution monitoring
	GetExecution(ctx context.Context, executionID string) (ExecutionInfo, error)
	ListExecutions(ctx context.Context, filter ExecutionFilter) ([]ExecutionInfo, error)

	// Configuration
	SetConfig(config EngineConfig) error
	GetConfig() EngineConfig
}

// DefaultExecutionEngine implements the ExecutionEngine interface
type DefaultExecutionEngine struct {
	config     EngineConfig
	executions map[string]*ExecutionContext
	logger     *logger.Logger
	mutex      sync.RWMutex
}

// EngineConfig provides configuration for the execution engine
type EngineConfig struct {
	MaxConcurrentExecutions int           `json:"max_concurrent_executions"`
	DefaultTimeout          time.Duration `json:"default_timeout"`
	MaxRetries              int           `json:"max_retries"`
	RetryDelay              time.Duration `json:"retry_delay"`
	EnableParallelExecution bool          `json:"enable_parallel_execution"`
	MaxParallelNodes        int           `json:"max_parallel_nodes"`
	MemoryLimit             int64         `json:"memory_limit"`
	EnableTracing           bool          `json:"enable_tracing"`
	EnableMetrics           bool          `json:"enable_metrics"`
}

// ExecutionContext represents an active graph execution
type ExecutionContext struct {
	ID            string                 `json:"id"`
	GraphID       string                 `json:"graph_id"`
	Status        ExecutionStatus        `json:"status"`
	CurrentNode   string                 `json:"current_node"`
	State         llm.GraphState         `json:"state"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       *time.Time             `json:"end_time,omitempty"`
	Error         error                  `json:"error,omitempty"`
	Metadata      map[string]interface{} `json:"metadata"`
	CancelFunc    context.CancelFunc     `json:"-"`
	UpdateChannel chan ExecutionUpdate   `json:"-"`
	mutex         sync.RWMutex
}

// ExecutionStatus represents the status of a graph execution
type ExecutionStatus string

const (
	StatusPending   ExecutionStatus = "pending"
	StatusRunning   ExecutionStatus = "running"
	StatusPaused    ExecutionStatus = "paused"
	StatusCompleted ExecutionStatus = "completed"
	StatusFailed    ExecutionStatus = "failed"
	StatusCancelled ExecutionStatus = "cancelled"
)

// ExecutionUpdate represents an update during graph execution
type ExecutionUpdate struct {
	ExecutionID string                 `json:"execution_id"`
	Type        UpdateType             `json:"type"`
	NodeID      string                 `json:"node_id,omitempty"`
	State       llm.GraphState         `json:"state"`
	Error       error                  `json:"error,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// UpdateType represents the type of execution update
type UpdateType string

const (
	UpdateNodeStarted   UpdateType = "node_started"
	UpdateNodeCompleted UpdateType = "node_completed"
	UpdateNodeFailed    UpdateType = "node_failed"
	UpdateStateChanged  UpdateType = "state_changed"
	UpdateExecutionDone UpdateType = "execution_done"
	UpdateError         UpdateType = "error"
)

// ExecutionInfo provides information about a graph execution
type ExecutionInfo struct {
	ID            string                 `json:"id"`
	GraphID       string                 `json:"graph_id"`
	Status        ExecutionStatus        `json:"status"`
	CurrentNode   string                 `json:"current_node"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       *time.Time             `json:"end_time,omitempty"`
	Duration      time.Duration          `json:"duration"`
	NodesExecuted int                    `json:"nodes_executed"`
	Error         string                 `json:"error,omitempty"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ExecutionFilter provides filtering options for execution queries
type ExecutionFilter struct {
	GraphID   string          `json:"graph_id,omitempty"`
	Status    ExecutionStatus `json:"status,omitempty"`
	StartTime *time.Time      `json:"start_time,omitempty"`
	EndTime   *time.Time      `json:"end_time,omitempty"`
	Limit     int             `json:"limit"`
	Offset    int             `json:"offset"`
}

// NewDefaultExecutionEngine creates a new default execution engine
func NewDefaultExecutionEngine(config EngineConfig, logger *logger.Logger) *DefaultExecutionEngine {
	return &DefaultExecutionEngine{
		config:     config,
		executions: make(map[string]*ExecutionContext),
		logger:     logger,
	}
}

// Execute executes a graph synchronously
func (e *DefaultExecutionEngine) Execute(ctx context.Context, graph llm.StateGraph, initialState llm.GraphState) (llm.GraphState, error) {
	ctx, span := engineTracer.Start(ctx, "engine.execute",
		trace.WithAttributes(
			attribute.String("graph.id", graph.ID()),
			attribute.String("graph.name", graph.Name()),
		),
	)
	defer span.End()

	// Create execution context
	execCtx := e.createExecutionContext(graph.ID(), initialState)

	// Store execution
	e.mutex.Lock()
	e.executions[execCtx.ID] = execCtx
	e.mutex.Unlock()

	// Ensure cleanup
	defer func() {
		e.mutex.Lock()
		delete(e.executions, execCtx.ID)
		e.mutex.Unlock()
	}()

	// Execute the graph
	finalState, err := e.executeGraph(ctx, graph, execCtx)

	// Update execution status
	execCtx.mutex.Lock()
	if err != nil {
		execCtx.Status = StatusFailed
		execCtx.Error = err
	} else {
		execCtx.Status = StatusCompleted
	}
	now := time.Now()
	execCtx.EndTime = &now
	execCtx.mutex.Unlock()

	span.SetAttributes(
		attribute.Bool("execution.success", err == nil),
		attribute.String("execution.status", string(execCtx.Status)),
	)

	if err != nil {
		span.RecordError(err)
		e.logger.Error("Graph execution failed",
			"execution_id", execCtx.ID,
			"graph_id", graph.ID(),
			"error", err,
		)
		return finalState, err
	}

	e.logger.Info("Graph execution completed",
		"execution_id", execCtx.ID,
		"graph_id", graph.ID(),
		"duration", time.Since(execCtx.StartTime),
	)

	return finalState, nil
}

// ExecuteAsync executes a graph asynchronously
func (e *DefaultExecutionEngine) ExecuteAsync(ctx context.Context, graph llm.StateGraph, initialState llm.GraphState) (<-chan ExecutionUpdate, error) {
	// Create execution context
	execCtx := e.createExecutionContext(graph.ID(), initialState)
	execCtx.UpdateChannel = make(chan ExecutionUpdate, 100)

	// Store execution
	e.mutex.Lock()
	e.executions[execCtx.ID] = execCtx
	e.mutex.Unlock()

	// Start execution in goroutine
	go func() {
		defer close(execCtx.UpdateChannel)
		defer func() {
			e.mutex.Lock()
			delete(e.executions, execCtx.ID)
			e.mutex.Unlock()
		}()

		finalState, err := e.executeGraph(ctx, graph, execCtx)

		// Send final update
		update := ExecutionUpdate{
			ExecutionID: execCtx.ID,
			Type:        UpdateExecutionDone,
			State:       finalState,
			Error:       err,
			Timestamp:   time.Now(),
		}

		select {
		case execCtx.UpdateChannel <- update:
		case <-ctx.Done():
		}
	}()

	return execCtx.UpdateChannel, nil
}

// executeGraph performs the actual graph execution
func (e *DefaultExecutionEngine) executeGraph(ctx context.Context, graph llm.StateGraph, execCtx *ExecutionContext) (llm.GraphState, error) {
	ctx, span := engineTracer.Start(ctx, "engine.execute_graph",
		trace.WithAttributes(attribute.String("execution.id", execCtx.ID)),
	)
	defer span.End()

	// Create cancellable context
	execCtx.mutex.Lock()
	ctx, cancel := context.WithCancel(ctx)
	execCtx.CancelFunc = cancel
	execCtx.Status = StatusRunning
	execCtx.mutex.Unlock()

	defer cancel()

	// Get graph nodes and edges
	nodes := graph.GetNodes()
	edges := graph.GetEdges()

	// Start with initial state
	currentState := execCtx.State
	currentNode := currentState.CurrentNode

	// If no current node, find start node
	if currentNode == "" {
		startNode := e.findStartNode(nodes, edges)
		if startNode == "" {
			return currentState, fmt.Errorf("no start node found in graph")
		}
		currentNode = startNode
		currentState.CurrentNode = currentNode
	}

	// Execute nodes until completion
	for {
		select {
		case <-ctx.Done():
			execCtx.mutex.Lock()
			execCtx.Status = StatusCancelled
			execCtx.mutex.Unlock()
			return currentState, ctx.Err()
		default:
		}

		// Get current node
		node, exists := nodes[currentNode]
		if !exists {
			return currentState, fmt.Errorf("node %s not found", currentNode)
		}

		// Send node started update
		e.sendUpdate(execCtx, ExecutionUpdate{
			ExecutionID: execCtx.ID,
			Type:        UpdateNodeStarted,
			NodeID:      currentNode,
			State:       currentState,
			Timestamp:   time.Now(),
		})

		// Execute node
		newState, err := node.Execute(ctx, currentState)
		if err != nil {
			e.sendUpdate(execCtx, ExecutionUpdate{
				ExecutionID: execCtx.ID,
				Type:        UpdateNodeFailed,
				NodeID:      currentNode,
				State:       currentState,
				Error:       err,
				Timestamp:   time.Now(),
			})
			return currentState, fmt.Errorf("node %s execution failed: %w", currentNode, err)
		}

		// Update state
		currentState = newState
		currentState.UpdateTime = time.Now()

		// Send node completed update
		e.sendUpdate(execCtx, ExecutionUpdate{
			ExecutionID: execCtx.ID,
			Type:        UpdateNodeCompleted,
			NodeID:      currentNode,
			State:       currentState,
			Timestamp:   time.Now(),
		})

		// Find next node
		nextNode, err := e.findNextNode(currentNode, currentState, edges)
		if err != nil {
			return currentState, err
		}

		// If no next node, execution is complete
		if nextNode == "" {
			break
		}

		// Move to next node
		currentNode = nextNode
		currentState.CurrentNode = currentNode

		// Add state transition
		currentState.History = append(currentState.History, llm.StateTransition{
			From:      currentState.CurrentNode,
			To:        nextNode,
			Timestamp: time.Now(),
			Data:      currentState.Data,
		})
	}

	return currentState, nil
}

// Helper methods

// createExecutionContext creates a new execution context
func (e *DefaultExecutionEngine) createExecutionContext(graphID string, initialState llm.GraphState) *ExecutionContext {
	return &ExecutionContext{
		ID:        fmt.Sprintf("exec_%d", time.Now().UnixNano()),
		GraphID:   graphID,
		Status:    StatusPending,
		State:     initialState,
		StartTime: time.Now(),
		Metadata:  make(map[string]interface{}),
	}
}

// findStartNode finds the start node of a graph
func (e *DefaultExecutionEngine) findStartNode(nodes map[string]llm.Node, edges map[string][]llm.Edge) string {
	// Find node with no incoming edges
	hasIncoming := make(map[string]bool)
	for _, edgeList := range edges {
		for _, edge := range edgeList {
			hasIncoming[edge.To] = true
		}
	}

	for nodeID := range nodes {
		if !hasIncoming[nodeID] {
			return nodeID
		}
	}

	// If all nodes have incoming edges, return the first one
	for nodeID := range nodes {
		return nodeID
	}

	return ""
}

// findNextNode finds the next node to execute based on conditions
func (e *DefaultExecutionEngine) findNextNode(currentNode string, state llm.GraphState, edges map[string][]llm.Edge) (string, error) {
	edgeList, exists := edges[currentNode]
	if !exists || len(edgeList) == 0 {
		return "", nil // No outgoing edges, execution complete
	}

	// Evaluate conditions for each edge
	for _, edge := range edgeList {
		if edge.Condition == nil {
			return edge.To, nil // No condition, take this edge
		}

		match, err := edge.Condition.Evaluate(context.Background(), state)
		if err != nil {
			return "", fmt.Errorf("condition evaluation failed: %w", err)
		}

		if match {
			return edge.To, nil
		}
	}

	return "", fmt.Errorf("no valid edge found from node %s", currentNode)
}

// sendUpdate sends an execution update if channel is available
func (e *DefaultExecutionEngine) sendUpdate(execCtx *ExecutionContext, update ExecutionUpdate) {
	if execCtx.UpdateChannel != nil {
		select {
		case execCtx.UpdateChannel <- update:
		default:
			// Channel full, skip update
		}
	}
}

// Pause pauses a running execution
func (e *DefaultExecutionEngine) Pause(ctx context.Context, executionID string) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	execCtx, exists := e.executions[executionID]
	if !exists {
		return fmt.Errorf("execution %s not found", executionID)
	}

	execCtx.mutex.Lock()
	defer execCtx.mutex.Unlock()

	if execCtx.Status != StatusRunning {
		return fmt.Errorf("execution %s is not running", executionID)
	}

	execCtx.Status = StatusPaused
	e.logger.Info("Execution paused", "execution_id", executionID)
	return nil
}

// Resume resumes a paused execution
func (e *DefaultExecutionEngine) Resume(ctx context.Context, executionID string) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	execCtx, exists := e.executions[executionID]
	if !exists {
		return fmt.Errorf("execution %s not found", executionID)
	}

	execCtx.mutex.Lock()
	defer execCtx.mutex.Unlock()

	if execCtx.Status != StatusPaused {
		return fmt.Errorf("execution %s is not paused", executionID)
	}

	execCtx.Status = StatusRunning
	e.logger.Info("Execution resumed", "execution_id", executionID)
	return nil
}

// Cancel cancels a running execution
func (e *DefaultExecutionEngine) Cancel(ctx context.Context, executionID string) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	execCtx, exists := e.executions[executionID]
	if !exists {
		return fmt.Errorf("execution %s not found", executionID)
	}

	execCtx.mutex.Lock()
	defer execCtx.mutex.Unlock()

	if execCtx.Status == StatusCompleted || execCtx.Status == StatusFailed || execCtx.Status == StatusCancelled {
		return fmt.Errorf("execution %s is already finished", executionID)
	}

	if execCtx.CancelFunc != nil {
		execCtx.CancelFunc()
	}

	execCtx.Status = StatusCancelled
	now := time.Now()
	execCtx.EndTime = &now

	e.logger.Info("Execution cancelled", "execution_id", executionID)
	return nil
}

// GetExecution retrieves information about an execution
func (e *DefaultExecutionEngine) GetExecution(ctx context.Context, executionID string) (ExecutionInfo, error) {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	execCtx, exists := e.executions[executionID]
	if !exists {
		return ExecutionInfo{}, fmt.Errorf("execution %s not found", executionID)
	}

	execCtx.mutex.RLock()
	defer execCtx.mutex.RUnlock()

	duration := time.Since(execCtx.StartTime)
	if execCtx.EndTime != nil {
		duration = execCtx.EndTime.Sub(execCtx.StartTime)
	}

	errorMsg := ""
	if execCtx.Error != nil {
		errorMsg = execCtx.Error.Error()
	}

	return ExecutionInfo{
		ID:            execCtx.ID,
		GraphID:       execCtx.GraphID,
		Status:        execCtx.Status,
		CurrentNode:   execCtx.CurrentNode,
		StartTime:     execCtx.StartTime,
		EndTime:       execCtx.EndTime,
		Duration:      duration,
		NodesExecuted: len(execCtx.State.History),
		Error:         errorMsg,
		Metadata:      execCtx.Metadata,
	}, nil
}

// ListExecutions lists executions with filtering
func (e *DefaultExecutionEngine) ListExecutions(ctx context.Context, filter ExecutionFilter) ([]ExecutionInfo, error) {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	var results []ExecutionInfo

	for _, execCtx := range e.executions {
		execCtx.mutex.RLock()

		// Apply filters
		if filter.GraphID != "" && execCtx.GraphID != filter.GraphID {
			execCtx.mutex.RUnlock()
			continue
		}
		if filter.Status != "" && execCtx.Status != filter.Status {
			execCtx.mutex.RUnlock()
			continue
		}
		if filter.StartTime != nil && execCtx.StartTime.Before(*filter.StartTime) {
			execCtx.mutex.RUnlock()
			continue
		}
		if filter.EndTime != nil && execCtx.EndTime != nil && execCtx.EndTime.After(*filter.EndTime) {
			execCtx.mutex.RUnlock()
			continue
		}

		duration := time.Since(execCtx.StartTime)
		if execCtx.EndTime != nil {
			duration = execCtx.EndTime.Sub(execCtx.StartTime)
		}

		errorMsg := ""
		if execCtx.Error != nil {
			errorMsg = execCtx.Error.Error()
		}

		info := ExecutionInfo{
			ID:            execCtx.ID,
			GraphID:       execCtx.GraphID,
			Status:        execCtx.Status,
			CurrentNode:   execCtx.CurrentNode,
			StartTime:     execCtx.StartTime,
			EndTime:       execCtx.EndTime,
			Duration:      duration,
			NodesExecuted: len(execCtx.State.History),
			Error:         errorMsg,
			Metadata:      execCtx.Metadata,
		}

		results = append(results, info)
		execCtx.mutex.RUnlock()
	}

	// Apply pagination
	if filter.Offset > 0 && filter.Offset < len(results) {
		results = results[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(results) {
		results = results[:filter.Limit]
	}

	return results, nil
}

// SetConfig sets the engine configuration
func (e *DefaultExecutionEngine) SetConfig(config EngineConfig) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.config = config
	e.logger.Info("Engine configuration updated")
	return nil
}

// GetConfig gets the engine configuration
func (e *DefaultExecutionEngine) GetConfig() EngineConfig {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	return e.config
}
