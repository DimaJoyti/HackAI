package llm

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/llm/memory"
	"github.com/dimajoyti/hackai/pkg/llm/providers"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var tracer = otel.Tracer("hackai/llm/orchestrator")

// OrchestratorRequest represents a request for chain or graph execution
type OrchestratorRequest struct {
	Type        string      // "chain" or "graph"
	ID          string      // Chain or Graph ID
	Input       interface{} // ChainInput or GraphState
	Context     context.Context
	ResultChan  chan OrchestratorResult
	SubmittedAt time.Time
}

// OrchestratorResult represents the result of an execution
type OrchestratorResult struct {
	Output   interface{} // ChainOutput or GraphState
	Error    error
	Duration time.Duration
}

// Worker represents a worker in the orchestrator worker pool
type Worker struct {
	ID           int
	orchestrator *DefaultOrchestrator
	stopChan     chan struct{}
	logger       *logger.Logger
}

// DefaultOrchestrator implements the Orchestrator interface
type DefaultOrchestrator struct {
	chains         map[string]Chain
	graphs         map[string]StateGraph
	providers      map[string]providers.LLMProvider
	memoryManager  *memory.MemoryManager
	logger         *logger.Logger
	config         OrchestratorConfig
	mutex          sync.RWMutex
	running        bool
	executionStats *ExecutionStats

	// Enhanced components
	providerManager providers.ProviderManager
	requestQueue    chan *OrchestratorRequest
	workerPool      []*Worker
	stopChan        chan struct{}

	// Performance tracking
	activeExecutions int64
	queueDepth       int64
}

// OrchestratorConfig represents configuration for the orchestrator
type OrchestratorConfig struct {
	MaxConcurrentChains int                 `json:"max_concurrent_chains"`
	MaxConcurrentGraphs int                 `json:"max_concurrent_graphs"`
	DefaultTimeout      time.Duration       `json:"default_timeout"`
	EnableMetrics       bool                `json:"enable_metrics"`
	EnableTracing       bool                `json:"enable_tracing"`
	MemoryConfig        memory.MemoryConfig `json:"memory_config"`
}

// ExecutionStats tracks orchestrator execution statistics
type ExecutionStats struct {
	TotalChainExecutions int64         `json:"total_chain_executions"`
	TotalGraphExecutions int64         `json:"total_graph_executions"`
	SuccessfulExecutions int64         `json:"successful_executions"`
	FailedExecutions     int64         `json:"failed_executions"`
	AverageExecutionTime time.Duration `json:"average_execution_time"`
	LastExecutionTime    time.Time     `json:"last_execution_time"`
	mutex                sync.RWMutex
}

// NewDefaultOrchestrator creates a new default orchestrator
func NewDefaultOrchestrator(config OrchestratorConfig, logger *logger.Logger) *DefaultOrchestrator {
	// Set default values
	if config.MaxConcurrentChains == 0 {
		config.MaxConcurrentChains = 100
	}
	if config.MaxConcurrentGraphs == 0 {
		config.MaxConcurrentGraphs = 50
	}
	if config.DefaultTimeout == 0 {
		config.DefaultTimeout = 5 * time.Minute
	}

	// Initialize memory manager
	memoryManager := memory.NewMemoryManager(config.MemoryConfig)

	return &DefaultOrchestrator{
		chains:         make(map[string]Chain),
		graphs:         make(map[string]StateGraph),
		providers:      make(map[string]providers.LLMProvider),
		memoryManager:  memoryManager,
		logger:         logger,
		config:         config,
		executionStats: &ExecutionStats{},
	}
}

// RegisterChain registers a new chain
func (o *DefaultOrchestrator) RegisterChain(chain Chain) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if err := chain.Validate(); err != nil {
		return fmt.Errorf("chain validation failed: %w", err)
	}

	o.chains[chain.ID()] = chain
	o.logger.Info("Chain registered", "chain_id", chain.ID(), "chain_name", chain.Name())

	return nil
}

// UnregisterChain unregisters a chain
func (o *DefaultOrchestrator) UnregisterChain(chainID string) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if _, exists := o.chains[chainID]; !exists {
		return fmt.Errorf("chain %s not found", chainID)
	}

	delete(o.chains, chainID)
	o.logger.Info("Chain unregistered", "chain_id", chainID)

	return nil
}

// ExecuteChain executes a registered chain
func (o *DefaultOrchestrator) ExecuteChain(ctx context.Context, chainID string, input ChainInput) (ChainOutput, error) {
	ctx, span := tracer.Start(ctx, "orchestrator.execute_chain",
		trace.WithAttributes(
			attribute.String("chain.id", chainID),
		),
	)
	defer span.End()

	startTime := time.Now()

	// Get chain
	o.mutex.RLock()
	chain, exists := o.chains[chainID]
	o.mutex.RUnlock()

	if !exists {
		err := fmt.Errorf("chain %s not found", chainID)
		span.RecordError(err)
		o.updateExecutionStats(startTime, false)
		return nil, err
	}

	// Apply default timeout if not set in context
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.config.DefaultTimeout)
		defer cancel()
	}

	// Set up memory for the chain if it doesn't have one
	if chain.GetMemory() == nil && o.memoryManager != nil {
		// Create a simple in-memory storage for this execution
		simpleMemory := &SimpleMemory{data: make(map[string]interface{})}
		chain.SetMemory(simpleMemory)
	}

	// Execute chain
	output, err := chain.Execute(ctx, input)

	// Update statistics
	success := err == nil
	o.updateExecutionStats(startTime, success)

	if err != nil {
		span.RecordError(err)
		o.logger.Error("Chain execution failed", "chain_id", chainID, "error", err)
		return nil, fmt.Errorf("chain execution failed: %w", err)
	}

	span.SetAttributes(
		attribute.Bool("success", true),
		attribute.String("duration", time.Since(startTime).String()),
	)

	o.logger.Info("Chain executed successfully",
		"chain_id", chainID,
		"duration", time.Since(startTime),
	)

	return output, nil
}

// ListChains returns information about all registered chains
func (o *DefaultOrchestrator) ListChains() []ChainInfo {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	chains := make([]ChainInfo, 0, len(o.chains))
	for _, chain := range o.chains {
		chains = append(chains, ChainInfo{
			ID:          chain.ID(),
			Name:        chain.Name(),
			Description: chain.Description(),
			Status:      "active",
			CreatedAt:   time.Now(), // TODO: track actual creation time
			UpdatedAt:   time.Now(),
		})
	}

	return chains
}

// RegisterGraph registers a new state graph
func (o *DefaultOrchestrator) RegisterGraph(graph StateGraph) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if err := graph.Validate(); err != nil {
		return fmt.Errorf("graph validation failed: %w", err)
	}

	o.graphs[graph.ID()] = graph
	o.logger.Info("Graph registered", "graph_id", graph.ID(), "graph_name", graph.Name())

	return nil
}

// UnregisterGraph unregisters a graph
func (o *DefaultOrchestrator) UnregisterGraph(graphID string) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if _, exists := o.graphs[graphID]; !exists {
		return fmt.Errorf("graph %s not found", graphID)
	}

	delete(o.graphs, graphID)
	o.logger.Info("Graph unregistered", "graph_id", graphID)

	return nil
}

// ExecuteGraph executes a registered state graph
func (o *DefaultOrchestrator) ExecuteGraph(ctx context.Context, graphID string, initialState GraphState) (GraphState, error) {
	ctx, span := tracer.Start(ctx, "orchestrator.execute_graph",
		trace.WithAttributes(
			attribute.String("graph.id", graphID),
		),
	)
	defer span.End()

	startTime := time.Now()

	// Get graph
	o.mutex.RLock()
	graph, exists := o.graphs[graphID]
	o.mutex.RUnlock()

	if !exists {
		err := fmt.Errorf("graph %s not found", graphID)
		span.RecordError(err)
		o.updateExecutionStats(startTime, false)
		return GraphState{}, err
	}

	// Apply default timeout if not set in context
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.config.DefaultTimeout)
		defer cancel()
	}

	// Execute graph
	finalState, err := graph.Execute(ctx, initialState)

	// Update statistics
	success := err == nil
	o.updateExecutionStats(startTime, success)

	if err != nil {
		span.RecordError(err)
		o.logger.Error("Graph execution failed", "graph_id", graphID, "error", err)
		return GraphState{}, fmt.Errorf("graph execution failed: %w", err)
	}

	span.SetAttributes(
		attribute.Bool("success", true),
		attribute.String("duration", time.Since(startTime).String()),
	)

	o.logger.Info("Graph executed successfully",
		"graph_id", graphID,
		"duration", time.Since(startTime),
	)

	return finalState, nil
}

// ListGraphs returns information about all registered graphs
func (o *DefaultOrchestrator) ListGraphs() []GraphInfo {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	graphs := make([]GraphInfo, 0, len(o.graphs))
	for _, graph := range o.graphs {
		nodeCount := len(graph.GetNodes())
		edgeCount := 0
		for _, edges := range graph.GetEdges() {
			edgeCount += len(edges)
		}

		graphs = append(graphs, GraphInfo{
			ID:          graph.ID(),
			Name:        graph.Name(),
			Description: graph.Description(),
			NodeCount:   nodeCount,
			EdgeCount:   edgeCount,
			Status:      "active",
			CreatedAt:   time.Now(), // TODO: track actual creation time
			UpdatedAt:   time.Now(),
		})
	}

	return graphs
}

// Start starts the orchestrator
func (o *DefaultOrchestrator) Start(ctx context.Context) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if o.running {
		return fmt.Errorf("orchestrator is already running")
	}

	o.running = true
	o.logger.Info("Orchestrator started")

	return nil
}

// Stop stops the orchestrator
func (o *DefaultOrchestrator) Stop(ctx context.Context) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if !o.running {
		return fmt.Errorf("orchestrator is not running")
	}

	// Close all providers
	for name, provider := range o.providers {
		if err := provider.Close(); err != nil {
			o.logger.Error("Failed to close provider", "provider", name, "error", err)
		}
	}

	o.running = false
	o.logger.Info("Orchestrator stopped")

	return nil
}

// Health returns the health status of the orchestrator
func (o *DefaultOrchestrator) Health() HealthStatus {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	status := "healthy"
	details := make(map[string]string)

	details["chains_registered"] = fmt.Sprintf("%d", len(o.chains))
	details["graphs_registered"] = fmt.Sprintf("%d", len(o.graphs))
	details["providers_registered"] = fmt.Sprintf("%d", len(o.providers))
	details["running"] = fmt.Sprintf("%t", o.running)

	// Check provider health
	for name, provider := range o.providers {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := provider.Health(ctx)
		cancel()

		if err != nil {
			status = "degraded"
			details[fmt.Sprintf("provider_%s", name)] = "unhealthy"
		} else {
			details[fmt.Sprintf("provider_%s", name)] = "healthy"
		}
	}

	return HealthStatus{
		Status:    status,
		Timestamp: time.Now(),
		Details:   details,
	}
}

// RegisterProvider registers an LLM provider
func (o *DefaultOrchestrator) RegisterProvider(name string, provider providers.LLMProvider) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	o.providers[name] = provider
	o.logger.Info("Provider registered", "provider", name, "type", provider.GetType())

	return nil
}

// GetProvider returns a registered provider
func (o *DefaultOrchestrator) GetProvider(name string) (providers.LLMProvider, error) {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	provider, exists := o.providers[name]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", name)
	}

	return provider, nil
}

// GetStats returns execution statistics
func (o *DefaultOrchestrator) GetStats() *ExecutionStats {
	o.executionStats.mutex.RLock()
	defer o.executionStats.mutex.RUnlock()

	// Return a copy to avoid race conditions
	return &ExecutionStats{
		TotalChainExecutions: o.executionStats.TotalChainExecutions,
		TotalGraphExecutions: o.executionStats.TotalGraphExecutions,
		SuccessfulExecutions: o.executionStats.SuccessfulExecutions,
		FailedExecutions:     o.executionStats.FailedExecutions,
		AverageExecutionTime: o.executionStats.AverageExecutionTime,
		LastExecutionTime:    o.executionStats.LastExecutionTime,
	}
}

// updateExecutionStats updates execution statistics
func (o *DefaultOrchestrator) updateExecutionStats(startTime time.Time, success bool) {
	o.executionStats.mutex.Lock()
	defer o.executionStats.mutex.Unlock()

	duration := time.Since(startTime)

	o.executionStats.TotalChainExecutions++
	o.executionStats.LastExecutionTime = time.Now()

	if success {
		o.executionStats.SuccessfulExecutions++
	} else {
		o.executionStats.FailedExecutions++
	}

	// Update average execution time (simple moving average)
	if o.executionStats.AverageExecutionTime == 0 {
		o.executionStats.AverageExecutionTime = duration
	} else {
		o.executionStats.AverageExecutionTime = (o.executionStats.AverageExecutionTime + duration) / 2
	}
}

// SimpleMemory implements a simple in-memory storage for Memory interface
type SimpleMemory struct {
	data  map[string]interface{}
	mutex sync.RWMutex
}

// Store stores a value
func (m *SimpleMemory) Store(ctx context.Context, key string, value interface{}) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.data[key] = value
	return nil
}

// Retrieve retrieves a value
func (m *SimpleMemory) Retrieve(ctx context.Context, key string) (interface{}, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	value, exists := m.data[key]
	if !exists {
		return nil, fmt.Errorf("key %s not found", key)
	}
	return value, nil
}

// Delete deletes a value
func (m *SimpleMemory) Delete(ctx context.Context, key string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.data, key)
	return nil
}

// Clear clears all values
func (m *SimpleMemory) Clear(ctx context.Context) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.data = make(map[string]interface{})
	return nil
}

// Keys returns all keys
func (m *SimpleMemory) Keys(ctx context.Context) ([]string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	keys := make([]string, 0, len(m.data))
	for key := range m.data {
		keys = append(keys, key)
	}
	return keys, nil
}

// SetProviderManager sets the provider manager for the orchestrator
func (o *DefaultOrchestrator) SetProviderManager(pm providers.ProviderManager) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	o.providerManager = pm
}

// StartWorkerPool starts the worker pool for concurrent execution
func (o *DefaultOrchestrator) StartWorkerPool(ctx context.Context, workerCount int) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if o.running {
		return fmt.Errorf("orchestrator already running")
	}

	// Initialize request queue
	o.requestQueue = make(chan *OrchestratorRequest, 1000)
	o.stopChan = make(chan struct{})

	// Start workers
	o.workerPool = make([]*Worker, workerCount)
	for i := 0; i < workerCount; i++ {
		worker := &Worker{
			ID:           i,
			orchestrator: o,
			stopChan:     make(chan struct{}),
			logger:       o.logger,
		}
		o.workerPool[i] = worker
		go worker.Start(ctx)
	}

	o.running = true
	o.logger.Info("Worker pool started", "worker_count", workerCount)

	return nil
}

// StopWorkerPool stops the worker pool
func (o *DefaultOrchestrator) StopWorkerPool() error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if !o.running {
		return nil
	}

	// Stop all workers
	for _, worker := range o.workerPool {
		close(worker.stopChan)
	}

	// Close request queue
	close(o.requestQueue)
	close(o.stopChan)

	o.running = false
	o.logger.Info("Worker pool stopped")

	return nil
}

// ExecuteChainAsync executes a chain asynchronously
func (o *DefaultOrchestrator) ExecuteChainAsync(ctx context.Context, chainID string, input ChainInput) (<-chan OrchestratorResult, error) {
	if !o.running {
		return nil, fmt.Errorf("orchestrator not running")
	}

	resultChan := make(chan OrchestratorResult, 1)
	request := &OrchestratorRequest{
		Type:        "chain",
		ID:          chainID,
		Input:       input,
		Context:     ctx,
		ResultChan:  resultChan,
		SubmittedAt: time.Now(),
	}

	select {
	case o.requestQueue <- request:
		o.queueDepth++
		return resultChan, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, fmt.Errorf("request queue full")
	}
}

// ExecuteGraphAsync executes a graph asynchronously
func (o *DefaultOrchestrator) ExecuteGraphAsync(ctx context.Context, graphID string, state GraphState) (<-chan OrchestratorResult, error) {
	if !o.running {
		return nil, fmt.Errorf("orchestrator not running")
	}

	resultChan := make(chan OrchestratorResult, 1)
	request := &OrchestratorRequest{
		Type:        "graph",
		ID:          graphID,
		Input:       state,
		Context:     ctx,
		ResultChan:  resultChan,
		SubmittedAt: time.Now(),
	}

	select {
	case o.requestQueue <- request:
		o.queueDepth++
		return resultChan, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, fmt.Errorf("request queue full")
	}
}

// GetQueueDepth returns the current queue depth
func (o *DefaultOrchestrator) GetQueueDepth() int64 {
	return o.queueDepth
}

// GetActiveExecutions returns the number of active executions
func (o *DefaultOrchestrator) GetActiveExecutions() int64 {
	return o.activeExecutions
}

// Start starts the worker
func (w *Worker) Start(ctx context.Context) {
	w.logger.Info("Worker started", "worker_id", w.ID)
	defer w.logger.Info("Worker stopped", "worker_id", w.ID)

	for {
		select {
		case request := <-w.orchestrator.requestQueue:
			if request == nil {
				return // Channel closed
			}
			w.processRequest(request)

		case <-w.stopChan:
			return

		case <-ctx.Done():
			return
		}
	}
}

// processRequest processes a single request
func (w *Worker) processRequest(request *OrchestratorRequest) {
	startTime := time.Now()
	w.orchestrator.activeExecutions++
	w.orchestrator.queueDepth--

	defer func() {
		w.orchestrator.activeExecutions--
		duration := time.Since(startTime)

		w.logger.Debug("Request processed",
			"worker_id", w.ID,
			"type", request.Type,
			"id", request.ID,
			"duration", duration,
		)
	}()

	var result OrchestratorResult

	switch request.Type {
	case "chain":
		if input, ok := request.Input.(ChainInput); ok {
			output, err := w.orchestrator.ExecuteChain(request.Context, request.ID, input)
			result = OrchestratorResult{
				Output:   output,
				Error:    err,
				Duration: time.Since(startTime),
			}
		} else {
			result = OrchestratorResult{
				Error:    fmt.Errorf("invalid input type for chain execution"),
				Duration: time.Since(startTime),
			}
		}

	case "graph":
		if state, ok := request.Input.(GraphState); ok {
			finalState, err := w.orchestrator.ExecuteGraph(request.Context, request.ID, state)
			result = OrchestratorResult{
				Output:   finalState,
				Error:    err,
				Duration: time.Since(startTime),
			}
		} else {
			result = OrchestratorResult{
				Error:    fmt.Errorf("invalid input type for graph execution"),
				Duration: time.Since(startTime),
			}
		}

	default:
		result = OrchestratorResult{
			Error:    fmt.Errorf("unknown request type: %s", request.Type),
			Duration: time.Since(startTime),
		}
	}

	// Send result
	select {
	case request.ResultChan <- result:
	case <-request.Context.Done():
		// Request context cancelled
	default:
		// Result channel full or closed
	}
}
