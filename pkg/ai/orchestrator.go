package ai

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var orchestratorTracer = otel.Tracer("hackai/ai/orchestrator")

// Orchestrator manages and coordinates AI chains, graphs, and agents
type Orchestrator interface {
	// Chain operations
	RegisterChain(chain Chain) error
	UnregisterChain(chainID string) error
	ExecuteChain(ctx context.Context, chainID string, input map[string]interface{}) (map[string]interface{}, error)
	ExecuteChainAsync(ctx context.Context, chainID string, input map[string]interface{}) (<-chan OrchestratorResult, error)
	ListChains() []ChainInfo

	// Graph operations
	RegisterGraph(graph Graph) error
	UnregisterGraph(graphID string) error
	ExecuteGraph(ctx context.Context, graphID string, state GraphState) (GraphState, error)
	ExecuteGraphAsync(ctx context.Context, graphID string, state GraphState) (<-chan OrchestratorResult, error)
	ListGraphs() []GraphInfo

	// Agent operations
	RegisterAgent(agent Agent) error
	UnregisterAgent(agentID string) error
	ExecuteAgent(ctx context.Context, agentID string, input AgentInput) (AgentOutput, error)
	ExecuteAgentAsync(ctx context.Context, agentID string, input AgentInput) (<-chan OrchestratorResult, error)
	ListAgents() []AgentInfo

	// Tool operations
	RegisterTool(tool Tool) error
	UnregisterTool(toolName string) error
	GetTool(toolName string) (Tool, error)
	ListTools() []string

	// Lifecycle management
	Start(ctx context.Context) error
	Stop() error
	Health() HealthStatus
	GetStats() OrchestratorStats
}

// DefaultOrchestrator implements the Orchestrator interface
type DefaultOrchestrator struct {
	chains       map[string]Chain
	graphs       map[string]Graph
	agents       map[string]Agent
	toolRegistry *ToolRegistry

	logger *logger.Logger
	tracer trace.Tracer
	config OrchestratorConfig

	// Concurrency management
	executionPool chan struct{}
	requestQueue  chan *OrchestratorRequest
	workerPool    []*Worker
	wg            sync.WaitGroup
	stopChan      chan struct{}
	running       bool

	// Performance tracking
	stats            OrchestratorStats
	activeExecutions int64
	queueDepth       int64

	mutex sync.RWMutex
}

// OrchestratorConfig represents configuration for the orchestrator
type OrchestratorConfig struct {
	MaxConcurrentExecutions int           `json:"max_concurrent_executions"`
	WorkerPoolSize          int           `json:"worker_pool_size"`
	RequestQueueSize        int           `json:"request_queue_size"`
	DefaultTimeout          time.Duration `json:"default_timeout"`
	EnableMetrics           bool          `json:"enable_metrics"`
	EnableTracing           bool          `json:"enable_tracing"`
	HealthCheckInterval     time.Duration `json:"health_check_interval"`
}

// OrchestratorRequest represents a request for execution
type OrchestratorRequest struct {
	Type        string      // "chain", "graph", "agent"
	ID          string      // Chain/Graph/Agent ID
	Input       interface{} // Input data
	Context     context.Context
	ResultChan  chan OrchestratorResult
	SubmittedAt time.Time
}

// OrchestratorResult represents the result of an execution
type OrchestratorResult struct {
	Output   interface{}
	Error    error
	Duration time.Duration
	Metadata map[string]interface{}
}

// OrchestratorStats tracks orchestrator statistics
type OrchestratorStats struct {
	TotalExecutions      int64         `json:"total_executions"`
	SuccessfulExecutions int64         `json:"successful_executions"`
	FailedExecutions     int64         `json:"failed_executions"`
	AverageExecutionTime time.Duration `json:"average_execution_time"`
	ActiveExecutions     int64         `json:"active_executions"`
	QueueDepth           int64         `json:"queue_depth"`
	RegisteredChains     int           `json:"registered_chains"`
	RegisteredGraphs     int           `json:"registered_graphs"`
	RegisteredAgents     int           `json:"registered_agents"`
	RegisteredTools      int           `json:"registered_tools"`
	LastExecutionTime    time.Time     `json:"last_execution_time"`
	UptimeSeconds        int64         `json:"uptime_seconds"`
	startTime            time.Time
}

// Worker represents a worker in the orchestrator worker pool
type Worker struct {
	ID           int
	orchestrator *DefaultOrchestrator
	stopChan     chan struct{}
	logger       *logger.Logger
}

// ChainInfo provides metadata about a registered chain
type ChainInfo struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Type        ChainType    `json:"type"`
	Metrics     ChainMetrics `json:"metrics"`
	CreatedAt   time.Time    `json:"created_at"`
}

// GraphInfo provides metadata about a registered graph
type GraphInfo struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	NodeCount   int          `json:"node_count"`
	Metrics     GraphMetrics `json:"metrics"`
	CreatedAt   time.Time    `json:"created_at"`
}

// AgentInfo provides metadata about a registered agent
type AgentInfo struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	ToolCount   int          `json:"tool_count"`
	Metrics     AgentMetrics `json:"metrics"`
	CreatedAt   time.Time    `json:"created_at"`
}

// HealthStatus represents the health status of the orchestrator
type HealthStatus struct {
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Details   map[string]string `json:"details"`
	Uptime    time.Duration     `json:"uptime"`
	Version   string            `json:"version"`
}

// NewOrchestrator creates a new orchestrator
func NewOrchestrator(config OrchestratorConfig, logger *logger.Logger) *DefaultOrchestrator {
	// Set default values
	if config.MaxConcurrentExecutions == 0 {
		config.MaxConcurrentExecutions = 100
	}
	if config.WorkerPoolSize == 0 {
		config.WorkerPoolSize = 10
	}
	if config.RequestQueueSize == 0 {
		config.RequestQueueSize = 1000
	}
	if config.DefaultTimeout == 0 {
		config.DefaultTimeout = 5 * time.Minute
	}
	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = 30 * time.Second
	}

	return &DefaultOrchestrator{
		chains:        make(map[string]Chain),
		graphs:        make(map[string]Graph),
		agents:        make(map[string]Agent),
		toolRegistry:  NewToolRegistry(logger),
		logger:        logger,
		tracer:        orchestratorTracer,
		config:        config,
		executionPool: make(chan struct{}, config.MaxConcurrentExecutions),
		requestQueue:  make(chan *OrchestratorRequest, config.RequestQueueSize),
		stopChan:      make(chan struct{}),
		stats: OrchestratorStats{
			startTime: time.Now(),
		},
	}
}

// Start starts the orchestrator
func (o *DefaultOrchestrator) Start(ctx context.Context) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if o.running {
		return fmt.Errorf("orchestrator is already running")
	}

	// Initialize worker pool
	o.workerPool = make([]*Worker, o.config.WorkerPoolSize)
	for i := 0; i < o.config.WorkerPoolSize; i++ {
		worker := &Worker{
			ID:           i,
			orchestrator: o,
			stopChan:     make(chan struct{}),
			logger:       o.logger,
		}
		o.workerPool[i] = worker

		// Start worker goroutine
		o.wg.Add(1)
		go worker.run()
	}

	// Start health check goroutine
	o.wg.Add(1)
	go o.healthCheckLoop()

	o.running = true
	o.stats.startTime = time.Now()

	o.logger.Info("Orchestrator started",
		"worker_pool_size", o.config.WorkerPoolSize,
		"max_concurrent_executions", o.config.MaxConcurrentExecutions)

	return nil
}

// Stop stops the orchestrator
func (o *DefaultOrchestrator) Stop() error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if !o.running {
		return fmt.Errorf("orchestrator is not running")
	}

	// Signal stop to all workers
	close(o.stopChan)

	// Stop all workers
	for _, worker := range o.workerPool {
		close(worker.stopChan)
	}

	// Wait for all goroutines to finish
	o.wg.Wait()

	o.running = false

	o.logger.Info("Orchestrator stopped")

	return nil
}

// RegisterChain registers a new chain
func (o *DefaultOrchestrator) RegisterChain(chain Chain) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if chain == nil {
		return fmt.Errorf("chain cannot be nil")
	}

	if err := chain.Validate(); err != nil {
		return fmt.Errorf("chain validation failed: %w", err)
	}

	chainID := chain.ID()
	if _, exists := o.chains[chainID]; exists {
		return fmt.Errorf("chain %s already registered", chainID)
	}

	o.chains[chainID] = chain
	o.stats.RegisteredChains = len(o.chains)

	o.logger.Info("Chain registered",
		"chain_id", chainID,
		"chain_name", chain.Name())

	return nil
}

// ExecuteChain executes a chain synchronously
func (o *DefaultOrchestrator) ExecuteChain(ctx context.Context, chainID string, input map[string]interface{}) (map[string]interface{}, error) {
	ctx, span := o.tracer.Start(ctx, "orchestrator.execute_chain",
		trace.WithAttributes(
			attribute.String("chain.id", chainID),
		),
	)
	defer span.End()

	// Acquire execution slot
	select {
	case o.executionPool <- struct{}{}:
		defer func() { <-o.executionPool }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	atomic.AddInt64(&o.activeExecutions, 1)
	defer atomic.AddInt64(&o.activeExecutions, -1)

	// Get chain
	o.mutex.RLock()
	chain, exists := o.chains[chainID]
	o.mutex.RUnlock()

	if !exists {
		err := fmt.Errorf("chain %s not found", chainID)
		span.RecordError(err)
		return nil, err
	}

	// Execute with timeout
	execCtx, cancel := context.WithTimeout(ctx, o.config.DefaultTimeout)
	defer cancel()

	startTime := time.Now()
	output, err := chain.Execute(execCtx, input)
	duration := time.Since(startTime)

	// Update stats
	o.updateExecutionStats(err == nil, duration)

	if err != nil {
		span.RecordError(err)
		o.logger.Error("Chain execution failed",
			"chain_id", chainID,
			"error", err,
			"duration", duration)
		return nil, err
	}

	span.SetAttributes(
		attribute.String("execution.duration", duration.String()),
		attribute.Bool("execution.success", true),
	)

	o.logger.Info("Chain executed successfully",
		"chain_id", chainID,
		"duration", duration)

	return output, nil
}

// run executes the worker loop
func (w *Worker) run() {
	defer w.orchestrator.wg.Done()

	w.logger.Debug("Worker started", "worker_id", w.ID)

	for {
		select {
		case request := <-w.orchestrator.requestQueue:
			w.processRequest(request)
		case <-w.stopChan:
			w.logger.Debug("Worker stopped", "worker_id", w.ID)
			return
		case <-w.orchestrator.stopChan:
			w.logger.Debug("Worker stopped by orchestrator", "worker_id", w.ID)
			return
		}
	}
}

// processRequest processes a single request
func (w *Worker) processRequest(request *OrchestratorRequest) {
	startTime := time.Now()
	var result OrchestratorResult

	// Acquire execution slot
	select {
	case w.orchestrator.executionPool <- struct{}{}:
		defer func() { <-w.orchestrator.executionPool }()
	case <-request.Context.Done():
		result.Error = request.Context.Err()
		request.ResultChan <- result
		return
	}

	atomic.AddInt64(&w.orchestrator.activeExecutions, 1)
	defer atomic.AddInt64(&w.orchestrator.activeExecutions, -1)

	// Process based on request type
	switch request.Type {
	case "chain":
		result.Output, result.Error = w.orchestrator.executeChainInternal(request.Context, request.ID, request.Input)
	case "graph":
		result.Output, result.Error = w.orchestrator.executeGraphInternal(request.Context, request.ID, request.Input)
	case "agent":
		result.Output, result.Error = w.orchestrator.executeAgentInternal(request.Context, request.ID, request.Input)
	default:
		result.Error = fmt.Errorf("unknown request type: %s", request.Type)
	}

	result.Duration = time.Since(startTime)
	result.Metadata = map[string]interface{}{
		"worker_id":    w.ID,
		"queue_time":   startTime.Sub(request.SubmittedAt),
		"request_type": request.Type,
	}

	// Update stats
	w.orchestrator.updateExecutionStats(result.Error == nil, result.Duration)

	// Send result
	select {
	case request.ResultChan <- result:
	case <-request.Context.Done():
		// Request was cancelled
	}
}

// updateExecutionStats updates execution statistics
func (o *DefaultOrchestrator) updateExecutionStats(success bool, duration time.Duration) {
	atomic.AddInt64(&o.stats.TotalExecutions, 1)

	if success {
		atomic.AddInt64(&o.stats.SuccessfulExecutions, 1)
	} else {
		atomic.AddInt64(&o.stats.FailedExecutions, 1)
	}

	// Update average execution time (simplified)
	o.stats.LastExecutionTime = time.Now()

	// Calculate uptime
	o.stats.UptimeSeconds = int64(time.Since(o.stats.startTime).Seconds())
}

// healthCheckLoop performs periodic health checks
func (o *DefaultOrchestrator) healthCheckLoop() {
	defer o.wg.Done()

	ticker := time.NewTicker(o.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			o.performHealthCheck()
		case <-o.stopChan:
			return
		}
	}
}

// performHealthCheck performs a health check
func (o *DefaultOrchestrator) performHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check tool health
	toolHealth := o.toolRegistry.HealthCheck(ctx)
	unhealthyTools := 0
	for _, healthy := range toolHealth {
		if !healthy {
			unhealthyTools++
		}
	}

	if unhealthyTools > 0 {
		o.logger.Warn("Unhealthy tools detected",
			"unhealthy_count", unhealthyTools,
			"total_tools", len(toolHealth))
	}

	// Update stats
	atomic.StoreInt64(&o.stats.ActiveExecutions, atomic.LoadInt64(&o.activeExecutions))
	atomic.StoreInt64(&o.stats.QueueDepth, int64(len(o.requestQueue)))
}

// Health returns the current health status
func (o *DefaultOrchestrator) Health() HealthStatus {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	status := "healthy"
	details := make(map[string]string)

	if !o.running {
		status = "stopped"
		details["reason"] = "orchestrator not running"
	}

	return HealthStatus{
		Status:    status,
		Timestamp: time.Now(),
		Details:   details,
		Uptime:    time.Since(o.stats.startTime),
		Version:   "1.0.0",
	}
}

// GetStats returns current orchestrator statistics
func (o *DefaultOrchestrator) GetStats() OrchestratorStats {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	stats := o.stats
	stats.ActiveExecutions = atomic.LoadInt64(&o.activeExecutions)
	stats.QueueDepth = int64(len(o.requestQueue))
	stats.UptimeSeconds = int64(time.Since(o.stats.startTime).Seconds())

	return stats
}

// Additional orchestrator methods

// UnregisterChain unregisters a chain
func (o *DefaultOrchestrator) UnregisterChain(chainID string) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if _, exists := o.chains[chainID]; !exists {
		return fmt.Errorf("chain %s not found", chainID)
	}

	delete(o.chains, chainID)
	o.stats.RegisteredChains = len(o.chains)

	o.logger.Info("Chain unregistered", "chain_id", chainID)
	return nil
}

// ExecuteChainAsync executes a chain asynchronously
func (o *DefaultOrchestrator) ExecuteChainAsync(ctx context.Context, chainID string, input map[string]interface{}) (<-chan OrchestratorResult, error) {
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
		atomic.AddInt64(&o.queueDepth, 1)
		return resultChan, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, fmt.Errorf("request queue is full")
	}
}

// ListChains returns information about all registered chains
func (o *DefaultOrchestrator) ListChains() []ChainInfo {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	chains := make([]ChainInfo, 0, len(o.chains))
	for _, chain := range o.chains {
		config := chain.GetConfig()
		chains = append(chains, ChainInfo{
			ID:          chain.ID(),
			Name:        chain.Name(),
			Description: chain.Description(),
			Type:        config.Type,
			Metrics:     chain.GetMetrics(),
			CreatedAt:   config.CreatedAt,
		})
	}

	return chains
}

// RegisterGraph registers a new graph
func (o *DefaultOrchestrator) RegisterGraph(graph Graph) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if graph == nil {
		return fmt.Errorf("graph cannot be nil")
	}

	if err := graph.Validate(); err != nil {
		return fmt.Errorf("graph validation failed: %w", err)
	}

	graphID := graph.ID()
	if _, exists := o.graphs[graphID]; exists {
		return fmt.Errorf("graph %s already registered", graphID)
	}

	o.graphs[graphID] = graph
	o.stats.RegisteredGraphs = len(o.graphs)

	o.logger.Info("Graph registered",
		"graph_id", graphID,
		"graph_name", graph.Name())

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
	o.stats.RegisteredGraphs = len(o.graphs)

	o.logger.Info("Graph unregistered", "graph_id", graphID)
	return nil
}

// ExecuteGraph executes a graph synchronously
func (o *DefaultOrchestrator) ExecuteGraph(ctx context.Context, graphID string, state GraphState) (GraphState, error) {
	ctx, span := o.tracer.Start(ctx, "orchestrator.execute_graph",
		trace.WithAttributes(
			attribute.String("graph.id", graphID),
		),
	)
	defer span.End()

	// Acquire execution slot
	select {
	case o.executionPool <- struct{}{}:
		defer func() { <-o.executionPool }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	atomic.AddInt64(&o.activeExecutions, 1)
	defer atomic.AddInt64(&o.activeExecutions, -1)

	result, err := o.executeGraphInternal(ctx, graphID, state)
	if err != nil {
		return nil, err
	}
	return result.(GraphState), nil
}

// executeGraphInternal executes a graph internally
func (o *DefaultOrchestrator) executeGraphInternal(ctx context.Context, graphID string, state interface{}) (interface{}, error) {
	// Get graph
	o.mutex.RLock()
	graph, exists := o.graphs[graphID]
	o.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("graph %s not found", graphID)
	}

	// Execute with timeout
	execCtx, cancel := context.WithTimeout(ctx, o.config.DefaultTimeout)
	defer cancel()

	startTime := time.Now()
	output, err := graph.Execute(execCtx, state.(GraphState))
	duration := time.Since(startTime)

	if err != nil {
		o.logger.Error("Graph execution failed",
			"graph_id", graphID,
			"error", err,
			"duration", duration)
		return nil, err
	}

	o.logger.Info("Graph executed successfully",
		"graph_id", graphID,
		"duration", duration)

	return output, nil
}

// executeChainInternal executes a chain internally
func (o *DefaultOrchestrator) executeChainInternal(ctx context.Context, chainID string, input interface{}) (interface{}, error) {
	// Get chain
	o.mutex.RLock()
	chain, exists := o.chains[chainID]
	o.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("chain %s not found", chainID)
	}

	// Execute with timeout
	execCtx, cancel := context.WithTimeout(ctx, o.config.DefaultTimeout)
	defer cancel()

	startTime := time.Now()
	output, err := chain.Execute(execCtx, input.(map[string]interface{}))
	duration := time.Since(startTime)

	if err != nil {
		o.logger.Error("Chain execution failed",
			"chain_id", chainID,
			"error", err,
			"duration", duration)
		return nil, err
	}

	o.logger.Info("Chain executed successfully",
		"chain_id", chainID,
		"duration", duration)

	return output, nil
}

// executeAgentInternal executes an agent internally
func (o *DefaultOrchestrator) executeAgentInternal(ctx context.Context, agentID string, input interface{}) (interface{}, error) {
	// Get agent
	o.mutex.RLock()
	agent, exists := o.agents[agentID]
	o.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("agent %s not found", agentID)
	}

	// Execute with timeout
	execCtx, cancel := context.WithTimeout(ctx, o.config.DefaultTimeout)
	defer cancel()

	startTime := time.Now()
	output, err := agent.Execute(execCtx, input.(AgentInput))
	duration := time.Since(startTime)

	if err != nil {
		o.logger.Error("Agent execution failed",
			"agent_id", agentID,
			"error", err,
			"duration", duration)
		return nil, err
	}

	o.logger.Info("Agent executed successfully",
		"agent_id", agentID,
		"duration", duration)

	return output, nil
}

// Agent operations

// RegisterAgent registers a new agent
func (o *DefaultOrchestrator) RegisterAgent(agent Agent) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if agent == nil {
		return fmt.Errorf("agent cannot be nil")
	}

	if err := agent.Validate(); err != nil {
		return fmt.Errorf("agent validation failed: %w", err)
	}

	agentID := agent.ID()
	if _, exists := o.agents[agentID]; exists {
		return fmt.Errorf("agent %s already registered", agentID)
	}

	o.agents[agentID] = agent
	o.stats.RegisteredAgents = len(o.agents)

	o.logger.Info("Agent registered",
		"agent_id", agentID,
		"agent_name", agent.Name())

	return nil
}

// UnregisterAgent unregisters an agent
func (o *DefaultOrchestrator) UnregisterAgent(agentID string) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if _, exists := o.agents[agentID]; !exists {
		return fmt.Errorf("agent %s not found", agentID)
	}

	delete(o.agents, agentID)
	o.stats.RegisteredAgents = len(o.agents)

	o.logger.Info("Agent unregistered", "agent_id", agentID)
	return nil
}

// ExecuteAgent executes an agent synchronously
func (o *DefaultOrchestrator) ExecuteAgent(ctx context.Context, agentID string, input AgentInput) (AgentOutput, error) {
	ctx, span := o.tracer.Start(ctx, "orchestrator.execute_agent",
		trace.WithAttributes(
			attribute.String("agent.id", agentID),
		),
	)
	defer span.End()

	// Acquire execution slot
	select {
	case o.executionPool <- struct{}{}:
		defer func() { <-o.executionPool }()
	case <-ctx.Done():
		return AgentOutput{}, ctx.Err()
	}

	atomic.AddInt64(&o.activeExecutions, 1)
	defer atomic.AddInt64(&o.activeExecutions, -1)

	result, err := o.executeAgentInternal(ctx, agentID, input)
	if err != nil {
		return AgentOutput{}, err
	}
	return result.(AgentOutput), nil
}

// ExecuteAgentAsync executes an agent asynchronously
func (o *DefaultOrchestrator) ExecuteAgentAsync(ctx context.Context, agentID string, input AgentInput) (<-chan OrchestratorResult, error) {
	resultChan := make(chan OrchestratorResult, 1)

	request := &OrchestratorRequest{
		Type:        "agent",
		ID:          agentID,
		Input:       input,
		Context:     ctx,
		ResultChan:  resultChan,
		SubmittedAt: time.Now(),
	}

	select {
	case o.requestQueue <- request:
		atomic.AddInt64(&o.queueDepth, 1)
		return resultChan, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, fmt.Errorf("request queue is full")
	}
}

// ExecuteGraphAsync executes a graph asynchronously
func (o *DefaultOrchestrator) ExecuteGraphAsync(ctx context.Context, graphID string, state GraphState) (<-chan OrchestratorResult, error) {
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
		atomic.AddInt64(&o.queueDepth, 1)
		return resultChan, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, fmt.Errorf("request queue is full")
	}
}

// ListAgents returns information about all registered agents
func (o *DefaultOrchestrator) ListAgents() []AgentInfo {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	agents := make([]AgentInfo, 0, len(o.agents))
	for _, agent := range o.agents {
		agents = append(agents, AgentInfo{
			ID:          agent.ID(),
			Name:        agent.Name(),
			Description: agent.Description(),
			ToolCount:   len(agent.GetAvailableTools()),
			Metrics:     agent.GetMetrics(),
			CreatedAt:   time.Now(), // TODO: Add CreatedAt to agent interface
		})
	}

	return agents
}

// ListGraphs returns information about all registered graphs
func (o *DefaultOrchestrator) ListGraphs() []GraphInfo {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	graphs := make([]GraphInfo, 0, len(o.graphs))
	for _, graph := range o.graphs {
		graphs = append(graphs, GraphInfo{
			ID:          graph.ID(),
			Name:        graph.Name(),
			Description: graph.Description(),
			NodeCount:   len(graph.GetNodes()),
			Metrics:     graph.GetMetrics(),
			CreatedAt:   time.Now(), // TODO: Add CreatedAt to graph interface
		})
	}

	return graphs
}

// Tool operations

// RegisterTool registers a new tool
func (o *DefaultOrchestrator) RegisterTool(tool Tool) error {
	if err := o.toolRegistry.RegisterTool(tool); err != nil {
		return err
	}

	o.mutex.Lock()
	o.stats.RegisteredTools = len(o.toolRegistry.ListTools())
	o.mutex.Unlock()

	return nil
}

// UnregisterTool unregisters a tool
func (o *DefaultOrchestrator) UnregisterTool(toolName string) error {
	if err := o.toolRegistry.UnregisterTool(toolName); err != nil {
		return err
	}

	o.mutex.Lock()
	o.stats.RegisteredTools = len(o.toolRegistry.ListTools())
	o.mutex.Unlock()

	return nil
}

// GetTool retrieves a tool by name
func (o *DefaultOrchestrator) GetTool(toolName string) (Tool, error) {
	return o.toolRegistry.GetTool(toolName)
}

// ListTools returns a list of all registered tool names
func (o *DefaultOrchestrator) ListTools() []string {
	return o.toolRegistry.ListTools()
}
