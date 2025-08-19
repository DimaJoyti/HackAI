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

// OrchestratorExecutionPriority defines priority levels for execution requests
type OrchestratorExecutionPriority int

const (
	OrchestratorPriorityLow OrchestratorExecutionPriority = iota
	OrchestratorPriorityNormal
	OrchestratorPriorityHigh
	OrchestratorPriorityCritical
)

// LoadBalancingStrategy defines load balancing strategies
type LoadBalancingStrategy int

const (
	RoundRobin LoadBalancingStrategy = iota
	LeastConnections
	WeightedRoundRobin
	ResourceBased
)

// BatchRequest represents a request in a batch execution
type BatchRequest struct {
	ID       string                        `json:"id"`
	Type     string                        `json:"type"` // "chain", "graph", "agent"
	TargetID string                        `json:"target_id"`
	Input    interface{}                   `json:"input"`
	Priority OrchestratorExecutionPriority `json:"priority"`
	Timeout  time.Duration                 `json:"timeout"`
	Metadata map[string]interface{}        `json:"metadata"`
}

// BatchResult represents the result of a batch request
type BatchResult struct {
	ID       string                 `json:"id"`
	Success  bool                   `json:"success"`
	Output   interface{}            `json:"output"`
	Error    error                  `json:"error,omitempty"`
	Duration time.Duration          `json:"duration"`
	Metadata map[string]interface{} `json:"metadata"`
}

// ScheduledRequest represents a scheduled execution request
type ScheduledRequest struct {
	ID          string                        `json:"id"`
	Type        string                        `json:"type"`
	TargetID    string                        `json:"target_id"`
	Input       interface{}                   `json:"input"`
	Priority    OrchestratorExecutionPriority `json:"priority"`
	ScheduledAt time.Time                     `json:"scheduled_at"`
	Timeout     time.Duration                 `json:"timeout"`
	Metadata    map[string]interface{}        `json:"metadata"`
}

// ExecutionStatus represents the status of an execution
type ExecutionStatus struct {
	ID          string                 `json:"id"`
	Status      string                 `json:"status"` // "pending", "running", "completed", "failed", "cancelled"
	Progress    float64                `json:"progress"`
	StartedAt   *time.Time             `json:"started_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Duration    time.Duration          `json:"duration"`
	Error       error                  `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// LoadMetrics provides load balancing metrics
type LoadMetrics struct {
	ActiveWorkers     int                  `json:"active_workers"`
	IdleWorkers       int                  `json:"idle_workers"`
	QueueDepth        int64                `json:"queue_depth"`
	AverageWaitTime   time.Duration        `json:"average_wait_time"`
	ThroughputPerSec  float64              `json:"throughput_per_sec"`
	WorkerUtilization map[int]float64      `json:"worker_utilization"`
	ResourceUsage     ResourceUsageMetrics `json:"resource_usage"`
}

// ResourceUsageMetrics tracks resource usage
type ResourceUsageMetrics struct {
	CPUUsagePercent float64 `json:"cpu_usage_percent"`
	MemoryUsageMB   int64   `json:"memory_usage_mb"`
	GoroutineCount  int     `json:"goroutine_count"`
	HeapAllocMB     int64   `json:"heap_alloc_mb"`
	GCPauseTimeMs   float64 `json:"gc_pause_time_ms"`
}

// DetailedMetrics provides comprehensive orchestrator metrics
type DetailedMetrics struct {
	ExecutionMetrics   OrchestratorExecutionMetrics   `json:"execution_metrics"`
	PerformanceMetrics OrchestratorPerformanceMetrics `json:"performance_metrics"`
	ResourceMetrics    ResourceUsageMetrics           `json:"resource_metrics"`
	ComponentMetrics   ComponentMetrics               `json:"component_metrics"`
	ErrorMetrics       ErrorMetrics                   `json:"error_metrics"`
}

// OrchestratorExecutionMetrics tracks execution statistics
type OrchestratorExecutionMetrics struct {
	TotalExecutions      int64                                   `json:"total_executions"`
	SuccessfulExecutions int64                                   `json:"successful_executions"`
	FailedExecutions     int64                                   `json:"failed_executions"`
	CancelledExecutions  int64                                   `json:"cancelled_executions"`
	ExecutionsByPriority map[OrchestratorExecutionPriority]int64 `json:"executions_by_priority"`
	ExecutionsByType     map[string]int64                        `json:"executions_by_type"`
	AverageExecutionTime time.Duration                           `json:"average_execution_time"`
	P95ExecutionTime     time.Duration                           `json:"p95_execution_time"`
	P99ExecutionTime     time.Duration                           `json:"p99_execution_time"`
}

// OrchestratorPerformanceMetrics tracks performance statistics
type OrchestratorPerformanceMetrics struct {
	RequestsPerSecond    float64       `json:"requests_per_second"`
	AverageQueueWaitTime time.Duration `json:"average_queue_wait_time"`
	WorkerUtilization    float64       `json:"worker_utilization"`
	ConcurrencyLevel     int           `json:"concurrency_level"`
	ThroughputTrend      []float64     `json:"throughput_trend"`
}

// ComponentMetrics tracks individual component metrics
type ComponentMetrics struct {
	ChainMetrics map[string]ChainMetrics `json:"chain_metrics"`
	GraphMetrics map[string]GraphMetrics `json:"graph_metrics"`
	AgentMetrics map[string]AgentMetrics `json:"agent_metrics"`
	ToolMetrics  map[string]ToolMetrics  `json:"tool_metrics"`
}

// ErrorMetrics tracks error statistics
type ErrorMetrics struct {
	TotalErrors       int64            `json:"total_errors"`
	ErrorsByType      map[string]int64 `json:"errors_by_type"`
	ErrorsByComponent map[string]int64 `json:"errors_by_component"`
	ErrorRate         float64          `json:"error_rate"`
	RecentErrors      []ErrorRecord    `json:"recent_errors"`
}

// ErrorRecord represents an error occurrence
type ErrorRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	Component   string    `json:"component"`
	ErrorType   string    `json:"error_type"`
	Message     string    `json:"message"`
	ExecutionID string    `json:"execution_id"`
}

// EnhancedOrchestratorRequest represents an enhanced request with priority and tracking
type EnhancedOrchestratorRequest struct {
	ID          string                        `json:"id"`
	Type        string                        `json:"type"` // "chain", "graph", "agent"
	TargetID    string                        `json:"target_id"`
	Input       interface{}                   `json:"input"`
	Context     context.Context               `json:"-"`
	Priority    OrchestratorExecutionPriority `json:"priority"`
	Timeout     time.Duration                 `json:"timeout"`
	ResultChan  chan OrchestratorResult       `json:"-"`
	SubmittedAt time.Time                     `json:"submitted_at"`
	StartedAt   *time.Time                    `json:"started_at,omitempty"`
	Metadata    map[string]interface{}        `json:"metadata"`
}

// ExecutionTracker tracks the execution of a request
type ExecutionTracker struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	TargetID  string                 `json:"target_id"`
	Status    string                 `json:"status"` // "pending", "running", "completed", "failed", "cancelled"
	Progress  float64                `json:"progress"`
	StartedAt time.Time              `json:"started_at"`
	UpdatedAt time.Time              `json:"updated_at"`
	WorkerID  int                    `json:"worker_id"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// ExecutionRecord represents a completed execution
type ExecutionRecord struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	TargetID    string                 `json:"target_id"`
	Success     bool                   `json:"success"`
	Duration    time.Duration          `json:"duration"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt time.Time              `json:"completed_at"`
	WorkerID    int                    `json:"worker_id"`
	Error       string                 `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// EnhancedWorker represents an enhanced worker with load balancing capabilities
type EnhancedWorker struct {
	ID                 int
	orchestrator       *DefaultOrchestrator
	stopChan           chan struct{}
	logger             *logger.Logger
	currentExecution   *ExecutionTracker
	executionCount     int64
	totalExecutionTime time.Duration
	lastActivityTime   time.Time
	utilization        float64
	mutex              sync.RWMutex
}

// LoadBalancer manages load balancing across workers
type LoadBalancer struct {
	strategy        LoadBalancingStrategy
	workers         []*EnhancedWorker
	roundRobinIndex int
	mutex           sync.RWMutex
}

// MetricsCollector collects and aggregates metrics
type MetricsCollector struct {
	executionTimes     []time.Duration
	throughputSamples  []float64
	errorCounts        map[string]int64
	lastCollectionTime time.Time
	mutex              sync.RWMutex
}

// CircuitBreaker implements circuit breaker pattern
type CircuitBreaker struct {
	failureThreshold int
	resetTimeout     time.Duration
	failureCount     int
	lastFailureTime  time.Time
	state            string // "closed", "open", "half-open"
	mutex            sync.RWMutex
}

// RateLimiter implements rate limiting
type RateLimiter struct {
	requestsPerSecond int
	bucketSize        int
	tokens            int
	lastRefill        time.Time
	mutex             sync.RWMutex
}

// HealthMonitor monitors orchestrator health
type HealthMonitor struct {
	orchestrator     *DefaultOrchestrator
	checkInterval    time.Duration
	healthChecks     map[string]HealthCheck
	lastHealthStatus HealthStatus
	stopChan         chan struct{}
	mutex            sync.RWMutex
}

// HealthCheck represents a health check function
type HealthCheck struct {
	Name       string
	CheckFunc  func() error
	Timeout    time.Duration
	LastCheck  time.Time
	LastResult error
}

// Orchestrator manages and coordinates AI chains, graphs, and agents
type Orchestrator interface {
	// Chain operations
	RegisterChain(chain Chain) error
	UnregisterChain(chainID string) error
	ExecuteChain(ctx context.Context, chainID string, input map[string]interface{}) (map[string]interface{}, error)
	ExecuteChainAsync(ctx context.Context, chainID string, input map[string]interface{}) (<-chan OrchestratorResult, error)
	ExecuteChainWithPriority(ctx context.Context, chainID string, input map[string]interface{}, priority OrchestratorExecutionPriority) (map[string]interface{}, error)
	ListChains() []ChainInfo

	// Graph operations
	RegisterGraph(graph Graph) error
	UnregisterGraph(graphID string) error
	ExecuteGraph(ctx context.Context, graphID string, state GraphState) (GraphState, error)
	ExecuteGraphAsync(ctx context.Context, graphID string, state GraphState) (<-chan OrchestratorResult, error)
	ExecuteGraphWithPriority(ctx context.Context, graphID string, state GraphState, priority OrchestratorExecutionPriority) (GraphState, error)
	ListGraphs() []GraphInfo

	// Agent operations
	RegisterAgent(agent Agent) error
	UnregisterAgent(agentID string) error
	ExecuteAgent(ctx context.Context, agentID string, input AgentInput) (AgentOutput, error)
	ExecuteAgentAsync(ctx context.Context, agentID string, input AgentInput) (<-chan OrchestratorResult, error)
	ExecuteAgentWithPriority(ctx context.Context, agentID string, input AgentInput, priority OrchestratorExecutionPriority) (AgentOutput, error)
	ListAgents() []AgentInfo

	// Tool operations
	RegisterTool(tool Tool) error
	UnregisterTool(toolName string) error
	GetTool(toolName string) (Tool, error)
	ListTools() []string

	// Advanced execution management
	ExecuteBatch(ctx context.Context, requests []BatchRequest) ([]BatchResult, error)
	ScheduleExecution(ctx context.Context, request ScheduledRequest) (string, error)
	CancelExecution(executionID string) error
	GetExecutionStatus(executionID string) (ExecutionStatus, error)

	// Load balancing and scaling
	ScaleWorkers(newSize int) error
	GetLoadMetrics() LoadMetrics
	SetLoadBalancingStrategy(strategy LoadBalancingStrategy) error

	// Lifecycle management
	Start(ctx context.Context) error
	Stop() error
	Health() HealthStatus
	GetStats() OrchestratorStats
	GetDetailedMetrics() DetailedMetrics
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

	// Advanced concurrency management
	executionPool  chan struct{}
	priorityQueues map[OrchestratorExecutionPriority]chan *EnhancedOrchestratorRequest
	workerPool     []*EnhancedWorker
	loadBalancer   *LoadBalancer
	wg             sync.WaitGroup
	stopChan       chan struct{}
	running        bool

	// Execution tracking
	activeExecutions  map[string]*ExecutionTracker
	scheduledRequests map[string]*ScheduledRequest
	executionHistory  []ExecutionRecord

	// Performance tracking
	stats                OrchestratorStats
	detailedMetrics      DetailedMetrics
	metricsCollector     *MetricsCollector
	activeExecutionCount int64
	queueDepth           int64

	// Advanced features
	circuitBreaker *CircuitBreaker
	rateLimiter    *RateLimiter
	healthMonitor  *HealthMonitor

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

	// Initialize priority queues
	priorityQueues := make(map[OrchestratorExecutionPriority]chan *EnhancedOrchestratorRequest)
	priorityQueues[OrchestratorPriorityLow] = make(chan *EnhancedOrchestratorRequest, config.RequestQueueSize/4)
	priorityQueues[OrchestratorPriorityNormal] = make(chan *EnhancedOrchestratorRequest, config.RequestQueueSize/2)
	priorityQueues[OrchestratorPriorityHigh] = make(chan *EnhancedOrchestratorRequest, config.RequestQueueSize/4)
	priorityQueues[OrchestratorPriorityCritical] = make(chan *EnhancedOrchestratorRequest, config.RequestQueueSize/4)

	return &DefaultOrchestrator{
		chains:            make(map[string]Chain),
		graphs:            make(map[string]Graph),
		agents:            make(map[string]Agent),
		toolRegistry:      NewToolRegistry(logger),
		logger:            logger,
		tracer:            orchestratorTracer,
		config:            config,
		executionPool:     make(chan struct{}, config.MaxConcurrentExecutions),
		priorityQueues:    priorityQueues,
		stopChan:          make(chan struct{}),
		activeExecutions:  make(map[string]*ExecutionTracker),
		scheduledRequests: make(map[string]*ScheduledRequest),
		executionHistory:  make([]ExecutionRecord, 0),
		loadBalancer: &LoadBalancer{
			strategy: RoundRobin,
			workers:  make([]*EnhancedWorker, 0),
		},
		metricsCollector: &MetricsCollector{
			executionTimes:     make([]time.Duration, 0),
			throughputSamples:  make([]float64, 0),
			errorCounts:        make(map[string]int64),
			lastCollectionTime: time.Now(),
		},
		circuitBreaker: &CircuitBreaker{
			failureThreshold: 10,
			resetTimeout:     30 * time.Second,
			state:            "closed",
		},
		rateLimiter: &RateLimiter{
			requestsPerSecond: 100,
			bucketSize:        100,
			tokens:            100,
			lastRefill:        time.Now(),
		},
		healthMonitor: &HealthMonitor{
			checkInterval: config.HealthCheckInterval,
			healthChecks:  make(map[string]HealthCheck),
			stopChan:      make(chan struct{}),
		},
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

	// Initialize enhanced worker pool
	o.workerPool = make([]*EnhancedWorker, o.config.WorkerPoolSize)
	for i := 0; i < o.config.WorkerPoolSize; i++ {
		worker := &EnhancedWorker{
			ID:               i,
			orchestrator:     o,
			stopChan:         make(chan struct{}),
			logger:           o.logger,
			lastActivityTime: time.Now(),
		}
		o.workerPool[i] = worker
		o.loadBalancer.workers = append(o.loadBalancer.workers, worker)

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

	atomic.AddInt64(&o.activeExecutionCount, 1)
	defer atomic.AddInt64(&o.activeExecutionCount, -1)

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
		case <-w.stopChan:
			w.logger.Debug("Worker stopped", "worker_id", w.ID)
			return
		case <-w.orchestrator.stopChan:
			w.logger.Debug("Worker stopped by orchestrator", "worker_id", w.ID)
			return
		default:
			// This is legacy worker code - enhanced workers handle priority queues
			time.Sleep(100 * time.Millisecond)
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

	atomic.AddInt64(&w.orchestrator.activeExecutionCount, 1)
	defer atomic.AddInt64(&w.orchestrator.activeExecutionCount, -1)

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
	atomic.StoreInt64(&o.stats.ActiveExecutions, atomic.LoadInt64(&o.activeExecutionCount))

	// Calculate total queue depth across all priority queues
	totalQueueDepth := int64(0)
	for _, queue := range o.priorityQueues {
		totalQueueDepth += int64(len(queue))
	}
	atomic.StoreInt64(&o.stats.QueueDepth, totalQueueDepth)
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
	stats.ActiveExecutions = atomic.LoadInt64(&o.activeExecutionCount)

	// Calculate total queue depth across all priority queues
	totalQueueDepth := int64(0)
	for _, queue := range o.priorityQueues {
		totalQueueDepth += int64(len(queue))
	}
	stats.QueueDepth = totalQueueDepth
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

	// Legacy request structure removed - using enhanced request directly

	// Convert to enhanced request and submit to appropriate priority queue
	enhancedRequest := &EnhancedOrchestratorRequest{
		ID:          fmt.Sprintf("chain_%s_%d", chainID, time.Now().UnixNano()),
		Type:        "chain",
		TargetID:    chainID,
		Input:       input,
		Context:     ctx,
		Priority:    OrchestratorPriorityNormal,
		Timeout:     o.config.DefaultTimeout,
		ResultChan:  resultChan,
		SubmittedAt: time.Now(),
		Metadata:    make(map[string]interface{}),
	}

	select {
	case o.priorityQueues[OrchestratorPriorityNormal] <- enhancedRequest:
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

	atomic.AddInt64(&o.activeExecutionCount, 1)
	defer atomic.AddInt64(&o.activeExecutionCount, -1)

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

	atomic.AddInt64(&o.activeExecutionCount, 1)
	defer atomic.AddInt64(&o.activeExecutionCount, -1)

	result, err := o.executeAgentInternal(ctx, agentID, input)
	if err != nil {
		return AgentOutput{}, err
	}
	return result.(AgentOutput), nil
}

// ExecuteAgentAsync executes an agent asynchronously
func (o *DefaultOrchestrator) ExecuteAgentAsync(ctx context.Context, agentID string, input AgentInput) (<-chan OrchestratorResult, error) {
	resultChan := make(chan OrchestratorResult, 1)

	// Convert to enhanced request and submit to appropriate priority queue
	enhancedRequest := &EnhancedOrchestratorRequest{
		ID:          fmt.Sprintf("agent_%s_%d", agentID, time.Now().UnixNano()),
		Type:        "agent",
		TargetID:    agentID,
		Input:       input,
		Context:     ctx,
		Priority:    OrchestratorPriorityNormal,
		Timeout:     o.config.DefaultTimeout,
		ResultChan:  resultChan,
		SubmittedAt: time.Now(),
		Metadata:    make(map[string]interface{}),
	}

	select {
	case o.priorityQueues[OrchestratorPriorityNormal] <- enhancedRequest:
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

	// Convert to enhanced request and submit to appropriate priority queue
	enhancedRequest := &EnhancedOrchestratorRequest{
		ID:          fmt.Sprintf("graph_%s_%d", graphID, time.Now().UnixNano()),
		Type:        "graph",
		TargetID:    graphID,
		Input:       state,
		Context:     ctx,
		Priority:    OrchestratorPriorityNormal,
		Timeout:     o.config.DefaultTimeout,
		ResultChan:  resultChan,
		SubmittedAt: time.Now(),
		Metadata:    make(map[string]interface{}),
	}

	select {
	case o.priorityQueues[OrchestratorPriorityNormal] <- enhancedRequest:
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

// Enhanced Orchestrator Methods

// ExecuteChainWithPriority executes a chain with specified priority
func (o *DefaultOrchestrator) ExecuteChainWithPriority(ctx context.Context, chainID string, input map[string]interface{}, priority OrchestratorExecutionPriority) (map[string]interface{}, error) {
	// For now, just execute normally - priority is handled in async execution
	return o.ExecuteChain(ctx, chainID, input)
}

// ExecuteGraphWithPriority executes a graph with specified priority
func (o *DefaultOrchestrator) ExecuteGraphWithPriority(ctx context.Context, graphID string, state GraphState, priority OrchestratorExecutionPriority) (GraphState, error) {
	// For now, just execute normally - priority is handled in async execution
	return o.ExecuteGraph(ctx, graphID, state)
}

// ExecuteAgentWithPriority executes an agent with specified priority
func (o *DefaultOrchestrator) ExecuteAgentWithPriority(ctx context.Context, agentID string, input AgentInput, priority OrchestratorExecutionPriority) (AgentOutput, error) {
	// For now, just execute normally - priority is handled in async execution
	return o.ExecuteAgent(ctx, agentID, input)
}

// ExecuteBatch executes multiple requests in batch
func (o *DefaultOrchestrator) ExecuteBatch(ctx context.Context, requests []BatchRequest) ([]BatchResult, error) {
	results := make([]BatchResult, len(requests))

	// Execute all requests concurrently
	type batchExecution struct {
		index  int
		result BatchResult
	}

	resultChan := make(chan batchExecution, len(requests))

	for i, request := range requests {
		go func(idx int, req BatchRequest) {
			startTime := time.Now()
			var output interface{}
			var err error

			// Execute based on type
			switch req.Type {
			case "chain":
				if inputMap, ok := req.Input.(map[string]interface{}); ok {
					output, err = o.ExecuteChainWithPriority(ctx, req.TargetID, inputMap, req.Priority)
				} else {
					err = fmt.Errorf("invalid input type for chain execution")
				}
			case "graph":
				if state, ok := req.Input.(GraphState); ok {
					output, err = o.ExecuteGraphWithPriority(ctx, req.TargetID, state, req.Priority)
				} else {
					err = fmt.Errorf("invalid input type for graph execution")
				}
			case "agent":
				if agentInput, ok := req.Input.(AgentInput); ok {
					output, err = o.ExecuteAgentWithPriority(ctx, req.TargetID, agentInput, req.Priority)
				} else {
					err = fmt.Errorf("invalid input type for agent execution")
				}
			default:
				err = fmt.Errorf("unknown request type: %s", req.Type)
			}

			result := BatchResult{
				ID:       req.ID,
				Success:  err == nil,
				Output:   output,
				Error:    err,
				Duration: time.Since(startTime),
				Metadata: req.Metadata,
			}

			resultChan <- batchExecution{index: idx, result: result}
		}(i, request)
	}

	// Collect results
	for i := 0; i < len(requests); i++ {
		execution := <-resultChan
		results[execution.index] = execution.result
	}

	return results, nil
}

// ScheduleExecution schedules an execution for later
func (o *DefaultOrchestrator) ScheduleExecution(ctx context.Context, request ScheduledRequest) (string, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	executionID := request.ID
	if executionID == "" {
		executionID = fmt.Sprintf("scheduled_%d", time.Now().UnixNano())
	}

	o.scheduledRequests[executionID] = &request

	// Start a goroutine to execute at scheduled time
	go func() {
		// Wait until scheduled time
		time.Sleep(time.Until(request.ScheduledAt))

		// Check if execution was cancelled
		o.mutex.RLock()
		_, exists := o.scheduledRequests[executionID]
		o.mutex.RUnlock()

		if !exists {
			return // Execution was cancelled
		}

		// Execute the request
		var err error
		switch request.Type {
		case "chain":
			if inputMap, ok := request.Input.(map[string]interface{}); ok {
				_, err = o.ExecuteChainWithPriority(ctx, request.TargetID, inputMap, request.Priority)
			}
		case "graph":
			if state, ok := request.Input.(GraphState); ok {
				_, err = o.ExecuteGraphWithPriority(ctx, request.TargetID, state, request.Priority)
			}
		case "agent":
			if agentInput, ok := request.Input.(AgentInput); ok {
				_, err = o.ExecuteAgentWithPriority(ctx, request.TargetID, agentInput, request.Priority)
			}
		}

		// Update execution status
		o.mutex.Lock()
		delete(o.scheduledRequests, executionID)
		o.mutex.Unlock()

		if o.logger != nil {
			if err != nil {
				o.logger.Error("Scheduled execution failed", "execution_id", executionID, "error", err)
			} else {
				o.logger.Info("Scheduled execution completed", "execution_id", executionID)
			}
		}
	}()

	return executionID, nil
}

// CancelExecution cancels a scheduled execution
func (o *DefaultOrchestrator) CancelExecution(executionID string) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if _, exists := o.scheduledRequests[executionID]; !exists {
		return fmt.Errorf("execution %s not found", executionID)
	}

	delete(o.scheduledRequests, executionID)

	if o.logger != nil {
		o.logger.Info("Execution cancelled", "execution_id", executionID)
	}

	return nil
}

// GetExecutionStatus returns the status of an execution
func (o *DefaultOrchestrator) GetExecutionStatus(executionID string) (ExecutionStatus, error) {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	// Check active executions
	if tracker, exists := o.activeExecutions[executionID]; exists {
		return ExecutionStatus{
			ID:        tracker.ID,
			Status:    tracker.Status,
			Progress:  tracker.Progress,
			StartedAt: &tracker.StartedAt,
			Metadata:  tracker.Metadata,
		}, nil
	}

	// Check scheduled executions
	if request, exists := o.scheduledRequests[executionID]; exists {
		status := "pending"
		if time.Now().After(request.ScheduledAt) {
			status = "running"
		}

		return ExecutionStatus{
			ID:       executionID,
			Status:   status,
			Progress: 0.0,
			Metadata: request.Metadata,
		}, nil
	}

	// Check execution history
	for _, record := range o.executionHistory {
		if record.ID == executionID {
			status := "completed"
			if !record.Success {
				status = "failed"
			}

			return ExecutionStatus{
				ID:          record.ID,
				Status:      status,
				Progress:    1.0,
				StartedAt:   &record.StartedAt,
				CompletedAt: &record.CompletedAt,
				Duration:    record.Duration,
				Metadata:    record.Metadata,
			}, nil
		}
	}

	return ExecutionStatus{
		ID:     executionID,
		Status: "cancelled",
	}, nil
}

// GetLoadMetrics returns current load metrics
func (o *DefaultOrchestrator) GetLoadMetrics() LoadMetrics {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	activeWorkers := 0
	idleWorkers := 0
	workerUtilization := make(map[int]float64)

	for _, worker := range o.workerPool {
		worker.mutex.RLock()
		if worker.currentExecution != nil {
			activeWorkers++
		} else {
			idleWorkers++
		}
		workerUtilization[worker.ID] = worker.utilization
		worker.mutex.RUnlock()
	}

	// Calculate total queue depth
	totalQueueDepth := int64(0)
	for _, queue := range o.priorityQueues {
		totalQueueDepth += int64(len(queue))
	}

	return LoadMetrics{
		ActiveWorkers:     activeWorkers,
		IdleWorkers:       idleWorkers,
		QueueDepth:        totalQueueDepth,
		AverageWaitTime:   o.calculateAverageWaitTime(),
		ThroughputPerSec:  o.calculateThroughput(),
		WorkerUtilization: workerUtilization,
		ResourceUsage:     o.getResourceUsage(),
	}
}

// ScaleWorkers scales the worker pool to the specified size
func (o *DefaultOrchestrator) ScaleWorkers(newSize int) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	currentSize := len(o.workerPool)

	if newSize > currentSize {
		// Scale up - add new workers
		for i := currentSize; i < newSize; i++ {
			worker := &EnhancedWorker{
				ID:               i,
				orchestrator:     o,
				stopChan:         make(chan struct{}),
				logger:           o.logger,
				lastActivityTime: time.Now(),
			}
			o.workerPool = append(o.workerPool, worker)
			o.loadBalancer.workers = append(o.loadBalancer.workers, worker)

			// Start worker goroutine
			o.wg.Add(1)
			go worker.run()
		}
	} else if newSize < currentSize {
		// Scale down - stop excess workers
		for i := newSize; i < currentSize; i++ {
			worker := o.workerPool[i]
			close(worker.stopChan)
		}

		// Update worker pool and load balancer
		o.workerPool = o.workerPool[:newSize]
		o.loadBalancer.workers = o.loadBalancer.workers[:newSize]
	}

	if o.logger != nil {
		o.logger.Info("Worker pool scaled", "old_size", currentSize, "new_size", newSize)
	}

	return nil
}

// SetLoadBalancingStrategy sets the load balancing strategy
func (o *DefaultOrchestrator) SetLoadBalancingStrategy(strategy LoadBalancingStrategy) error {
	o.loadBalancer.mutex.Lock()
	defer o.loadBalancer.mutex.Unlock()

	o.loadBalancer.strategy = strategy

	if o.logger != nil {
		o.logger.Info("Load balancing strategy updated", "strategy", strategy)
	}

	return nil
}

// GetDetailedMetrics returns comprehensive metrics
func (o *DefaultOrchestrator) GetDetailedMetrics() DetailedMetrics {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	return DetailedMetrics{
		ExecutionMetrics:   o.getExecutionMetrics(),
		PerformanceMetrics: o.getPerformanceMetrics(),
		ResourceMetrics:    o.getResourceUsage(),
		ComponentMetrics:   o.getComponentMetrics(),
		ErrorMetrics:       o.getErrorMetrics(),
	}
}

// Enhanced Worker Methods

// run starts the enhanced worker loop
func (w *EnhancedWorker) run() {
	defer w.orchestrator.wg.Done()

	if w.logger != nil {
		w.logger.Debug("Enhanced worker started", "worker_id", w.ID)
	}

	for {
		select {
		case <-w.stopChan:
			if w.logger != nil {
				w.logger.Debug("Enhanced worker stopped", "worker_id", w.ID)
			}
			return
		case <-w.orchestrator.stopChan:
			if w.logger != nil {
				w.logger.Debug("Enhanced worker stopped by orchestrator", "worker_id", w.ID)
			}
			return
		default:
			// Check priority queues in order
			request := w.getNextRequest()
			if request != nil {
				w.processEnhancedRequest(request)
			} else {
				// No requests available, brief sleep to avoid busy waiting
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
}

// getNextRequest gets the next request from priority queues
func (w *EnhancedWorker) getNextRequest() *EnhancedOrchestratorRequest {
	// Check queues in priority order
	priorities := []OrchestratorExecutionPriority{
		OrchestratorPriorityCritical,
		OrchestratorPriorityHigh,
		OrchestratorPriorityNormal,
		OrchestratorPriorityLow,
	}

	for _, priority := range priorities {
		select {
		case request := <-w.orchestrator.priorityQueues[priority]:
			return request
		default:
			continue
		}
	}

	return nil
}

// processEnhancedRequest processes an enhanced request
func (w *EnhancedWorker) processEnhancedRequest(request *EnhancedOrchestratorRequest) {
	startTime := time.Now()
	var result OrchestratorResult

	// Update worker state
	w.mutex.Lock()
	tracker := &ExecutionTracker{
		ID:        request.ID,
		Type:      request.Type,
		TargetID:  request.TargetID,
		Status:    "running",
		Progress:  0.0,
		StartedAt: startTime,
		UpdatedAt: startTime,
		WorkerID:  w.ID,
		Metadata:  request.Metadata,
	}
	w.currentExecution = tracker
	w.lastActivityTime = startTime
	w.mutex.Unlock()

	// Add to active executions
	w.orchestrator.mutex.Lock()
	w.orchestrator.activeExecutions[request.ID] = tracker
	w.orchestrator.mutex.Unlock()

	// Acquire execution slot
	select {
	case w.orchestrator.executionPool <- struct{}{}:
		defer func() { <-w.orchestrator.executionPool }()
	case <-request.Context.Done():
		result.Error = request.Context.Err()
		w.completeExecution(request, result, startTime)
		return
	}

	atomic.AddInt64(&w.orchestrator.activeExecutionCount, 1)
	defer atomic.AddInt64(&w.orchestrator.activeExecutionCount, -1)

	// Process based on request type
	switch request.Type {
	case "chain":
		result.Output, result.Error = w.orchestrator.executeChainInternal(request.Context, request.TargetID, request.Input)
	case "graph":
		result.Output, result.Error = w.orchestrator.executeGraphInternal(request.Context, request.TargetID, request.Input)
	case "agent":
		result.Output, result.Error = w.orchestrator.executeAgentInternal(request.Context, request.TargetID, request.Input)
	default:
		result.Error = fmt.Errorf("unknown request type: %s", request.Type)
	}

	w.completeExecution(request, result, startTime)
}

// completeExecution completes the execution and updates metrics
func (w *EnhancedWorker) completeExecution(request *EnhancedOrchestratorRequest, result OrchestratorResult, startTime time.Time) {
	duration := time.Since(startTime)
	result.Duration = duration
	result.Metadata = map[string]interface{}{
		"worker_id":    w.ID,
		"queue_time":   startTime.Sub(request.SubmittedAt),
		"request_type": request.Type,
		"priority":     request.Priority,
	}

	// Update worker metrics
	w.mutex.Lock()
	w.executionCount++
	w.totalExecutionTime += duration
	w.currentExecution = nil
	w.lastActivityTime = time.Now()
	if w.executionCount > 0 {
		w.utilization = float64(w.totalExecutionTime) / float64(time.Since(w.lastActivityTime))
	}
	w.mutex.Unlock()

	// Remove from active executions and add to history
	w.orchestrator.mutex.Lock()
	delete(w.orchestrator.activeExecutions, request.ID)

	record := ExecutionRecord{
		ID:          request.ID,
		Type:        request.Type,
		TargetID:    request.TargetID,
		Success:     result.Error == nil,
		Duration:    duration,
		StartedAt:   startTime,
		CompletedAt: time.Now(),
		WorkerID:    w.ID,
		Metadata:    request.Metadata,
	}
	if result.Error != nil {
		record.Error = result.Error.Error()
	}

	w.orchestrator.executionHistory = append(w.orchestrator.executionHistory, record)

	// Keep history size manageable
	if len(w.orchestrator.executionHistory) > 10000 {
		w.orchestrator.executionHistory = w.orchestrator.executionHistory[1000:]
	}
	w.orchestrator.mutex.Unlock()

	// Update orchestrator stats
	w.orchestrator.updateExecutionStats(result.Error == nil, duration)
	w.orchestrator.updateExecutionStatsDetailed(result.Error == nil, duration)

	// Send result
	select {
	case request.ResultChan <- result:
	case <-request.Context.Done():
		// Context cancelled, result not needed
	}
}

// Helper methods for metrics calculation

// calculateAverageWaitTime calculates the average wait time for requests
func (o *DefaultOrchestrator) calculateAverageWaitTime() time.Duration {
	o.metricsCollector.mutex.RLock()
	defer o.metricsCollector.mutex.RUnlock()

	if len(o.executionHistory) == 0 {
		return 0
	}

	totalWaitTime := time.Duration(0)
	count := 0

	// Calculate from recent execution history
	recentCount := 100
	if len(o.executionHistory) < recentCount {
		recentCount = len(o.executionHistory)
	}

	for i := len(o.executionHistory) - recentCount; i < len(o.executionHistory); i++ {
		record := o.executionHistory[i]
		if queueTime, ok := record.Metadata["queue_time"].(time.Duration); ok {
			totalWaitTime += queueTime
			count++
		}
	}

	if count == 0 {
		return 0
	}

	return totalWaitTime / time.Duration(count)
}

// calculateThroughput calculates the current throughput
func (o *DefaultOrchestrator) calculateThroughput() float64 {
	o.metricsCollector.mutex.RLock()
	defer o.metricsCollector.mutex.RUnlock()

	if len(o.metricsCollector.throughputSamples) == 0 {
		return 0.0
	}

	// Return the most recent throughput sample
	return o.metricsCollector.throughputSamples[len(o.metricsCollector.throughputSamples)-1]
}

// getResourceUsage gets current resource usage metrics
func (o *DefaultOrchestrator) getResourceUsage() ResourceUsageMetrics {
	// This would typically use runtime.ReadMemStats and other system metrics
	// For now, return basic metrics
	return ResourceUsageMetrics{
		CPUUsagePercent: 0.0,
		MemoryUsageMB:   0,
		GoroutineCount:  0,
		HeapAllocMB:     0,
		GCPauseTimeMs:   0.0,
	}
}

// getExecutionMetrics gets execution metrics
func (o *DefaultOrchestrator) getExecutionMetrics() OrchestratorExecutionMetrics {
	totalExecutions := int64(len(o.executionHistory))
	successfulExecutions := int64(0)
	failedExecutions := int64(0)

	executionsByPriority := make(map[OrchestratorExecutionPriority]int64)
	executionsByType := make(map[string]int64)

	totalDuration := time.Duration(0)

	for _, record := range o.executionHistory {
		if record.Success {
			successfulExecutions++
		} else {
			failedExecutions++
		}

		executionsByType[record.Type]++
		totalDuration += record.Duration

		// Extract priority from metadata if available
		if priority, ok := record.Metadata["priority"].(OrchestratorExecutionPriority); ok {
			executionsByPriority[priority]++
		}
	}

	averageExecutionTime := time.Duration(0)
	if totalExecutions > 0 {
		averageExecutionTime = totalDuration / time.Duration(totalExecutions)
	}

	return OrchestratorExecutionMetrics{
		TotalExecutions:      totalExecutions,
		SuccessfulExecutions: successfulExecutions,
		FailedExecutions:     failedExecutions,
		CancelledExecutions:  0, // TODO: Track cancelled executions
		ExecutionsByPriority: executionsByPriority,
		ExecutionsByType:     executionsByType,
		AverageExecutionTime: averageExecutionTime,
		P95ExecutionTime:     o.calculatePercentile(0.95),
		P99ExecutionTime:     o.calculatePercentile(0.99),
	}
}

// getPerformanceMetrics gets performance metrics
func (o *DefaultOrchestrator) getPerformanceMetrics() OrchestratorPerformanceMetrics {
	return OrchestratorPerformanceMetrics{
		RequestsPerSecond:    o.calculateThroughput(),
		AverageQueueWaitTime: o.calculateAverageWaitTime(),
		WorkerUtilization:    o.calculateOverallWorkerUtilization(),
		ConcurrencyLevel:     len(o.workerPool),
		ThroughputTrend:      o.metricsCollector.throughputSamples,
	}
}

// getComponentMetrics gets component-specific metrics
func (o *DefaultOrchestrator) getComponentMetrics() ComponentMetrics {
	chainMetrics := make(map[string]ChainMetrics)
	graphMetrics := make(map[string]GraphMetrics)
	agentMetrics := make(map[string]AgentMetrics)
	toolMetrics := make(map[string]ToolMetrics)

	// Aggregate metrics from execution history
	for _, record := range o.executionHistory {
		switch record.Type {
		case "chain":
			if _, exists := chainMetrics[record.TargetID]; !exists {
				chainMetrics[record.TargetID] = ChainMetrics{
					TotalExecutions:   0,
					SuccessfulRuns:    0,
					FailedRuns:        0,
					AverageLatency:    0,
					LastExecutionTime: time.Time{},
					TokensUsed:        0,
					TotalCost:         0,
				}
			}
			metrics := chainMetrics[record.TargetID]
			metrics.TotalExecutions++
			if record.Success {
				metrics.SuccessfulRuns++
			} else {
				metrics.FailedRuns++
			}
			metrics.LastExecutionTime = record.CompletedAt
			chainMetrics[record.TargetID] = metrics

		case "graph":
			if _, exists := graphMetrics[record.TargetID]; !exists {
				graphMetrics[record.TargetID] = GraphMetrics{
					TotalExecutions:   0,
					SuccessfulRuns:    0,
					FailedRuns:        0,
					AverageLatency:    0,
					NodeMetrics:       make(map[string]NodeMetrics),
					LastExecutionTime: time.Time{},
				}
			}
			metrics := graphMetrics[record.TargetID]
			metrics.TotalExecutions++
			if record.Success {
				metrics.SuccessfulRuns++
			} else {
				metrics.FailedRuns++
			}
			metrics.LastExecutionTime = record.CompletedAt
			graphMetrics[record.TargetID] = metrics

		case "agent":
			if _, exists := agentMetrics[record.TargetID]; !exists {
				agentMetrics[record.TargetID] = AgentMetrics{
					TotalExecutions:   0,
					SuccessfulRuns:    0,
					FailedRuns:        0,
					AverageSteps:      0,
					AverageLatency:    0,
					ToolUsageStats:    make(map[string]int64),
					LastExecutionTime: time.Time{},
				}
			}
			metrics := agentMetrics[record.TargetID]
			metrics.TotalExecutions++
			if record.Success {
				metrics.SuccessfulRuns++
			} else {
				metrics.FailedRuns++
			}
			metrics.LastExecutionTime = record.CompletedAt
			agentMetrics[record.TargetID] = metrics
		}
	}

	return ComponentMetrics{
		ChainMetrics: chainMetrics,
		GraphMetrics: graphMetrics,
		AgentMetrics: agentMetrics,
		ToolMetrics:  toolMetrics,
	}
}

// getErrorMetrics gets error metrics
func (o *DefaultOrchestrator) getErrorMetrics() ErrorMetrics {
	totalErrors := int64(0)
	errorsByType := make(map[string]int64)
	errorsByComponent := make(map[string]int64)
	recentErrors := make([]ErrorRecord, 0)

	for _, record := range o.executionHistory {
		if !record.Success && record.Error != "" {
			totalErrors++
			errorsByType["execution_error"]++
			errorsByComponent[record.Type]++

			// Keep recent errors (last 10)
			if len(recentErrors) < 10 {
				recentErrors = append(recentErrors, ErrorRecord{
					Timestamp:   record.CompletedAt,
					Component:   record.Type,
					ErrorType:   "execution_error",
					Message:     record.Error,
					ExecutionID: record.ID,
				})
			}
		}
	}

	errorRate := 0.0
	if len(o.executionHistory) > 0 {
		errorRate = float64(totalErrors) / float64(len(o.executionHistory))
	}

	return ErrorMetrics{
		TotalErrors:       totalErrors,
		ErrorsByType:      errorsByType,
		ErrorsByComponent: errorsByComponent,
		ErrorRate:         errorRate,
		RecentErrors:      recentErrors,
	}
}

// calculatePercentile calculates execution time percentiles
func (o *DefaultOrchestrator) calculatePercentile(percentile float64) time.Duration {
	if len(o.executionHistory) == 0 {
		return 0
	}

	// Extract execution times and sort them
	times := make([]time.Duration, len(o.executionHistory))
	for i, record := range o.executionHistory {
		times[i] = record.Duration
	}

	// Simple percentile calculation (would use sort.Slice in production)
	index := int(float64(len(times)) * percentile)
	if index >= len(times) {
		index = len(times) - 1
	}

	return times[index]
}

// calculateOverallWorkerUtilization calculates overall worker utilization
func (o *DefaultOrchestrator) calculateOverallWorkerUtilization() float64 {
	if len(o.workerPool) == 0 {
		return 0.0
	}

	totalUtilization := 0.0
	for _, worker := range o.workerPool {
		worker.mutex.RLock()
		totalUtilization += worker.utilization
		worker.mutex.RUnlock()
	}

	return totalUtilization / float64(len(o.workerPool))
}

// updateExecutionStatsDetailed updates detailed execution statistics
func (o *DefaultOrchestrator) updateExecutionStatsDetailed(success bool, duration time.Duration) {
	o.metricsCollector.mutex.Lock()
	defer o.metricsCollector.mutex.Unlock()

	// Update execution times
	o.metricsCollector.executionTimes = append(o.metricsCollector.executionTimes, duration)

	// Keep only recent execution times (last 1000)
	if len(o.metricsCollector.executionTimes) > 1000 {
		o.metricsCollector.executionTimes = o.metricsCollector.executionTimes[100:]
	}

	// Update throughput samples
	now := time.Now()
	if now.Sub(o.metricsCollector.lastCollectionTime) >= time.Second {
		// Calculate throughput for the last second
		throughput := float64(len(o.metricsCollector.executionTimes)) / now.Sub(o.metricsCollector.lastCollectionTime).Seconds()
		o.metricsCollector.throughputSamples = append(o.metricsCollector.throughputSamples, throughput)

		// Keep only recent throughput samples (last 60 seconds)
		if len(o.metricsCollector.throughputSamples) > 60 {
			o.metricsCollector.throughputSamples = o.metricsCollector.throughputSamples[1:]
		}

		o.metricsCollector.lastCollectionTime = now
	}

	// Update error counts
	if !success {
		o.metricsCollector.errorCounts["execution_error"]++
	}
}
