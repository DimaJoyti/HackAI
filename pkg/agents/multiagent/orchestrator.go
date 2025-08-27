package multiagent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/agents"
	"github.com/dimajoyti/hackai/pkg/ai"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

var multiAgentTracer = otel.Tracer("hackai/agents/multiagent")

// TaskPriority represents task priority levels
type TaskPriority string

const (
	TaskPriorityLow      TaskPriority = "low"
	TaskPriorityMedium   TaskPriority = "medium"
	TaskPriorityHigh     TaskPriority = "high"
	TaskPriorityCritical TaskPriority = "critical"
)

// MultiAgentOrchestrator provides sophisticated multi-agent coordination
type MultiAgentOrchestrator struct {
	agents               map[string]ai.Agent
	coordinationEngine   *CoordinationEngine
	conflictResolver     *ConflictResolver
	collaborationManager *CollaborationManager
	taskScheduler        *TaskScheduler
	consensusEngine      *ConsensusEngine
	config               *OrchestratorConfig
	logger               *logger.Logger
	metrics              *OrchestratorMetrics
	running              bool
	stopChan             chan struct{}
	wg                   sync.WaitGroup
	mutex                sync.RWMutex
}

// OrchestratorConfig configures the multi-agent orchestrator
type OrchestratorConfig struct {
	MaxConcurrentTasks     int           `json:"max_concurrent_tasks"`
	TaskTimeout            time.Duration `json:"task_timeout"`
	ConflictResolutionMode string        `json:"conflict_resolution_mode"` // "voting", "priority", "consensus"
	ConsensusThreshold     float64       `json:"consensus_threshold"`
	EnableLoadBalancing    bool          `json:"enable_load_balancing"`
	EnableFailover         bool          `json:"enable_failover"`
	HealthCheckInterval    time.Duration `json:"health_check_interval"`
	MetricsEnabled         bool          `json:"metrics_enabled"`
}

// CoordinationEngine manages agent coordination
type CoordinationEngine struct {
	orchestrator *MultiAgentOrchestrator
	logger       *logger.Logger
}

// ConflictResolver handles conflicts between agents
type ConflictResolver struct {
	resolutionStrategies map[string]ConflictResolutionStrategy
	logger               *logger.Logger
}

// CollaborationManager manages collaborative workflows
type CollaborationManager struct {
	activeCollaborations  map[string]*ActiveCollaboration
	collaborationPatterns map[string]*CollaborationPattern
	logger                *logger.Logger
	mutex                 sync.RWMutex
}

// TaskScheduler handles task distribution and scheduling
type TaskScheduler struct {
	taskQueue       chan *MultiAgentTask
	priorityQueue   *PriorityQueue
	loadBalancer    *LoadBalancer
	failoverManager *FailoverManager
	logger          *logger.Logger
}

// ConsensusEngine manages consensus-based decision making
type ConsensusEngine struct {
	consensusAlgorithm string // "majority", "weighted", "byzantine"
	threshold          float64
	logger             *logger.Logger
}

// MultiAgentTask represents a task for multi-agent execution
type MultiAgentTask struct {
	ID                string                 `json:"id"`
	Type              string                 `json:"type"`
	Priority          TaskPriority           `json:"priority"`
	Description       string                 `json:"description"`
	RequiredAgents    []string               `json:"required_agents"`
	OptionalAgents    []string               `json:"optional_agents"`
	Constraints       []TaskConstraint       `json:"constraints"`
	Dependencies      []string               `json:"dependencies"`
	Parameters        map[string]interface{} `json:"parameters"`
	Context           map[string]interface{} `json:"context"`
	Deadline          *time.Time             `json:"deadline,omitempty"`
	CollaborationMode string                 `json:"collaboration_mode"` // "sequential", "parallel", "consensus"
	CreatedAt         time.Time              `json:"created_at"`
}

// TaskConstraint defines constraints for task execution
type TaskConstraint struct {
	Type        string      `json:"type"`
	Value       interface{} `json:"value"`
	Description string      `json:"description"`
}

// ActiveCollaboration represents an ongoing collaboration
type ActiveCollaboration struct {
	ID              string                 `json:"id"`
	Task            *MultiAgentTask        `json:"task"`
	Participants    map[string]ai.Agent    `json:"-"`
	Coordinator     string                 `json:"coordinator"`
	Status          string                 `json:"status"`
	Progress        float64                `json:"progress"`
	Results         map[string]interface{} `json:"results"`
	Conflicts       []ConflictRecord       `json:"conflicts"`
	DecisionHistory []DecisionRecord       `json:"decision_history"`
	StartedAt       time.Time              `json:"started_at"`
	CompletedAt     *time.Time             `json:"completed_at,omitempty"`
}

// CollaborationPattern defines reusable collaboration patterns
type CollaborationPattern struct {
	Name          string                   `json:"name"`
	Description   string                   `json:"description"`
	AgentRoles    map[string]string        `json:"agent_roles"`
	Workflow      []CollaborationStep      `json:"workflow"`
	ConflictRules []ConflictResolutionRule `json:"conflict_rules"`
}

// CollaborationStep represents a step in collaboration
type CollaborationStep struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         string                 `json:"type"` // "sequential", "parallel", "consensus"
	AgentRole    string                 `json:"agent_role"`
	Action       string                 `json:"action"`
	Parameters   map[string]interface{} `json:"parameters"`
	Dependencies []string               `json:"dependencies"`
	Timeout      time.Duration          `json:"timeout"`
	Required     bool                   `json:"required"`
}

// ConflictRecord tracks conflicts during collaboration
type ConflictRecord struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Agents      []string               `json:"agents"`
	Data        map[string]interface{} `json:"data"`
	Resolution  *ConflictResolution    `json:"resolution,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
}

// ConflictResolution represents the resolution of a conflict
type ConflictResolution struct {
	Strategy   string                 `json:"strategy"`
	Decision   map[string]interface{} `json:"decision"`
	Confidence float64                `json:"confidence"`
	ResolvedBy string                 `json:"resolved_by"`
	ResolvedAt time.Time              `json:"resolved_at"`
}

// DecisionRecord tracks decisions made during collaboration
type DecisionRecord struct {
	ID          string           `json:"id"`
	Type        string           `json:"type"`
	Description string           `json:"description"`
	Options     []DecisionOption `json:"options"`
	Decision    *DecisionOption  `json:"decision"`
	Consensus   float64          `json:"consensus"`
	MadeBy      string           `json:"made_by"`
	MadeAt      time.Time        `json:"made_at"`
}

// DecisionOption represents an option in decision making
type DecisionOption struct {
	ID          string                 `json:"id"`
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data"`
	Score       float64                `json:"score"`
	SupportedBy []string               `json:"supported_by"`
}

// ConflictResolutionStrategy defines how to resolve conflicts
type ConflictResolutionStrategy interface {
	Resolve(ctx context.Context, conflict *ConflictRecord, agents map[string]ai.Agent) (*ConflictResolution, error)
	GetType() string
	GetPriority() int
}

// ConflictResolutionRule defines rules for conflict resolution
type ConflictResolutionRule struct {
	ConflictType string   `json:"conflict_type"`
	Strategy     string   `json:"strategy"`
	Priority     int      `json:"priority"`
	Conditions   []string `json:"conditions"`
}

// OrchestratorMetrics tracks orchestrator performance
type OrchestratorMetrics struct {
	TasksExecuted        int64         `json:"tasks_executed"`
	TasksSuccessful      int64         `json:"tasks_successful"`
	TasksFailed          int64         `json:"tasks_failed"`
	CollaborationsActive int64         `json:"collaborations_active"`
	ConflictsResolved    int64         `json:"conflicts_resolved"`
	AvgExecutionTime     time.Duration `json:"avg_execution_time"`
	SuccessRate          float64       `json:"success_rate"`
	LastActivity         time.Time     `json:"last_activity"`
	mutex                sync.RWMutex
}

// PriorityQueue manages task prioritization
type PriorityQueue struct {
	tasks []*MultiAgentTask
	mutex sync.RWMutex
}

// LoadBalancer distributes tasks across agents
type LoadBalancer struct {
	strategy string // "round_robin", "least_loaded", "capability_based"
	metrics  map[string]*AgentLoadMetrics
	mutex    sync.RWMutex
}

// AgentLoadMetrics tracks agent load
type AgentLoadMetrics struct {
	ActiveTasks  int           `json:"active_tasks"`
	QueuedTasks  int           `json:"queued_tasks"`
	AvgResponse  time.Duration `json:"avg_response"`
	SuccessRate  float64       `json:"success_rate"`
	LastActivity time.Time     `json:"last_activity"`
}

// FailoverManager handles agent failures
type FailoverManager struct {
	backupAgents map[string][]string // Primary agent -> backup agents
	healthStatus map[string]bool
	logger       *logger.Logger
	mutex        sync.RWMutex
}

// NewMultiAgentOrchestrator creates a new multi-agent orchestrator
func NewMultiAgentOrchestrator(config *OrchestratorConfig, logger *logger.Logger) *MultiAgentOrchestrator {
	if config == nil {
		config = &OrchestratorConfig{
			MaxConcurrentTasks:     20,
			TaskTimeout:            10 * time.Minute,
			ConflictResolutionMode: "consensus",
			ConsensusThreshold:     0.7,
			EnableLoadBalancing:    true,
			EnableFailover:         true,
			HealthCheckInterval:    30 * time.Second,
			MetricsEnabled:         true,
		}
	}

	orchestrator := &MultiAgentOrchestrator{
		agents:   make(map[string]ai.Agent),
		config:   config,
		logger:   logger,
		metrics:  &OrchestratorMetrics{LastActivity: time.Now()},
		stopChan: make(chan struct{}),
	}

	// Initialize components
	orchestrator.coordinationEngine = &CoordinationEngine{
		orchestrator: orchestrator,
		logger:       logger,
	}

	orchestrator.conflictResolver = &ConflictResolver{
		resolutionStrategies: make(map[string]ConflictResolutionStrategy),
		logger:               logger,
	}

	orchestrator.collaborationManager = &CollaborationManager{
		activeCollaborations:  make(map[string]*ActiveCollaboration),
		collaborationPatterns: make(map[string]*CollaborationPattern),
		logger:                logger,
	}

	orchestrator.taskScheduler = &TaskScheduler{
		taskQueue:     make(chan *MultiAgentTask, config.MaxConcurrentTasks),
		priorityQueue: &PriorityQueue{},
		loadBalancer: &LoadBalancer{
			strategy: "capability_based",
			metrics:  make(map[string]*AgentLoadMetrics),
		},
		failoverManager: &FailoverManager{
			backupAgents: make(map[string][]string),
			healthStatus: make(map[string]bool),
			logger:       logger,
		},
		logger: logger,
	}

	orchestrator.consensusEngine = &ConsensusEngine{
		consensusAlgorithm: "weighted",
		threshold:          config.ConsensusThreshold,
		logger:             logger,
	}

	// Initialize conflict resolution strategies
	orchestrator.initializeConflictResolutionStrategies()

	// Initialize collaboration patterns
	orchestrator.initializeCollaborationPatterns()

	return orchestrator
}

// RegisterAgent registers an agent with the orchestrator
func (o *MultiAgentOrchestrator) RegisterAgent(agent ai.Agent) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if _, exists := o.agents[agent.ID()]; exists {
		return fmt.Errorf("agent %s already registered", agent.ID())
	}

	o.agents[agent.ID()] = agent

	// Initialize load metrics
	o.taskScheduler.loadBalancer.mutex.Lock()
	o.taskScheduler.loadBalancer.metrics[agent.ID()] = &AgentLoadMetrics{
		LastActivity: time.Now(),
	}
	o.taskScheduler.loadBalancer.mutex.Unlock()

	// Initialize health status
	o.taskScheduler.failoverManager.mutex.Lock()
	o.taskScheduler.failoverManager.healthStatus[agent.ID()] = true
	o.taskScheduler.failoverManager.mutex.Unlock()

	o.logger.Info("Agent registered with multi-agent orchestrator",
		"agent_id", agent.ID(),
		"agent_name", agent.Name())

	return nil
}

// Start starts the multi-agent orchestrator
func (o *MultiAgentOrchestrator) Start(ctx context.Context) error {
	o.mutex.Lock()
	if o.running {
		o.mutex.Unlock()
		return fmt.Errorf("orchestrator is already running")
	}
	o.running = true
	o.mutex.Unlock()

	// Start task scheduler
	o.wg.Add(1)
	go o.taskScheduler.run(ctx, o)

	// Start health monitoring
	if o.config.EnableFailover {
		o.wg.Add(1)
		go o.healthMonitor(ctx)
	}

	// Start metrics collection
	if o.config.MetricsEnabled {
		o.wg.Add(1)
		go o.metricsCollector(ctx)
	}

	o.logger.Info("Multi-agent orchestrator started",
		"max_concurrent_tasks", o.config.MaxConcurrentTasks,
		"conflict_resolution_mode", o.config.ConflictResolutionMode,
		"consensus_threshold", o.config.ConsensusThreshold)

	return nil
}

// Stop stops the multi-agent orchestrator
func (o *MultiAgentOrchestrator) Stop() error {
	o.mutex.Lock()
	if !o.running {
		o.mutex.Unlock()
		return fmt.Errorf("orchestrator is not running")
	}
	o.running = false
	o.mutex.Unlock()

	close(o.stopChan)
	o.wg.Wait()

	o.logger.Info("Multi-agent orchestrator stopped")
	return nil
}

// ExecuteTask executes a multi-agent task
func (o *MultiAgentOrchestrator) ExecuteTask(ctx context.Context, task *MultiAgentTask) (*MultiAgentTaskResult, error) {
	ctx, span := multiAgentTracer.Start(ctx, "multiagent_orchestrator.execute_task",
		trace.WithAttributes(
			attribute.String("task.id", task.ID),
			attribute.String("task.type", task.Type),
			attribute.String("collaboration_mode", task.CollaborationMode),
		),
	)
	defer span.End()

	startTime := time.Now()

	// Validate task
	if err := o.validateTask(task); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("task validation failed: %w", err)
	}

	// Create collaboration
	collaboration, err := o.collaborationManager.createCollaboration(task, o.agents)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to create collaboration: %w", err)
	}

	// Execute collaboration
	result, err := o.executeCollaboration(ctx, collaboration)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("collaboration execution failed: %w", err)
	}

	// Update metrics
	o.updateMetrics(true, time.Since(startTime))

	span.SetAttributes(
		attribute.Bool("task.success", result.Success),
		attribute.Float64("task.confidence", result.Confidence),
		attribute.Int("participants_count", len(collaboration.Participants)),
	)

	return result, nil
}

// MultiAgentTaskResult represents the result of multi-agent task execution
type MultiAgentTaskResult struct {
	TaskID           string                 `json:"task_id"`
	Success          bool                   `json:"success"`
	Result           map[string]interface{} `json:"result"`
	Confidence       float64                `json:"confidence"`
	ExecutionTime    time.Duration          `json:"execution_time"`
	ParticipantCount int                    `json:"participant_count"`
	ConflictsCount   int                    `json:"conflicts_count"`
	ConsensusScore   float64                `json:"consensus_score"`
	Metadata         map[string]interface{} `json:"metadata"`
	Error            string                 `json:"error,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
}

// executeCollaboration executes a collaboration between agents
func (o *MultiAgentOrchestrator) executeCollaboration(ctx context.Context, collaboration *ActiveCollaboration) (*MultiAgentTaskResult, error) {
	ctx, span := multiAgentTracer.Start(ctx, "multiagent_orchestrator.execute_collaboration",
		trace.WithAttributes(
			attribute.String("collaboration.id", collaboration.ID),
			attribute.String("collaboration.mode", collaboration.Task.CollaborationMode),
		),
	)
	defer span.End()

	startTime := time.Now()
	collaboration.Status = "running"

	result := &MultiAgentTaskResult{
		TaskID:    collaboration.Task.ID,
		CreatedAt: startTime,
		Metadata:  make(map[string]interface{}),
	}

	switch collaboration.Task.CollaborationMode {
	case "sequential":
		err := o.executeSequentialCollaboration(ctx, collaboration)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
			return result, err
		}
	case "parallel":
		err := o.executeParallelCollaboration(ctx, collaboration)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
			return result, err
		}
	case "consensus":
		err := o.executeConsensusCollaboration(ctx, collaboration)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
			return result, err
		}
	default:
		err := fmt.Errorf("unknown collaboration mode: %s", collaboration.Task.CollaborationMode)
		result.Success = false
		result.Error = err.Error()
		return result, err
	}

	// Finalize collaboration
	collaboration.Status = "completed"
	completedAt := time.Now()
	collaboration.CompletedAt = &completedAt

	// Calculate results
	result.Success = true
	result.ExecutionTime = time.Since(startTime)
	result.ParticipantCount = len(collaboration.Participants)
	result.ConflictsCount = len(collaboration.Conflicts)
	result.Result = collaboration.Results
	result.Confidence = o.calculateCollaborationConfidence(collaboration)
	result.ConsensusScore = o.calculateConsensusScore(collaboration)

	return result, nil
}

// executeSequentialCollaboration executes agents sequentially
func (o *MultiAgentOrchestrator) executeSequentialCollaboration(ctx context.Context, collaboration *ActiveCollaboration) error {
	pattern := o.collaborationManager.getCollaborationPattern(collaboration.Task.Type)
	if pattern == nil {
		return fmt.Errorf("no collaboration pattern found for task type: %s", collaboration.Task.Type)
	}

	for _, step := range pattern.Workflow {
		// Find agent for this step
		agent := o.findAgentForRole(collaboration.Participants, step.AgentRole)
		if agent == nil {
			return fmt.Errorf("no agent found for role: %s", step.AgentRole)
		}

		// Execute step
		stepResult, err := o.executeCollaborationStep(ctx, collaboration, step, agent)
		if err != nil {
			return fmt.Errorf("step %s failed: %w", step.ID, err)
		}

		// Store step result
		collaboration.Results[step.ID] = stepResult
		collaboration.Progress = float64(len(collaboration.Results)) / float64(len(pattern.Workflow))
	}

	return nil
}

// executeParallelCollaboration executes agents in parallel
func (o *MultiAgentOrchestrator) executeParallelCollaboration(ctx context.Context, collaboration *ActiveCollaboration) error {
	pattern := o.collaborationManager.getCollaborationPattern(collaboration.Task.Type)
	if pattern == nil {
		return fmt.Errorf("no collaboration pattern found for task type: %s", collaboration.Task.Type)
	}

	// Group steps by dependencies
	stepGroups := o.groupStepsByDependencies(pattern.Workflow)

	for _, stepGroup := range stepGroups {
		// Execute steps in parallel
		var wg sync.WaitGroup
		results := make(chan stepExecutionResult, len(stepGroup))

		for _, step := range stepGroup {
			wg.Add(1)
			go func(s CollaborationStep) {
				defer wg.Done()

				agent := o.findAgentForRole(collaboration.Participants, s.AgentRole)
				if agent == nil {
					results <- stepExecutionResult{
						stepID: s.ID,
						error:  fmt.Errorf("no agent found for role: %s", s.AgentRole),
					}
					return
				}

				stepResult, err := o.executeCollaborationStep(ctx, collaboration, s, agent)
				results <- stepExecutionResult{
					stepID: s.ID,
					result: stepResult,
					error:  err,
				}
			}(step)
		}

		wg.Wait()
		close(results)

		// Collect results
		for result := range results {
			if result.error != nil {
				return fmt.Errorf("step %s failed: %w", result.stepID, result.error)
			}
			collaboration.Results[result.stepID] = result.result
		}

		collaboration.Progress = float64(len(collaboration.Results)) / float64(len(pattern.Workflow))
	}

	return nil
}

// executeConsensusCollaboration executes with consensus-based decision making
func (o *MultiAgentOrchestrator) executeConsensusCollaboration(ctx context.Context, collaboration *ActiveCollaboration) error {
	// Create agent input for each agent
	agentInput := ai.AgentInput{
		Query:       collaboration.Task.Description,
		Context:     collaboration.Task.Context,
		MaxSteps:    5,
		Tools:       []string{},
		Constraints: []string{},
		Goals:       []string{collaboration.Task.Type},
	}

	// Collect proposals from all agents
	proposals := make(map[string]ai.AgentOutput)
	var wg sync.WaitGroup
	proposalChan := make(chan agentProposal, len(collaboration.Participants))

	for agentID, agent := range collaboration.Participants {
		wg.Add(1)
		go func(id string, a ai.Agent) {
			defer wg.Done()

			result, err := a.Execute(ctx, agentInput)
			proposalChan <- agentProposal{
				agentID: id,
				result:  result,
				error:   err,
			}
		}(agentID, agent)
	}

	wg.Wait()
	close(proposalChan)

	// Collect proposals
	for proposal := range proposalChan {
		if proposal.error != nil {
			o.logger.Warn("Agent proposal failed",
				"agent_id", proposal.agentID,
				"error", proposal.error)
			continue
		}
		proposals[proposal.agentID] = proposal.result
	}

	// Reach consensus
	consensus, err := o.consensusEngine.reachConsensus(ctx, proposals, collaboration)
	if err != nil {
		return fmt.Errorf("failed to reach consensus: %w", err)
	}

	collaboration.Results["consensus"] = consensus
	return nil
}

// stepExecutionResult represents the result of step execution
type stepExecutionResult struct {
	stepID string
	result interface{}
	error  error
}

// agentProposal represents a proposal from an agent
type agentProposal struct {
	agentID string
	result  ai.AgentOutput
	error   error
}

// initializeConflictResolutionStrategies initializes conflict resolution strategies
func (o *MultiAgentOrchestrator) initializeConflictResolutionStrategies() {
	// Voting strategy
	o.conflictResolver.resolutionStrategies["voting"] = &VotingStrategy{
		logger: o.logger,
	}

	// Priority strategy
	o.conflictResolver.resolutionStrategies["priority"] = &PriorityStrategy{
		logger: o.logger,
	}

	// Consensus strategy
	o.conflictResolver.resolutionStrategies["consensus"] = &ConsensusStrategy{
		threshold: o.config.ConsensusThreshold,
		logger:    o.logger,
	}
}

// initializeCollaborationPatterns initializes collaboration patterns
func (o *MultiAgentOrchestrator) initializeCollaborationPatterns() {
	// Security analysis pattern
	o.collaborationManager.collaborationPatterns["security_analysis"] = &CollaborationPattern{
		Name:        "Security Analysis",
		Description: "Multi-agent security analysis workflow",
		AgentRoles: map[string]string{
			"threat_detector":       "cybersecurity",
			"vulnerability_scanner": "cybersecurity",
			"incident_analyzer":     "cybersecurity",
		},
		Workflow: []CollaborationStep{
			{
				ID:        "threat_detection",
				Name:      "Threat Detection",
				Type:      "parallel",
				AgentRole: "threat_detector",
				Action:    "detect_threats",
				Required:  true,
			},
			{
				ID:        "vulnerability_scan",
				Name:      "Vulnerability Scanning",
				Type:      "parallel",
				AgentRole: "vulnerability_scanner",
				Action:    "scan_vulnerabilities",
				Required:  true,
			},
			{
				ID:           "incident_analysis",
				Name:         "Incident Analysis",
				Type:         "sequential",
				AgentRole:    "incident_analyzer",
				Action:       "analyze_incidents",
				Dependencies: []string{"threat_detection", "vulnerability_scan"},
				Required:     true,
			},
		},
	}

	// Business analysis pattern
	o.collaborationManager.collaborationPatterns["business_analysis"] = &CollaborationPattern{
		Name:        "Business Analysis",
		Description: "Multi-agent business analysis workflow",
		AgentRoles: map[string]string{
			"researcher": "research",
			"analyst":    "analyst",
			"strategist": "strategist",
		},
		Workflow: []CollaborationStep{
			{
				ID:        "research",
				Name:      "Market Research",
				Type:      "parallel",
				AgentRole: "researcher",
				Action:    "conduct_research",
				Required:  true,
			},
			{
				ID:           "analysis",
				Name:         "Data Analysis",
				Type:         "sequential",
				AgentRole:    "analyst",
				Action:       "analyze_data",
				Dependencies: []string{"research"},
				Required:     true,
			},
			{
				ID:           "strategy",
				Name:         "Strategy Development",
				Type:         "sequential",
				AgentRole:    "strategist",
				Action:       "develop_strategy",
				Dependencies: []string{"analysis"},
				Required:     true,
			},
		},
	}
}

// validateTask validates a multi-agent task
func (o *MultiAgentOrchestrator) validateTask(task *MultiAgentTask) error {
	if task.ID == "" {
		task.ID = uuid.New().String()
	}

	if task.Type == "" {
		return fmt.Errorf("task type is required")
	}

	if task.Description == "" {
		return fmt.Errorf("task description is required")
	}

	if len(task.RequiredAgents) == 0 {
		return fmt.Errorf("at least one required agent must be specified")
	}

	// Validate required agents exist
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	for _, agentID := range task.RequiredAgents {
		if _, exists := o.agents[agentID]; !exists {
			return fmt.Errorf("required agent %s not found", agentID)
		}
	}

	return nil
}

// updateMetrics updates orchestrator metrics
func (o *MultiAgentOrchestrator) updateMetrics(success bool, executionTime time.Duration) {
	o.metrics.mutex.Lock()
	defer o.metrics.mutex.Unlock()

	o.metrics.TasksExecuted++
	if success {
		o.metrics.TasksSuccessful++
	} else {
		o.metrics.TasksFailed++
	}

	// Update average execution time
	if o.metrics.TasksExecuted == 1 {
		o.metrics.AvgExecutionTime = executionTime
	} else {
		o.metrics.AvgExecutionTime = time.Duration(
			(int64(o.metrics.AvgExecutionTime)*(o.metrics.TasksExecuted-1) + int64(executionTime)) / o.metrics.TasksExecuted,
		)
	}

	// Update success rate
	o.metrics.SuccessRate = float64(o.metrics.TasksSuccessful) / float64(o.metrics.TasksExecuted)
	o.metrics.LastActivity = time.Now()
}

// calculateCollaborationConfidence calculates confidence score for collaboration
func (o *MultiAgentOrchestrator) calculateCollaborationConfidence(collaboration *ActiveCollaboration) float64 {
	if len(collaboration.Participants) == 0 {
		return 0.0
	}

	totalConfidence := 0.0
	count := 0

	for _, result := range collaboration.Results {
		if taskResult, ok := result.(*agents.BusinessTaskResult); ok {
			totalConfidence += taskResult.Confidence
			count++
		}
	}

	if count == 0 {
		return 0.5 // Default confidence
	}

	baseConfidence := totalConfidence / float64(count)

	// Adjust for conflicts
	conflictPenalty := float64(len(collaboration.Conflicts)) * 0.1
	if conflictPenalty > 0.3 {
		conflictPenalty = 0.3 // Cap penalty at 30%
	}

	return baseConfidence * (1.0 - conflictPenalty)
}

// calculateConsensusScore calculates consensus score for collaboration
func (o *MultiAgentOrchestrator) calculateConsensusScore(collaboration *ActiveCollaboration) float64 {
	if len(collaboration.DecisionHistory) == 0 {
		return 1.0 // No decisions means perfect consensus
	}

	totalConsensus := 0.0
	for _, decision := range collaboration.DecisionHistory {
		totalConsensus += decision.Consensus
	}

	return totalConsensus / float64(len(collaboration.DecisionHistory))
}
