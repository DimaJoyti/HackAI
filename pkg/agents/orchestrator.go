package agents

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var orchestratorTracer = otel.Tracer("hackai/agents/orchestrator")

// BusinessAgentOrchestrator coordinates multiple business agents
type BusinessAgentOrchestrator struct {
	agents         map[string]BusinessAgent
	workflows      map[string]*Workflow
	taskQueue      chan *BusinessTask
	resultChannel  chan *BusinessTaskResult
	collaborations map[string]*ActiveCollaboration
	logger         *logger.Logger
	config         *OrchestratorConfig
	running        bool
	stopChan       chan struct{}
	wg             sync.WaitGroup
	mutex          sync.RWMutex
}

// OrchestratorConfig holds orchestrator configuration
type OrchestratorConfig struct {
	MaxConcurrentTasks int           `json:"max_concurrent_tasks"`
	TaskTimeout        time.Duration `json:"task_timeout"`
	WorkerPoolSize     int           `json:"worker_pool_size"`
	EnableMetrics      bool          `json:"enable_metrics"`
	EnableTracing      bool          `json:"enable_tracing"`
}

// Workflow represents a multi-agent workflow
type Workflow struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Steps       []*WorkflowStep        `json:"steps"`
	Status      string                 `json:"status"`
	Context     *BusinessContext       `json:"context"`
	Results     map[string]interface{} `json:"results"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
}

// WorkflowStep represents a step in a workflow
type WorkflowStep struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	AgentType    BusinessAgentType      `json:"agent_type"`
	TaskType     string                 `json:"task_type"`
	Parameters   map[string]interface{} `json:"parameters"`
	Dependencies []string               `json:"dependencies"`
	Status       string                 `json:"status"`
	Result       *BusinessTaskResult    `json:"result,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
}

// ActiveCollaboration represents an ongoing collaboration
type ActiveCollaboration struct {
	ID           string                   `json:"id"`
	Task         *CollaborationTask       `json:"task"`
	Participants map[string]BusinessAgent `json:"-"` // Not serialized
	Status       string                   `json:"status"`
	Results      map[string]interface{}   `json:"results"`
	StartedAt    time.Time                `json:"started_at"`
	CompletedAt  *time.Time               `json:"completed_at,omitempty"`
}

// TradingWorkflow represents a complete trading workflow
type TradingWorkflow struct {
	*Workflow
	Symbol       string       `json:"symbol"`
	Strategy     string       `json:"strategy"`
	RiskProfile  *RiskProfile `json:"risk_profile"`
	TargetReturn float64      `json:"target_return"`
}

// NewBusinessAgentOrchestrator creates a new business agent orchestrator
func NewBusinessAgentOrchestrator(config *OrchestratorConfig, logger *logger.Logger) *BusinessAgentOrchestrator {
	if config == nil {
		config = &OrchestratorConfig{
			MaxConcurrentTasks: 10,
			TaskTimeout:        5 * time.Minute,
			WorkerPoolSize:     5,
			EnableMetrics:      true,
			EnableTracing:      true,
		}
	}

	return &BusinessAgentOrchestrator{
		agents:         make(map[string]BusinessAgent),
		workflows:      make(map[string]*Workflow),
		taskQueue:      make(chan *BusinessTask, config.MaxConcurrentTasks),
		resultChannel:  make(chan *BusinessTaskResult, config.MaxConcurrentTasks),
		collaborations: make(map[string]*ActiveCollaboration),
		logger:         logger,
		config:         config,
		stopChan:       make(chan struct{}),
	}
}

// RegisterAgent registers a business agent
func (o *BusinessAgentOrchestrator) RegisterAgent(agent BusinessAgent) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if _, exists := o.agents[agent.ID()]; exists {
		return fmt.Errorf("agent %s already registered", agent.ID())
	}

	o.agents[agent.ID()] = agent
	o.logger.Info("Agent registered",
		"agent_id", agent.ID(),
		"agent_type", string(agent.GetAgentType()),
		"specializations", agent.GetSpecializations())

	return nil
}

// Start starts the orchestrator
func (o *BusinessAgentOrchestrator) Start(ctx context.Context) error {
	o.mutex.Lock()
	if o.running {
		o.mutex.Unlock()
		return fmt.Errorf("orchestrator is already running")
	}
	o.running = true
	o.mutex.Unlock()

	// Start worker pool
	for i := 0; i < o.config.WorkerPoolSize; i++ {
		o.wg.Add(1)
		go o.worker(ctx, i)
	}

	// Start result processor
	o.wg.Add(1)
	go o.resultProcessor(ctx)

	o.logger.Info("Business agent orchestrator started",
		"worker_pool_size", o.config.WorkerPoolSize,
		"max_concurrent_tasks", o.config.MaxConcurrentTasks)

	return nil
}

// Stop stops the orchestrator
func (o *BusinessAgentOrchestrator) Stop() error {
	o.mutex.Lock()
	if !o.running {
		o.mutex.Unlock()
		return fmt.Errorf("orchestrator is not running")
	}
	o.running = false
	o.mutex.Unlock()

	close(o.stopChan)
	o.wg.Wait()

	o.logger.Info("Business agent orchestrator stopped")
	return nil
}

// ExecuteTask executes a business task
func (o *BusinessAgentOrchestrator) ExecuteTask(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	ctx, span := orchestratorTracer.Start(ctx, "orchestrator.execute_task",
		trace.WithAttributes(
			attribute.String("task.id", task.ID),
			attribute.String("task.type", task.Type),
		),
	)
	defer span.End()

	// Find appropriate agent
	agent, err := o.findAgentForTask(task)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to find agent for task: %w", err)
	}

	// Execute task
	result, err := agent.ExecuteBusinessTask(ctx, task)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("task execution failed: %w", err)
	}

	span.SetAttributes(
		attribute.Bool("task.success", result.Success),
		attribute.Float64("task.confidence", result.Confidence),
		attribute.String("agent.id", agent.ID()),
	)

	return result, nil
}

// ExecuteWorkflow executes a multi-step workflow
func (o *BusinessAgentOrchestrator) ExecuteWorkflow(ctx context.Context, workflow *Workflow) error {
	ctx, span := orchestratorTracer.Start(ctx, "orchestrator.execute_workflow",
		trace.WithAttributes(
			attribute.String("workflow.id", workflow.ID),
			attribute.String("workflow.name", workflow.Name),
		),
	)
	defer span.End()

	workflow.Status = "running"
	workflow.UpdatedAt = time.Now()

	o.mutex.Lock()
	o.workflows[workflow.ID] = workflow
	o.mutex.Unlock()

	// Execute steps in order, respecting dependencies
	for _, step := range workflow.Steps {
		if err := o.executeWorkflowStep(ctx, workflow, step); err != nil {
			workflow.Status = "failed"
			span.RecordError(err)
			return fmt.Errorf("workflow step %s failed: %w", step.ID, err)
		}
	}

	workflow.Status = "completed"
	completedAt := time.Now()
	workflow.CompletedAt = &completedAt
	workflow.UpdatedAt = completedAt

	span.SetAttributes(
		attribute.String("workflow.status", workflow.Status),
		attribute.Int("workflow.steps", len(workflow.Steps)),
	)

	return nil
}

// CreateTradingWorkflow creates a comprehensive trading workflow
func (o *BusinessAgentOrchestrator) CreateTradingWorkflow(symbol, strategy string, riskProfile *RiskProfile) *TradingWorkflow {
	workflowID := uuid.New().String()

	workflow := &Workflow{
		ID:          workflowID,
		Name:        fmt.Sprintf("Trading Workflow - %s", symbol),
		Description: fmt.Sprintf("Complete trading workflow for %s using %s strategy", symbol, strategy),
		Status:      "created",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Results:     make(map[string]interface{}),
	}

	// Define workflow steps
	step1 := &WorkflowStep{
		ID:        uuid.New().String(),
		Name:      "Market Research",
		AgentType: AgentTypeResearch,
		TaskType:  "market_analysis",
		Parameters: map[string]interface{}{
			"symbol": symbol,
			"depth":  "comprehensive",
		},
		Status:    "pending",
		CreatedAt: time.Now(),
	}

	step2 := &WorkflowStep{
		ID:        uuid.New().String(),
		Name:      "Risk Assessment",
		AgentType: AgentTypeAnalyst,
		TaskType:  "risk_analysis",
		Parameters: map[string]interface{}{
			"symbol":       symbol,
			"risk_profile": riskProfile,
		},
		Dependencies: []string{step1.ID}, // Depends on market research
		Status:       "pending",
		CreatedAt:    time.Now(),
	}

	step3 := &WorkflowStep{
		ID:        uuid.New().String(),
		Name:      "Strategy Generation",
		AgentType: AgentTypeCreator,
		TaskType:  "create_strategy",
		Parameters: map[string]interface{}{
			"symbol":   symbol,
			"strategy": strategy,
		},
		Dependencies: []string{step1.ID, step2.ID},
		Status:       "pending",
		CreatedAt:    time.Now(),
	}

	step4 := &WorkflowStep{
		ID:        uuid.New().String(),
		Name:      "Strategic Decision",
		AgentType: AgentTypeStrategist,
		TaskType:  "make_decision",
		Parameters: map[string]interface{}{
			"symbol": symbol,
		},
		Dependencies: []string{step3.ID},
		Status:       "pending",
		CreatedAt:    time.Now(),
	}

	step5 := &WorkflowStep{
		ID:        uuid.New().String(),
		Name:      "Execute Trade",
		AgentType: AgentTypeOperator,
		TaskType:  "execute_signal",
		Parameters: map[string]interface{}{
			"symbol": symbol,
		},
		Dependencies: []string{step4.ID},
		Status:       "pending",
		CreatedAt:    time.Now(),
	}

	workflow.Steps = []*WorkflowStep{step1, step2, step3, step4, step5}

	return &TradingWorkflow{
		Workflow:     workflow,
		Symbol:       symbol,
		Strategy:     strategy,
		RiskProfile:  riskProfile,
		TargetReturn: 0.1, // 10% target return
	}
}

// StartCollaboration starts a collaboration between agents
func (o *BusinessAgentOrchestrator) StartCollaboration(ctx context.Context, task *CollaborationTask) (*ActiveCollaboration, error) {
	ctx, span := orchestratorTracer.Start(ctx, "orchestrator.start_collaboration",
		trace.WithAttributes(
			attribute.String("collaboration.id", task.ID),
			attribute.String("collaboration.type", task.Type),
		),
	)
	defer span.End()

	// Find participating agents
	participants := make(map[string]BusinessAgent)
	for _, agentID := range task.Participants {
		agent, exists := o.agents[agentID]
		if !exists {
			return nil, fmt.Errorf("agent %s not found", agentID)
		}
		participants[agentID] = agent
	}

	collaboration := &ActiveCollaboration{
		ID:           task.ID,
		Task:         task,
		Participants: participants,
		Status:       "active",
		Results:      make(map[string]interface{}),
		StartedAt:    time.Now(),
	}

	o.mutex.Lock()
	o.collaborations[collaboration.ID] = collaboration
	o.mutex.Unlock()

	// Execute collaboration workflow
	go o.executeCollaboration(ctx, collaboration)

	return collaboration, nil
}

// worker processes tasks from the task queue
func (o *BusinessAgentOrchestrator) worker(ctx context.Context, workerID int) {
	defer o.wg.Done()

	o.logger.Debug("Worker started", "worker_id", workerID)

	for {
		select {
		case task := <-o.taskQueue:
			result, err := o.ExecuteTask(ctx, task)
			if err != nil {
				o.logger.Error("Task execution failed",
					"task_id", task.ID,
					"worker_id", workerID,
					"error", err)

				result = &BusinessTaskResult{
					TaskID:    task.ID,
					Success:   false,
					Error:     err.Error(),
					CreatedAt: time.Now(),
				}
			}

			select {
			case o.resultChannel <- result:
			case <-ctx.Done():
				return
			case <-o.stopChan:
				return
			}

		case <-ctx.Done():
			return
		case <-o.stopChan:
			return
		}
	}
}

// resultProcessor processes task results
func (o *BusinessAgentOrchestrator) resultProcessor(ctx context.Context) {
	defer o.wg.Done()

	for {
		select {
		case result := <-o.resultChannel:
			o.logger.Debug("Task result processed",
				"task_id", result.TaskID,
				"success", result.Success,
				"confidence", result.Confidence)

		case <-ctx.Done():
			return
		case <-o.stopChan:
			return
		}
	}
}

// findAgentForTask finds the most suitable agent for a task
func (o *BusinessAgentOrchestrator) findAgentForTask(task *BusinessTask) (BusinessAgent, error) {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	// Task type to agent type mapping
	taskToAgentMap := map[string]BusinessAgentType{
		"market_analysis":     AgentTypeResearch,
		"price_analysis":      AgentTypeResearch,
		"sentiment_analysis":  AgentTypeResearch,
		"technical_analysis":  AgentTypeResearch,
		"risk_assessment":     AgentTypeAnalyst,
		"data_analysis":       AgentTypeAnalyst,
		"pattern_recognition": AgentTypeAnalyst,
		"create_strategy":     AgentTypeCreator,
		"generate_report":     AgentTypeCreator,
		"create_content":      AgentTypeCreator,
		"execute_trade":       AgentTypeOperator,
		"manage_portfolio":    AgentTypeOperator,
		"monitor_positions":   AgentTypeOperator,
		"make_decision":       AgentTypeStrategist,
		"strategic_planning":  AgentTypeStrategist,
		"risk_management":     AgentTypeStrategist,
	}

	requiredAgentType, exists := taskToAgentMap[task.Type]
	if !exists {
		return nil, fmt.Errorf("no agent type mapping for task type: %s", task.Type)
	}

	// Find agent of the required type
	for _, agent := range o.agents {
		if agent.GetAgentType() == requiredAgentType {
			return agent, nil
		}
	}

	return nil, fmt.Errorf("no agent found for type: %s", requiredAgentType)
}

// executeWorkflowStep executes a single workflow step
func (o *BusinessAgentOrchestrator) executeWorkflowStep(ctx context.Context, workflow *Workflow, step *WorkflowStep) error {
	// Check dependencies
	for _, depID := range step.Dependencies {
		depStep := o.findWorkflowStep(workflow, depID)
		if depStep == nil || depStep.Status != "completed" {
			return fmt.Errorf("dependency %s not completed", depID)
		}
	}

	// Create task from step
	task := &BusinessTask{
		ID:         step.ID,
		Type:       step.TaskType,
		Parameters: step.Parameters,
		Context:    workflow.Context,
		CreatedAt:  time.Now(),
	}

	// Execute task
	step.Status = "running"
	result, err := o.ExecuteTask(ctx, task)
	if err != nil {
		step.Status = "failed"
		return err
	}

	step.Result = result
	step.Status = "completed"
	completedAt := time.Now()
	step.CompletedAt = &completedAt

	// Store result in workflow
	workflow.Results[step.ID] = result.Result

	return nil
}

// findWorkflowStep finds a workflow step by ID
func (o *BusinessAgentOrchestrator) findWorkflowStep(workflow *Workflow, stepID string) *WorkflowStep {
	for _, step := range workflow.Steps {
		if step.ID == stepID {
			return step
		}
	}
	return nil
}

// executeCollaboration executes a collaboration
func (o *BusinessAgentOrchestrator) executeCollaboration(ctx context.Context, collaboration *ActiveCollaboration) {
	// Implementation for executing collaboration between agents
	// This would involve coordinating the workflow steps between multiple agents

	defer func() {
		completedAt := time.Now()
		collaboration.CompletedAt = &completedAt
		collaboration.Status = "completed"
	}()

	// Execute collaboration workflow
	for _, step := range collaboration.Task.Workflow.Steps {
		// Find agent for this step
		var agent BusinessAgent
		for _, participant := range collaboration.Participants {
			if participant.GetAgentType() == step.AgentType {
				agent = participant
				break
			}
		}

		if agent == nil {
			o.logger.Error("No agent found for collaboration step",
				"step_id", step.ID,
				"agent_type", step.AgentType)
			continue
		}

		// Execute step
		task := &BusinessTask{
			ID:         step.ID,
			Type:       step.Action,
			Parameters: make(map[string]interface{}),
			Context:    collaboration.Task.Context,
			CreatedAt:  time.Now(),
		}

		result, err := agent.ExecuteBusinessTask(ctx, task)
		if err != nil {
			o.logger.Error("Collaboration step failed",
				"step_id", step.ID,
				"agent_id", agent.ID(),
				"error", err)
			continue
		}

		collaboration.Results[step.ID] = result.Result
	}
}

// GetAgentMetrics returns metrics for all agents
func (o *BusinessAgentOrchestrator) GetAgentMetrics() map[string]*BusinessAgentMetrics {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	metrics := make(map[string]*BusinessAgentMetrics)
	for id, agent := range o.agents {
		metrics[id] = agent.GetPerformanceMetrics()
	}

	return metrics
}

// GetWorkflowStatus returns the status of a workflow
func (o *BusinessAgentOrchestrator) GetWorkflowStatus(workflowID string) (*Workflow, error) {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	workflow, exists := o.workflows[workflowID]
	if !exists {
		return nil, fmt.Errorf("workflow %s not found", workflowID)
	}

	return workflow, nil
}
