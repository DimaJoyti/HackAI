package multiagent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/messaging"
	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var multiAgentTracer = otel.Tracer("hackai/langgraph/agents/multiagent")

// MultiAgentSystem manages collaboration between multiple agents
type MultiAgentSystem struct {
	ID               string
	Name             string
	Agents           map[string]Agent
	MessageRouter    *messaging.MessageRouter
	Coordinator      *AgentCoordinator
	WorkflowEngine   *WorkflowEngine
	ConflictResolver *ConflictResolver
	Logger           *logger.Logger
	config           *MultiAgentConfig
	mutex            sync.RWMutex
}

// MultiAgentConfig holds configuration for the multi-agent system
type MultiAgentConfig struct {
	MaxConcurrentAgents    int           `json:"max_concurrent_agents"`
	MessageTimeout         time.Duration `json:"message_timeout"`
	CoordinationTimeout    time.Duration `json:"coordination_timeout"`
	EnableConflictResolution bool        `json:"enable_conflict_resolution"`
	EnableWorkflowEngine   bool          `json:"enable_workflow_engine"`
	EnableLoadBalancing    bool          `json:"enable_load_balancing"`
	HeartbeatInterval      time.Duration `json:"heartbeat_interval"`
}

// Agent interface for multi-agent collaboration
type Agent interface {
	ID() string
	Name() string
	GetCapabilities() map[string]interface{}
	Execute(ctx context.Context, input AgentInput) (*AgentOutput, error)
	HandleMessage(ctx context.Context, message *messaging.AgentMessage) error
	GetStatus() AgentStatus
	Start(ctx context.Context) error
	Stop() error
}

// AgentInput represents input to an agent
type AgentInput struct {
	Task        CollaborativeTask      `json:"task"`
	Context     map[string]interface{} `json:"context"`
	Priority    Priority               `json:"priority"`
	Deadline    *time.Time             `json:"deadline,omitempty"`
	Constraints []string               `json:"constraints"`
}

// AgentOutput represents output from an agent
type AgentOutput struct {
	Success    bool                   `json:"success"`
	Result     interface{}            `json:"result"`
	Confidence float64                `json:"confidence"`
	Duration   time.Duration          `json:"duration"`
	Messages   []*messaging.AgentMessage `json:"messages"`
	Error      string                 `json:"error,omitempty"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// CollaborativeTask represents a task that requires multiple agents
type CollaborativeTask struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        TaskType               `json:"type"`
	Objective   string                 `json:"objective"`
	Subtasks    []*Subtask             `json:"subtasks"`
	Dependencies map[string][]string   `json:"dependencies"`
	RequiredAgents []string            `json:"required_agents"`
	OptionalAgents []string            `json:"optional_agents"`
	Deadline    *time.Time             `json:"deadline,omitempty"`
	Priority    Priority               `json:"priority"`
	Status      TaskStatus             `json:"status"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Subtask represents a portion of a collaborative task
type Subtask struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	AssignedAgent string                `json:"assigned_agent"`
	Status       TaskStatus             `json:"status"`
	Input        map[string]interface{} `json:"input"`
	Output       interface{}            `json:"output,omitempty"`
	Dependencies []string               `json:"dependencies"`
	Priority     Priority               `json:"priority"`
	StartTime    *time.Time             `json:"start_time,omitempty"`
	EndTime      *time.Time             `json:"end_time,omitempty"`
	Error        string                 `json:"error,omitempty"`
}

// TaskType represents different types of collaborative tasks
type TaskType string

const (
	TaskTypeSecurityAssessment TaskType = "security_assessment"
	TaskTypeDataAnalysis       TaskType = "data_analysis"
	TaskTypeInvestigation      TaskType = "investigation"
	TaskTypeReporting          TaskType = "reporting"
	TaskTypeIntegration        TaskType = "integration"
	TaskTypeMonitoring         TaskType = "monitoring"
	TaskTypeCustom             TaskType = "custom"
)

// TaskStatus represents the status of a task
type TaskStatus string

const (
	TaskStatusPending    TaskStatus = "pending"
	TaskStatusAssigned   TaskStatus = "assigned"
	TaskStatusInProgress TaskStatus = "in_progress"
	TaskStatusCompleted  TaskStatus = "completed"
	TaskStatusFailed     TaskStatus = "failed"
	TaskStatusCancelled  TaskStatus = "cancelled"
)

// Priority represents task priority
type Priority int

const (
	PriorityLow    Priority = 1
	PriorityNormal Priority = 5
	PriorityHigh   Priority = 8
	PriorityCritical Priority = 10
)

// AgentStatus represents the status of an agent
type AgentStatus string

const (
	AgentStatusIdle      AgentStatus = "idle"
	AgentStatusBusy      AgentStatus = "busy"
	AgentStatusOffline   AgentStatus = "offline"
	AgentStatusError     AgentStatus = "error"
	AgentStatusStarting  AgentStatus = "starting"
	AgentStatusStopping  AgentStatus = "stopping"
)

// NewMultiAgentSystem creates a new multi-agent system
func NewMultiAgentSystem(id, name string, logger *logger.Logger) *MultiAgentSystem {
	config := &MultiAgentConfig{
		MaxConcurrentAgents:      10,
		MessageTimeout:           30 * time.Second,
		CoordinationTimeout:      5 * time.Minute,
		EnableConflictResolution: true,
		EnableWorkflowEngine:     true,
		EnableLoadBalancing:      true,
		HeartbeatInterval:        30 * time.Second,
	}

	return &MultiAgentSystem{
		ID:               id,
		Name:             name,
		Agents:           make(map[string]Agent),
		MessageRouter:    messaging.NewMessageRouter(logger),
		Coordinator:      NewAgentCoordinator(config, logger),
		WorkflowEngine:   NewWorkflowEngine(logger),
		ConflictResolver: NewConflictResolver(logger),
		Logger:           logger,
		config:           config,
	}
}

// RegisterAgent registers an agent with the system
func (mas *MultiAgentSystem) RegisterAgent(agent Agent) error {
	mas.mutex.Lock()
	defer mas.mutex.Unlock()

	if agent == nil {
		return fmt.Errorf("agent cannot be nil")
	}

	agentID := agent.ID()
	if _, exists := mas.Agents[agentID]; exists {
		return fmt.Errorf("agent %s already registered", agentID)
	}

	mas.Agents[agentID] = agent
	mas.Logger.Info("Agent registered with multi-agent system",
		"system_id", mas.ID,
		"agent_id", agentID,
		"agent_name", agent.Name())

	return nil
}

// UnregisterAgent removes an agent from the system
func (mas *MultiAgentSystem) UnregisterAgent(agentID string) error {
	mas.mutex.Lock()
	defer mas.mutex.Unlock()

	if _, exists := mas.Agents[agentID]; !exists {
		return fmt.Errorf("agent %s not found", agentID)
	}

	delete(mas.Agents, agentID)
	mas.Logger.Info("Agent unregistered from multi-agent system",
		"system_id", mas.ID,
		"agent_id", agentID)

	return nil
}

// ExecuteCollaborativeTask executes a task that requires multiple agents
func (mas *MultiAgentSystem) ExecuteCollaborativeTask(ctx context.Context, task CollaborativeTask) (*CollaborationResult, error) {
	ctx, span := multiAgentTracer.Start(ctx, "multi_agent_system.execute_collaborative_task",
		trace.WithAttributes(
			attribute.String("system.id", mas.ID),
			attribute.String("task.id", task.ID),
			attribute.String("task.type", string(task.Type)),
			attribute.Int("required_agents", len(task.RequiredAgents)),
		),
	)
	defer span.End()

	startTime := time.Now()
	task.Status = TaskStatusInProgress

	mas.Logger.Info("Starting collaborative task execution",
		"system_id", mas.ID,
		"task_id", task.ID,
		"task_name", task.Name,
		"required_agents", len(task.RequiredAgents))

	// Phase 1: Task decomposition and agent assignment
	assignments, err := mas.Coordinator.AssignTask(ctx, &task, mas.Agents)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("task assignment failed: %w", err)
	}

	// Phase 2: Execute subtasks with coordination
	results, err := mas.executeSubtasks(ctx, &task, assignments)
	if err != nil {
		span.RecordError(err)
		task.Status = TaskStatusFailed
		return nil, fmt.Errorf("subtask execution failed: %w", err)
	}

	// Phase 3: Aggregate results and resolve conflicts
	finalResult, err := mas.aggregateResults(ctx, &task, results)
	if err != nil {
		span.RecordError(err)
		task.Status = TaskStatusFailed
		return nil, fmt.Errorf("result aggregation failed: %w", err)
	}

	task.Status = TaskStatusCompleted
	duration := time.Since(startTime)

	collaborationResult := &CollaborationResult{
		TaskID:           task.ID,
		Success:          true,
		Result:           finalResult,
		Duration:         duration,
		ParticipatingAgents: assignments,
		SubtaskResults:   results,
		Metadata: map[string]interface{}{
			"total_agents":    len(assignments),
			"total_subtasks":  len(task.Subtasks),
			"execution_mode":  "collaborative",
		},
	}

	span.SetAttributes(
		attribute.Bool("execution.success", true),
		attribute.Int("execution.participating_agents", len(assignments)),
		attribute.Float64("execution.duration", duration.Seconds()),
	)

	mas.Logger.Info("Collaborative task execution completed",
		"system_id", mas.ID,
		"task_id", task.ID,
		"duration", duration,
		"participating_agents", len(assignments))

	return collaborationResult, nil
}

// executeSubtasks executes all subtasks with proper coordination
func (mas *MultiAgentSystem) executeSubtasks(ctx context.Context, task *CollaborativeTask, assignments map[string]string) (map[string]*SubtaskResult, error) {
	results := make(map[string]*SubtaskResult)
	var wg sync.WaitGroup
	var mutex sync.Mutex
	errors := make([]error, 0)

	// Execute subtasks based on dependencies
	executionLevels := mas.buildExecutionLevels(task)

	for levelIndex, level := range executionLevels {
		mas.Logger.Debug("Executing subtask level",
			"task_id", task.ID,
			"level", levelIndex,
			"subtasks", len(level))

		// Execute all subtasks in this level in parallel
		for _, subtask := range level {
			wg.Add(1)
			go func(st *Subtask) {
				defer wg.Done()

				agentID, assigned := assignments[st.ID]
				if !assigned {
					mutex.Lock()
					errors = append(errors, fmt.Errorf("subtask %s not assigned to any agent", st.ID))
					mutex.Unlock()
					return
				}

				agent, exists := mas.Agents[agentID]
				if !exists {
					mutex.Lock()
					errors = append(errors, fmt.Errorf("assigned agent %s not found", agentID))
					mutex.Unlock()
					return
				}

				// Execute subtask
				result, err := mas.executeSubtask(ctx, st, agent)
				
				mutex.Lock()
				if err != nil {
					errors = append(errors, err)
					st.Status = TaskStatusFailed
					st.Error = err.Error()
				} else {
					st.Status = TaskStatusCompleted
					st.Output = result.Result
					results[st.ID] = result
				}
				mutex.Unlock()
			}(subtask)
		}

		wg.Wait()

		// Check for errors at this level
		if len(errors) > 0 {
			return results, fmt.Errorf("subtask execution failed: %d errors", len(errors))
		}
	}

	return results, nil
}

// executeSubtask executes a single subtask
func (mas *MultiAgentSystem) executeSubtask(ctx context.Context, subtask *Subtask, agent Agent) (*SubtaskResult, error) {
	startTime := time.Now()
	subtask.StartTime = &startTime
	subtask.Status = TaskStatusInProgress

	// Prepare agent input
	agentInput := AgentInput{
		Task: CollaborativeTask{
			ID:          subtask.ID,
			Name:        subtask.Name,
			Description: subtask.Description,
			Objective:   subtask.Description,
		},
		Context:  subtask.Input,
		Priority: subtask.Priority,
	}

	// Execute with agent
	output, err := agent.Execute(ctx, agentInput)
	
	endTime := time.Now()
	subtask.EndTime = &endTime

	if err != nil {
		return nil, fmt.Errorf("agent %s failed to execute subtask %s: %w", agent.ID(), subtask.ID, err)
	}

	result := &SubtaskResult{
		SubtaskID:    subtask.ID,
		AgentID:      agent.ID(),
		Success:      output.Success,
		Result:       output.Result,
		Confidence:   output.Confidence,
		Duration:     endTime.Sub(startTime),
		Messages:     output.Messages,
		Error:        output.Error,
		Metadata:     output.Metadata,
	}

	return result, nil
}

// buildExecutionLevels builds levels of subtasks that can be executed in parallel
func (mas *MultiAgentSystem) buildExecutionLevels(task *CollaborativeTask) [][]*Subtask {
	levels := make([][]*Subtask, 0)
	remaining := make([]*Subtask, len(task.Subtasks))
	copy(remaining, task.Subtasks)

	for len(remaining) > 0 {
		currentLevel := make([]*Subtask, 0)
		newRemaining := make([]*Subtask, 0)

		for _, subtask := range remaining {
			if mas.areDependenciesSatisfied(subtask, task) {
				currentLevel = append(currentLevel, subtask)
			} else {
				newRemaining = append(newRemaining, subtask)
			}
		}

		if len(currentLevel) == 0 {
			// No subtasks can be executed, break to avoid infinite loop
			mas.Logger.Warn("Circular dependency detected or unsatisfied dependencies",
				"task_id", task.ID,
				"remaining_subtasks", len(newRemaining))
			break
		}

		levels = append(levels, currentLevel)
		remaining = newRemaining

		// Mark current level subtasks as ready
		for _, subtask := range currentLevel {
			subtask.Status = TaskStatusAssigned
		}
	}

	return levels
}

// areDependenciesSatisfied checks if all dependencies for a subtask are satisfied
func (mas *MultiAgentSystem) areDependenciesSatisfied(subtask *Subtask, task *CollaborativeTask) bool {
	for _, depID := range subtask.Dependencies {
		for _, taskSubtask := range task.Subtasks {
			if taskSubtask.ID == depID && taskSubtask.Status != TaskStatusCompleted {
				return false
			}
		}
	}
	return true
}

// aggregateResults aggregates results from all subtasks
func (mas *MultiAgentSystem) aggregateResults(ctx context.Context, task *CollaborativeTask, results map[string]*SubtaskResult) (interface{}, error) {
	if mas.config.EnableConflictResolution {
		return mas.ConflictResolver.ResolveAndAggregate(ctx, task, results)
	}

	// Simple aggregation - combine all results
	aggregated := map[string]interface{}{
		"task_id":     task.ID,
		"task_name":   task.Name,
		"subtasks":    len(task.Subtasks),
		"results":     results,
		"timestamp":   time.Now(),
	}

	return aggregated, nil
}

// GetSystemStatus returns the current status of the multi-agent system
func (mas *MultiAgentSystem) GetSystemStatus() SystemStatus {
	mas.mutex.RLock()
	defer mas.mutex.RUnlock()

	agentStatuses := make(map[string]AgentStatus)
	for agentID, agent := range mas.Agents {
		agentStatuses[agentID] = agent.GetStatus()
	}

	return SystemStatus{
		SystemID:      mas.ID,
		TotalAgents:   len(mas.Agents),
		AgentStatuses: agentStatuses,
		Timestamp:     time.Now(),
		Metadata: map[string]interface{}{
			"message_router_active": mas.MessageRouter != nil,
			"coordinator_active":    mas.Coordinator != nil,
			"workflow_engine_active": mas.WorkflowEngine != nil,
		},
	}
}

// StartSystem starts the multi-agent system
func (mas *MultiAgentSystem) StartSystem(ctx context.Context) error {
	mas.Logger.Info("Starting multi-agent system", "system_id", mas.ID)

	// Start all registered agents
	for agentID, agent := range mas.Agents {
		if err := agent.Start(ctx); err != nil {
			mas.Logger.Error("Failed to start agent", "agent_id", agentID, "error", err)
			return fmt.Errorf("failed to start agent %s: %w", agentID, err)
		}
	}

	mas.Logger.Info("Multi-agent system started successfully",
		"system_id", mas.ID,
		"agents", len(mas.Agents))

	return nil
}

// StopSystem stops the multi-agent system
func (mas *MultiAgentSystem) StopSystem() error {
	mas.Logger.Info("Stopping multi-agent system", "system_id", mas.ID)

	// Stop all agents
	for agentID, agent := range mas.Agents {
		if err := agent.Stop(); err != nil {
			mas.Logger.Error("Failed to stop agent", "agent_id", agentID, "error", err)
		}
	}

	mas.Logger.Info("Multi-agent system stopped", "system_id", mas.ID)
	return nil
}

// CollaborationResult holds the result of collaborative task execution
type CollaborationResult struct {
	TaskID              string                    `json:"task_id"`
	Success             bool                      `json:"success"`
	Result              interface{}               `json:"result"`
	Duration            time.Duration             `json:"duration"`
	ParticipatingAgents map[string]string         `json:"participating_agents"`
	SubtaskResults      map[string]*SubtaskResult `json:"subtask_results"`
	ConflictsResolved   int                       `json:"conflicts_resolved"`
	Error               string                    `json:"error,omitempty"`
	Metadata            map[string]interface{}    `json:"metadata"`
}

// SubtaskResult holds the result of a subtask execution
type SubtaskResult struct {
	SubtaskID  string                    `json:"subtask_id"`
	AgentID    string                    `json:"agent_id"`
	Success    bool                      `json:"success"`
	Result     interface{}               `json:"result"`
	Confidence float64                   `json:"confidence"`
	Duration   time.Duration             `json:"duration"`
	Messages   []*messaging.AgentMessage `json:"messages"`
	Error      string                    `json:"error,omitempty"`
	Metadata   map[string]interface{}    `json:"metadata"`
}

// SystemStatus represents the status of the multi-agent system
type SystemStatus struct {
	SystemID      string                    `json:"system_id"`
	TotalAgents   int                       `json:"total_agents"`
	AgentStatuses map[string]AgentStatus    `json:"agent_statuses"`
	Timestamp     time.Time                 `json:"timestamp"`
	Metadata      map[string]interface{}    `json:"metadata"`
}

// UpdateConfig updates the system configuration
func (mas *MultiAgentSystem) UpdateConfig(config *MultiAgentConfig) {
	mas.mutex.Lock()
	defer mas.mutex.Unlock()

	if config.MaxConcurrentAgents > 0 {
		mas.config.MaxConcurrentAgents = config.MaxConcurrentAgents
	}
	
	if config.MessageTimeout > 0 {
		mas.config.MessageTimeout = config.MessageTimeout
	}

	if config.CoordinationTimeout > 0 {
		mas.config.CoordinationTimeout = config.CoordinationTimeout
	}

	mas.config.EnableConflictResolution = config.EnableConflictResolution
	mas.config.EnableWorkflowEngine = config.EnableWorkflowEngine
	mas.config.EnableLoadBalancing = config.EnableLoadBalancing

	if config.HeartbeatInterval > 0 {
		mas.config.HeartbeatInterval = config.HeartbeatInterval
	}

	mas.Logger.Info("Multi-agent system configuration updated",
		"system_id", mas.ID,
		"max_concurrent_agents", mas.config.MaxConcurrentAgents,
		"conflict_resolution", mas.config.EnableConflictResolution)
}
