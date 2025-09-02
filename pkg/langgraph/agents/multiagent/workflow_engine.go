package multiagent

import (
	"context"
	"fmt"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// WorkflowEngine manages complex multi-agent workflows
type WorkflowEngine struct {
	logger          *logger.Logger
	workflows       map[string]*Workflow
	executionEngine *WorkflowExecutionEngine
	templateManager *WorkflowTemplateManager
	stateManager    *WorkflowStateManager
}

// Workflow represents a multi-agent workflow
type Workflow struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Steps       []*WorkflowStep        `json:"steps"`
	Status      WorkflowStatus         `json:"status"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// WorkflowStep represents a step in a workflow
type WorkflowStep struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         StepType               `json:"type"`
	AgentID      string                 `json:"agent_id"`
	Input        map[string]interface{} `json:"input"`
	Output       interface{}            `json:"output,omitempty"`
	Status       StepStatus             `json:"status"`
	Dependencies []string               `json:"dependencies"`
	Conditions   []StepCondition        `json:"conditions"`
	Timeout      time.Duration          `json:"timeout"`
	Retries      int                    `json:"retries"`
	MaxRetries   int                    `json:"max_retries"`
	StartTime    *time.Time             `json:"start_time,omitempty"`
	EndTime      *time.Time             `json:"end_time,omitempty"`
	Error        string                 `json:"error,omitempty"`
}

// WorkflowStatus represents the status of a workflow
type WorkflowStatus string

const (
	WorkflowStatusDraft     WorkflowStatus = "draft"
	WorkflowStatusReady     WorkflowStatus = "ready"
	WorkflowStatusRunning   WorkflowStatus = "running"
	WorkflowStatusCompleted WorkflowStatus = "completed"
	WorkflowStatusFailed    WorkflowStatus = "failed"
	WorkflowStatusCancelled WorkflowStatus = "cancelled"
	WorkflowStatusPaused    WorkflowStatus = "paused"
)

// StepType represents the type of workflow step
type StepType string

const (
	StepTypeAgentTask    StepType = "agent_task"
	StepTypeDecision     StepType = "decision"
	StepTypeParallel     StepType = "parallel"
	StepTypeSequential   StepType = "sequential"
	StepTypeConditional  StepType = "conditional"
	StepTypeLoop         StepType = "loop"
	StepTypeWait         StepType = "wait"
	StepTypeNotification StepType = "notification"
)

// StepStatus represents the status of a workflow step
type StepStatus string

const (
	StepStatusPending   StepStatus = "pending"
	StepStatusReady     StepStatus = "ready"
	StepStatusRunning   StepStatus = "running"
	StepStatusCompleted StepStatus = "completed"
	StepStatusFailed    StepStatus = "failed"
	StepStatusSkipped   StepStatus = "skipped"
	StepStatusCancelled StepStatus = "cancelled"
)

// StepCondition represents a condition for step execution
type StepCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// WorkflowExecutionEngine executes workflows
type WorkflowExecutionEngine struct {
	logger *logger.Logger
}

// WorkflowTemplateManager manages workflow templates
type WorkflowTemplateManager struct {
	logger    *logger.Logger
	templates map[string]*WorkflowTemplate
}

// WorkflowStateManager manages workflow state
type WorkflowStateManager struct {
	logger *logger.Logger
	states map[string]*WorkflowState
}

// WorkflowTemplate represents a reusable workflow template
type WorkflowTemplate struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	Category    string                  `json:"category"`
	Steps       []*WorkflowStepTemplate `json:"steps"`
	Parameters  []TemplateParameter     `json:"parameters"`
	Metadata    map[string]interface{}  `json:"metadata"`
}

// WorkflowStepTemplate represents a step template
type WorkflowStepTemplate struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         StepType               `json:"type"`
	AgentType    string                 `json:"agent_type"`
	Input        map[string]interface{} `json:"input"`
	Dependencies []string               `json:"dependencies"`
	Conditions   []StepCondition        `json:"conditions"`
	Timeout      time.Duration          `json:"timeout"`
	MaxRetries   int                    `json:"max_retries"`
}

// TemplateParameter represents a workflow template parameter
type TemplateParameter struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Required     bool        `json:"required"`
	DefaultValue interface{} `json:"default_value"`
	Description  string      `json:"description"`
}

// WorkflowState represents the current state of a workflow execution
type WorkflowState struct {
	WorkflowID  string                 `json:"workflow_id"`
	CurrentStep string                 `json:"current_step"`
	Variables   map[string]interface{} `json:"variables"`
	StepResults map[string]interface{} `json:"step_results"`
	LastUpdated time.Time              `json:"last_updated"`
}

// NewWorkflowEngine creates a new workflow engine
func NewWorkflowEngine(logger *logger.Logger) *WorkflowEngine {
	we := &WorkflowEngine{
		logger:          logger,
		workflows:       make(map[string]*Workflow),
		executionEngine: &WorkflowExecutionEngine{logger: logger},
		templateManager: &WorkflowTemplateManager{
			logger:    logger,
			templates: make(map[string]*WorkflowTemplate),
		},
		stateManager: &WorkflowStateManager{
			logger: logger,
			states: make(map[string]*WorkflowState),
		},
	}

	// Initialize default templates
	we.initializeDefaultTemplates()

	return we
}

// initializeDefaultTemplates sets up default workflow templates
func (we *WorkflowEngine) initializeDefaultTemplates() {
	templates := []*WorkflowTemplate{
		{
			ID:          "security_assessment_workflow",
			Name:        "Security Assessment Workflow",
			Description: "Comprehensive security assessment workflow",
			Category:    "security",
			Steps: []*WorkflowStepTemplate{
				{
					ID:        "recon",
					Name:      "Reconnaissance",
					Type:      StepTypeAgentTask,
					AgentType: "security",
					Input: map[string]interface{}{
						"scan_type": "passive",
					},
					Timeout:    10 * time.Minute,
					MaxRetries: 2,
				},
				{
					ID:           "vulnerability_scan",
					Name:         "Vulnerability Scanning",
					Type:         StepTypeAgentTask,
					AgentType:    "security",
					Dependencies: []string{"recon"},
					Input: map[string]interface{}{
						"scan_type": "comprehensive",
					},
					Timeout:    20 * time.Minute,
					MaxRetries: 3,
				},
				{
					ID:           "risk_analysis",
					Name:         "Risk Analysis",
					Type:         StepTypeAgentTask,
					AgentType:    "analysis",
					Dependencies: []string{"vulnerability_scan"},
					Input: map[string]interface{}{
						"analysis_type": "risk_assessment",
					},
					Timeout:    15 * time.Minute,
					MaxRetries: 2,
				},
				{
					ID:           "report_generation",
					Name:         "Report Generation",
					Type:         StepTypeAgentTask,
					AgentType:    "reporting",
					Dependencies: []string{"risk_analysis"},
					Input: map[string]interface{}{
						"report_type": "security_assessment",
					},
					Timeout:    10 * time.Minute,
					MaxRetries: 2,
				},
			},
			Parameters: []TemplateParameter{
				{
					Name:        "target",
					Type:        "string",
					Required:    true,
					Description: "Target system or domain to assess",
				},
				{
					Name:         "scan_depth",
					Type:         "string",
					Required:     false,
					DefaultValue: "standard",
					Description:  "Depth of security scanning (basic, standard, comprehensive)",
				},
			},
		},
		{
			ID:          "data_analysis_workflow",
			Name:        "Data Analysis Workflow",
			Description: "Multi-stage data analysis workflow",
			Category:    "analytics",
			Steps: []*WorkflowStepTemplate{
				{
					ID:        "data_collection",
					Name:      "Data Collection",
					Type:      StepTypeAgentTask,
					AgentType: "data",
					Input: map[string]interface{}{
						"collection_method": "automated",
					},
					Timeout:    30 * time.Minute,
					MaxRetries: 3,
				},
				{
					ID:           "data_processing",
					Name:         "Data Processing",
					Type:         StepTypeAgentTask,
					AgentType:    "data",
					Dependencies: []string{"data_collection"},
					Input: map[string]interface{}{
						"processing_type": "standard",
					},
					Timeout:    45 * time.Minute,
					MaxRetries: 2,
				},
				{
					ID:           "analysis",
					Name:         "Statistical Analysis",
					Type:         StepTypeAgentTask,
					AgentType:    "analysis",
					Dependencies: []string{"data_processing"},
					Input: map[string]interface{}{
						"analysis_methods": []string{"statistical", "pattern_recognition"},
					},
					Timeout:    60 * time.Minute,
					MaxRetries: 2,
				},
			},
			Parameters: []TemplateParameter{
				{
					Name:        "data_sources",
					Type:        "array",
					Required:    true,
					Description: "List of data sources to analyze",
				},
				{
					Name:         "analysis_type",
					Type:         "string",
					Required:     false,
					DefaultValue: "comprehensive",
					Description:  "Type of analysis to perform",
				},
			},
		},
	}

	for _, template := range templates {
		we.templateManager.templates[template.ID] = template
	}
}

// CreateWorkflowFromTemplate creates a workflow from a template
func (we *WorkflowEngine) CreateWorkflowFromTemplate(templateID string, parameters map[string]interface{}) (*Workflow, error) {
	template, exists := we.templateManager.templates[templateID]
	if !exists {
		return nil, fmt.Errorf("template %s not found", templateID)
	}

	// Validate parameters
	if err := we.validateTemplateParameters(template, parameters); err != nil {
		return nil, fmt.Errorf("parameter validation failed: %w", err)
	}

	// Create workflow from template
	workflow := &Workflow{
		ID:          fmt.Sprintf("workflow-%d", time.Now().UnixNano()),
		Name:        template.Name,
		Description: template.Description,
		Steps:       make([]*WorkflowStep, 0),
		Status:      WorkflowStatusDraft,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Metadata: map[string]interface{}{
			"template_id": templateID,
			"parameters":  parameters,
		},
	}

	// Convert template steps to workflow steps
	for _, stepTemplate := range template.Steps {
		step := &WorkflowStep{
			ID:           stepTemplate.ID,
			Name:         stepTemplate.Name,
			Type:         stepTemplate.Type,
			Input:        make(map[string]interface{}),
			Status:       StepStatusPending,
			Dependencies: stepTemplate.Dependencies,
			Conditions:   stepTemplate.Conditions,
			Timeout:      stepTemplate.Timeout,
			MaxRetries:   stepTemplate.MaxRetries,
		}

		// Copy input and substitute parameters
		for key, value := range stepTemplate.Input {
			step.Input[key] = we.substituteParameter(value, parameters)
		}

		// Add parameters to input
		for key, value := range parameters {
			step.Input[key] = value
		}

		workflow.Steps = append(workflow.Steps, step)
	}

	workflow.Status = WorkflowStatusReady
	we.workflows[workflow.ID] = workflow

	we.logger.Info("Workflow created from template",
		"workflow_id", workflow.ID,
		"template_id", templateID,
		"steps", len(workflow.Steps))

	return workflow, nil
}

// ExecuteWorkflow executes a workflow
func (we *WorkflowEngine) ExecuteWorkflow(ctx context.Context, workflowID string, agents map[string]Agent) (*WorkflowExecutionResult, error) {
	workflow, exists := we.workflows[workflowID]
	if !exists {
		return nil, fmt.Errorf("workflow %s not found", workflowID)
	}

	we.logger.Info("Starting workflow execution",
		"workflow_id", workflowID,
		"steps", len(workflow.Steps))

	return we.executionEngine.Execute(ctx, workflow, agents, we.stateManager)
}

// Execute executes a workflow
func (wee *WorkflowExecutionEngine) Execute(ctx context.Context, workflow *Workflow, agents map[string]Agent, stateManager *WorkflowStateManager) (*WorkflowExecutionResult, error) {
	startTime := time.Now()
	workflow.Status = WorkflowStatusRunning

	// Initialize workflow state
	state := &WorkflowState{
		WorkflowID:  workflow.ID,
		Variables:   make(map[string]interface{}),
		StepResults: make(map[string]interface{}),
		LastUpdated: time.Now(),
	}
	stateManager.states[workflow.ID] = state

	// Execute steps based on dependencies
	executionLevels := wee.buildExecutionLevels(workflow)

	for levelIndex, level := range executionLevels {
		wee.logger.Debug("Executing workflow level",
			"workflow_id", workflow.ID,
			"level", levelIndex,
			"steps", len(level))

		for _, step := range level {
			if err := wee.executeStep(ctx, step, agents, state); err != nil {
				workflow.Status = WorkflowStatusFailed
				return &WorkflowExecutionResult{
					WorkflowID: workflow.ID,
					Success:    false,
					Error:      err.Error(),
					Duration:   time.Since(startTime),
				}, err
			}
		}
	}

	workflow.Status = WorkflowStatusCompleted
	duration := time.Since(startTime)

	result := &WorkflowExecutionResult{
		WorkflowID:  workflow.ID,
		Success:     true,
		Duration:    duration,
		StepResults: state.StepResults,
		FinalState:  state.Variables,
	}

	wee.logger.Info("Workflow execution completed",
		"workflow_id", workflow.ID,
		"duration", duration,
		"steps_executed", len(workflow.Steps))

	return result, nil
}

// executeStep executes a single workflow step
func (wee *WorkflowExecutionEngine) executeStep(ctx context.Context, step *WorkflowStep, agents map[string]Agent, state *WorkflowState) error {
	startTime := time.Now()
	step.StartTime = &startTime
	step.Status = StepStatusRunning

	wee.logger.Debug("Executing workflow step",
		"step_id", step.ID,
		"step_name", step.Name,
		"step_type", step.Type)

	// Check conditions
	if !wee.evaluateConditions(step.Conditions, state) {
		step.Status = StepStatusSkipped
		wee.logger.Debug("Step skipped due to conditions", "step_id", step.ID)
		return nil
	}

	var result interface{}
	var err error

	switch step.Type {
	case StepTypeAgentTask:
		result, err = wee.executeAgentTask(ctx, step, agents, state)
	case StepTypeDecision:
		result, err = wee.executeDecision(ctx, step, state)
	case StepTypeWait:
		result, err = wee.executeWait(ctx, step)
	case StepTypeNotification:
		result, err = wee.executeNotification(ctx, step, state)
	default:
		err = fmt.Errorf("unsupported step type: %s", step.Type)
	}

	endTime := time.Now()
	step.EndTime = &endTime

	if err != nil {
		step.Status = StepStatusFailed
		step.Error = err.Error()
		return fmt.Errorf("step %s failed: %w", step.ID, err)
	}

	step.Status = StepStatusCompleted
	step.Output = result
	state.StepResults[step.ID] = result
	state.LastUpdated = time.Now()

	wee.logger.Debug("Step execution completed",
		"step_id", step.ID,
		"duration", endTime.Sub(startTime))

	return nil
}

// executeAgentTask executes an agent task step
func (wee *WorkflowExecutionEngine) executeAgentTask(ctx context.Context, step *WorkflowStep, agents map[string]Agent, state *WorkflowState) (interface{}, error) {
	agent, exists := agents[step.AgentID]
	if !exists {
		return nil, fmt.Errorf("agent %s not found", step.AgentID)
	}

	// Prepare agent input
	agentInput := AgentInput{
		Task: CollaborativeTask{
			ID:        step.ID,
			Name:      step.Name,
			Objective: fmt.Sprintf("Execute workflow step: %s", step.Name),
		},
		Context: step.Input,
	}

	// Add state variables to context
	for key, value := range state.Variables {
		agentInput.Context[key] = value
	}

	// Execute with timeout
	stepCtx := ctx
	if step.Timeout > 0 {
		var cancel context.CancelFunc
		stepCtx, cancel = context.WithTimeout(ctx, step.Timeout)
		defer cancel()
	}

	output, err := agent.Execute(stepCtx, agentInput)
	if err != nil {
		return nil, err
	}

	return output.Result, nil
}

// executeDecision executes a decision step
func (wee *WorkflowExecutionEngine) executeDecision(ctx context.Context, step *WorkflowStep, state *WorkflowState) (interface{}, error) {
	// Simple decision logic based on conditions
	decision := map[string]interface{}{
		"step_id":   step.ID,
		"decision":  "proceed",
		"timestamp": time.Now(),
	}

	return decision, nil
}

// executeWait executes a wait step
func (wee *WorkflowExecutionEngine) executeWait(ctx context.Context, step *WorkflowStep) (interface{}, error) {
	waitDuration := step.Timeout
	if waitDuration == 0 {
		waitDuration = 5 * time.Second
	}

	select {
	case <-time.After(waitDuration):
		return map[string]interface{}{
			"waited": waitDuration.String(),
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// executeNotification executes a notification step
func (wee *WorkflowExecutionEngine) executeNotification(ctx context.Context, step *WorkflowStep, state *WorkflowState) (interface{}, error) {
	notification := map[string]interface{}{
		"step_id":   step.ID,
		"message":   step.Input["message"],
		"timestamp": time.Now(),
		"sent":      true,
	}

	wee.logger.Info("Workflow notification", "step_id", step.ID, "message", step.Input["message"])

	return notification, nil
}

// buildExecutionLevels builds execution levels for workflow steps
func (wee *WorkflowExecutionEngine) buildExecutionLevels(workflow *Workflow) [][]*WorkflowStep {
	levels := make([][]*WorkflowStep, 0)
	remaining := make([]*WorkflowStep, len(workflow.Steps))
	copy(remaining, workflow.Steps)

	for len(remaining) > 0 {
		currentLevel := make([]*WorkflowStep, 0)
		newRemaining := make([]*WorkflowStep, 0)

		for _, step := range remaining {
			if wee.areDependenciesSatisfied(step, workflow) {
				currentLevel = append(currentLevel, step)
			} else {
				newRemaining = append(newRemaining, step)
			}
		}

		if len(currentLevel) == 0 {
			break // Avoid infinite loop
		}

		levels = append(levels, currentLevel)
		remaining = newRemaining
	}

	return levels
}

// areDependenciesSatisfied checks if step dependencies are satisfied
func (wee *WorkflowExecutionEngine) areDependenciesSatisfied(step *WorkflowStep, workflow *Workflow) bool {
	for _, depID := range step.Dependencies {
		for _, workflowStep := range workflow.Steps {
			if workflowStep.ID == depID && workflowStep.Status != StepStatusCompleted {
				return false
			}
		}
	}
	return true
}

// evaluateConditions evaluates step conditions
func (wee *WorkflowExecutionEngine) evaluateConditions(conditions []StepCondition, state *WorkflowState) bool {
	if len(conditions) == 0 {
		return true
	}

	for _, condition := range conditions {
		if !wee.evaluateCondition(condition, state) {
			return false
		}
	}

	return true
}

// evaluateCondition evaluates a single condition
func (wee *WorkflowExecutionEngine) evaluateCondition(condition StepCondition, state *WorkflowState) bool {
	value, exists := state.Variables[condition.Field]
	if !exists {
		return false
	}

	switch condition.Operator {
	case "eq":
		return value == condition.Value
	case "ne":
		return value != condition.Value
	case "exists":
		return exists
	default:
		return false
	}
}

// validateTemplateParameters validates template parameters
func (we *WorkflowEngine) validateTemplateParameters(template *WorkflowTemplate, parameters map[string]interface{}) error {
	for _, param := range template.Parameters {
		if param.Required {
			if _, exists := parameters[param.Name]; !exists {
				return fmt.Errorf("required parameter %s missing", param.Name)
			}
		}
	}
	return nil
}

// substituteParameter substitutes template parameters
func (we *WorkflowEngine) substituteParameter(value interface{}, parameters map[string]interface{}) interface{} {
	if str, ok := value.(string); ok {
		if paramValue, exists := parameters[str]; exists {
			return paramValue
		}
	}
	return value
}

// WorkflowExecutionResult holds the result of workflow execution
type WorkflowExecutionResult struct {
	WorkflowID  string                 `json:"workflow_id"`
	Success     bool                   `json:"success"`
	Duration    time.Duration          `json:"duration"`
	StepResults map[string]interface{} `json:"step_results"`
	FinalState  map[string]interface{} `json:"final_state"`
	Error       string                 `json:"error,omitempty"`
}

// GetWorkflow returns a workflow by ID
func (we *WorkflowEngine) GetWorkflow(workflowID string) (*Workflow, error) {
	workflow, exists := we.workflows[workflowID]
	if !exists {
		return nil, fmt.Errorf("workflow %s not found", workflowID)
	}
	return workflow, nil
}

// ListWorkflows returns all workflows
func (we *WorkflowEngine) ListWorkflows() []*Workflow {
	workflows := make([]*Workflow, 0, len(we.workflows))
	for _, workflow := range we.workflows {
		workflows = append(workflows, workflow)
	}
	return workflows
}

// GetTemplate returns a template by ID
func (we *WorkflowEngine) GetTemplate(templateID string) (*WorkflowTemplate, error) {
	template, exists := we.templateManager.templates[templateID]
	if !exists {
		return nil, fmt.Errorf("template %s not found", templateID)
	}
	return template, nil
}

// ListTemplates returns all templates
func (we *WorkflowEngine) ListTemplates() []*WorkflowTemplate {
	templates := make([]*WorkflowTemplate, 0, len(we.templateManager.templates))
	for _, template := range we.templateManager.templates {
		templates = append(templates, template)
	}
	return templates
}
