package planexecute

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/tools"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// TaskPlanner creates execution plans for objectives
type TaskPlanner struct {
	logger            *logger.Logger
	planningStrategies map[string]PlanningStrategy
	taskTemplates     map[string]TaskTemplate
	dependencyAnalyzer *DependencyAnalyzer
}

// PlanningStrategy defines different approaches to planning
type PlanningStrategy struct {
	Name        string
	Description string
	Keywords    []string
	Approach    PlanningApproach
}

// PlanningApproach defines the planning methodology
type PlanningApproach string

const (
	ApproachSequential   PlanningApproach = "sequential"
	ApproachParallel     PlanningApproach = "parallel"
	ApproachHierarchical PlanningApproach = "hierarchical"
	ApproachIterative    PlanningApproach = "iterative"
	ApproachAdaptive     PlanningApproach = "adaptive"
)

// TaskTemplate defines a template for common task types
type TaskTemplate struct {
	Type         TaskType               `json:"type"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	RequiredTools []string              `json:"required_tools"`
	EstimatedDuration time.Duration     `json:"estimated_duration"`
	DefaultInput map[string]interface{} `json:"default_input"`
	Dependencies []string               `json:"dependencies"`
}

// DependencyAnalyzer analyzes task dependencies
type DependencyAnalyzer struct {
	logger *logger.Logger
}

// NewTaskPlanner creates a new task planner
func NewTaskPlanner(logger *logger.Logger) *TaskPlanner {
	tp := &TaskPlanner{
		logger:             logger,
		planningStrategies: make(map[string]PlanningStrategy),
		taskTemplates:      make(map[string]TaskTemplate),
		dependencyAnalyzer: &DependencyAnalyzer{logger: logger},
	}

	// Initialize planning strategies and templates
	tp.initializePlanningStrategies()
	tp.initializeTaskTemplates()

	return tp
}

// initializePlanningStrategies sets up different planning strategies
func (tp *TaskPlanner) initializePlanningStrategies() {
	strategies := []PlanningStrategy{
		{
			Name:        "security_analysis",
			Description: "Plan for comprehensive security analysis",
			Keywords:    []string{"security", "vulnerability", "scan", "audit", "penetration"},
			Approach:    ApproachHierarchical,
		},
		{
			Name:        "data_processing",
			Description: "Plan for data collection and processing workflows",
			Keywords:    []string{"data", "process", "analyze", "transform", "extract"},
			Approach:    ApproachSequential,
		},
		{
			Name:        "investigation",
			Description: "Plan for investigative workflows",
			Keywords:    []string{"investigate", "research", "gather", "evidence", "forensic"},
			Approach:    ApproachIterative,
		},
		{
			Name:        "reporting",
			Description: "Plan for report generation and documentation",
			Keywords:    []string{"report", "document", "generate", "summary", "findings"},
			Approach:    ApproachSequential,
		},
		{
			Name:        "integration",
			Description: "Plan for system integration tasks",
			Keywords:    []string{"integrate", "connect", "sync", "api", "webhook"},
			Approach:    ApproachParallel,
		},
	}

	for _, strategy := range strategies {
		tp.planningStrategies[strategy.Name] = strategy
	}
}

// initializeTaskTemplates sets up common task templates
func (tp *TaskPlanner) initializeTaskTemplates() {
	templates := []TaskTemplate{
		{
			Type:              TaskTypeAnalysis,
			Name:              "Security Scan",
			Description:       "Perform security scanning on target",
			RequiredTools:     []string{"security_scanner", "port_scanner"},
			EstimatedDuration: 10 * time.Minute,
			DefaultInput: map[string]interface{}{
				"scan_type": "comprehensive",
				"timeout":   "300s",
			},
		},
		{
			Type:              TaskTypeDataCollection,
			Name:              "Data Gathering",
			Description:       "Collect data from various sources",
			RequiredTools:     []string{"web_scraper", "api_client"},
			EstimatedDuration: 5 * time.Minute,
			DefaultInput: map[string]interface{}{
				"max_results": 100,
				"format":      "json",
			},
		},
		{
			Type:              TaskTypeProcessing,
			Name:              "Data Processing",
			Description:       "Process and transform collected data",
			RequiredTools:     []string{"data_processor", "transformer"},
			EstimatedDuration: 3 * time.Minute,
			Dependencies:      []string{"data_gathering"},
		},
		{
			Type:              TaskTypeValidation,
			Name:              "Result Validation",
			Description:       "Validate processing results",
			RequiredTools:     []string{"validator", "quality_checker"},
			EstimatedDuration: 2 * time.Minute,
			Dependencies:      []string{"data_processing"},
		},
		{
			Type:              TaskTypeReporting,
			Name:              "Report Generation",
			Description:       "Generate final report",
			RequiredTools:     []string{"report_generator", "formatter"},
			EstimatedDuration: 5 * time.Minute,
			Dependencies:      []string{"result_validation"},
		},
	}

	for _, template := range templates {
		tp.taskTemplates[string(template.Type)] = template
	}
}

// CreatePlan creates an execution plan for the given objective
func (tp *TaskPlanner) CreatePlan(ctx context.Context, input AgentInput, availableTools map[string]tools.Tool) (*ExecutionPlan, error) {
	tp.logger.Debug("Creating execution plan", "objective", input.Objective)

	// Analyze objective to determine planning strategy
	strategy := tp.selectPlanningStrategy(input.Objective)
	
	// Create base plan
	plan := &ExecutionPlan{
		ID:           uuid.New().String(),
		Objective:    input.Objective,
		Tasks:        make([]*Task, 0),
		Dependencies: make(map[string][]string),
		Status:       PlanStatusDraft,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Metadata: map[string]interface{}{
			"strategy":        strategy.Name,
			"approach":        strategy.Approach,
			"planning_method": "template_based",
		},
	}

	// Generate tasks based on strategy
	tasks, err := tp.generateTasks(input, strategy, availableTools)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tasks: %w", err)
	}

	plan.Tasks = tasks

	// Analyze and set dependencies
	dependencies, err := tp.dependencyAnalyzer.AnalyzeDependencies(tasks, input)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze dependencies: %w", err)
	}

	plan.Dependencies = dependencies

	// Apply dependencies to tasks
	tp.applyDependenciesToTasks(plan)

	// Optimize plan
	tp.optimizePlan(plan, strategy)

	tp.logger.Info("Execution plan created",
		"plan_id", plan.ID,
		"tasks", len(plan.Tasks),
		"strategy", strategy.Name)

	return plan, nil
}

// selectPlanningStrategy selects the most appropriate planning strategy
func (tp *TaskPlanner) selectPlanningStrategy(objective string) PlanningStrategy {
	objectiveLower := strings.ToLower(objective)
	
	// Score each strategy based on keyword matches
	bestStrategy := tp.planningStrategies["investigation"] // Default
	bestScore := 0

	for _, strategy := range tp.planningStrategies {
		score := 0
		for _, keyword := range strategy.Keywords {
			if strings.Contains(objectiveLower, keyword) {
				score++
			}
		}
		
		if score > bestScore {
			bestScore = score
			bestStrategy = strategy
		}
	}

	return bestStrategy
}

// generateTasks generates tasks based on the planning strategy
func (tp *TaskPlanner) generateTasks(input AgentInput, strategy PlanningStrategy, availableTools map[string]tools.Tool) ([]*Task, error) {
	var tasks []*Task

	switch strategy.Approach {
	case ApproachSequential:
		tasks = tp.generateSequentialTasks(input, availableTools)
	case ApproachParallel:
		tasks = tp.generateParallelTasks(input, availableTools)
	case ApproachHierarchical:
		tasks = tp.generateHierarchicalTasks(input, availableTools)
	case ApproachIterative:
		tasks = tp.generateIterativeTasks(input, availableTools)
	case ApproachAdaptive:
		tasks = tp.generateAdaptiveTasks(input, availableTools)
	default:
		tasks = tp.generateDefaultTasks(input, availableTools)
	}

	// Validate that required tools are available
	for _, task := range tasks {
		if task.Tool != "" {
			if _, exists := availableTools[task.Tool]; !exists {
				return nil, fmt.Errorf("required tool %s not available for task %s", task.Tool, task.ID)
			}
		}
	}

	return tasks, nil
}

// generateSequentialTasks generates tasks for sequential execution
func (tp *TaskPlanner) generateSequentialTasks(input AgentInput, availableTools map[string]tools.Tool) []*Task {
	tasks := make([]*Task, 0)

	// Create a sequence of tasks based on common workflow patterns
	taskSequence := []TaskType{
		TaskTypeDataCollection,
		TaskTypeAnalysis,
		TaskTypeProcessing,
		TaskTypeValidation,
		TaskTypeReporting,
	}

	for i, taskType := range taskSequence {
		if template, exists := tp.taskTemplates[string(taskType)]; exists {
			task := tp.createTaskFromTemplate(template, input)
			task.Priority = len(taskSequence) - i // Higher priority for earlier tasks
			
			// Set dependencies (each task depends on the previous one)
			if i > 0 {
				prevTask := tasks[i-1]
				task.Dependencies = []string{prevTask.ID}
			}
			
			tasks = append(tasks, task)
		}
	}

	return tasks
}

// generateParallelTasks generates tasks that can be executed in parallel
func (tp *TaskPlanner) generateParallelTasks(input AgentInput, availableTools map[string]tools.Tool) []*Task {
	tasks := make([]*Task, 0)

	// Create parallel data collection tasks
	parallelTypes := []TaskType{
		TaskTypeDataCollection,
		TaskTypeAnalysis,
	}

	for _, taskType := range parallelTypes {
		if template, exists := tp.taskTemplates[string(taskType)]; exists {
			task := tp.createTaskFromTemplate(template, input)
			task.Priority = 5 // Same priority for parallel tasks
			tasks = append(tasks, task)
		}
	}

	// Add a final aggregation task that depends on all parallel tasks
	if len(tasks) > 0 {
		aggregationTask := &Task{
			ID:          uuid.New().String(),
			Name:        "Aggregate Results",
			Description: "Aggregate results from parallel tasks",
			Type:        TaskTypeProcessing,
			Priority:    1,
			Dependencies: make([]string, 0),
			EstimatedDuration: 2 * time.Minute,
			Status:      TaskStatusPending,
			Metadata:    make(map[string]interface{}),
		}

		// Add all parallel tasks as dependencies
		for _, task := range tasks {
			aggregationTask.Dependencies = append(aggregationTask.Dependencies, task.ID)
		}

		tasks = append(tasks, aggregationTask)
	}

	return tasks
}

// generateHierarchicalTasks generates tasks in a hierarchical structure
func (tp *TaskPlanner) generateHierarchicalTasks(input AgentInput, availableTools map[string]tools.Tool) []*Task {
	tasks := make([]*Task, 0)

	// Level 1: Initial analysis
	analysisTask := tp.createTaskFromTemplate(tp.taskTemplates[string(TaskTypeAnalysis)], input)
	analysisTask.Name = "Initial Analysis"
	analysisTask.Priority = 10
	tasks = append(tasks, analysisTask)

	// Level 2: Detailed tasks based on analysis
	detailedTasks := []string{"Security Scan", "Data Collection", "Vulnerability Assessment"}
	for i, taskName := range detailedTasks {
		task := &Task{
			ID:          uuid.New().String(),
			Name:        taskName,
			Description: fmt.Sprintf("Detailed %s based on initial analysis", strings.ToLower(taskName)),
			Type:        TaskTypeAnalysis,
			Priority:    8 - i,
			Dependencies: []string{analysisTask.ID},
			EstimatedDuration: 5 * time.Minute,
			Status:      TaskStatusPending,
			Metadata:    make(map[string]interface{}),
		}
		tasks = append(tasks, task)
	}

	// Level 3: Final reporting
	reportTask := tp.createTaskFromTemplate(tp.taskTemplates[string(TaskTypeReporting)], input)
	reportTask.Priority = 1
	
	// Report depends on all detailed tasks
	for _, task := range tasks[1:] { // Skip the first analysis task
		reportTask.Dependencies = append(reportTask.Dependencies, task.ID)
	}
	
	tasks = append(tasks, reportTask)

	return tasks
}

// generateIterativeTasks generates tasks for iterative execution
func (tp *TaskPlanner) generateIterativeTasks(input AgentInput, availableTools map[string]tools.Tool) []*Task {
	tasks := make([]*Task, 0)

	// Create iterative investigation tasks
	iterations := 3
	for i := 0; i < iterations; i++ {
		task := &Task{
			ID:          uuid.New().String(),
			Name:        fmt.Sprintf("Investigation Iteration %d", i+1),
			Description: fmt.Sprintf("Iterative investigation step %d", i+1),
			Type:        TaskTypeAnalysis,
			Priority:    iterations - i,
			EstimatedDuration: 7 * time.Minute,
			Status:      TaskStatusPending,
			Metadata: map[string]interface{}{
				"iteration": i + 1,
				"max_iterations": iterations,
			},
		}

		// Each iteration depends on the previous one (except the first)
		if i > 0 {
			task.Dependencies = []string{tasks[i-1].ID}
		}

		tasks = append(tasks, task)
	}

	return tasks
}

// generateAdaptiveTasks generates tasks that can adapt based on results
func (tp *TaskPlanner) generateAdaptiveTasks(input AgentInput, availableTools map[string]tools.Tool) []*Task {
	// Start with a basic set of tasks that can be expanded
	return tp.generateDefaultTasks(input, availableTools)
}

// generateDefaultTasks generates a default set of tasks
func (tp *TaskPlanner) generateDefaultTasks(input AgentInput, availableTools map[string]tools.Tool) []*Task {
	tasks := make([]*Task, 0)

	// Create basic workflow: Analyze -> Process -> Report
	basicTypes := []TaskType{TaskTypeAnalysis, TaskTypeProcessing, TaskTypeReporting}
	
	for i, taskType := range basicTypes {
		if template, exists := tp.taskTemplates[string(taskType)]; exists {
			task := tp.createTaskFromTemplate(template, input)
			task.Priority = len(basicTypes) - i
			
			if i > 0 {
				task.Dependencies = []string{tasks[i-1].ID}
			}
			
			tasks = append(tasks, task)
		}
	}

	return tasks
}

// createTaskFromTemplate creates a task from a template
func (tp *TaskPlanner) createTaskFromTemplate(template TaskTemplate, input AgentInput) *Task {
	task := &Task{
		ID:                uuid.New().String(),
		Name:              template.Name,
		Description:       template.Description,
		Type:              template.Type,
		EstimatedDuration: template.EstimatedDuration,
		Status:            TaskStatusPending,
		Dependencies:      make([]string, 0),
		Input:             make(map[string]interface{}),
		Metadata:          make(map[string]interface{}),
	}

	// Copy default input
	for key, value := range template.DefaultInput {
		task.Input[key] = value
	}

	// Add context from agent input
	if input.Context != nil {
		for key, value := range input.Context {
			task.Input[key] = value
		}
	}

	// Set tool if available
	if len(template.RequiredTools) > 0 {
		task.Tool = template.RequiredTools[0] // Use first required tool
	}

	// Add template metadata
	task.Metadata["template_type"] = template.Type
	task.Metadata["required_tools"] = template.RequiredTools

	return task
}

// applyDependenciesToTasks applies the analyzed dependencies to tasks
func (tp *TaskPlanner) applyDependenciesToTasks(plan *ExecutionPlan) {
	for taskID, deps := range plan.Dependencies {
		for _, task := range plan.Tasks {
			if task.ID == taskID {
				task.Dependencies = deps
				break
			}
		}
	}
}

// optimizePlan optimizes the execution plan
func (tp *TaskPlanner) optimizePlan(plan *ExecutionPlan, strategy PlanningStrategy) {
	// Optimize task ordering based on priority and dependencies
	tp.optimizeTaskOrdering(plan)
	
	// Optimize resource allocation
	tp.optimizeResourceAllocation(plan)
	
	// Add strategy-specific optimizations
	switch strategy.Approach {
	case ApproachParallel:
		tp.optimizeForParallelExecution(plan)
	case ApproachSequential:
		tp.optimizeForSequentialExecution(plan)
	}
}

// optimizeTaskOrdering optimizes the order of tasks
func (tp *TaskPlanner) optimizeTaskOrdering(plan *ExecutionPlan) {
	// Sort tasks by priority (higher priority first)
	for i := 0; i < len(plan.Tasks)-1; i++ {
		for j := i + 1; j < len(plan.Tasks); j++ {
			if plan.Tasks[j].Priority > plan.Tasks[i].Priority {
				plan.Tasks[i], plan.Tasks[j] = plan.Tasks[j], plan.Tasks[i]
			}
		}
	}
}

// optimizeResourceAllocation optimizes resource allocation for tasks
func (tp *TaskPlanner) optimizeResourceAllocation(plan *ExecutionPlan) {
	// Add resource allocation metadata
	for _, task := range plan.Tasks {
		task.Metadata["resource_requirements"] = map[string]interface{}{
			"cpu":    "medium",
			"memory": "medium",
			"io":     "low",
		}
	}
}

// optimizeForParallelExecution optimizes plan for parallel execution
func (tp *TaskPlanner) optimizeForParallelExecution(plan *ExecutionPlan) {
	// Identify tasks that can be parallelized
	for _, task := range plan.Tasks {
		if len(task.Dependencies) == 0 {
			task.Metadata["parallel_group"] = "initial"
		}
	}
}

// optimizeForSequentialExecution optimizes plan for sequential execution
func (tp *TaskPlanner) optimizeForSequentialExecution(plan *ExecutionPlan) {
	// Ensure proper sequencing
	for i, task := range plan.Tasks {
		task.Metadata["sequence_order"] = i + 1
	}
}

// AnalyzeDependencies analyzes task dependencies
func (da *DependencyAnalyzer) AnalyzeDependencies(tasks []*Task, input AgentInput) (map[string][]string, error) {
	dependencies := make(map[string][]string)

	for _, task := range tasks {
		deps := make([]string, 0)

		// Analyze task dependencies based on type and content
		for _, otherTask := range tasks {
			if task.ID != otherTask.ID && da.shouldDependOn(task, otherTask) {
				deps = append(deps, otherTask.ID)
			}
		}

		dependencies[task.ID] = deps
	}

	return dependencies, nil
}

// shouldDependOn determines if one task should depend on another
func (da *DependencyAnalyzer) shouldDependOn(task, otherTask *Task) bool {
	// Basic dependency rules
	dependencyRules := map[TaskType][]TaskType{
		TaskTypeProcessing:  {TaskTypeDataCollection, TaskTypeAnalysis},
		TaskTypeValidation:  {TaskTypeProcessing},
		TaskTypeReporting:   {TaskTypeValidation, TaskTypeAnalysis},
		TaskTypeIntegration: {TaskTypeProcessing, TaskTypeValidation},
	}

	if deps, exists := dependencyRules[task.Type]; exists {
		for _, depType := range deps {
			if otherTask.Type == depType {
				return true
			}
		}
	}

	return false
}
