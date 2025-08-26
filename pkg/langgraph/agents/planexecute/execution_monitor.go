package planexecute

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// ExecutionMonitor monitors plan execution progress
type ExecutionMonitor struct {
	logger           *logger.Logger
	progressTracker  *ProgressTracker
	alertManager     *AlertManager
	metricsCollector *MetricsCollector
	running          bool
	stopChan         chan struct{}
	mutex            sync.RWMutex
}

// ProgressTracker tracks execution progress
type ProgressTracker struct {
	logger *logger.Logger
}

// AlertManager manages alerts during execution
type AlertManager struct {
	logger *logger.Logger
	alerts []Alert
	mutex  sync.RWMutex
}

// MetricsCollector collects execution metrics
type MetricsCollector struct {
	logger  *logger.Logger
	metrics ExecutionMetrics
	mutex   sync.RWMutex
}

// Alert represents an execution alert
type Alert struct {
	ID         string                 `json:"id"`
	Type       AlertType              `json:"type"`
	Severity   AlertSeverity          `json:"severity"`
	Message    string                 `json:"message"`
	Timestamp  time.Time              `json:"timestamp"`
	PlanID     string                 `json:"plan_id"`
	TaskID     string                 `json:"task_id,omitempty"`
	Metadata   map[string]interface{} `json:"metadata"`
	Resolved   bool                   `json:"resolved"`
	ResolvedAt *time.Time             `json:"resolved_at,omitempty"`
}

// AlertType represents the type of alert
type AlertType string

const (
	AlertTypeTaskFailure   AlertType = "task_failure"
	AlertTypeTimeout       AlertType = "timeout"
	AlertTypeResourceLimit AlertType = "resource_limit"
	AlertTypePerformance   AlertType = "performance"
	AlertTypeDependency    AlertType = "dependency"
	AlertTypeCustom        AlertType = "custom"
)

// AlertSeverity represents the severity of an alert
type AlertSeverity string

const (
	AlertSeverityLow      AlertSeverity = "low"
	AlertSeverityMedium   AlertSeverity = "medium"
	AlertSeverityHigh     AlertSeverity = "high"
	AlertSeverityCritical AlertSeverity = "critical"
)

// ExecutionMetrics holds execution metrics
type ExecutionMetrics struct {
	PlanID              string                 `json:"plan_id"`
	StartTime           time.Time              `json:"start_time"`
	LastUpdate          time.Time              `json:"last_update"`
	TotalTasks          int                    `json:"total_tasks"`
	CompletedTasks      int                    `json:"completed_tasks"`
	FailedTasks         int                    `json:"failed_tasks"`
	RunningTasks        int                    `json:"running_tasks"`
	PendingTasks        int                    `json:"pending_tasks"`
	ProgressPercentage  float64                `json:"progress_percentage"`
	EstimatedCompletion *time.Time             `json:"estimated_completion,omitempty"`
	AverageTaskDuration time.Duration          `json:"average_task_duration"`
	TotalDuration       time.Duration          `json:"total_duration"`
	Throughput          float64                `json:"throughput"` // tasks per minute
	ErrorRate           float64                `json:"error_rate"`
	Metadata            map[string]interface{} `json:"metadata"`
}

// ProgressSnapshot represents a point-in-time progress snapshot
type ProgressSnapshot struct {
	Timestamp          time.Time              `json:"timestamp"`
	PlanID             string                 `json:"plan_id"`
	ProgressPercentage float64                `json:"progress_percentage"`
	TaskStatuses       map[string]TaskStatus  `json:"task_statuses"`
	Metrics            ExecutionMetrics       `json:"metrics"`
	Alerts             []Alert                `json:"alerts"`
	Metadata           map[string]interface{} `json:"metadata"`
}

// NewExecutionMonitor creates a new execution monitor
func NewExecutionMonitor(logger *logger.Logger) *ExecutionMonitor {
	return &ExecutionMonitor{
		logger:           logger,
		progressTracker:  &ProgressTracker{logger: logger},
		alertManager:     &AlertManager{logger: logger, alerts: make([]Alert, 0)},
		metricsCollector: &MetricsCollector{logger: logger},
		stopChan:         make(chan struct{}),
	}
}

// StartMonitoring starts monitoring the execution plan
func (em *ExecutionMonitor) StartMonitoring(ctx context.Context, plan *ExecutionPlan) {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	if em.running {
		em.logger.Warn("Execution monitor already running", "plan_id", plan.ID)
		return
	}

	em.running = true
	em.metricsCollector.InitializeMetrics(plan)

	go em.monitoringLoop(ctx, plan)

	em.logger.Info("Execution monitoring started", "plan_id", plan.ID)
}

// StopMonitoring stops monitoring
func (em *ExecutionMonitor) StopMonitoring() {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	if !em.running {
		return
	}

	close(em.stopChan)
	em.running = false

	em.logger.Info("Execution monitoring stopped")
}

// monitoringLoop runs the main monitoring loop
func (em *ExecutionMonitor) monitoringLoop(ctx context.Context, plan *ExecutionPlan) {
	ticker := time.NewTicker(5 * time.Second) // Monitor every 5 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			em.updateMetrics(plan)
			em.checkForAlerts(plan)
			em.logProgress(plan)

		case <-em.stopChan:
			return

		case <-ctx.Done():
			return
		}
	}
}

// updateMetrics updates execution metrics
func (em *ExecutionMonitor) updateMetrics(plan *ExecutionPlan) {
	em.metricsCollector.UpdateMetrics(plan)
}

// checkForAlerts checks for conditions that should trigger alerts
func (em *ExecutionMonitor) checkForAlerts(plan *ExecutionPlan) {
	metrics := em.metricsCollector.GetMetrics()

	// Check for high error rate
	if metrics.ErrorRate > 0.5 {
		em.alertManager.CreateAlert(AlertTypePerformance, AlertSeverityHigh,
			"High error rate detected", plan.ID, "", map[string]interface{}{
				"error_rate": metrics.ErrorRate,
			})
	}

	// Check for stalled execution
	if metrics.RunningTasks == 0 && metrics.PendingTasks > 0 {
		em.alertManager.CreateAlert(AlertTypeDependency, AlertSeverityMedium,
			"Execution appears stalled - no running tasks but pending tasks exist", plan.ID, "", nil)
	}

	// Check for timeout conditions
	if metrics.EstimatedCompletion != nil && time.Now().After(*metrics.EstimatedCompletion) {
		em.alertManager.CreateAlert(AlertTypeTimeout, AlertSeverityHigh,
			"Execution is taking longer than estimated", plan.ID, "", map[string]interface{}{
				"estimated_completion": metrics.EstimatedCompletion,
				"current_time":         time.Now(),
			})
	}
}

// logProgress logs current progress
func (em *ExecutionMonitor) logProgress(plan *ExecutionPlan) {
	metrics := em.metricsCollector.GetMetrics()

	em.logger.Debug("Execution progress",
		"plan_id", plan.ID,
		"progress", fmt.Sprintf("%.1f%%", metrics.ProgressPercentage),
		"completed", metrics.CompletedTasks,
		"total", metrics.TotalTasks,
		"running", metrics.RunningTasks,
		"failed", metrics.FailedTasks)
}

// GetProgressSnapshot returns a current progress snapshot
func (em *ExecutionMonitor) GetProgressSnapshot(plan *ExecutionPlan) ProgressSnapshot {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	taskStatuses := make(map[string]TaskStatus)
	for _, task := range plan.Tasks {
		taskStatuses[task.ID] = task.Status
	}

	return ProgressSnapshot{
		Timestamp:          time.Now(),
		PlanID:             plan.ID,
		ProgressPercentage: em.progressTracker.CalculateProgress(plan),
		TaskStatuses:       taskStatuses,
		Metrics:            em.metricsCollector.GetMetrics(),
		Alerts:             em.alertManager.GetActiveAlerts(),
		Metadata: map[string]interface{}{
			"monitoring_duration": time.Since(em.metricsCollector.GetMetrics().StartTime),
		},
	}
}

// UpdatePlan updates the plan being monitored
func (em *ExecutionMonitor) UpdatePlan(ctx context.Context, plan *ExecutionPlan, task *Task, result interface{}) *ExecutionPlan {
	// Update task result in context
	if result != nil {
		// This would typically update the plan's context or state
		// For now, we'll just log the update
		em.logger.Debug("Plan updated with task result",
			"plan_id", plan.ID,
			"task_id", task.ID,
			"task_status", task.Status)
	}

	// Update metrics
	em.updateMetrics(plan)

	return plan
}

// CalculateProgress calculates the current progress percentage
func (pt *ProgressTracker) CalculateProgress(plan *ExecutionPlan) float64 {
	if len(plan.Tasks) == 0 {
		return 0.0
	}

	completedTasks := 0
	for _, task := range plan.Tasks {
		if task.Status == TaskStatusCompleted {
			completedTasks++
		}
	}

	return (float64(completedTasks) / float64(len(plan.Tasks))) * 100.0
}

// EstimateCompletion estimates when the plan will complete
func (pt *ProgressTracker) EstimateCompletion(plan *ExecutionPlan) *time.Time {
	completedTasks := 0
	totalDuration := time.Duration(0)

	for _, task := range plan.Tasks {
		if task.Status == TaskStatusCompleted && task.ActualDuration > 0 {
			completedTasks++
			totalDuration += task.ActualDuration
		}
	}

	if completedTasks == 0 {
		return nil
	}

	averageDuration := totalDuration / time.Duration(completedTasks)
	remainingTasks := len(plan.Tasks) - completedTasks
	estimatedRemainingTime := time.Duration(remainingTasks) * averageDuration

	completion := time.Now().Add(estimatedRemainingTime)
	return &completion
}

// CreateAlert creates a new alert
func (am *AlertManager) CreateAlert(alertType AlertType, severity AlertSeverity, message, planID, taskID string, metadata map[string]interface{}) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	alert := Alert{
		ID:        fmt.Sprintf("alert-%d", time.Now().UnixNano()),
		Type:      alertType,
		Severity:  severity,
		Message:   message,
		Timestamp: time.Now(),
		PlanID:    planID,
		TaskID:    taskID,
		Metadata:  metadata,
		Resolved:  false,
	}

	am.alerts = append(am.alerts, alert)

	am.logger.Warn("Alert created",
		"alert_id", alert.ID,
		"type", alertType,
		"severity", severity,
		"message", message,
		"plan_id", planID,
		"task_id", taskID)
}

// GetActiveAlerts returns all active (unresolved) alerts
func (am *AlertManager) GetActiveAlerts() []Alert {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	activeAlerts := make([]Alert, 0)
	for _, alert := range am.alerts {
		if !alert.Resolved {
			activeAlerts = append(activeAlerts, alert)
		}
	}

	return activeAlerts
}

// ResolveAlert resolves an alert
func (am *AlertManager) ResolveAlert(alertID string) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	for i, alert := range am.alerts {
		if alert.ID == alertID {
			now := time.Now()
			am.alerts[i].Resolved = true
			am.alerts[i].ResolvedAt = &now

			am.logger.Info("Alert resolved",
				"alert_id", alertID,
				"resolved_at", now)
			break
		}
	}
}

// InitializeMetrics initializes metrics for a plan
func (mc *MetricsCollector) InitializeMetrics(plan *ExecutionPlan) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.metrics = ExecutionMetrics{
		PlanID:              plan.ID,
		StartTime:           time.Now(),
		LastUpdate:          time.Now(),
		TotalTasks:          len(plan.Tasks),
		CompletedTasks:      0,
		FailedTasks:         0,
		RunningTasks:        0,
		PendingTasks:        len(plan.Tasks),
		ProgressPercentage:  0.0,
		AverageTaskDuration: 0,
		TotalDuration:       0,
		Throughput:          0.0,
		ErrorRate:           0.0,
		Metadata:            make(map[string]interface{}),
	}
}

// UpdateMetrics updates metrics based on current plan state
func (mc *MetricsCollector) UpdateMetrics(plan *ExecutionPlan) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	now := time.Now()
	completedTasks := 0
	failedTasks := 0
	runningTasks := 0
	pendingTasks := 0
	totalDuration := time.Duration(0)

	for _, task := range plan.Tasks {
		switch task.Status {
		case TaskStatusCompleted:
			completedTasks++
			if task.ActualDuration > 0 {
				totalDuration += task.ActualDuration
			}
		case TaskStatusFailed:
			failedTasks++
		case TaskStatusRunning:
			runningTasks++
		case TaskStatusPending, TaskStatusReady:
			pendingTasks++
		}
	}

	mc.metrics.LastUpdate = now
	mc.metrics.CompletedTasks = completedTasks
	mc.metrics.FailedTasks = failedTasks
	mc.metrics.RunningTasks = runningTasks
	mc.metrics.PendingTasks = pendingTasks
	mc.metrics.TotalDuration = now.Sub(mc.metrics.StartTime)

	// Calculate progress percentage
	if mc.metrics.TotalTasks > 0 {
		mc.metrics.ProgressPercentage = (float64(completedTasks) / float64(mc.metrics.TotalTasks)) * 100.0
	}

	// Calculate average task duration
	if completedTasks > 0 {
		mc.metrics.AverageTaskDuration = totalDuration / time.Duration(completedTasks)
	}

	// Calculate throughput (tasks per minute)
	if mc.metrics.TotalDuration > 0 {
		mc.metrics.Throughput = float64(completedTasks) / mc.metrics.TotalDuration.Minutes()
	}

	// Calculate error rate
	totalProcessedTasks := completedTasks + failedTasks
	if totalProcessedTasks > 0 {
		mc.metrics.ErrorRate = float64(failedTasks) / float64(totalProcessedTasks)
	}

	// Estimate completion time
	if completedTasks > 0 && pendingTasks > 0 {
		remainingTime := time.Duration(pendingTasks) * mc.metrics.AverageTaskDuration
		estimatedCompletion := now.Add(remainingTime)
		mc.metrics.EstimatedCompletion = &estimatedCompletion
	}
}

// GetMetrics returns current metrics
func (mc *MetricsCollector) GetMetrics() ExecutionMetrics {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	return mc.metrics
}

// Replanner handles replanning when execution fails
type Replanner struct {
	logger *logger.Logger
}

// NewReplanner creates a new replanner
func NewReplanner(logger *logger.Logger) *Replanner {
	return &Replanner{
		logger: logger,
	}
}

// Replan creates a new plan when the current plan fails
func (r *Replanner) Replan(ctx context.Context, originalPlan *ExecutionPlan, failedTask *Task, err error, input AgentInput) (*ExecutionPlan, error) {
	r.logger.Info("Replanning execution",
		"original_plan_id", originalPlan.ID,
		"failed_task_id", failedTask.ID,
		"error", err)

	// Create a new plan based on the original plan
	newPlan := &ExecutionPlan{
		ID:           fmt.Sprintf("%s-replan-%d", originalPlan.ID, time.Now().Unix()),
		Objective:    originalPlan.Objective,
		Tasks:        make([]*Task, 0),
		Dependencies: make(map[string][]string),
		Status:       PlanStatusDraft,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Metadata: map[string]interface{}{
			"original_plan_id": originalPlan.ID,
			"replan_reason":    "task_failure",
			"failed_task_id":   failedTask.ID,
			"failure_error":    err.Error(),
		},
	}

	// Copy successful tasks from original plan
	for _, task := range originalPlan.Tasks {
		if task.Status == TaskStatusCompleted {
			newTask := *task // Copy task
			newPlan.Tasks = append(newPlan.Tasks, &newTask)
		}
	}

	// Create alternative approach for failed task
	alternativeTask := r.createAlternativeTask(failedTask, err)
	if alternativeTask != nil {
		newPlan.Tasks = append(newPlan.Tasks, alternativeTask)
	}

	// Add remaining tasks from original plan (if they weren't dependent on failed task)
	for _, task := range originalPlan.Tasks {
		if task.Status == TaskStatusPending && !r.isDependentOn(task, failedTask.ID) {
			newTask := *task // Copy task
			newPlan.Tasks = append(newPlan.Tasks, &newTask)
		}
	}

	newPlan.Status = PlanStatusApproved

	r.logger.Info("Replanning completed",
		"new_plan_id", newPlan.ID,
		"tasks", len(newPlan.Tasks))

	return newPlan, nil
}

// createAlternativeTask creates an alternative task for a failed task
func (r *Replanner) createAlternativeTask(failedTask *Task, err error) *Task {
	alternativeTask := &Task{
		ID:                fmt.Sprintf("%s-alt", failedTask.ID),
		Name:              fmt.Sprintf("%s (Alternative)", failedTask.Name),
		Description:       fmt.Sprintf("Alternative approach for: %s", failedTask.Description),
		Type:              failedTask.Type,
		Priority:          failedTask.Priority,
		EstimatedDuration: failedTask.EstimatedDuration,
		Status:            TaskStatusPending,
		Dependencies:      failedTask.Dependencies,
		Input:             make(map[string]interface{}),
		Metadata: map[string]interface{}{
			"original_task_id": failedTask.ID,
			"alternative":      true,
			"failure_reason":   err.Error(),
		},
	}

	// Copy input but modify approach
	for key, value := range failedTask.Input {
		alternativeTask.Input[key] = value
	}

	// Modify approach based on error type
	if contains(err.Error(), "timeout") {
		alternativeTask.Input["timeout"] = "600s" // Increase timeout
		alternativeTask.EstimatedDuration = failedTask.EstimatedDuration * 2
	}

	return alternativeTask
}

// isDependentOn checks if a task is dependent on another task
func (r *Replanner) isDependentOn(task *Task, taskID string) bool {
	for _, dep := range task.Dependencies {
		if dep == taskID {
			return true
		}
	}
	return false
}
