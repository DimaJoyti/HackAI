package multiagent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/ai"
	"github.com/google/uuid"
)

// createCollaboration creates a new collaboration for a task
func (cm *CollaborationManager) createCollaboration(task *MultiAgentTask, availableAgents map[string]ai.Agent) (*ActiveCollaboration, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// Find suitable agents for the task
	participants := make(map[string]ai.Agent)

	// Add required agents
	for _, agentID := range task.RequiredAgents {
		if agent, exists := availableAgents[agentID]; exists {
			participants[agentID] = agent
		} else {
			return nil, fmt.Errorf("required agent %s not available", agentID)
		}
	}

	// Add optional agents if available
	for _, agentID := range task.OptionalAgents {
		if agent, exists := availableAgents[agentID]; exists {
			participants[agentID] = agent
		}
	}

	// Select coordinator (first required agent by default)
	coordinator := task.RequiredAgents[0]
	if len(task.RequiredAgents) == 0 {
		return nil, fmt.Errorf("no coordinator available")
	}

	collaboration := &ActiveCollaboration{
		ID:              uuid.New().String(),
		Task:            task,
		Participants:    participants,
		Coordinator:     coordinator,
		Status:          "created",
		Progress:        0.0,
		Results:         make(map[string]interface{}),
		Conflicts:       []ConflictRecord{},
		DecisionHistory: []DecisionRecord{},
		StartedAt:       time.Now(),
	}

	cm.activeCollaborations[collaboration.ID] = collaboration

	cm.logger.Info("Collaboration created",
		"collaboration_id", collaboration.ID,
		"task_type", task.Type,
		"participants", len(participants),
		"coordinator", coordinator)

	return collaboration, nil
}

// getCollaborationPattern retrieves a collaboration pattern by type
func (cm *CollaborationManager) getCollaborationPattern(taskType string) *CollaborationPattern {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if pattern, exists := cm.collaborationPatterns[taskType]; exists {
		return pattern
	}

	// Return default pattern if specific pattern not found
	if defaultPattern, exists := cm.collaborationPatterns["default"]; exists {
		return defaultPattern
	}

	return nil
}

// findAgentForRole finds an agent suitable for a specific role
func (o *MultiAgentOrchestrator) findAgentForRole(participants map[string]ai.Agent, role string) ai.Agent {
	// Simple role matching based on agent name/ID patterns
	for agentID, agent := range participants {
		// Match based on agent ID patterns
		if strings.Contains(strings.ToLower(agentID), strings.ToLower(role)) {
			return agent
		}

		// Match based on agent name patterns
		if strings.Contains(strings.ToLower(agent.Name()), strings.ToLower(role)) {
			return agent
		}
	}

	// Role-based pattern matching
	rolePatterns := map[string][]string{
		"threat_detector":       {"security", "threat", "cyber"},
		"vulnerability_scanner": {"security", "vulnerability", "scan"},
		"incident_analyzer":     {"security", "incident", "analysis"},
		"researcher":            {"research", "market", "data"},
		"analyst":               {"analyst", "analysis", "data"},
		"strategist":            {"strategy", "strategic", "business"},
	}

	if patterns, exists := rolePatterns[role]; exists {
		for agentID, agent := range participants {
			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(agentID), pattern) ||
					strings.Contains(strings.ToLower(agent.Name()), pattern) {
					return agent
				}
			}
		}
	}

	// Return any available agent as fallback
	for _, agent := range participants {
		return agent
	}

	return nil
}

// executeCollaborationStep executes a single collaboration step
func (o *MultiAgentOrchestrator) executeCollaborationStep(ctx context.Context, collaboration *ActiveCollaboration, step CollaborationStep, agent ai.Agent) (interface{}, error) {
	// Create simple agent input for the step
	agentInput := ai.AgentInput{
		Query:       fmt.Sprintf("%s for %s", step.Name, collaboration.Task.Description),
		Context:     collaboration.Task.Context,
		MaxSteps:    5,
		Tools:       []string{},
		Constraints: []string{},
		Goals:       []string{step.Action},
	}

	// Add collaboration context to agent input
	if agentInput.Context == nil {
		agentInput.Context = make(map[string]interface{})
	}
	agentInput.Context["collaboration_id"] = collaboration.ID
	agentInput.Context["step_id"] = step.ID
	agentInput.Context["step_type"] = step.Type

	// Execute the task
	result, err := agent.Execute(ctx, agentInput)
	if err != nil {
		return nil, fmt.Errorf("agent %s failed to execute step %s: %w", agent.ID(), step.ID, err)
	}

	// Check for conflicts
	if o.detectStepConflict(collaboration, step, result) {
		conflict := ConflictRecord{
			ID:          uuid.New().String(),
			Type:        "step_execution_conflict",
			Description: fmt.Sprintf("Conflict detected in step %s", step.ID),
			Agents:      []string{agent.ID()},
			Data: map[string]interface{}{
				"step_id": step.ID,
				"result":  result,
			},
			Timestamp: time.Now(),
		}

		collaboration.Conflicts = append(collaboration.Conflicts, conflict)

		// Attempt to resolve conflict
		resolution, err := o.conflictResolver.resolveConflict(ctx, &conflict, collaboration.Participants)
		if err != nil {
			o.logger.Warn("Failed to resolve step conflict",
				"collaboration_id", collaboration.ID,
				"step_id", step.ID,
				"error", err)
		} else {
			conflict.Resolution = resolution
			o.logger.Info("Step conflict resolved",
				"collaboration_id", collaboration.ID,
				"step_id", step.ID,
				"strategy", resolution.Strategy)
		}
	}

	return result, nil
}

// detectStepConflict detects conflicts in step execution
func (o *MultiAgentOrchestrator) detectStepConflict(collaboration *ActiveCollaboration, step CollaborationStep, result ai.AgentOutput) bool {
	// Simple conflict detection based on confidence threshold
	if result.Confidence < 0.5 {
		return true
	}

	// Check for conflicting results with previous steps
	for stepID, prevResult := range collaboration.Results {
		if prevAgentOutput, ok := prevResult.(ai.AgentOutput); ok {
			// Simplified conflict detection - in practice would use more sophisticated logic
			if abs(result.Confidence-prevAgentOutput.Confidence) > 0.4 {
				o.logger.Debug("Potential conflict detected",
					"current_step", step.ID,
					"previous_step", stepID,
					"confidence_diff", abs(result.Confidence-prevAgentOutput.Confidence))
				return true
			}
		}
	}

	return false
}

// groupStepsByDependencies groups steps by their dependencies for parallel execution
func (o *MultiAgentOrchestrator) groupStepsByDependencies(workflow []CollaborationStep) [][]CollaborationStep {
	var groups [][]CollaborationStep
	processed := make(map[string]bool)

	for len(processed) < len(workflow) {
		var currentGroup []CollaborationStep

		for _, step := range workflow {
			if processed[step.ID] {
				continue
			}

			// Check if all dependencies are satisfied
			canExecute := true
			for _, dep := range step.Dependencies {
				if !processed[dep] {
					canExecute = false
					break
				}
			}

			if canExecute {
				currentGroup = append(currentGroup, step)
				processed[step.ID] = true
			}
		}

		if len(currentGroup) == 0 {
			// Circular dependency or other issue
			break
		}

		groups = append(groups, currentGroup)
	}

	return groups
}

// resolveConflict resolves a conflict using available strategies
func (cr *ConflictResolver) resolveConflict(ctx context.Context, conflict *ConflictRecord, agents map[string]ai.Agent) (*ConflictResolution, error) {
	// Try strategies in priority order
	var strategies []ConflictResolutionStrategy
	for _, strategy := range cr.resolutionStrategies {
		strategies = append(strategies, strategy)
	}

	// Sort by priority
	for i := 0; i < len(strategies)-1; i++ {
		for j := i + 1; j < len(strategies); j++ {
			if strategies[j].GetPriority() > strategies[i].GetPriority() {
				strategies[i], strategies[j] = strategies[j], strategies[i]
			}
		}
	}

	// Try each strategy
	for _, strategy := range strategies {
		resolution, err := strategy.Resolve(ctx, conflict, agents)
		if err != nil {
			cr.logger.Debug("Conflict resolution strategy failed",
				"strategy", strategy.GetType(),
				"conflict_id", conflict.ID,
				"error", err)
			continue
		}

		cr.logger.Info("Conflict resolved",
			"strategy", strategy.GetType(),
			"conflict_id", conflict.ID,
			"confidence", resolution.Confidence)

		return resolution, nil
	}

	return nil, fmt.Errorf("all conflict resolution strategies failed")
}

// Task scheduler methods
func (ts *TaskScheduler) run(ctx context.Context, orchestrator *MultiAgentOrchestrator) {
	defer orchestrator.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-orchestrator.stopChan:
			return
		case task := <-ts.taskQueue:
			// Process task
			go ts.processTask(ctx, task, orchestrator)
		}
	}
}

// processTask processes a single task
func (ts *TaskScheduler) processTask(ctx context.Context, task *MultiAgentTask, orchestrator *MultiAgentOrchestrator) {
	ts.logger.Info("Processing multi-agent task",
		"task_id", task.ID,
		"task_type", task.Type,
		"priority", task.Priority)

	result, err := orchestrator.ExecuteTask(ctx, task)
	if err != nil {
		ts.logger.Error("Task execution failed",
			"task_id", task.ID,
			"error", err)
		return
	}

	ts.logger.Info("Task execution completed",
		"task_id", task.ID,
		"success", result.Success,
		"execution_time", result.ExecutionTime)
}

// Health monitor
func (o *MultiAgentOrchestrator) healthMonitor(ctx context.Context) {
	defer o.wg.Done()

	ticker := time.NewTicker(o.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-o.stopChan:
			return
		case <-ticker.C:
			o.performHealthChecks(ctx)
		}
	}
}

// performHealthChecks checks the health of all agents
func (o *MultiAgentOrchestrator) performHealthChecks(ctx context.Context) {
	o.mutex.RLock()
	agents := make(map[string]ai.Agent)
	for id, agent := range o.agents {
		agents[id] = agent
	}
	o.mutex.RUnlock()

	for agentID, agent := range agents {
		go func(id string, a ai.Agent) {
			healthy := o.checkAgentHealth(ctx, a)

			// Update health status if failover manager exists
			if o.taskScheduler != nil && o.taskScheduler.failoverManager != nil {
				o.taskScheduler.failoverManager.mutex.Lock()
				o.taskScheduler.failoverManager.healthStatus[id] = healthy
				o.taskScheduler.failoverManager.mutex.Unlock()
			}

			if !healthy {
				o.logger.Warn("Agent health check failed", "agent_id", id)
			}
		}(agentID, agent)
	}
}

// checkAgentHealth checks if an agent is healthy
func (o *MultiAgentOrchestrator) checkAgentHealth(ctx context.Context, agent ai.Agent) bool {
	// Simple health check - in practice would be more sophisticated
	metrics := agent.GetMetrics()
	successRate := float64(metrics.SuccessfulRuns) / float64(metrics.TotalExecutions)
	if metrics.TotalExecutions == 0 {
		successRate = 1.0 // New agents are considered healthy
	}
	return successRate > 0.5 && time.Since(metrics.LastExecutionTime) < 5*time.Minute
}

// Metrics collector
func (o *MultiAgentOrchestrator) metricsCollector(ctx context.Context) {
	defer o.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-o.stopChan:
			return
		case <-ticker.C:
			o.collectMetrics()
		}
	}
}

// collectMetrics collects orchestrator metrics
func (o *MultiAgentOrchestrator) collectMetrics() {
	o.collaborationManager.mutex.RLock()
	activeCollaborations := int64(len(o.collaborationManager.activeCollaborations))
	o.collaborationManager.mutex.RUnlock()

	o.metrics.mutex.Lock()
	o.metrics.CollaborationsActive = activeCollaborations
	o.metrics.mutex.Unlock()

	o.logger.Debug("Metrics collected",
		"active_collaborations", activeCollaborations,
		"tasks_executed", o.metrics.TasksExecuted,
		"success_rate", o.metrics.SuccessRate)
}

// Helper function
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
