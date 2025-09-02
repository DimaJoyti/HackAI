package multiagent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// AgentCoordinator coordinates task assignment and agent collaboration
type AgentCoordinator struct {
	config             *MultiAgentConfig
	logger             *logger.Logger
	assignmentStrategy AssignmentStrategy
	loadBalancer       *LoadBalancer
	capabilityMatcher  *CapabilityMatcher
}

// AssignmentStrategy defines different strategies for task assignment
type AssignmentStrategy string

const (
	StrategyCapabilityBased AssignmentStrategy = "capability_based"
	StrategyLoadBalanced    AssignmentStrategy = "load_balanced"
	StrategyRoundRobin      AssignmentStrategy = "round_robin"
	StrategyPriorityBased   AssignmentStrategy = "priority_based"
	StrategyHybrid          AssignmentStrategy = "hybrid"
)

// LoadBalancer manages agent workload distribution
type LoadBalancer struct {
	logger     *logger.Logger
	agentLoads map[string]int
	maxLoad    int
}

// CapabilityMatcher matches tasks to agents based on capabilities
type CapabilityMatcher struct {
	logger *logger.Logger
}

// AgentAssignment represents an assignment of a subtask to an agent
type AgentAssignment struct {
	SubtaskID         string                 `json:"subtask_id"`
	AgentID           string                 `json:"agent_id"`
	Confidence        float64                `json:"confidence"`
	Reasoning         string                 `json:"reasoning"`
	Priority          Priority               `json:"priority"`
	EstimatedDuration time.Duration          `json:"estimated_duration"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// NewAgentCoordinator creates a new agent coordinator
func NewAgentCoordinator(config *MultiAgentConfig, logger *logger.Logger) *AgentCoordinator {
	return &AgentCoordinator{
		config:             config,
		logger:             logger,
		assignmentStrategy: StrategyHybrid,
		loadBalancer:       NewLoadBalancer(config.MaxConcurrentAgents, logger),
		capabilityMatcher:  &CapabilityMatcher{logger: logger},
	}
}

// NewLoadBalancer creates a new load balancer
func NewLoadBalancer(maxLoad int, logger *logger.Logger) *LoadBalancer {
	return &LoadBalancer{
		logger:     logger,
		agentLoads: make(map[string]int),
		maxLoad:    maxLoad,
	}
}

// AssignTask assigns subtasks to appropriate agents
func (ac *AgentCoordinator) AssignTask(ctx context.Context, task *CollaborativeTask, availableAgents map[string]Agent) (map[string]string, error) {
	ac.logger.Debug("Starting task assignment",
		"task_id", task.ID,
		"subtasks", len(task.Subtasks),
		"available_agents", len(availableAgents),
		"strategy", ac.assignmentStrategy)

	// Validate that required agents are available
	if err := ac.validateRequiredAgents(task, availableAgents); err != nil {
		return nil, fmt.Errorf("required agent validation failed: %w", err)
	}

	// Create subtasks if not already decomposed
	if len(task.Subtasks) == 0 {
		if err := ac.decomposeTask(task); err != nil {
			return nil, fmt.Errorf("task decomposition failed: %w", err)
		}
	}

	// Assign subtasks to agents based on strategy
	assignments, err := ac.assignSubtasks(ctx, task, availableAgents)
	if err != nil {
		return nil, fmt.Errorf("subtask assignment failed: %w", err)
	}

	// Validate assignments
	if err := ac.validateAssignments(task, assignments, availableAgents); err != nil {
		return nil, fmt.Errorf("assignment validation failed: %w", err)
	}

	ac.logger.Info("Task assignment completed",
		"task_id", task.ID,
		"assignments", len(assignments),
		"strategy", ac.assignmentStrategy)

	return assignments, nil
}

// validateRequiredAgents validates that all required agents are available
func (ac *AgentCoordinator) validateRequiredAgents(task *CollaborativeTask, availableAgents map[string]Agent) error {
	for _, requiredAgentID := range task.RequiredAgents {
		if _, exists := availableAgents[requiredAgentID]; !exists {
			return fmt.Errorf("required agent %s not available", requiredAgentID)
		}
	}
	return nil
}

// decomposeTask decomposes a task into subtasks if not already done
func (ac *AgentCoordinator) decomposeTask(task *CollaborativeTask) error {
	ac.logger.Debug("Decomposing task", "task_id", task.ID, "task_type", task.Type)

	switch task.Type {
	case TaskTypeSecurityAssessment:
		task.Subtasks = ac.createSecurityAssessmentSubtasks(task)
	case TaskTypeDataAnalysis:
		task.Subtasks = ac.createDataAnalysisSubtasks(task)
	case TaskTypeInvestigation:
		task.Subtasks = ac.createInvestigationSubtasks(task)
	case TaskTypeReporting:
		task.Subtasks = ac.createReportingSubtasks(task)
	default:
		task.Subtasks = ac.createGenericSubtasks(task)
	}

	ac.logger.Debug("Task decomposition completed",
		"task_id", task.ID,
		"subtasks_created", len(task.Subtasks))

	return nil
}

// createSecurityAssessmentSubtasks creates subtasks for security assessment
func (ac *AgentCoordinator) createSecurityAssessmentSubtasks(task *CollaborativeTask) []*Subtask {
	subtasks := []*Subtask{
		{
			ID:          fmt.Sprintf("%s-recon", task.ID),
			Name:        "Reconnaissance",
			Description: "Gather information about the target",
			Status:      TaskStatusPending,
			Priority:    PriorityHigh,
			Input: map[string]interface{}{
				"target":    task.Metadata["target"],
				"scan_type": "passive",
			},
		},
		{
			ID:           fmt.Sprintf("%s-vuln-scan", task.ID),
			Name:         "Vulnerability Scanning",
			Description:  "Scan for vulnerabilities",
			Status:       TaskStatusPending,
			Priority:     PriorityHigh,
			Dependencies: []string{fmt.Sprintf("%s-recon", task.ID)},
			Input: map[string]interface{}{
				"target":    task.Metadata["target"],
				"scan_type": "comprehensive",
			},
		},
		{
			ID:           fmt.Sprintf("%s-analysis", task.ID),
			Name:         "Risk Analysis",
			Description:  "Analyze identified vulnerabilities and assess risk",
			Status:       TaskStatusPending,
			Priority:     PriorityNormal,
			Dependencies: []string{fmt.Sprintf("%s-vuln-scan", task.ID)},
			Input: map[string]interface{}{
				"analysis_type": "risk_assessment",
			},
		},
		{
			ID:           fmt.Sprintf("%s-report", task.ID),
			Name:         "Security Report",
			Description:  "Generate comprehensive security report",
			Status:       TaskStatusPending,
			Priority:     PriorityNormal,
			Dependencies: []string{fmt.Sprintf("%s-analysis", task.ID)},
			Input: map[string]interface{}{
				"report_type": "security_assessment",
				"format":      "detailed",
			},
		},
	}

	return subtasks
}

// createDataAnalysisSubtasks creates subtasks for data analysis
func (ac *AgentCoordinator) createDataAnalysisSubtasks(task *CollaborativeTask) []*Subtask {
	subtasks := []*Subtask{
		{
			ID:          fmt.Sprintf("%s-collection", task.ID),
			Name:        "Data Collection",
			Description: "Collect data from various sources",
			Status:      TaskStatusPending,
			Priority:    PriorityHigh,
			Input: map[string]interface{}{
				"sources": task.Metadata["data_sources"],
			},
		},
		{
			ID:           fmt.Sprintf("%s-processing", task.ID),
			Name:         "Data Processing",
			Description:  "Clean and process collected data",
			Status:       TaskStatusPending,
			Priority:     PriorityNormal,
			Dependencies: []string{fmt.Sprintf("%s-collection", task.ID)},
			Input: map[string]interface{}{
				"processing_type": "standard",
			},
		},
		{
			ID:           fmt.Sprintf("%s-analysis", task.ID),
			Name:         "Data Analysis",
			Description:  "Perform statistical analysis on processed data",
			Status:       TaskStatusPending,
			Priority:     PriorityNormal,
			Dependencies: []string{fmt.Sprintf("%s-processing", task.ID)},
			Input: map[string]interface{}{
				"analysis_methods": []string{"statistical", "pattern_recognition"},
			},
		},
	}

	return subtasks
}

// createInvestigationSubtasks creates subtasks for investigation
func (ac *AgentCoordinator) createInvestigationSubtasks(task *CollaborativeTask) []*Subtask {
	subtasks := []*Subtask{
		{
			ID:          fmt.Sprintf("%s-evidence", task.ID),
			Name:        "Evidence Gathering",
			Description: "Collect and preserve evidence",
			Status:      TaskStatusPending,
			Priority:    PriorityCritical,
			Input: map[string]interface{}{
				"evidence_types": []string{"digital", "network", "system"},
			},
		},
		{
			ID:           fmt.Sprintf("%s-forensics", task.ID),
			Name:         "Forensic Analysis",
			Description:  "Perform forensic analysis on collected evidence",
			Status:       TaskStatusPending,
			Priority:     PriorityHigh,
			Dependencies: []string{fmt.Sprintf("%s-evidence", task.ID)},
			Input: map[string]interface{}{
				"analysis_depth": "comprehensive",
			},
		},
	}

	return subtasks
}

// createReportingSubtasks creates subtasks for reporting
func (ac *AgentCoordinator) createReportingSubtasks(task *CollaborativeTask) []*Subtask {
	subtasks := []*Subtask{
		{
			ID:          fmt.Sprintf("%s-compile", task.ID),
			Name:        "Data Compilation",
			Description: "Compile data from various sources",
			Status:      TaskStatusPending,
			Priority:    PriorityNormal,
			Input: map[string]interface{}{
				"data_sources": task.Metadata["sources"],
			},
		},
		{
			ID:           fmt.Sprintf("%s-generate", task.ID),
			Name:         "Report Generation",
			Description:  "Generate formatted report",
			Status:       TaskStatusPending,
			Priority:     PriorityNormal,
			Dependencies: []string{fmt.Sprintf("%s-compile", task.ID)},
			Input: map[string]interface{}{
				"format":   "comprehensive",
				"template": "standard",
			},
		},
	}

	return subtasks
}

// createGenericSubtasks creates generic subtasks for unknown task types
func (ac *AgentCoordinator) createGenericSubtasks(task *CollaborativeTask) []*Subtask {
	subtasks := []*Subtask{
		{
			ID:          fmt.Sprintf("%s-main", task.ID),
			Name:        "Main Task",
			Description: task.Description,
			Status:      TaskStatusPending,
			Priority:    PriorityNormal,
			Input: map[string]interface{}{
				"objective": task.Objective,
			},
		},
	}

	return subtasks
}

// assignSubtasks assigns subtasks to agents based on the selected strategy
func (ac *AgentCoordinator) assignSubtasks(ctx context.Context, task *CollaborativeTask, availableAgents map[string]Agent) (map[string]string, error) {
	switch ac.assignmentStrategy {
	case StrategyCapabilityBased:
		return ac.assignByCapability(task, availableAgents)
	case StrategyLoadBalanced:
		return ac.assignByLoadBalance(task, availableAgents)
	case StrategyRoundRobin:
		return ac.assignRoundRobin(task, availableAgents)
	case StrategyPriorityBased:
		return ac.assignByPriority(task, availableAgents)
	case StrategyHybrid:
		return ac.assignHybrid(task, availableAgents)
	default:
		return ac.assignByCapability(task, availableAgents)
	}
}

// assignByCapability assigns subtasks based on agent capabilities
func (ac *AgentCoordinator) assignByCapability(task *CollaborativeTask, availableAgents map[string]Agent) (map[string]string, error) {
	assignments := make(map[string]string)

	for _, subtask := range task.Subtasks {
		bestAgent, confidence := ac.capabilityMatcher.FindBestMatch(subtask, availableAgents)
		if bestAgent == "" {
			return nil, fmt.Errorf("no suitable agent found for subtask %s", subtask.ID)
		}

		assignments[subtask.ID] = bestAgent
		subtask.AssignedAgent = bestAgent

		ac.logger.Debug("Subtask assigned by capability",
			"subtask_id", subtask.ID,
			"agent_id", bestAgent,
			"confidence", confidence)
	}

	return assignments, nil
}

// assignByLoadBalance assigns subtasks based on agent load
func (ac *AgentCoordinator) assignByLoadBalance(task *CollaborativeTask, availableAgents map[string]Agent) (map[string]string, error) {
	assignments := make(map[string]string)

	for _, subtask := range task.Subtasks {
		leastLoadedAgent := ac.loadBalancer.GetLeastLoadedAgent(availableAgents)
		if leastLoadedAgent == "" {
			return nil, fmt.Errorf("no available agent for subtask %s", subtask.ID)
		}

		assignments[subtask.ID] = leastLoadedAgent
		subtask.AssignedAgent = leastLoadedAgent
		ac.loadBalancer.IncrementLoad(leastLoadedAgent)

		ac.logger.Debug("Subtask assigned by load balance",
			"subtask_id", subtask.ID,
			"agent_id", leastLoadedAgent)
	}

	return assignments, nil
}

// assignRoundRobin assigns subtasks in round-robin fashion
func (ac *AgentCoordinator) assignRoundRobin(task *CollaborativeTask, availableAgents map[string]Agent) (map[string]string, error) {
	assignments := make(map[string]string)
	agentIDs := make([]string, 0, len(availableAgents))

	for agentID := range availableAgents {
		agentIDs = append(agentIDs, agentID)
	}

	if len(agentIDs) == 0 {
		return nil, fmt.Errorf("no available agents")
	}

	for i, subtask := range task.Subtasks {
		agentID := agentIDs[i%len(agentIDs)]
		assignments[subtask.ID] = agentID
		subtask.AssignedAgent = agentID

		ac.logger.Debug("Subtask assigned round-robin",
			"subtask_id", subtask.ID,
			"agent_id", agentID)
	}

	return assignments, nil
}

// assignByPriority assigns subtasks based on priority
func (ac *AgentCoordinator) assignByPriority(task *CollaborativeTask, availableAgents map[string]Agent) (map[string]string, error) {
	// Sort subtasks by priority (highest first)
	sortedSubtasks := make([]*Subtask, len(task.Subtasks))
	copy(sortedSubtasks, task.Subtasks)

	sort.Slice(sortedSubtasks, func(i, j int) bool {
		return sortedSubtasks[i].Priority > sortedSubtasks[j].Priority
	})

	assignments := make(map[string]string)

	for _, subtask := range sortedSubtasks {
		bestAgent, _ := ac.capabilityMatcher.FindBestMatch(subtask, availableAgents)
		if bestAgent == "" {
			return nil, fmt.Errorf("no suitable agent found for high-priority subtask %s", subtask.ID)
		}

		assignments[subtask.ID] = bestAgent
		subtask.AssignedAgent = bestAgent

		ac.logger.Debug("Subtask assigned by priority",
			"subtask_id", subtask.ID,
			"agent_id", bestAgent,
			"priority", subtask.Priority)
	}

	return assignments, nil
}

// assignHybrid uses a hybrid approach combining capability and load balancing
func (ac *AgentCoordinator) assignHybrid(task *CollaborativeTask, availableAgents map[string]Agent) (map[string]string, error) {
	assignments := make(map[string]string)

	for _, subtask := range task.Subtasks {
		// Get top candidates based on capability
		candidates := ac.capabilityMatcher.GetTopCandidates(subtask, availableAgents, 3)
		if len(candidates) == 0 {
			return nil, fmt.Errorf("no suitable agents found for subtask %s", subtask.ID)
		}

		// Among candidates, choose the least loaded
		bestAgent := ac.loadBalancer.GetLeastLoadedFromCandidates(candidates)

		assignments[subtask.ID] = bestAgent
		subtask.AssignedAgent = bestAgent
		ac.loadBalancer.IncrementLoad(bestAgent)

		ac.logger.Debug("Subtask assigned by hybrid strategy",
			"subtask_id", subtask.ID,
			"agent_id", bestAgent,
			"candidates", len(candidates))
	}

	return assignments, nil
}

// validateAssignments validates that all assignments are valid
func (ac *AgentCoordinator) validateAssignments(task *CollaborativeTask, assignments map[string]string, availableAgents map[string]Agent) error {
	// Check that all subtasks are assigned
	for _, subtask := range task.Subtasks {
		if _, assigned := assignments[subtask.ID]; !assigned {
			return fmt.Errorf("subtask %s not assigned", subtask.ID)
		}
	}

	// Check that all assigned agents exist
	for subtaskID, agentID := range assignments {
		if _, exists := availableAgents[agentID]; !exists {
			return fmt.Errorf("assigned agent %s for subtask %s does not exist", agentID, subtaskID)
		}
	}

	return nil
}

// FindBestMatch finds the best agent for a subtask based on capabilities
func (cm *CapabilityMatcher) FindBestMatch(subtask *Subtask, availableAgents map[string]Agent) (string, float64) {
	bestAgent := ""
	bestScore := 0.0

	for agentID, agent := range availableAgents {
		score := cm.calculateMatchScore(subtask, agent)
		if score > bestScore {
			bestScore = score
			bestAgent = agentID
		}
	}

	return bestAgent, bestScore
}

// GetTopCandidates returns the top N candidates for a subtask
func (cm *CapabilityMatcher) GetTopCandidates(subtask *Subtask, availableAgents map[string]Agent, n int) []string {
	type candidate struct {
		agentID string
		score   float64
	}

	candidates := make([]candidate, 0)
	for agentID, agent := range availableAgents {
		score := cm.calculateMatchScore(subtask, agent)
		if score > 0.3 { // Minimum threshold
			candidates = append(candidates, candidate{agentID: agentID, score: score})
		}
	}

	// Sort by score (highest first)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})

	// Return top N
	result := make([]string, 0, n)
	for i := 0; i < len(candidates) && i < n; i++ {
		result = append(result, candidates[i].agentID)
	}

	return result
}

// calculateMatchScore calculates how well an agent matches a subtask
func (cm *CapabilityMatcher) calculateMatchScore(subtask *Subtask, agent Agent) float64 {
	capabilities := agent.GetCapabilities()
	score := 0.0

	// Check agent type compatibility
	if agentType, exists := capabilities["agent_type"]; exists {
		score += cm.getTypeCompatibilityScore(subtask, agentType.(string))
	}

	// Check available tools
	if tools, exists := capabilities["available_tools"]; exists {
		score += cm.getToolCompatibilityScore(subtask, tools)
	}

	// Check specific capabilities
	score += cm.getCapabilityScore(subtask, capabilities)

	return score
}

// getTypeCompatibilityScore calculates type compatibility score
func (cm *CapabilityMatcher) getTypeCompatibilityScore(subtask *Subtask, agentType string) float64 {
	subtaskName := strings.ToLower(subtask.Name)
	agentTypeLower := strings.ToLower(agentType)

	compatibilityMap := map[string][]string{
		"react":            {"analysis", "investigation", "reasoning", "scan"},
		"plan_and_execute": {"planning", "coordination", "workflow", "process"},
		"security":         {"security", "vulnerability", "scan", "audit", "penetration"},
		"data":             {"data", "collection", "processing", "analysis"},
	}

	for agentTypeKey, keywords := range compatibilityMap {
		if strings.Contains(agentTypeLower, agentTypeKey) {
			for _, keyword := range keywords {
				if strings.Contains(subtaskName, keyword) {
					return 0.4
				}
			}
		}
	}

	return 0.1
}

// getToolCompatibilityScore calculates tool compatibility score
func (cm *CapabilityMatcher) getToolCompatibilityScore(subtask *Subtask, tools interface{}) float64 {
	toolList, ok := tools.([]string)
	if !ok {
		return 0.0
	}

	subtaskName := strings.ToLower(subtask.Name)
	score := 0.0

	for _, tool := range toolList {
		toolLower := strings.ToLower(tool)
		if strings.Contains(subtaskName, "security") && strings.Contains(toolLower, "security") {
			score += 0.3
		}
		if strings.Contains(subtaskName, "scan") && strings.Contains(toolLower, "scan") {
			score += 0.3
		}
		if strings.Contains(subtaskName, "analysis") && strings.Contains(toolLower, "analy") {
			score += 0.2
		}
	}

	return score
}

// getCapabilityScore calculates general capability score
func (cm *CapabilityMatcher) getCapabilityScore(subtask *Subtask, capabilities map[string]interface{}) float64 {
	score := 0.0

	// Base score for having capabilities
	if len(capabilities) > 0 {
		score += 0.1
	}

	// Bonus for specific capabilities
	if parallel, exists := capabilities["parallel_execution"]; exists && parallel.(bool) {
		score += 0.1
	}

	if selfReflection, exists := capabilities["self_reflection"]; exists && selfReflection.(bool) {
		score += 0.1
	}

	return score
}

// GetLeastLoadedAgent returns the agent with the least load
func (lb *LoadBalancer) GetLeastLoadedAgent(availableAgents map[string]Agent) string {
	leastLoadedAgent := ""
	minLoad := lb.maxLoad + 1

	for agentID := range availableAgents {
		load := lb.agentLoads[agentID]
		if load < minLoad {
			minLoad = load
			leastLoadedAgent = agentID
		}
	}

	return leastLoadedAgent
}

// GetLeastLoadedFromCandidates returns the least loaded agent from candidates
func (lb *LoadBalancer) GetLeastLoadedFromCandidates(candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}

	leastLoadedAgent := candidates[0]
	minLoad := lb.agentLoads[leastLoadedAgent]

	for _, agentID := range candidates[1:] {
		load := lb.agentLoads[agentID]
		if load < minLoad {
			minLoad = load
			leastLoadedAgent = agentID
		}
	}

	return leastLoadedAgent
}

// IncrementLoad increments the load for an agent
func (lb *LoadBalancer) IncrementLoad(agentID string) {
	lb.agentLoads[agentID]++
}

// DecrementLoad decrements the load for an agent
func (lb *LoadBalancer) DecrementLoad(agentID string) {
	if lb.agentLoads[agentID] > 0 {
		lb.agentLoads[agentID]--
	}
}

// GetAgentLoad returns the current load for an agent
func (lb *LoadBalancer) GetAgentLoad(agentID string) int {
	return lb.agentLoads[agentID]
}
