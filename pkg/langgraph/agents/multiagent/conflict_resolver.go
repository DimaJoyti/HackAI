package multiagent

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// ConflictResolver resolves conflicts between agent results
type ConflictResolver struct {
	logger               *logger.Logger
	resolutionStrategies map[ConflictType]ResolutionStrategy
	consensusEngine      *ConsensusEngine
	votingSystem         *VotingSystem
	confidenceAnalyzer   *ConfidenceAnalyzer
}

// ConflictType represents different types of conflicts
type ConflictType string

const (
	ConflictTypeDataInconsistency ConflictType = "data_inconsistency"
	ConflictTypeResultMismatch    ConflictType = "result_mismatch"
	ConflictTypeConfidenceGap     ConflictType = "confidence_gap"
	ConflictTypeTimeoutConflict   ConflictType = "timeout_conflict"
	ConflictTypeResourceConflict  ConflictType = "resource_conflict"
	ConflictTypeMethodological    ConflictType = "methodological"
)

// ResolutionStrategy defines how to resolve different types of conflicts
type ResolutionStrategy struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Method      ResolutionMethod       `json:"method"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// ResolutionMethod represents different resolution methods
type ResolutionMethod string

const (
	MethodConsensus       ResolutionMethod = "consensus"
	MethodVoting          ResolutionMethod = "voting"
	MethodConfidenceBased ResolutionMethod = "confidence_based"
	MethodMajorityRule    ResolutionMethod = "majority_rule"
	MethodExpertOverride  ResolutionMethod = "expert_override"
	MethodWeightedAverage ResolutionMethod = "weighted_average"
	MethodArbitration     ResolutionMethod = "arbitration"
)

// Conflict represents a conflict between agent results
type Conflict struct {
	ID           string                 `json:"id"`
	Type         ConflictType           `json:"type"`
	Description  string                 `json:"description"`
	Participants []string               `json:"participants"`
	ConflictData map[string]interface{} `json:"conflict_data"`
	Resolution   *ConflictResolution    `json:"resolution,omitempty"`
	Status       ConflictStatus         `json:"status"`
	CreatedAt    time.Time              `json:"created_at"`
	ResolvedAt   *time.Time             `json:"resolved_at,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// ConflictResolution represents the resolution of a conflict
type ConflictResolution struct {
	Method       ResolutionMethod       `json:"method"`
	Result       interface{}            `json:"result"`
	Confidence   float64                `json:"confidence"`
	Reasoning    string                 `json:"reasoning"`
	Participants []string               `json:"participants"`
	Votes        map[string]interface{} `json:"votes,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// ConflictStatus represents the status of a conflict
type ConflictStatus string

const (
	ConflictStatusDetected  ConflictStatus = "detected"
	ConflictStatusAnalyzing ConflictStatus = "analyzing"
	ConflictStatusResolving ConflictStatus = "resolving"
	ConflictStatusResolved  ConflictStatus = "resolved"
	ConflictStatusEscalated ConflictStatus = "escalated"
	ConflictStatusAbandoned ConflictStatus = "abandoned"
)

// ConsensusEngine builds consensus among agents
type ConsensusEngine struct {
	logger *logger.Logger
}

// VotingSystem manages voting-based conflict resolution
type VotingSystem struct {
	logger *logger.Logger
}

// ConfidenceAnalyzer analyzes confidence levels in results
type ConfidenceAnalyzer struct {
	logger *logger.Logger
}

// Vote represents a vote in conflict resolution
type Vote struct {
	AgentID    string      `json:"agent_id"`
	Choice     interface{} `json:"choice"`
	Confidence float64     `json:"confidence"`
	Reasoning  string      `json:"reasoning"`
	Timestamp  time.Time   `json:"timestamp"`
}

// NewConflictResolver creates a new conflict resolver
func NewConflictResolver(logger *logger.Logger) *ConflictResolver {
	cr := &ConflictResolver{
		logger:               logger,
		resolutionStrategies: make(map[ConflictType]ResolutionStrategy),
		consensusEngine:      &ConsensusEngine{logger: logger},
		votingSystem:         &VotingSystem{logger: logger},
		confidenceAnalyzer:   &ConfidenceAnalyzer{logger: logger},
	}

	// Initialize resolution strategies
	cr.initializeResolutionStrategies()

	return cr
}

// initializeResolutionStrategies sets up default resolution strategies
func (cr *ConflictResolver) initializeResolutionStrategies() {
	strategies := map[ConflictType]ResolutionStrategy{
		ConflictTypeDataInconsistency: {
			Name:        "Data Inconsistency Resolution",
			Description: "Resolve conflicts in data interpretation",
			Method:      MethodConsensus,
			Parameters: map[string]interface{}{
				"min_agreement":  0.7,
				"max_iterations": 3,
			},
		},
		ConflictTypeResultMismatch: {
			Name:        "Result Mismatch Resolution",
			Description: "Resolve conflicts in agent results",
			Method:      MethodConfidenceBased,
			Parameters: map[string]interface{}{
				"confidence_threshold": 0.8,
				"weight_by_expertise":  true,
			},
		},
		ConflictTypeConfidenceGap: {
			Name:        "Confidence Gap Resolution",
			Description: "Resolve conflicts due to confidence differences",
			Method:      MethodWeightedAverage,
			Parameters: map[string]interface{}{
				"confidence_weight": 0.6,
				"expertise_weight":  0.4,
			},
		},
		ConflictTypeTimeoutConflict: {
			Name:        "Timeout Conflict Resolution",
			Description: "Resolve conflicts due to timeouts",
			Method:      MethodMajorityRule,
			Parameters: map[string]interface{}{
				"exclude_timeouts": true,
			},
		},
		ConflictTypeResourceConflict: {
			Name:        "Resource Conflict Resolution",
			Description: "Resolve conflicts over resource allocation",
			Method:      MethodArbitration,
			Parameters: map[string]interface{}{
				"arbitrator": "system",
			},
		},
		ConflictTypeMethodological: {
			Name:        "Methodological Conflict Resolution",
			Description: "Resolve conflicts in methodology",
			Method:      MethodExpertOverride,
			Parameters: map[string]interface{}{
				"expert_threshold": 0.9,
			},
		},
	}

	cr.resolutionStrategies = strategies
}

// ResolveAndAggregate resolves conflicts and aggregates results
func (cr *ConflictResolver) ResolveAndAggregate(ctx context.Context, task *CollaborativeTask, results map[string]*SubtaskResult) (interface{}, error) {
	cr.logger.Debug("Starting conflict resolution and aggregation",
		"task_id", task.ID,
		"results", len(results))

	// Detect conflicts
	conflicts, err := cr.detectConflicts(results)
	if err != nil {
		return nil, fmt.Errorf("conflict detection failed: %w", err)
	}

	cr.logger.Debug("Conflicts detected",
		"task_id", task.ID,
		"conflicts", len(conflicts))

	// Resolve conflicts
	resolvedResults := make(map[string]*SubtaskResult)
	for resultID, result := range results {
		resolvedResults[resultID] = result
	}

	for _, conflict := range conflicts {
		resolution, err := cr.resolveConflict(ctx, conflict, results)
		if err != nil {
			cr.logger.Error("Failed to resolve conflict",
				"conflict_id", conflict.ID,
				"error", err)
			continue
		}

		// Apply resolution to results
		cr.applyResolution(conflict, resolution, resolvedResults)
	}

	// Aggregate resolved results
	aggregatedResult := cr.aggregateResults(task, resolvedResults)

	cr.logger.Info("Conflict resolution and aggregation completed",
		"task_id", task.ID,
		"conflicts_resolved", len(conflicts))

	return aggregatedResult, nil
}

// detectConflicts detects conflicts in agent results
func (cr *ConflictResolver) detectConflicts(results map[string]*SubtaskResult) ([]*Conflict, error) {
	conflicts := make([]*Conflict, 0)

	// Check for confidence gaps
	confidenceConflicts := cr.detectConfidenceConflicts(results)
	conflicts = append(conflicts, confidenceConflicts...)

	// Check for result mismatches
	resultConflicts := cr.detectResultConflicts(results)
	conflicts = append(conflicts, resultConflicts...)

	// Check for timeout conflicts
	timeoutConflicts := cr.detectTimeoutConflicts(results)
	conflicts = append(conflicts, timeoutConflicts...)

	return conflicts, nil
}

// detectConfidenceConflicts detects conflicts based on confidence levels
func (cr *ConflictResolver) detectConfidenceConflicts(results map[string]*SubtaskResult) []*Conflict {
	conflicts := make([]*Conflict, 0)

	confidences := make([]float64, 0)
	for _, result := range results {
		confidences = append(confidences, result.Confidence)
	}

	if len(confidences) < 2 {
		return conflicts
	}

	// Calculate confidence variance
	variance := cr.confidenceAnalyzer.CalculateVariance(confidences)
	if variance > 0.3 { // Threshold for significant confidence gap
		participants := make([]string, 0)
		for _, result := range results {
			participants = append(participants, result.AgentID)
		}

		conflict := &Conflict{
			ID:           fmt.Sprintf("confidence-conflict-%d", time.Now().UnixNano()),
			Type:         ConflictTypeConfidenceGap,
			Description:  "Significant confidence gap detected between agent results",
			Participants: participants,
			ConflictData: map[string]interface{}{
				"confidences": confidences,
				"variance":    variance,
			},
			Status:    ConflictStatusDetected,
			CreatedAt: time.Now(),
			Metadata:  make(map[string]interface{}),
		}

		conflicts = append(conflicts, conflict)
	}

	return conflicts
}

// detectResultConflicts detects conflicts in result content
func (cr *ConflictResolver) detectResultConflicts(results map[string]*SubtaskResult) []*Conflict {
	conflicts := make([]*Conflict, 0)

	// Simple result comparison - in practice, this would be more sophisticated
	resultValues := make(map[string]interface{})
	for resultID, result := range results {
		resultValues[resultID] = result.Result
	}

	// Check for contradictory boolean results
	boolResults := make(map[string]bool)
	for resultID, result := range results {
		if boolVal, ok := result.Result.(bool); ok {
			boolResults[resultID] = boolVal
		}
	}

	if len(boolResults) > 1 {
		firstValue := ""
		firstResult := false
		hasConflict := false

		for resultID, value := range boolResults {
			if firstValue == "" {
				firstValue = resultID
				firstResult = value
			} else if value != firstResult {
				hasConflict = true
				break
			}
		}

		if hasConflict {
			participants := make([]string, 0)
			for _, result := range results {
				participants = append(participants, result.AgentID)
			}

			conflict := &Conflict{
				ID:           fmt.Sprintf("result-conflict-%d", time.Now().UnixNano()),
				Type:         ConflictTypeResultMismatch,
				Description:  "Contradictory boolean results detected",
				Participants: participants,
				ConflictData: map[string]interface{}{
					"bool_results": boolResults,
				},
				Status:    ConflictStatusDetected,
				CreatedAt: time.Now(),
				Metadata:  make(map[string]interface{}),
			}

			conflicts = append(conflicts, conflict)
		}
	}

	return conflicts
}

// detectTimeoutConflicts detects conflicts due to timeouts
func (cr *ConflictResolver) detectTimeoutConflicts(results map[string]*SubtaskResult) []*Conflict {
	conflicts := make([]*Conflict, 0)

	timeoutResults := make([]string, 0)
	for resultID, result := range results {
		if !result.Success && result.Error != "" &&
			(result.Error == "timeout" || result.Error == "context deadline exceeded") {
			timeoutResults = append(timeoutResults, resultID)
		}
	}

	if len(timeoutResults) > 0 {
		participants := make([]string, 0)
		for _, result := range results {
			participants = append(participants, result.AgentID)
		}

		conflict := &Conflict{
			ID:           fmt.Sprintf("timeout-conflict-%d", time.Now().UnixNano()),
			Type:         ConflictTypeTimeoutConflict,
			Description:  "Some agents timed out while others completed",
			Participants: participants,
			ConflictData: map[string]interface{}{
				"timeout_results": timeoutResults,
			},
			Status:    ConflictStatusDetected,
			CreatedAt: time.Now(),
			Metadata:  make(map[string]interface{}),
		}

		conflicts = append(conflicts, conflict)
	}

	return conflicts
}

// resolveConflict resolves a specific conflict
func (cr *ConflictResolver) resolveConflict(ctx context.Context, conflict *Conflict, results map[string]*SubtaskResult) (*ConflictResolution, error) {
	conflict.Status = ConflictStatusResolving

	strategy, exists := cr.resolutionStrategies[conflict.Type]
	if !exists {
		return nil, fmt.Errorf("no resolution strategy for conflict type %s", conflict.Type)
	}

	cr.logger.Debug("Resolving conflict",
		"conflict_id", conflict.ID,
		"type", conflict.Type,
		"method", strategy.Method)

	var resolution *ConflictResolution
	var err error

	switch strategy.Method {
	case MethodConsensus:
		resolution, err = cr.resolveByConsensus(ctx, conflict, results, strategy.Parameters)
	case MethodVoting:
		resolution, err = cr.resolveByVoting(ctx, conflict, results, strategy.Parameters)
	case MethodConfidenceBased:
		resolution, err = cr.resolveByConfidence(ctx, conflict, results, strategy.Parameters)
	case MethodMajorityRule:
		resolution, err = cr.resolveByMajority(ctx, conflict, results, strategy.Parameters)
	case MethodWeightedAverage:
		resolution, err = cr.resolveByWeightedAverage(ctx, conflict, results, strategy.Parameters)
	case MethodArbitration:
		resolution, err = cr.resolveByArbitration(ctx, conflict, results, strategy.Parameters)
	case MethodExpertOverride:
		resolution, err = cr.resolveByExpertOverride(ctx, conflict, results, strategy.Parameters)
	default:
		err = fmt.Errorf("unsupported resolution method: %s", strategy.Method)
	}

	if err != nil {
		conflict.Status = ConflictStatusEscalated
		return nil, err
	}

	conflict.Resolution = resolution
	conflict.Status = ConflictStatusResolved
	now := time.Now()
	conflict.ResolvedAt = &now

	cr.logger.Info("Conflict resolved",
		"conflict_id", conflict.ID,
		"method", strategy.Method,
		"confidence", resolution.Confidence)

	return resolution, nil
}

// resolveByConsensus resolves conflict using consensus building
func (cr *ConflictResolver) resolveByConsensus(ctx context.Context, conflict *Conflict, results map[string]*SubtaskResult, parameters map[string]interface{}) (*ConflictResolution, error) {
	return cr.consensusEngine.BuildConsensus(conflict, results, parameters)
}

// resolveByVoting resolves conflict using voting
func (cr *ConflictResolver) resolveByVoting(ctx context.Context, conflict *Conflict, results map[string]*SubtaskResult, parameters map[string]interface{}) (*ConflictResolution, error) {
	return cr.votingSystem.ConductVote(conflict, results, parameters)
}

// resolveByConfidence resolves conflict based on confidence levels
func (cr *ConflictResolver) resolveByConfidence(ctx context.Context, conflict *Conflict, results map[string]*SubtaskResult, parameters map[string]interface{}) (*ConflictResolution, error) {
	// Find result with highest confidence
	var bestResult *SubtaskResult
	highestConfidence := 0.0

	for _, result := range results {
		if result.Success && result.Confidence > highestConfidence {
			highestConfidence = result.Confidence
			bestResult = result
		}
	}

	if bestResult == nil {
		return nil, fmt.Errorf("no successful results found")
	}

	resolution := &ConflictResolution{
		Method:       MethodConfidenceBased,
		Result:       bestResult.Result,
		Confidence:   bestResult.Confidence,
		Reasoning:    fmt.Sprintf("Selected result with highest confidence: %.2f", bestResult.Confidence),
		Participants: []string{bestResult.AgentID},
		Metadata: map[string]interface{}{
			"selected_agent": bestResult.AgentID,
			"confidence":     bestResult.Confidence,
		},
	}

	return resolution, nil
}

// resolveByMajority resolves conflict using majority rule
func (cr *ConflictResolver) resolveByMajority(ctx context.Context, conflict *Conflict, results map[string]*SubtaskResult, parameters map[string]interface{}) (*ConflictResolution, error) {
	// Count occurrences of each result
	resultCounts := make(map[interface{}]int)
	resultAgents := make(map[interface{}][]string)

	for _, result := range results {
		if result.Success {
			resultCounts[result.Result]++
			resultAgents[result.Result] = append(resultAgents[result.Result], result.AgentID)
		}
	}

	// Find majority result
	var majorityResult interface{}
	maxCount := 0

	for result, count := range resultCounts {
		if count > maxCount {
			maxCount = count
			majorityResult = result
		}
	}

	if majorityResult == nil {
		return nil, fmt.Errorf("no majority result found")
	}

	confidence := float64(maxCount) / float64(len(results))

	resolution := &ConflictResolution{
		Method:       MethodMajorityRule,
		Result:       majorityResult,
		Confidence:   confidence,
		Reasoning:    fmt.Sprintf("Selected majority result with %d/%d votes", maxCount, len(results)),
		Participants: resultAgents[majorityResult],
		Metadata: map[string]interface{}{
			"vote_count":    maxCount,
			"total_results": len(results),
		},
	}

	return resolution, nil
}

// resolveByWeightedAverage resolves conflict using weighted average
func (cr *ConflictResolver) resolveByWeightedAverage(ctx context.Context, conflict *Conflict, results map[string]*SubtaskResult, parameters map[string]interface{}) (*ConflictResolution, error) {
	// This is a simplified implementation for numeric results
	numericResults := make([]float64, 0)
	weights := make([]float64, 0)
	participants := make([]string, 0)

	for _, result := range results {
		if result.Success {
			if numVal, ok := result.Result.(float64); ok {
				numericResults = append(numericResults, numVal)
				weights = append(weights, result.Confidence)
				participants = append(participants, result.AgentID)
			}
		}
	}

	if len(numericResults) == 0 {
		return nil, fmt.Errorf("no numeric results found for weighted average")
	}

	// Calculate weighted average
	weightedSum := 0.0
	totalWeight := 0.0

	for i, value := range numericResults {
		weight := weights[i]
		weightedSum += value * weight
		totalWeight += weight
	}

	if totalWeight == 0 {
		return nil, fmt.Errorf("total weight is zero")
	}

	average := weightedSum / totalWeight
	confidence := totalWeight / float64(len(numericResults))

	resolution := &ConflictResolution{
		Method:       MethodWeightedAverage,
		Result:       average,
		Confidence:   confidence,
		Reasoning:    fmt.Sprintf("Calculated weighted average: %.2f", average),
		Participants: participants,
		Metadata: map[string]interface{}{
			"weighted_sum": weightedSum,
			"total_weight": totalWeight,
			"result_count": len(numericResults),
		},
	}

	return resolution, nil
}

// resolveByArbitration resolves conflict using arbitration
func (cr *ConflictResolver) resolveByArbitration(ctx context.Context, conflict *Conflict, results map[string]*SubtaskResult, parameters map[string]interface{}) (*ConflictResolution, error) {
	// Simple arbitration - select first successful result
	for _, result := range results {
		if result.Success {
			resolution := &ConflictResolution{
				Method:       MethodArbitration,
				Result:       result.Result,
				Confidence:   0.7, // Moderate confidence for arbitrated decisions
				Reasoning:    "Arbitrated decision based on first successful result",
				Participants: []string{result.AgentID},
				Metadata: map[string]interface{}{
					"arbitrator":     "system",
					"selected_agent": result.AgentID,
				},
			}
			return resolution, nil
		}
	}

	return nil, fmt.Errorf("no successful results for arbitration")
}

// resolveByExpertOverride resolves conflict using expert override
func (cr *ConflictResolver) resolveByExpertOverride(ctx context.Context, conflict *Conflict, results map[string]*SubtaskResult, parameters map[string]interface{}) (*ConflictResolution, error) {
	expertThreshold := 0.9
	if threshold, exists := parameters["expert_threshold"]; exists {
		if thresholdVal, ok := threshold.(float64); ok {
			expertThreshold = thresholdVal
		}
	}

	// Find expert result (highest confidence above threshold)
	var expertResult *SubtaskResult
	for _, result := range results {
		if result.Success && result.Confidence >= expertThreshold {
			if expertResult == nil || result.Confidence > expertResult.Confidence {
				expertResult = result
			}
		}
	}

	if expertResult == nil {
		return nil, fmt.Errorf("no expert result found (threshold: %.2f)", expertThreshold)
	}

	resolution := &ConflictResolution{
		Method:       MethodExpertOverride,
		Result:       expertResult.Result,
		Confidence:   expertResult.Confidence,
		Reasoning:    fmt.Sprintf("Expert override with confidence %.2f", expertResult.Confidence),
		Participants: []string{expertResult.AgentID},
		Metadata: map[string]interface{}{
			"expert_agent":     expertResult.AgentID,
			"expert_threshold": expertThreshold,
		},
	}

	return resolution, nil
}

// applyResolution applies conflict resolution to results
func (cr *ConflictResolver) applyResolution(conflict *Conflict, resolution *ConflictResolution, results map[string]*SubtaskResult) {
	// Update results based on resolution
	// This is a simplified implementation
	cr.logger.Debug("Applying conflict resolution",
		"conflict_id", conflict.ID,
		"resolution_method", resolution.Method)
}

// aggregateResults aggregates all results into a final result
func (cr *ConflictResolver) aggregateResults(task *CollaborativeTask, results map[string]*SubtaskResult) interface{} {
	aggregated := map[string]interface{}{
		"task_id":             task.ID,
		"task_name":           task.Name,
		"subtask_count":       len(results),
		"successful_subtasks": cr.countSuccessfulResults(results),
		"results":             results,
		"timestamp":           time.Now(),
		"aggregation_method":  "conflict_resolved",
	}

	return aggregated
}

// countSuccessfulResults counts successful results
func (cr *ConflictResolver) countSuccessfulResults(results map[string]*SubtaskResult) int {
	count := 0
	for _, result := range results {
		if result.Success {
			count++
		}
	}
	return count
}

// BuildConsensus builds consensus among conflicting results
func (ce *ConsensusEngine) BuildConsensus(conflict *Conflict, results map[string]*SubtaskResult, parameters map[string]interface{}) (*ConflictResolution, error) {
	// Simplified consensus building
	successfulResults := make([]*SubtaskResult, 0)
	for _, result := range results {
		if result.Success {
			successfulResults = append(successfulResults, result)
		}
	}

	if len(successfulResults) == 0 {
		return nil, fmt.Errorf("no successful results for consensus")
	}

	// Sort by confidence
	sort.Slice(successfulResults, func(i, j int) bool {
		return successfulResults[i].Confidence > successfulResults[j].Confidence
	})

	// Use highest confidence result as consensus
	consensusResult := successfulResults[0]
	participants := make([]string, 0)
	for _, result := range successfulResults {
		participants = append(participants, result.AgentID)
	}

	resolution := &ConflictResolution{
		Method:       MethodConsensus,
		Result:       consensusResult.Result,
		Confidence:   consensusResult.Confidence,
		Reasoning:    "Consensus built around highest confidence result",
		Participants: participants,
		Metadata: map[string]interface{}{
			"consensus_agent":   consensusResult.AgentID,
			"participant_count": len(participants),
		},
	}

	return resolution, nil
}

// ConductVote conducts a vote among agents
func (vs *VotingSystem) ConductVote(conflict *Conflict, results map[string]*SubtaskResult, parameters map[string]interface{}) (*ConflictResolution, error) {
	votes := make(map[interface{}][]Vote)

	for _, result := range results {
		if result.Success {
			vote := Vote{
				AgentID:    result.AgentID,
				Choice:     result.Result,
				Confidence: result.Confidence,
				Reasoning:  "Agent result",
				Timestamp:  time.Now(),
			}

			votes[result.Result] = append(votes[result.Result], vote)
		}
	}

	// Find winning choice
	var winningChoice interface{}
	maxVotes := 0

	for choice, voteList := range votes {
		if len(voteList) > maxVotes {
			maxVotes = len(voteList)
			winningChoice = choice
		}
	}

	if winningChoice == nil {
		return nil, fmt.Errorf("no winning choice in vote")
	}

	participants := make([]string, 0)
	for _, vote := range votes[winningChoice] {
		participants = append(participants, vote.AgentID)
	}

	confidence := float64(maxVotes) / float64(len(results))

	resolution := &ConflictResolution{
		Method:       MethodVoting,
		Result:       winningChoice,
		Confidence:   confidence,
		Reasoning:    fmt.Sprintf("Winning choice with %d votes", maxVotes),
		Participants: participants,
		Votes:        map[string]interface{}{"all_votes": votes},
		Metadata: map[string]interface{}{
			"vote_count":   maxVotes,
			"total_voters": len(results),
		},
	}

	return resolution, nil
}

// CalculateVariance calculates variance in confidence levels
func (ca *ConfidenceAnalyzer) CalculateVariance(confidences []float64) float64 {
	if len(confidences) == 0 {
		return 0.0
	}

	// Calculate mean
	sum := 0.0
	for _, conf := range confidences {
		sum += conf
	}
	mean := sum / float64(len(confidences))

	// Calculate variance
	varianceSum := 0.0
	for _, conf := range confidences {
		diff := conf - mean
		varianceSum += diff * diff
	}

	return varianceSum / float64(len(confidences))
}
