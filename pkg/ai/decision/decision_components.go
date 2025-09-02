package decision

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// ContextAnalyzer analyzes decision context
type ContextAnalyzer struct {
	logger *logger.Logger
}

// NewContextAnalyzer creates a new context analyzer
func NewContextAnalyzer(logger *logger.Logger) *ContextAnalyzer {
	return &ContextAnalyzer{
		logger: logger,
	}
}

// AnalyzeContext analyzes the decision context
func (ca *ContextAnalyzer) AnalyzeContext(ctx context.Context, decisionContext *DecisionContext) (*ContextAnalysis, error) {
	analysis := &ContextAnalysis{
		ID:               uuid.New().String(),
		ComplexityScore:  decisionContext.Complexity,
		UrgencyScore:     decisionContext.Urgency,
		ResourceAnalysis: make(map[string]float64),
		Recommendations:  make([]string, 0),
		Timestamp:        time.Now(),
	}

	// Analyze resource availability
	for resource, amount := range decisionContext.Resources {
		analysis.ResourceAnalysis[resource] = amount
	}

	// Generate recommendations based on context
	if decisionContext.Urgency > 0.8 {
		analysis.Recommendations = append(analysis.Recommendations, "High urgency detected - consider fast execution strategies")
	}

	if decisionContext.Complexity > 0.7 {
		analysis.Recommendations = append(analysis.Recommendations, "High complexity detected - consider breaking down into smaller decisions")
	}

	return analysis, nil
}

// ContextAnalysis represents the result of context analysis
type ContextAnalysis struct {
	ID               string             `json:"id"`
	ComplexityScore  float64            `json:"complexity_score"`
	UrgencyScore     float64            `json:"urgency_score"`
	ResourceAnalysis map[string]float64 `json:"resource_analysis"`
	Recommendations  []string           `json:"recommendations"`
	Timestamp        time.Time          `json:"timestamp"`
}

// DecisionHistory manages decision history
type DecisionHistory struct {
	decisions  map[string]*DecisionRecord
	maxHistory int
	logger     *logger.Logger
	mutex      sync.RWMutex
}

// DecisionRecord represents a recorded decision
type DecisionRecord struct {
	Request   *DecisionRequest       `json:"request"`
	Result    *DecisionResult        `json:"result"`
	Outcome   *DecisionOutcome       `json:"outcome"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// NewDecisionHistory creates a new decision history
func NewDecisionHistory(maxHistory int, logger *logger.Logger) *DecisionHistory {
	return &DecisionHistory{
		decisions:  make(map[string]*DecisionRecord),
		maxHistory: maxHistory,
		logger:     logger,
	}
}

// RecordDecision records a decision
func (dh *DecisionHistory) RecordDecision(request *DecisionRequest, result *DecisionResult) {
	dh.mutex.Lock()
	defer dh.mutex.Unlock()

	record := &DecisionRecord{
		Request:   request,
		Result:    result,
		Timestamp: time.Now(),
	}

	dh.decisions[result.ID] = record

	// Cleanup old decisions if needed
	if len(dh.decisions) > dh.maxHistory {
		dh.cleanupOldDecisions()
	}
}

// UpdateOutcome updates the outcome of a decision
func (dh *DecisionHistory) UpdateOutcome(decisionID string, outcome *DecisionOutcome) error {
	dh.mutex.Lock()
	defer dh.mutex.Unlock()

	record, exists := dh.decisions[decisionID]
	if !exists {
		return fmt.Errorf("decision not found: %s", decisionID)
	}

	record.Outcome = outcome
	return nil
}

// GetDecision retrieves a decision by ID
func (dh *DecisionHistory) GetDecision(decisionID string) (*DecisionRecord, error) {
	dh.mutex.RLock()
	defer dh.mutex.RUnlock()

	record, exists := dh.decisions[decisionID]
	if !exists {
		return nil, fmt.Errorf("decision not found: %s", decisionID)
	}

	return record, nil
}

// cleanupOldDecisions removes old decisions to maintain size limit
func (dh *DecisionHistory) cleanupOldDecisions() {
	// Simple cleanup - remove oldest 10% of decisions
	removeCount := len(dh.decisions) / 10
	if removeCount == 0 {
		removeCount = 1
	}

	var oldestIDs []string
	oldestTime := time.Now()

	for _, record := range dh.decisions {
		if record.Timestamp.Before(oldestTime) {
			oldestTime = record.Timestamp
		}
	}

	// Find decisions to remove
	for id := range dh.decisions {
		if len(oldestIDs) < removeCount {
			oldestIDs = append(oldestIDs, id)
		}
	}

	// Remove old decisions
	for _, id := range oldestIDs {
		delete(dh.decisions, id)
	}
}

// ConfidenceCalculator calculates decision confidence
type ConfidenceCalculator struct {
	logger *logger.Logger
}

// NewConfidenceCalculator creates a new confidence calculator
func NewConfidenceCalculator(logger *logger.Logger) *ConfidenceCalculator {
	return &ConfidenceCalculator{
		logger: logger,
	}
}

// CalculateConfidence calculates confidence for a decision
func (cc *ConfidenceCalculator) CalculateConfidence(ctx context.Context, selectedOption *DecisionOption, alternatives []*DecisionOption, request *DecisionRequest) float64 {
	confidence := 0.5 // Base confidence

	// Factor 1: Expected outcome confidence
	if selectedOption.ExpectedOutcome != nil {
		confidence += selectedOption.ExpectedOutcome.Confidence * 0.3
	}

	// Factor 2: Success probability
	if selectedOption.ExpectedOutcome != nil {
		confidence += selectedOption.ExpectedOutcome.SuccessProbability * 0.2
	}

	// Factor 3: Margin over alternatives
	if len(alternatives) > 0 {
		margin := cc.calculateMarginOverAlternatives(selectedOption, alternatives)
		confidence += margin * 0.2
	}

	// Factor 4: Risk assessment
	riskFactor := 1.0 - selectedOption.Risk
	confidence += riskFactor * 0.1

	// Factor 5: Context certainty
	if request.Context != nil {
		contextCertainty := 1.0 - request.Context.Complexity
		confidence += contextCertainty * 0.2
	}

	// Normalize to [0, 1]
	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0.0 {
		confidence = 0.0
	}

	return confidence
}

// calculateMarginOverAlternatives calculates the margin of the selected option over alternatives
func (cc *ConfidenceCalculator) calculateMarginOverAlternatives(selected *DecisionOption, alternatives []*DecisionOption) float64 {
	if len(alternatives) == 0 {
		return 0.5
	}

	selectedScore := cc.getOptionScore(selected)
	var bestAlternativeScore float64

	for _, alt := range alternatives {
		score := cc.getOptionScore(alt)
		if score > bestAlternativeScore {
			bestAlternativeScore = score
		}
	}

	if selectedScore <= bestAlternativeScore {
		return 0.0
	}

	margin := (selectedScore - bestAlternativeScore) / selectedScore
	return margin
}

// getOptionScore gets a simple score for an option
func (cc *ConfidenceCalculator) getOptionScore(option *DecisionOption) float64 {
	score := 0.0
	if option.ExpectedOutcome != nil {
		score = option.ExpectedOutcome.ExpectedValue - option.Cost - option.Risk
	}
	return score
}

// RiskAssessment assesses decision risks
type RiskAssessment struct {
	logger *logger.Logger
}

// NewRiskAssessment creates a new risk assessment
func NewRiskAssessment(logger *logger.Logger) *RiskAssessment {
	return &RiskAssessment{
		logger: logger,
	}
}

// AssessRisks assesses risks for a decision request
func (ra *RiskAssessment) AssessRisks(ctx context.Context, request *DecisionRequest) (*RiskAssessmentResult, error) {
	result := &RiskAssessmentResult{
		ID:          uuid.New().String(),
		OverallRisk: 0.0,
		RiskFactors: make([]*RiskFactor, 0),
		Mitigations: make([]*RiskMitigation, 0),
		Timestamp:   time.Now(),
	}

	// Assess individual option risks
	for _, option := range request.Options {
		if option.Risk > result.OverallRisk {
			result.OverallRisk = option.Risk
		}

		if option.Risk > 0.7 {
			riskFactor := &RiskFactor{
				ID:          uuid.New().String(),
				Type:        "option_risk",
				Description: fmt.Sprintf("High risk option: %s", option.Name),
				Severity:    option.Risk,
				Probability: 0.8,
			}
			result.RiskFactors = append(result.RiskFactors, riskFactor)
		}
	}

	// Assess context risks
	if request.Context != nil {
		if request.Context.Urgency > 0.8 {
			riskFactor := &RiskFactor{
				ID:          uuid.New().String(),
				Type:        "urgency_risk",
				Description: "High urgency may lead to suboptimal decisions",
				Severity:    request.Context.Urgency,
				Probability: 0.6,
			}
			result.RiskFactors = append(result.RiskFactors, riskFactor)
		}

		if request.Context.Complexity > 0.8 {
			riskFactor := &RiskFactor{
				ID:          uuid.New().String(),
				Type:        "complexity_risk",
				Description: "High complexity increases uncertainty",
				Severity:    request.Context.Complexity,
				Probability: 0.7,
			}
			result.RiskFactors = append(result.RiskFactors, riskFactor)
		}
	}

	// Generate mitigations
	for _, riskFactor := range result.RiskFactors {
		mitigation := ra.generateMitigation(riskFactor)
		if mitigation != nil {
			result.Mitigations = append(result.Mitigations, mitigation)
		}
	}

	return result, nil
}

// generateMitigation generates a mitigation for a risk factor
func (ra *RiskAssessment) generateMitigation(riskFactor *RiskFactor) *RiskMitigation {
	switch riskFactor.Type {
	case "option_risk":
		return &RiskMitigation{
			ID:            uuid.New().String(),
			RiskID:        riskFactor.ID,
			Type:          "monitoring",
			Description:   "Implement close monitoring and rollback procedures",
			Effectiveness: 0.7,
		}
	case "urgency_risk":
		return &RiskMitigation{
			ID:            uuid.New().String(),
			RiskID:        riskFactor.ID,
			Type:          "process",
			Description:   "Use rapid decision-making frameworks",
			Effectiveness: 0.6,
		}
	case "complexity_risk":
		return &RiskMitigation{
			ID:            uuid.New().String(),
			RiskID:        riskFactor.ID,
			Type:          "decomposition",
			Description:   "Break down complex decisions into smaller parts",
			Effectiveness: 0.8,
		}
	}
	return nil
}

// RiskAssessmentResult represents the result of risk assessment
type RiskAssessmentResult struct {
	ID          string            `json:"id"`
	OverallRisk float64           `json:"overall_risk"`
	RiskFactors []*RiskFactor     `json:"risk_factors"`
	Mitigations []*RiskMitigation `json:"mitigations"`
	Timestamp   time.Time         `json:"timestamp"`
}

// RiskFactor represents a risk factor
type RiskFactor struct {
	ID          string  `json:"id"`
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Severity    float64 `json:"severity"`
	Probability float64 `json:"probability"`
}

// RiskMitigation represents a risk mitigation
type RiskMitigation struct {
	ID            string  `json:"id"`
	RiskID        string  `json:"risk_id"`
	Type          string  `json:"type"`
	Description   string  `json:"description"`
	Effectiveness float64 `json:"effectiveness"`
}
