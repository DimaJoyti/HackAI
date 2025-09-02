package decision

import (
	"context"
	"fmt"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// NewStrategyAdaptor creates a new strategy adaptor
func NewStrategyAdaptor(logger *logger.Logger) *StrategyAdaptor {
	sa := &StrategyAdaptor{
		strategies:      make(map[string]*DecisionStrategy),
		adaptationRules: make([]*AdaptationRule, 0),
		performanceData: make(map[string]*StrategyPerformance),
		logger:          logger,
	}

	// Initialize default strategies
	sa.initializeDefaultStrategies()

	return sa
}

// initializeDefaultStrategies initializes default decision strategies
func (sa *StrategyAdaptor) initializeDefaultStrategies() {
	strategies := []*DecisionStrategy{
		{
			ID:          uuid.New().String(),
			Name:        "Greedy Optimization",
			Description: "Selects option with highest immediate value",
			Algorithm:   AlgorithmGreedy,
			Parameters: map[string]interface{}{
				"optimization_target": "expected_value",
				"risk_tolerance":      0.5,
			},
			Effectiveness: 0.7,
			UsageCount:    0,
			SuccessRate:   0.0,
			LastUsed:      time.Time{},
			Metadata:      make(map[string]interface{}),
		},
		{
			ID:          uuid.New().String(),
			Name:        "Bayesian Decision",
			Description: "Uses Bayesian inference for decision making",
			Algorithm:   AlgorithmBayesian,
			Parameters: map[string]interface{}{
				"prior_weight":        0.3,
				"evidence_weight":     0.7,
				"uncertainty_penalty": 0.2,
			},
			Effectiveness: 0.8,
			UsageCount:    0,
			SuccessRate:   0.0,
			LastUsed:      time.Time{},
			Metadata:      make(map[string]interface{}),
		},
		{
			ID:          uuid.New().String(),
			Name:        "Risk-Aware Decision",
			Description: "Balances expected value with risk assessment",
			Algorithm:   AlgorithmHeuristic,
			Parameters: map[string]interface{}{
				"risk_weight":   0.4,
				"value_weight":  0.6,
				"safety_margin": 0.1,
			},
			Effectiveness: 0.75,
			UsageCount:    0,
			SuccessRate:   0.0,
			LastUsed:      time.Time{},
			Metadata:      make(map[string]interface{}),
		},
	}

	for _, strategy := range strategies {
		sa.strategies[strategy.ID] = strategy
		sa.performanceData[strategy.ID] = &StrategyPerformance{
			StrategyID:          strategy.ID,
			TotalDecisions:      0,
			SuccessfulDecisions: 0,
			AverageConfidence:   0.0,
			AverageOutcome:      0.0,
			LastUpdated:         time.Now(),
		}
	}
}

// SelectStrategy selects the best strategy for a decision request
func (sa *StrategyAdaptor) SelectStrategy(ctx context.Context, request *DecisionRequest) *DecisionStrategy {
	sa.mutex.RLock()
	defer sa.mutex.RUnlock()

	// Analyze request characteristics
	characteristics := sa.analyzeRequestCharacteristics(request)

	// Find best matching strategy
	var bestStrategy *DecisionStrategy
	var bestScore float64 = -1

	for _, strategy := range sa.strategies {
		score := sa.calculateStrategyScore(strategy, characteristics)
		if score > bestScore {
			bestScore = score
			bestStrategy = strategy
		}
	}

	// Default to greedy if no strategy found
	if bestStrategy == nil {
		for _, strategy := range sa.strategies {
			if strategy.Algorithm == AlgorithmGreedy {
				bestStrategy = strategy
				break
			}
		}
	}

	sa.logger.Debug("Strategy selected",
		"strategy_id", bestStrategy.ID,
		"strategy_name", bestStrategy.Name,
		"score", bestScore)

	return bestStrategy
}

// analyzeRequestCharacteristics analyzes characteristics of a decision request
func (sa *StrategyAdaptor) analyzeRequestCharacteristics(request *DecisionRequest) *RequestCharacteristics {
	characteristics := &RequestCharacteristics{
		Urgency:     0.5,
		Complexity:  0.5,
		RiskLevel:   0.5,
		Uncertainty: 0.5,
		OptionCount: len(request.Options),
	}

	// Analyze context if available
	if request.Context != nil {
		characteristics.Urgency = request.Context.Urgency
		characteristics.Complexity = request.Context.Complexity
	}

	// Analyze options
	totalRisk := 0.0
	totalUncertainty := 0.0
	for _, option := range request.Options {
		totalRisk += option.Risk
		if option.ExpectedOutcome != nil {
			totalUncertainty += (1.0 - option.ExpectedOutcome.Confidence)
		}
	}

	if len(request.Options) > 0 {
		characteristics.RiskLevel = totalRisk / float64(len(request.Options))
		characteristics.Uncertainty = totalUncertainty / float64(len(request.Options))
	}

	return characteristics
}

// RequestCharacteristics represents characteristics of a decision request
type RequestCharacteristics struct {
	Urgency     float64 `json:"urgency"`
	Complexity  float64 `json:"complexity"`
	RiskLevel   float64 `json:"risk_level"`
	Uncertainty float64 `json:"uncertainty"`
	OptionCount int     `json:"option_count"`
}

// calculateStrategyScore calculates how well a strategy matches request characteristics
func (sa *StrategyAdaptor) calculateStrategyScore(strategy *DecisionStrategy, characteristics *RequestCharacteristics) float64 {
	score := 0.0

	// Base effectiveness
	score += strategy.Effectiveness * 0.3

	// Success rate (if available)
	if performance, exists := sa.performanceData[strategy.ID]; exists {
		if performance.TotalDecisions > 0 {
			successRate := float64(performance.SuccessfulDecisions) / float64(performance.TotalDecisions)
			score += successRate * 0.3
		}
	}

	// Algorithm-specific scoring
	switch strategy.Algorithm {
	case AlgorithmGreedy:
		// Greedy works well for simple, low-risk decisions
		if characteristics.Complexity < 0.5 && characteristics.RiskLevel < 0.5 {
			score += 0.2
		}
		if characteristics.Urgency > 0.7 {
			score += 0.1 // Fast execution
		}

	case AlgorithmBayesian:
		// Bayesian works well for uncertain, complex decisions
		if characteristics.Uncertainty > 0.5 {
			score += 0.2
		}
		if characteristics.Complexity > 0.5 {
			score += 0.1
		}

	case AlgorithmHeuristic:
		// Heuristic works well for balanced decisions
		score += 0.1 // Generally applicable

	case AlgorithmMonteCarlo:
		// Monte Carlo works well for complex, uncertain decisions
		if characteristics.Complexity > 0.7 && characteristics.Uncertainty > 0.6 {
			score += 0.2
		}
	}

	// Recency bonus (prefer recently successful strategies)
	if performance, exists := sa.performanceData[strategy.ID]; exists {
		timeSinceLastUse := time.Since(performance.LastUpdated)
		if timeSinceLastUse < 24*time.Hour {
			score += 0.05
		}
	}

	return score
}

// UpdateStrategyUsage updates strategy usage statistics
func (sa *StrategyAdaptor) UpdateStrategyUsage(strategyID string) {
	sa.mutex.Lock()
	defer sa.mutex.Unlock()

	if strategy, exists := sa.strategies[strategyID]; exists {
		strategy.UsageCount++
		strategy.LastUsed = time.Now()
	}

	if performance, exists := sa.performanceData[strategyID]; exists {
		performance.TotalDecisions++
		performance.LastUpdated = time.Now()
	}
}

// UpdateStrategyPerformance updates strategy performance based on outcome
func (sa *StrategyAdaptor) UpdateStrategyPerformance(strategyID string, outcome *DecisionOutcome) {
	sa.mutex.Lock()
	defer sa.mutex.Unlock()

	performance, exists := sa.performanceData[strategyID]
	if !exists {
		return
	}

	// Update success count
	if outcome.Success {
		performance.SuccessfulDecisions++
	}

	// Update average outcome
	if performance.TotalDecisions > 0 {
		performance.AverageOutcome = ((performance.AverageOutcome * float64(performance.TotalDecisions-1)) + outcome.ActualValue) / float64(performance.TotalDecisions)
	} else {
		performance.AverageOutcome = outcome.ActualValue
	}

	performance.LastUpdated = time.Now()

	// Update strategy effectiveness
	if strategy, exists := sa.strategies[strategyID]; exists {
		if performance.TotalDecisions > 0 {
			successRate := float64(performance.SuccessfulDecisions) / float64(performance.TotalDecisions)
			// Weighted average of old effectiveness and new success rate
			strategy.Effectiveness = (strategy.Effectiveness*0.7 + successRate*0.3)
			strategy.SuccessRate = successRate
		}
	}

	sa.logger.Debug("Strategy performance updated",
		"strategy_id", strategyID,
		"success", outcome.Success,
		"total_decisions", performance.TotalDecisions,
		"success_rate", float64(performance.SuccessfulDecisions)/float64(performance.TotalDecisions))
}

// GetStrategyPerformance returns performance data for a strategy
func (sa *StrategyAdaptor) GetStrategyPerformance(strategyID string) (*StrategyPerformance, error) {
	sa.mutex.RLock()
	defer sa.mutex.RUnlock()

	performance, exists := sa.performanceData[strategyID]
	if !exists {
		return nil, fmt.Errorf("strategy performance not found: %s", strategyID)
	}

	return performance, nil
}

// ListStrategies returns all available strategies
func (sa *StrategyAdaptor) ListStrategies() []*DecisionStrategy {
	sa.mutex.RLock()
	defer sa.mutex.RUnlock()

	strategies := make([]*DecisionStrategy, 0, len(sa.strategies))
	for _, strategy := range sa.strategies {
		strategies = append(strategies, strategy)
	}

	return strategies
}

// AddStrategy adds a new strategy
func (sa *StrategyAdaptor) AddStrategy(strategy *DecisionStrategy) error {
	sa.mutex.Lock()
	defer sa.mutex.Unlock()

	if strategy.ID == "" {
		strategy.ID = uuid.New().String()
	}

	sa.strategies[strategy.ID] = strategy
	sa.performanceData[strategy.ID] = &StrategyPerformance{
		StrategyID:          strategy.ID,
		TotalDecisions:      0,
		SuccessfulDecisions: 0,
		AverageConfidence:   0.0,
		AverageOutcome:      0.0,
		LastUpdated:         time.Now(),
	}

	sa.logger.Info("Strategy added",
		"strategy_id", strategy.ID,
		"strategy_name", strategy.Name)

	return nil
}

// RemoveStrategy removes a strategy
func (sa *StrategyAdaptor) RemoveStrategy(strategyID string) error {
	sa.mutex.Lock()
	defer sa.mutex.Unlock()

	if _, exists := sa.strategies[strategyID]; !exists {
		return fmt.Errorf("strategy not found: %s", strategyID)
	}

	delete(sa.strategies, strategyID)
	delete(sa.performanceData, strategyID)

	sa.logger.Info("Strategy removed", "strategy_id", strategyID)
	return nil
}

// AdaptStrategies adapts strategies based on performance and rules
func (sa *StrategyAdaptor) AdaptStrategies(ctx context.Context) error {
	sa.mutex.Lock()
	defer sa.mutex.Unlock()

	// Apply adaptation rules
	for _, rule := range sa.adaptationRules {
		if !rule.Enabled {
			continue
		}

		if err := sa.applyAdaptationRule(rule); err != nil {
			sa.logger.Error("Failed to apply adaptation rule",
				"rule_id", rule.ID,
				"error", err)
		}
	}

	return nil
}

// applyAdaptationRule applies a single adaptation rule
func (sa *StrategyAdaptor) applyAdaptationRule(rule *AdaptationRule) error {
	// Simple rule application - in production, implement more sophisticated logic
	switch rule.Action {
	case "adjust_effectiveness":
		// Adjust effectiveness based on recent performance
		for strategyID, performance := range sa.performanceData {
			if performance.TotalDecisions >= 10 {
				successRate := float64(performance.SuccessfulDecisions) / float64(performance.TotalDecisions)
				if strategy, exists := sa.strategies[strategyID]; exists {
					strategy.Effectiveness = successRate
				}
			}
		}
	case "disable_poor_performers":
		// Disable strategies with very low success rates
		for strategyID, performance := range sa.performanceData {
			if performance.TotalDecisions >= 20 {
				successRate := float64(performance.SuccessfulDecisions) / float64(performance.TotalDecisions)
				if successRate < 0.3 {
					if strategy, exists := sa.strategies[strategyID]; exists {
						strategy.Effectiveness = 0.1 // Effectively disable
					}
				}
			}
		}
	}

	return nil
}

// AddAdaptationRule adds a new adaptation rule
func (sa *StrategyAdaptor) AddAdaptationRule(rule *AdaptationRule) {
	sa.mutex.Lock()
	defer sa.mutex.Unlock()

	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}

	sa.adaptationRules = append(sa.adaptationRules, rule)
}
