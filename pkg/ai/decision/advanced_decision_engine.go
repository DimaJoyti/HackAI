package decision

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var decisionTracer = otel.Tracer("hackai/ai/decision")

// AdvancedDecisionEngine provides sophisticated decision-making capabilities
type AdvancedDecisionEngine struct {
	id                   string
	strategyAdaptor      *StrategyAdaptor
	contextAnalyzer      *ContextAnalyzer
	reinforcementLearner *ReinforcementLearner
	decisionHistory      *DecisionHistory
	confidenceCalculator *ConfidenceCalculator
	riskAssessment       *RiskAssessment
	config               *DecisionEngineConfig
	logger               *logger.Logger
	mutex                sync.RWMutex
}

// DecisionEngineConfig configures the decision engine
type DecisionEngineConfig struct {
	EnableReinforcement   bool          `json:"enable_reinforcement"`
	EnableContextAnalysis bool          `json:"enable_context_analysis"`
	EnableRiskAssessment  bool          `json:"enable_risk_assessment"`
	LearningRate          float64       `json:"learning_rate"`
	ExplorationRate       float64       `json:"exploration_rate"`
	ConfidenceThreshold   float64       `json:"confidence_threshold"`
	MaxDecisionHistory    int           `json:"max_decision_history"`
	DecisionTimeout       time.Duration `json:"decision_timeout"`
	EnableAdaptation      bool          `json:"enable_adaptation"`
	AdaptationInterval    time.Duration `json:"adaptation_interval"`
}

// DecisionRequest represents a request for decision-making
type DecisionRequest struct {
	ID                 string                 `json:"id"`
	AgentID            string                 `json:"agent_id"`
	Context            *DecisionContext       `json:"context"`
	Options            []*DecisionOption      `json:"options"`
	Constraints        []*DecisionConstraint  `json:"constraints"`
	Priority           DecisionPriority       `json:"priority"`
	Deadline           *time.Time             `json:"deadline"`
	RequiredConfidence float64                `json:"required_confidence"`
	Metadata           map[string]interface{} `json:"metadata"`
	Timestamp          time.Time              `json:"timestamp"`
}

// DecisionContext provides context for decision-making
type DecisionContext struct {
	Situation       string                 `json:"situation"`
	Environment     map[string]interface{} `json:"environment"`
	Goals           []*Goal                `json:"goals"`
	Resources       map[string]float64     `json:"resources"`
	Constraints     []*ContextConstraint   `json:"constraints"`
	HistoricalData  []*HistoricalDataPoint `json:"historical_data"`
	ExternalFactors map[string]interface{} `json:"external_factors"`
	Urgency         float64                `json:"urgency"`
	Complexity      float64                `json:"complexity"`
}

// DecisionOption represents a possible decision choice
type DecisionOption struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	ExpectedOutcome *ExpectedOutcome       `json:"expected_outcome"`
	Cost            float64                `json:"cost"`
	Risk            float64                `json:"risk"`
	Probability     float64                `json:"probability"`
	Dependencies    []string               `json:"dependencies"`
	Prerequisites   []string               `json:"prerequisites"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ExpectedOutcome represents the expected outcome of a decision
type ExpectedOutcome struct {
	SuccessProbability float64                `json:"success_probability"`
	ExpectedValue      float64                `json:"expected_value"`
	TimeToCompletion   time.Duration          `json:"time_to_completion"`
	ResourceUsage      map[string]float64     `json:"resource_usage"`
	SideEffects        []string               `json:"side_effects"`
	Confidence         float64                `json:"confidence"`
	Metadata           map[string]interface{} `json:"metadata"`
}

// DecisionConstraint represents a constraint on decision-making
type DecisionConstraint struct {
	Type        ConstraintType `json:"type"`
	Field       string         `json:"field"`
	Operator    string         `json:"operator"`
	Value       interface{}    `json:"value"`
	Weight      float64        `json:"weight"`
	Description string         `json:"description"`
}

// ConstraintType defines the type of constraint
type ConstraintType string

const (
	ConstraintTypeResource   ConstraintType = "resource"
	ConstraintTypeTime       ConstraintType = "time"
	ConstraintTypeRisk       ConstraintType = "risk"
	ConstraintTypeDependency ConstraintType = "dependency"
	ConstraintTypePolicy     ConstraintType = "policy"
)

// DecisionPriority defines decision priority levels
type DecisionPriority int

const (
	PriorityLow      DecisionPriority = 1
	PriorityNormal   DecisionPriority = 5
	PriorityHigh     DecisionPriority = 8
	PriorityCritical DecisionPriority = 10
)

// Goal represents a decision goal
type Goal struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Weight      float64                `json:"weight"`
	Target      float64                `json:"target"`
	Current     float64                `json:"current"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ContextConstraint represents a contextual constraint
type ContextConstraint struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Value       interface{} `json:"value"`
	Severity    float64     `json:"severity"`
}

// HistoricalDataPoint represents historical decision data
type HistoricalDataPoint struct {
	Timestamp time.Time              `json:"timestamp"`
	Context   string                 `json:"context"`
	Decision  string                 `json:"decision"`
	Outcome   float64                `json:"outcome"`
	Success   bool                   `json:"success"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// DecisionResult represents the result of decision-making
type DecisionResult struct {
	ID                 string                 `json:"id"`
	RequestID          string                 `json:"request_id"`
	SelectedOption     *DecisionOption        `json:"selected_option"`
	Confidence         float64                `json:"confidence"`
	Reasoning          string                 `json:"reasoning"`
	AlternativeOptions []*DecisionOption      `json:"alternative_options"`
	RiskAssessment     *RiskAssessmentResult  `json:"risk_assessment"`
	ExpectedOutcome    *ExpectedOutcome       `json:"expected_outcome"`
	DecisionPath       []*DecisionStep        `json:"decision_path"`
	Metadata           map[string]interface{} `json:"metadata"`
	Timestamp          time.Time              `json:"timestamp"`
	ProcessingTime     time.Duration          `json:"processing_time"`
}

// DecisionStep represents a step in the decision-making process
type DecisionStep struct {
	StepID      string                 `json:"step_id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Input       map[string]interface{} `json:"input"`
	Output      map[string]interface{} `json:"output"`
	Duration    time.Duration          `json:"duration"`
	Timestamp   time.Time              `json:"timestamp"`
}

// StrategyAdaptor adapts decision strategies based on outcomes
type StrategyAdaptor struct {
	strategies      map[string]*DecisionStrategy
	adaptationRules []*AdaptationRule
	performanceData map[string]*StrategyPerformance
	logger          *logger.Logger
	mutex           sync.RWMutex
}

// DecisionStrategy represents a decision-making strategy
type DecisionStrategy struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	Algorithm     StrategyAlgorithm      `json:"algorithm"`
	Parameters    map[string]interface{} `json:"parameters"`
	Effectiveness float64                `json:"effectiveness"`
	UsageCount    int64                  `json:"usage_count"`
	SuccessRate   float64                `json:"success_rate"`
	LastUsed      time.Time              `json:"last_used"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// StrategyAlgorithm defines the algorithm type
type StrategyAlgorithm string

const (
	AlgorithmGreedy          StrategyAlgorithm = "greedy"
	AlgorithmMinimax         StrategyAlgorithm = "minimax"
	AlgorithmMonteCarlo      StrategyAlgorithm = "monte_carlo"
	AlgorithmReinforcementQL StrategyAlgorithm = "reinforcement_ql"
	AlgorithmBayesian        StrategyAlgorithm = "bayesian"
	AlgorithmEvolutionary    StrategyAlgorithm = "evolutionary"
	AlgorithmHeuristic       StrategyAlgorithm = "heuristic"
)

// AdaptationRule defines how strategies should be adapted
type AdaptationRule struct {
	ID         string                 `json:"id"`
	Condition  string                 `json:"condition"`
	Action     string                 `json:"action"`
	Parameters map[string]interface{} `json:"parameters"`
	Weight     float64                `json:"weight"`
	Enabled    bool                   `json:"enabled"`
}

// StrategyPerformance tracks strategy performance
type StrategyPerformance struct {
	StrategyID          string    `json:"strategy_id"`
	TotalDecisions      int64     `json:"total_decisions"`
	SuccessfulDecisions int64     `json:"successful_decisions"`
	AverageConfidence   float64   `json:"average_confidence"`
	AverageOutcome      float64   `json:"average_outcome"`
	LastUpdated         time.Time `json:"last_updated"`
}

// NewAdvancedDecisionEngine creates a new advanced decision engine
func NewAdvancedDecisionEngine(config *DecisionEngineConfig, logger *logger.Logger) *AdvancedDecisionEngine {
	if config == nil {
		config = DefaultDecisionEngineConfig()
	}

	engine := &AdvancedDecisionEngine{
		id:     uuid.New().String(),
		config: config,
		logger: logger,
	}

	// Initialize components
	engine.strategyAdaptor = NewStrategyAdaptor(logger)
	engine.contextAnalyzer = NewContextAnalyzer(logger)
	engine.decisionHistory = NewDecisionHistory(config.MaxDecisionHistory, logger)
	engine.confidenceCalculator = NewConfidenceCalculator(logger)
	engine.riskAssessment = NewRiskAssessment(logger)

	if config.EnableReinforcement {
		engine.reinforcementLearner = NewReinforcementLearner(config.LearningRate, config.ExplorationRate, logger)
	}

	return engine
}

// DefaultDecisionEngineConfig returns default configuration
func DefaultDecisionEngineConfig() *DecisionEngineConfig {
	return &DecisionEngineConfig{
		EnableReinforcement:   true,
		EnableContextAnalysis: true,
		EnableRiskAssessment:  true,
		LearningRate:          0.1,
		ExplorationRate:       0.1,
		ConfidenceThreshold:   0.7,
		MaxDecisionHistory:    1000,
		DecisionTimeout:       30 * time.Second,
		EnableAdaptation:      true,
		AdaptationInterval:    time.Hour,
	}
}

// MakeDecision makes a decision based on the request
func (ade *AdvancedDecisionEngine) MakeDecision(ctx context.Context, request *DecisionRequest) (*DecisionResult, error) {
	startTime := time.Now()

	ctx, span := decisionTracer.Start(ctx, "advanced_decision_engine.make_decision",
		trace.WithAttributes(
			attribute.String("request.id", request.ID),
			attribute.String("agent.id", request.AgentID),
			attribute.Int("options.count", len(request.Options)),
		),
	)
	defer span.End()

	// Apply timeout if specified
	if request.Deadline != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, *request.Deadline)
		defer cancel()
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, ade.config.DecisionTimeout)
		defer cancel()
	}

	result := &DecisionResult{
		ID:           uuid.New().String(),
		RequestID:    request.ID,
		DecisionPath: make([]*DecisionStep, 0),
		Metadata:     make(map[string]interface{}),
		Timestamp:    time.Now(),
	}

	// Step 1: Analyze context
	if ade.config.EnableContextAnalysis {
		step := ade.recordDecisionStep("context_analysis", "Analyzing decision context")
		contextAnalysis, err := ade.contextAnalyzer.AnalyzeContext(ctx, request.Context)
		if err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("context analysis failed: %w", err)
		}
		step.Output["context_analysis"] = contextAnalysis
		result.DecisionPath = append(result.DecisionPath, step)
	}

	// Step 2: Assess risks
	if ade.config.EnableRiskAssessment {
		step := ade.recordDecisionStep("risk_assessment", "Assessing decision risks")
		riskResult, err := ade.riskAssessment.AssessRisks(ctx, request)
		if err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("risk assessment failed: %w", err)
		}
		result.RiskAssessment = riskResult
		step.Output["risk_assessment"] = riskResult
		result.DecisionPath = append(result.DecisionPath, step)
	}

	// Step 3: Apply constraints and filter options
	step := ade.recordDecisionStep("constraint_filtering", "Filtering options by constraints")
	validOptions, err := ade.filterOptionsByConstraints(request.Options, request.Constraints)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("constraint filtering failed: %w", err)
	}
	step.Output["valid_options"] = len(validOptions)
	result.DecisionPath = append(result.DecisionPath, step)

	if len(validOptions) == 0 {
		return nil, fmt.Errorf("no valid options after constraint filtering")
	}

	// Step 4: Select strategy
	step = ade.recordDecisionStep("strategy_selection", "Selecting decision strategy")
	strategy := ade.strategyAdaptor.SelectStrategy(ctx, request)
	step.Output["selected_strategy"] = strategy.Name
	result.DecisionPath = append(result.DecisionPath, step)

	// Step 5: Evaluate options using selected strategy
	step = ade.recordDecisionStep("option_evaluation", "Evaluating options using strategy")
	evaluatedOptions, err := ade.evaluateOptions(ctx, validOptions, strategy, request)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("option evaluation failed: %w", err)
	}
	step.Output["evaluated_options"] = len(evaluatedOptions)
	result.DecisionPath = append(result.DecisionPath, step)

	// Step 6: Select best option
	step = ade.recordDecisionStep("option_selection", "Selecting best option")
	selectedOption, alternatives := ade.selectBestOption(evaluatedOptions)
	result.SelectedOption = selectedOption
	result.AlternativeOptions = alternatives
	step.Output["selected_option"] = selectedOption.ID
	result.DecisionPath = append(result.DecisionPath, step)

	// Step 7: Calculate confidence
	step = ade.recordDecisionStep("confidence_calculation", "Calculating decision confidence")
	confidence := ade.confidenceCalculator.CalculateConfidence(ctx, selectedOption, alternatives, request)
	result.Confidence = confidence
	step.Output["confidence"] = confidence
	result.DecisionPath = append(result.DecisionPath, step)

	// Step 8: Generate reasoning
	result.Reasoning = ade.generateReasoning(selectedOption, strategy, confidence, request)

	// Step 9: Record decision in history
	ade.decisionHistory.RecordDecision(request, result)

	// Step 10: Update strategy performance
	ade.strategyAdaptor.UpdateStrategyUsage(strategy.ID)

	result.ProcessingTime = time.Since(startTime)

	ade.logger.Info("Decision made",
		"request_id", request.ID,
		"selected_option", selectedOption.ID,
		"confidence", confidence,
		"processing_time", result.ProcessingTime)

	return result, nil
}

// recordDecisionStep creates and records a decision step
func (ade *AdvancedDecisionEngine) recordDecisionStep(stepType, description string) *DecisionStep {
	return &DecisionStep{
		StepID:      uuid.New().String(),
		Type:        stepType,
		Description: description,
		Input:       make(map[string]interface{}),
		Output:      make(map[string]interface{}),
		Timestamp:   time.Now(),
	}
}

// filterOptionsByConstraints filters options based on constraints
func (ade *AdvancedDecisionEngine) filterOptionsByConstraints(options []*DecisionOption, constraints []*DecisionConstraint) ([]*DecisionOption, error) {
	var validOptions []*DecisionOption

	for _, option := range options {
		valid := true
		for _, constraint := range constraints {
			if !ade.evaluateConstraint(option, constraint) {
				valid = false
				break
			}
		}
		if valid {
			validOptions = append(validOptions, option)
		}
	}

	return validOptions, nil
}

// evaluateConstraint evaluates a constraint against an option
func (ade *AdvancedDecisionEngine) evaluateConstraint(option *DecisionOption, constraint *DecisionConstraint) bool {
	// Simple constraint evaluation - in production, implement comprehensive logic
	switch constraint.Type {
	case ConstraintTypeResource:
		if constraint.Field == "cost" && constraint.Operator == "<=" {
			if maxCost, ok := constraint.Value.(float64); ok {
				return option.Cost <= maxCost
			}
		}
	case ConstraintTypeRisk:
		if constraint.Field == "risk" && constraint.Operator == "<=" {
			if maxRisk, ok := constraint.Value.(float64); ok {
				return option.Risk <= maxRisk
			}
		}
	}
	return true
}

// evaluateOptions evaluates options using the selected strategy
func (ade *AdvancedDecisionEngine) evaluateOptions(ctx context.Context, options []*DecisionOption, strategy *DecisionStrategy, request *DecisionRequest) ([]*DecisionOption, error) {
	// Apply strategy-specific evaluation
	switch strategy.Algorithm {
	case AlgorithmGreedy:
		return ade.evaluateGreedy(options, request)
	case AlgorithmBayesian:
		return ade.evaluateBayesian(options, request)
	default:
		return ade.evaluateDefault(options, request)
	}
}

// evaluateGreedy implements greedy evaluation
func (ade *AdvancedDecisionEngine) evaluateGreedy(options []*DecisionOption, request *DecisionRequest) ([]*DecisionOption, error) {
	// Simple greedy evaluation based on expected value
	for _, option := range options {
		if option.ExpectedOutcome != nil {
			// Calculate utility score
			utility := option.ExpectedOutcome.ExpectedValue - option.Cost - (option.Risk * 0.5)
			option.Metadata["utility_score"] = utility
		}
	}
	return options, nil
}

// evaluateBayesian implements Bayesian evaluation
func (ade *AdvancedDecisionEngine) evaluateBayesian(options []*DecisionOption, request *DecisionRequest) ([]*DecisionOption, error) {
	// Simple Bayesian evaluation
	for _, option := range options {
		if option.ExpectedOutcome != nil {
			// Calculate Bayesian score
			prior := 0.5 // Default prior
			likelihood := option.ExpectedOutcome.SuccessProbability
			evidence := 1.0 // Simplified
			posterior := (likelihood * prior) / evidence
			option.Metadata["bayesian_score"] = posterior
		}
	}
	return options, nil
}

// evaluateDefault implements default evaluation
func (ade *AdvancedDecisionEngine) evaluateDefault(options []*DecisionOption, request *DecisionRequest) ([]*DecisionOption, error) {
	// Default evaluation based on multiple criteria
	for _, option := range options {
		score := 0.0
		if option.ExpectedOutcome != nil {
			score += option.ExpectedOutcome.ExpectedValue * 0.4
			score += option.ExpectedOutcome.SuccessProbability * 0.3
			score -= option.Cost * 0.2
			score -= option.Risk * 0.1
		}
		option.Metadata["default_score"] = score
	}
	return options, nil
}

// selectBestOption selects the best option from evaluated options
func (ade *AdvancedDecisionEngine) selectBestOption(options []*DecisionOption) (*DecisionOption, []*DecisionOption) {
	if len(options) == 0 {
		return nil, nil
	}

	var bestOption *DecisionOption
	var bestScore float64 = math.Inf(-1)

	// Find option with highest score
	for _, option := range options {
		var score float64
		if utilityScore, exists := option.Metadata["utility_score"]; exists {
			if s, ok := utilityScore.(float64); ok {
				score = s
			}
		} else if bayesianScore, exists := option.Metadata["bayesian_score"]; exists {
			if s, ok := bayesianScore.(float64); ok {
				score = s
			}
		} else if defaultScore, exists := option.Metadata["default_score"]; exists {
			if s, ok := defaultScore.(float64); ok {
				score = s
			}
		}

		if score > bestScore {
			bestScore = score
			bestOption = option
		}
	}

	// Prepare alternatives (excluding the best option)
	var alternatives []*DecisionOption
	for _, option := range options {
		if option.ID != bestOption.ID {
			alternatives = append(alternatives, option)
		}
	}

	return bestOption, alternatives
}

// generateReasoning generates reasoning for the decision
func (ade *AdvancedDecisionEngine) generateReasoning(selectedOption *DecisionOption, strategy *DecisionStrategy, confidence float64, request *DecisionRequest) string {
	reasoning := fmt.Sprintf("Selected option '%s' using %s strategy with %.2f confidence. ",
		selectedOption.Name, strategy.Name, confidence)

	if selectedOption.ExpectedOutcome != nil {
		reasoning += fmt.Sprintf("Expected value: %.2f, Success probability: %.2f, Cost: %.2f, Risk: %.2f.",
			selectedOption.ExpectedOutcome.ExpectedValue,
			selectedOption.ExpectedOutcome.SuccessProbability,
			selectedOption.Cost,
			selectedOption.Risk)
	}

	return reasoning
}

// LearnFromOutcome learns from decision outcomes for future improvement
func (ade *AdvancedDecisionEngine) LearnFromOutcome(ctx context.Context, decisionID string, outcome *DecisionOutcome) error {
	ctx, span := decisionTracer.Start(ctx, "advanced_decision_engine.learn_from_outcome",
		trace.WithAttributes(
			attribute.String("decision.id", decisionID),
			attribute.Float64("outcome.value", outcome.ActualValue),
			attribute.Bool("outcome.success", outcome.Success),
		),
	)
	defer span.End()

	// Update decision history with outcome
	if err := ade.decisionHistory.UpdateOutcome(decisionID, outcome); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to update decision history: %w", err)
	}

	// Update reinforcement learning if enabled
	if ade.config.EnableReinforcement && ade.reinforcementLearner != nil {
		if err := ade.reinforcementLearner.UpdateFromOutcome(ctx, decisionID, outcome); err != nil {
			ade.logger.Error("Failed to update reinforcement learning", "error", err)
		}
	}

	// Update strategy performance
	decision, err := ade.decisionHistory.GetDecision(decisionID)
	if err == nil && decision.Metadata["strategy_id"] != nil {
		if strategyID, ok := decision.Metadata["strategy_id"].(string); ok {
			ade.strategyAdaptor.UpdateStrategyPerformance(strategyID, outcome)
		}
	}

	ade.logger.Info("Learned from decision outcome",
		"decision_id", decisionID,
		"success", outcome.Success,
		"actual_value", outcome.ActualValue)

	return nil
}

// GetDecisionHistory returns decision history
func (ade *AdvancedDecisionEngine) GetDecisionHistory() *DecisionHistory {
	return ade.decisionHistory
}

// GetStrategyAdaptor returns the strategy adaptor
func (ade *AdvancedDecisionEngine) GetStrategyAdaptor() *StrategyAdaptor {
	return ade.strategyAdaptor
}

// DecisionOutcome represents the actual outcome of a decision
type DecisionOutcome struct {
	DecisionID     string                 `json:"decision_id"`
	ActualValue    float64                `json:"actual_value"`
	Success        bool                   `json:"success"`
	CompletionTime time.Duration          `json:"completion_time"`
	ResourceUsage  map[string]float64     `json:"resource_usage"`
	SideEffects    []string               `json:"side_effects"`
	Feedback       string                 `json:"feedback"`
	Metadata       map[string]interface{} `json:"metadata"`
	Timestamp      time.Time              `json:"timestamp"`
}
