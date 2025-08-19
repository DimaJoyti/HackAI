package ai

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var decisionEngineTracer = otel.Tracer("hackai/ai/decision_engine")

// MLDecisionEngine implements machine learning-based decision making for agents
type MLDecisionEngine struct {
	id               string
	logger           *logger.Logger
	tracer           trace.Tracer
	featureExtractor FeatureExtractor
	strategySelector StrategySelector
	learningEnabled  bool
	decisionHistory  []DecisionRecord
	maxHistorySize   int
}

// FeatureExtractor extracts features from agent input and context
type FeatureExtractor interface {
	ExtractFeatures(ctx context.Context, input AgentInput, history []AgentStep) (map[string]float64, error)
}

// StrategySelector selects the best strategy based on features
type StrategySelector interface {
	SelectStrategy(ctx context.Context, features map[string]float64, availableTools []Tool) (*StrategyRecommendation, error)
	UpdateModel(ctx context.Context, examples []TrainingExample) error
}

// StrategyRecommendation represents a recommended strategy
type StrategyRecommendation struct {
	Action       AgentAction   `json:"action"`
	Confidence   float64       `json:"confidence"`
	Reasoning    string        `json:"reasoning"`
	Alternatives []AgentAction `json:"alternatives"`
}

// DecisionRecord tracks decision-making history for learning
type DecisionRecord struct {
	Features   map[string]float64     `json:"features"`
	Action     AgentAction            `json:"action"`
	Outcome    DecisionOutcome        `json:"outcome"`
	Timestamp  time.Time              `json:"timestamp"`
	Confidence float64                `json:"confidence"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// DecisionOutcome represents the outcome of a decision
type DecisionOutcome struct {
	Success  bool    `json:"success"`
	Reward   float64 `json:"reward"`
	Error    error   `json:"error,omitempty"`
	Feedback string  `json:"feedback"`
}

// TrainingExample represents a training example for the ML model
type TrainingExample struct {
	Features map[string]float64 `json:"features"`
	Action   AgentAction        `json:"action"`
	Reward   float64            `json:"reward"`
}

// NewMLDecisionEngine creates a new ML-based decision engine
func NewMLDecisionEngine(id string, logger *logger.Logger) *MLDecisionEngine {
	return &MLDecisionEngine{
		id:               id,
		logger:           logger,
		tracer:           decisionEngineTracer,
		featureExtractor: NewBasicFeatureExtractor(),
		strategySelector: NewHeuristicStrategySelector(),
		learningEnabled:  true,
		decisionHistory:  make([]DecisionRecord, 0),
		maxHistorySize:   1000,
	}
}

// DecideNextAction decides the next action for an agent
func (e *MLDecisionEngine) DecideNextAction(ctx context.Context, input AgentInput, history []AgentStep) (AgentAction, error) {
	ctx, span := e.tracer.Start(ctx, "ml_decision_engine.decide_next_action",
		trace.WithAttributes(
			attribute.String("engine.id", e.id),
			attribute.String("query", input.Query),
			attribute.Int("history.length", len(history)),
		),
	)
	defer span.End()

	// Extract features from input and history
	features, err := e.featureExtractor.ExtractFeatures(ctx, input, history)
	if err != nil {
		span.RecordError(err)
		return AgentAction{}, fmt.Errorf("feature extraction failed: %w", err)
	}

	// Get available tools (this would come from the agent's tool registry)
	availableTools := make([]Tool, 0) // Placeholder

	// Select strategy
	recommendation, err := e.strategySelector.SelectStrategy(ctx, features, availableTools)
	if err != nil {
		span.RecordError(err)
		return AgentAction{}, fmt.Errorf("strategy selection failed: %w", err)
	}

	// Record decision for learning
	if e.learningEnabled {
		record := DecisionRecord{
			Features:   features,
			Action:     recommendation.Action,
			Timestamp:  time.Now(),
			Confidence: recommendation.Confidence,
			Metadata:   make(map[string]interface{}),
		}
		e.addDecisionRecord(record)
	}

	span.SetAttributes(
		attribute.String("action.type", recommendation.Action.Type),
		attribute.Float64("confidence", recommendation.Confidence),
	)

	if e.logger != nil {
		e.logger.Debug("Decision made",
			"engine_id", e.id,
			"action_type", recommendation.Action.Type,
			"confidence", recommendation.Confidence,
			"reasoning", recommendation.Reasoning)
	}

	return recommendation.Action, nil
}

// addDecisionRecord adds a decision record to the history
func (e *MLDecisionEngine) addDecisionRecord(record DecisionRecord) {
	e.decisionHistory = append(e.decisionHistory, record)

	// Maintain history size limit
	if len(e.decisionHistory) > e.maxHistorySize {
		e.decisionHistory = e.decisionHistory[1:]
	}
}

// BasicFeatureExtractor implements a basic feature extraction strategy
type BasicFeatureExtractor struct{}

// NewBasicFeatureExtractor creates a new basic feature extractor
func NewBasicFeatureExtractor() *BasicFeatureExtractor {
	return &BasicFeatureExtractor{}
}

// ExtractFeatures extracts basic features from agent input and history
func (e *BasicFeatureExtractor) ExtractFeatures(ctx context.Context, input AgentInput, history []AgentStep) (map[string]float64, error) {
	features := make(map[string]float64)

	// Query-based features
	query := strings.ToLower(input.Query)
	features["query_length"] = float64(len(query))
	features["query_word_count"] = float64(len(strings.Fields(query)))

	// Security-related keywords
	securityKeywords := []string{"attack", "injection", "exploit", "vulnerability", "security", "hack", "penetration"}
	securityScore := 0.0
	for _, keyword := range securityKeywords {
		if strings.Contains(query, keyword) {
			securityScore += 1.0
		}
	}
	features["security_score"] = securityScore / float64(len(securityKeywords))

	// History-based features
	features["history_length"] = float64(len(history))

	if len(history) > 0 {
		// Recent success rate
		recentSteps := 5
		if len(history) < recentSteps {
			recentSteps = len(history)
		}

		successCount := 0
		for i := len(history) - recentSteps; i < len(history); i++ {
			// Check success field
			if history[i].Success {
				successCount++
			}
		}
		features["recent_success_rate"] = float64(successCount) / float64(recentSteps)

		// Tool usage diversity
		toolsUsed := make(map[string]bool)
		for _, step := range history {
			if step.Tool != "" {
				toolsUsed[step.Tool] = true
			}
		}
		features["tool_diversity"] = float64(len(toolsUsed))
	} else {
		features["recent_success_rate"] = 0.5 // Neutral starting point
		features["tool_diversity"] = 0.0
	}

	// Context-based features
	if input.Context != nil {
		features["context_size"] = float64(len(input.Context))

		// Check for specific context indicators
		if _, hasTarget := input.Context["target"]; hasTarget {
			features["has_target"] = 1.0
		} else {
			features["has_target"] = 0.0
		}
	}

	// Max steps constraint
	features["max_steps"] = float64(input.MaxSteps)
	if input.MaxSteps > 0 {
		features["steps_remaining"] = float64(input.MaxSteps - len(history))
	} else {
		features["steps_remaining"] = 10.0 // Default assumption
	}

	return features, nil
}

// HeuristicStrategySelector implements a heuristic-based strategy selection
type HeuristicStrategySelector struct {
	strategies []StrategyTemplate
}

// StrategyTemplate defines a strategy template with conditions
type StrategyTemplate struct {
	ID          string                                        `json:"id"`
	Name        string                                        `json:"name"`
	Description string                                        `json:"description"`
	Condition   func(features map[string]float64) bool        `json:"-"`
	ActionGen   func(features map[string]float64) AgentAction `json:"-"`
	Priority    int                                           `json:"priority"`
	Confidence  float64                                       `json:"confidence"`
}

// NewHeuristicStrategySelector creates a new heuristic strategy selector
func NewHeuristicStrategySelector() *HeuristicStrategySelector {
	selector := &HeuristicStrategySelector{
		strategies: make([]StrategyTemplate, 0),
	}

	// Initialize default strategies
	selector.initializeDefaultStrategies()

	return selector
}

// initializeDefaultStrategies initializes default strategy templates
func (s *HeuristicStrategySelector) initializeDefaultStrategies() {
	// High security score strategy
	s.strategies = append(s.strategies, StrategyTemplate{
		ID:          "security_analysis",
		Name:        "Security Analysis Strategy",
		Description: "Use security-focused tools for security-related queries",
		Priority:    10,
		Confidence:  0.8,
		Condition: func(features map[string]float64) bool {
			return features["security_score"] > 0.3
		},
		ActionGen: func(features map[string]float64) AgentAction {
			return AgentAction{
				Type:     "tool_use",
				ToolName: "security_scanner",
				ToolInput: map[string]interface{}{
					"mode": "comprehensive",
				},
				Reasoning: "High security score detected, using security analysis tools",
			}
		},
	})

	// Low success rate strategy
	s.strategies = append(s.strategies, StrategyTemplate{
		ID:          "recovery_strategy",
		Name:        "Recovery Strategy",
		Description: "Switch to simpler tools when success rate is low",
		Priority:    8,
		Confidence:  0.7,
		Condition: func(features map[string]float64) bool {
			return features["recent_success_rate"] < 0.3 && features["history_length"] > 2
		},
		ActionGen: func(features map[string]float64) AgentAction {
			return AgentAction{
				Type:     "tool_use",
				ToolName: "security_scanner",
				ToolInput: map[string]interface{}{
					"target":    "localhost",
					"scan_type": "quick",
				},
				Reasoning: "Low success rate detected, using basic security scan",
			}
		},
	})

	// Default strategy
	s.strategies = append(s.strategies, StrategyTemplate{
		ID:          "default_analysis",
		Name:        "Default Analysis Strategy",
		Description: "Default strategy for general queries",
		Priority:    1,
		Confidence:  0.5,
		Condition: func(features map[string]float64) bool {
			return true // Always applicable
		},
		ActionGen: func(features map[string]float64) AgentAction {
			return AgentAction{
				Type:     "tool_use",
				ToolName: "security_scanner",
				ToolInput: map[string]interface{}{
					"target":    "localhost",
					"scan_type": "quick",
				},
				Reasoning: "Using default security analysis strategy",
			}
		},
	})

	// Sort strategies by priority (higher first)
	sort.Slice(s.strategies, func(i, j int) bool {
		return s.strategies[i].Priority > s.strategies[j].Priority
	})
}

// SelectStrategy selects the best strategy based on features
func (s *HeuristicStrategySelector) SelectStrategy(ctx context.Context, features map[string]float64, availableTools []Tool) (*StrategyRecommendation, error) {
	// Find the first matching strategy
	for _, strategy := range s.strategies {
		if strategy.Condition(features) {
			action := strategy.ActionGen(features)

			return &StrategyRecommendation{
				Action:       action,
				Confidence:   strategy.Confidence,
				Reasoning:    strategy.Description,
				Alternatives: []AgentAction{}, // Could be populated with other matching strategies
			}, nil
		}
	}

	// Fallback (should not happen with default strategy)
	return &StrategyRecommendation{
		Action: AgentAction{
			Type:      "respond",
			Response:  "I need more information to proceed.",
			Reasoning: "No suitable strategy found",
		},
		Confidence: 0.1,
		Reasoning:  "Fallback strategy - no conditions matched",
	}, nil
}

// UpdateModel updates the strategy selection model (placeholder for ML implementation)
func (s *HeuristicStrategySelector) UpdateModel(ctx context.Context, examples []TrainingExample) error {
	// In a real ML implementation, this would update model weights
	// For now, this is a placeholder
	return nil
}
