package react

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// ReasoningEngine handles the reasoning phase of the ReAct cycle
type ReasoningEngine struct {
	logger            *logger.Logger
	reasoningPatterns map[string]ReasoningPattern
	contextAnalyzer   *ContextAnalyzer
}

// ReasoningPattern defines different reasoning approaches
type ReasoningPattern struct {
	Name        string
	Description string
	Keywords    []string
	Strategy    ReasoningStrategy
}

// ReasoningStrategy defines how to approach reasoning for different types of queries
type ReasoningStrategy string

const (
	StrategyAnalytical     ReasoningStrategy = "analytical"
	StrategyCreative       ReasoningStrategy = "creative"
	StrategyProblemSolving ReasoningStrategy = "problem_solving"
	StrategyInvestigative  ReasoningStrategy = "investigative"
	StrategyComparative    ReasoningStrategy = "comparative"
)

// ContextAnalyzer analyzes context to improve reasoning
type ContextAnalyzer struct {
	logger *logger.Logger
}

// NewReasoningEngine creates a new reasoning engine
func NewReasoningEngine(logger *logger.Logger) *ReasoningEngine {
	re := &ReasoningEngine{
		logger:            logger,
		reasoningPatterns: make(map[string]ReasoningPattern),
		contextAnalyzer:   &ContextAnalyzer{logger: logger},
	}

	// Initialize reasoning patterns
	re.initializeReasoningPatterns()

	return re
}

// initializeReasoningPatterns sets up different reasoning patterns
func (re *ReasoningEngine) initializeReasoningPatterns() {
	patterns := []ReasoningPattern{
		{
			Name:        "security_analysis",
			Description: "Analyze security vulnerabilities and threats",
			Keywords:    []string{"security", "vulnerability", "threat", "attack", "exploit", "CVE"},
			Strategy:    StrategyInvestigative,
		},
		{
			Name:        "problem_solving",
			Description: "Break down and solve complex problems",
			Keywords:    []string{"problem", "solve", "fix", "issue", "error", "debug"},
			Strategy:    StrategyProblemSolving,
		},
		{
			Name:        "data_analysis",
			Description: "Analyze and interpret data",
			Keywords:    []string{"analyze", "data", "statistics", "metrics", "report", "trends"},
			Strategy:    StrategyAnalytical,
		},
		{
			Name:        "comparison",
			Description: "Compare different options or solutions",
			Keywords:    []string{"compare", "versus", "difference", "better", "best", "choose"},
			Strategy:    StrategyComparative,
		},
		{
			Name:        "creative_thinking",
			Description: "Generate creative solutions and ideas",
			Keywords:    []string{"create", "design", "generate", "brainstorm", "innovative", "new"},
			Strategy:    StrategyCreative,
		},
	}

	for _, pattern := range patterns {
		re.reasoningPatterns[pattern.Name] = pattern
	}
}

// Think performs reasoning based on the current context
func (re *ReasoningEngine) Think(ctx context.Context, input AgentInput, previousThoughts []Thought, previousActions []Action) (Thought, error) {
	step := len(previousThoughts) + 1

	// Analyze the query to determine reasoning approach
	pattern := re.identifyReasoningPattern(input.Query)

	// Analyze context from previous thoughts and actions
	contextInsights := re.contextAnalyzer.AnalyzeContext(previousThoughts, previousActions)

	// Generate reasoning content based on the step and context
	var content string
	var reasoning string
	var confidence float64

	if step == 1 {
		// Initial reasoning
		content, reasoning, confidence = re.generateInitialReasoning(input, pattern)
	} else {
		// Subsequent reasoning based on previous actions
		content, reasoning, confidence = re.generateSubsequentReasoning(input, previousThoughts, previousActions, pattern, contextInsights)
	}

	thought := Thought{
		Step:       step,
		Content:    content,
		Reasoning:  reasoning,
		Confidence: confidence,
		Timestamp:  time.Now(),
		Metadata: map[string]interface{}{
			"pattern":          pattern.Name,
			"strategy":         pattern.Strategy,
			"context_insights": contextInsights,
		},
	}

	re.logger.Debug("Reasoning step completed",
		"step", step,
		"pattern", pattern.Name,
		"confidence", confidence,
		"content_length", len(content))

	return thought, nil
}

// identifyReasoningPattern identifies the most appropriate reasoning pattern for the query
func (re *ReasoningEngine) identifyReasoningPattern(query string) ReasoningPattern {
	queryLower := strings.ToLower(query)

	// Score each pattern based on keyword matches
	bestPattern := re.reasoningPatterns["problem_solving"] // Default
	bestScore := 0

	for _, pattern := range re.reasoningPatterns {
		score := 0
		for _, keyword := range pattern.Keywords {
			if strings.Contains(queryLower, keyword) {
				score++
			}
		}

		if score > bestScore {
			bestScore = score
			bestPattern = pattern
		}
	}

	return bestPattern
}

// generateInitialReasoning generates the first reasoning step
func (re *ReasoningEngine) generateInitialReasoning(input AgentInput, pattern ReasoningPattern) (string, string, float64) {
	var content, reasoning string
	var confidence float64

	switch pattern.Strategy {
	case StrategyInvestigative:
		content = fmt.Sprintf("I need to investigate: '%s'. Let me break this down systematically and identify what information I need to gather.", input.Query)
		reasoning = "Starting with an investigative approach to gather facts and evidence"
		confidence = 0.8

	case StrategyProblemSolving:
		content = fmt.Sprintf("I need to solve: '%s'. Let me analyze the problem, identify potential causes, and determine the best approach.", input.Query)
		reasoning = "Using problem-solving methodology to break down the issue"
		confidence = 0.8

	case StrategyAnalytical:
		content = fmt.Sprintf("I need to analyze: '%s'. Let me examine the data systematically and identify patterns or insights.", input.Query)
		reasoning = "Applying analytical thinking to examine data and metrics"
		confidence = 0.8

	case StrategyComparative:
		content = fmt.Sprintf("I need to compare: '%s'. Let me identify the key factors and evaluate different options.", input.Query)
		reasoning = "Using comparative analysis to evaluate options"
		confidence = 0.8

	case StrategyCreative:
		content = fmt.Sprintf("I need to create: '%s'. Let me think creatively and explore innovative approaches.", input.Query)
		reasoning = "Applying creative thinking to generate new ideas"
		confidence = 0.7

	default:
		content = fmt.Sprintf("I need to address: '%s'. Let me think through this step by step.", input.Query)
		reasoning = "Using general reasoning approach"
		confidence = 0.7
	}

	return content, reasoning, confidence
}

// generateSubsequentReasoning generates reasoning for subsequent steps
func (re *ReasoningEngine) generateSubsequentReasoning(input AgentInput, previousThoughts []Thought, previousActions []Action, pattern ReasoningPattern, insights ContextInsights) (string, string, float64) {
	var content string
	var reasoning string
	var confidence float64

	// Analyze the last action's result
	if len(previousActions) > 0 {
		lastAction := previousActions[len(previousActions)-1]

		if lastAction.Success {
			content, reasoning, confidence = re.reasonAboutSuccessfulAction(lastAction, pattern, insights)
		} else {
			content, reasoning, confidence = re.reasonAboutFailedAction(lastAction, pattern, insights)
		}
	} else {
		// No actions yet, need to plan first action
		content = "I haven't taken any actions yet. Let me identify what tools or information I need to proceed."
		reasoning = "Planning first action based on initial analysis"
		confidence = 0.7
	}

	// Adjust confidence based on context insights
	if insights.ProgressScore > 0.7 {
		confidence += 0.1
	} else if insights.ProgressScore < 0.3 {
		confidence -= 0.1
	}

	// Ensure confidence stays within bounds
	if confidence > 1.0 {
		confidence = 1.0
	} else if confidence < 0.1 {
		confidence = 0.1
	}

	return content, reasoning, confidence
}

// reasonAboutSuccessfulAction generates reasoning after a successful action
func (re *ReasoningEngine) reasonAboutSuccessfulAction(action Action, pattern ReasoningPattern, insights ContextInsights) (string, string, float64) {
	var content, reasoning string
	confidence := 0.8

	switch pattern.Strategy {
	case StrategyInvestigative:
		content = fmt.Sprintf("The %s tool provided useful information: %v. Let me analyze these findings and determine what additional investigation is needed.", action.Tool, action.Output)
		reasoning = "Analyzing investigation results to plan next steps"

	case StrategyProblemSolving:
		content = fmt.Sprintf("The %s tool execution was successful. Based on the results, I can see progress toward solving the problem. Let me evaluate if I need more information or if I can provide a solution.", action.Tool)
		reasoning = "Evaluating problem-solving progress"

	case StrategyAnalytical:
		content = fmt.Sprintf("The data from %s shows: %v. Let me analyze these results and see if I need additional data points for a complete analysis.", action.Tool, action.Output)
		reasoning = "Analyzing data results for completeness"

	default:
		content = fmt.Sprintf("The %s tool was successful. Let me review the results and determine the next best step.", action.Tool)
		reasoning = "Reviewing successful action results"
	}

	// Increase confidence if we're making good progress
	if insights.ProgressScore > 0.6 {
		confidence = 0.9
	}

	return content, reasoning, confidence
}

// reasonAboutFailedAction generates reasoning after a failed action
func (re *ReasoningEngine) reasonAboutFailedAction(action Action, pattern ReasoningPattern, insights ContextInsights) (string, string, float64) {
	var content, reasoning string
	confidence := 0.6

	content = fmt.Sprintf("The %s tool failed with error: %s. Let me think of an alternative approach or different tool to achieve the same goal.", action.Tool, action.Error)
	reasoning = "Adapting strategy after tool failure"

	// Decrease confidence after failures
	if insights.ErrorRate > 0.5 {
		confidence = 0.4
	}

	return content, reasoning, confidence
}

// ContextInsights provides insights about the current context
type ContextInsights struct {
	ProgressScore     float64            `json:"progress_score"`
	ErrorRate         float64            `json:"error_rate"`
	ToolEffectiveness map[string]float64 `json:"tool_effectiveness"`
	PatternMatches    []string           `json:"pattern_matches"`
	Recommendations   []string           `json:"recommendations"`
}

// AnalyzeContext analyzes the context from previous thoughts and actions
func (ca *ContextAnalyzer) AnalyzeContext(thoughts []Thought, actions []Action) ContextInsights {
	insights := ContextInsights{
		ToolEffectiveness: make(map[string]float64),
		PatternMatches:    make([]string, 0),
		Recommendations:   make([]string, 0),
	}

	if len(actions) == 0 {
		insights.ProgressScore = 0.0
		insights.ErrorRate = 0.0
		return insights
	}

	// Calculate error rate
	successCount := 0
	for _, action := range actions {
		if action.Success {
			successCount++
		}
	}
	insights.ErrorRate = 1.0 - (float64(successCount) / float64(len(actions)))

	// Calculate progress score based on confidence trends
	if len(thoughts) > 0 {
		totalConfidence := 0.0
		for _, thought := range thoughts {
			totalConfidence += thought.Confidence
		}
		insights.ProgressScore = totalConfidence / float64(len(thoughts))
	}

	// Analyze tool effectiveness
	toolUsage := make(map[string]int)
	toolSuccess := make(map[string]int)

	for _, action := range actions {
		toolUsage[action.Tool]++
		if action.Success {
			toolSuccess[action.Tool]++
		}
	}

	for tool, usage := range toolUsage {
		success := toolSuccess[tool]
		insights.ToolEffectiveness[tool] = float64(success) / float64(usage)
	}

	// Generate recommendations
	if insights.ErrorRate > 0.5 {
		insights.Recommendations = append(insights.Recommendations, "Consider trying different tools or approaches")
	}

	if insights.ProgressScore < 0.5 {
		insights.Recommendations = append(insights.Recommendations, "Break down the problem into smaller steps")
	}

	return insights
}
