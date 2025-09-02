package react

import (
	"context"
	"fmt"
	"strings"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// SelfReflector handles self-reflection in the ReAct cycle
type SelfReflector struct {
	logger           *logger.Logger
	reflectionRules  []ReflectionRule
	progressAnalyzer *ProgressAnalyzer
	qualityAssessor  *QualityAssessor
}

// ReflectionRule defines rules for self-reflection
type ReflectionRule struct {
	Name        string
	Description string
	Condition   func(thought Thought, action *Action, output *AgentOutput) bool
	Evaluate    func(thought Thought, action *Action, output *AgentOutput) (bool, string, float64)
	Priority    int
}

// ProgressAnalyzer analyzes progress toward the goal
type ProgressAnalyzer struct {
	logger *logger.Logger
}

// QualityAssessor assesses the quality of thoughts and actions
type QualityAssessor struct {
	logger *logger.Logger
}

// ReflectionResult holds the result of self-reflection
type ReflectionResult struct {
	ShouldContinue bool     `json:"should_continue"`
	FinalAnswer    string   `json:"final_answer"`
	Confidence     float64  `json:"confidence"`
	Reasoning      string   `json:"reasoning"`
	Improvements   []string `json:"improvements"`
}

// NewSelfReflector creates a new self-reflector
func NewSelfReflector(logger *logger.Logger) *SelfReflector {
	sr := &SelfReflector{
		logger:           logger,
		reflectionRules:  make([]ReflectionRule, 0),
		progressAnalyzer: &ProgressAnalyzer{logger: logger},
		qualityAssessor:  &QualityAssessor{logger: logger},
	}

	// Initialize reflection rules
	sr.initializeReflectionRules()

	return sr
}

// initializeReflectionRules sets up the reflection rules
func (sr *SelfReflector) initializeReflectionRules() {
	rules := []ReflectionRule{
		{
			Name:        "success_completion_rule",
			Description: "Stop if action was successful and provides complete answer",
			Priority:    1,
			Condition: func(thought Thought, action *Action, output *AgentOutput) bool {
				return action != nil && action.Success && thought.Confidence > 0.8
			},
			Evaluate: func(thought Thought, action *Action, output *AgentOutput) (bool, string, float64) {
				if sr.isCompleteAnswer(action.Output) {
					return false, fmt.Sprintf("Task completed successfully. %v", action.Output), 0.9
				}
				return true, "", 0.0
			},
		},
		{
			Name:        "error_recovery_rule",
			Description: "Continue if action failed but we can try alternatives",
			Priority:    2,
			Condition: func(thought Thought, action *Action, output *AgentOutput) bool {
				return action != nil && !action.Success
			},
			Evaluate: func(thought Thought, action *Action, output *AgentOutput) (bool, string, float64) {
				if len(output.Actions) >= 3 && sr.calculateErrorRate(output.Actions) > 0.6 {
					return false, "Multiple tool failures suggest the task cannot be completed with available tools", 0.3
				}
				return true, "", 0.0
			},
		},
		{
			Name:        "progress_assessment_rule",
			Description: "Evaluate overall progress and decide continuation",
			Priority:    3,
			Condition: func(thought Thought, action *Action, output *AgentOutput) bool {
				return len(output.Actions) >= 2
			},
			Evaluate: func(thought Thought, action *Action, output *AgentOutput) (bool, string, float64) {
				progress := sr.progressAnalyzer.AnalyzeProgress(output.Thoughts, output.Actions)
				if progress.CompletionScore > 0.8 {
					return false, progress.Summary, progress.OverallConfidence
				}
				return true, "", 0.0
			},
		},
		{
			Name:        "iteration_limit_rule",
			Description: "Stop if approaching iteration limit",
			Priority:    4,
			Condition: func(thought Thought, action *Action, output *AgentOutput) bool {
				return len(output.Thoughts) >= 8 // Close to typical max of 10
			},
			Evaluate: func(thought Thought, action *Action, output *AgentOutput) (bool, string, float64) {
				summary := sr.generateSummary(output.Thoughts, output.Actions)
				return false, summary, 0.7
			},
		},
	}

	sr.reflectionRules = rules
}

// Reflect performs self-reflection and decides whether to continue
func (sr *SelfReflector) Reflect(ctx context.Context, thought Thought, action *Action, output *AgentOutput) (bool, string, float64) {
	sr.logger.Debug("Performing self-reflection",
		"step", thought.Step,
		"action_success", action != nil && action.Success,
		"total_actions", len(output.Actions))

	// Apply reflection rules in priority order
	for _, rule := range sr.reflectionRules {
		if rule.Condition(thought, action, output) {
			shouldContinue, finalAnswer, confidence := rule.Evaluate(thought, action, output)

			if !shouldContinue {
				sr.logger.Info("Self-reflection decided to stop",
					"rule", rule.Name,
					"confidence", confidence,
					"answer_length", len(finalAnswer))
				return false, finalAnswer, confidence
			}
		}
	}

	// If no rule decided to stop, perform detailed analysis
	result := sr.performDetailedReflection(thought, action, output)

	sr.logger.Debug("Self-reflection completed",
		"should_continue", result.ShouldContinue,
		"confidence", result.Confidence)

	return result.ShouldContinue, result.FinalAnswer, result.Confidence
}

// performDetailedReflection performs comprehensive reflection analysis
func (sr *SelfReflector) performDetailedReflection(thought Thought, action *Action, output *AgentOutput) ReflectionResult {
	// Analyze progress
	progress := sr.progressAnalyzer.AnalyzeProgress(output.Thoughts, output.Actions)

	// Assess quality
	quality := sr.qualityAssessor.AssessQuality(output.Thoughts, output.Actions)

	// Make decision based on combined analysis
	shouldContinue := true
	finalAnswer := ""
	confidence := 0.5
	reasoning := "Continuing with more analysis needed"

	// Decision logic
	if progress.CompletionScore > 0.8 && quality.OverallScore > 0.7 {
		shouldContinue = false
		finalAnswer = progress.Summary
		confidence = (progress.OverallConfidence + quality.OverallScore) / 2
		reasoning = "High completion and quality scores indicate task completion"
	} else if progress.CompletionScore < 0.3 && len(output.Actions) > 5 {
		shouldContinue = false
		finalAnswer = "Unable to complete the task with available information and tools"
		confidence = 0.4
		reasoning = "Low progress after multiple attempts"
	} else if quality.OverallScore < 0.3 {
		reasoning = "Quality concerns require more careful analysis"
	}

	return ReflectionResult{
		ShouldContinue: shouldContinue,
		FinalAnswer:    finalAnswer,
		Confidence:     confidence,
		Reasoning:      reasoning,
		Improvements:   quality.Suggestions,
	}
}

// isCompleteAnswer checks if the action output represents a complete answer
func (sr *SelfReflector) isCompleteAnswer(output interface{}) bool {
	if output == nil {
		return false
	}

	outputStr := fmt.Sprintf("%v", output)

	// Check for completion indicators
	completionIndicators := []string{
		"completed", "finished", "done", "result:", "answer:", "conclusion:",
		"summary:", "total:", "final", "success",
	}

	outputLower := strings.ToLower(outputStr)
	for _, indicator := range completionIndicators {
		if strings.Contains(outputLower, indicator) {
			return true
		}
	}

	// Check for substantial content (not just error messages)
	return len(outputStr) > 20 && !strings.Contains(outputLower, "error") && !strings.Contains(outputLower, "failed")
}

// calculateErrorRate calculates the error rate from actions
func (sr *SelfReflector) calculateErrorRate(actions []Action) float64 {
	if len(actions) == 0 {
		return 0.0
	}

	errorCount := 0
	for _, action := range actions {
		if !action.Success {
			errorCount++
		}
	}

	return float64(errorCount) / float64(len(actions))
}

// generateSummary generates a summary of thoughts and actions
func (sr *SelfReflector) generateSummary(thoughts []Thought, actions []Action) string {
	if len(thoughts) == 0 {
		return "No analysis performed"
	}

	successfulActions := 0
	for _, action := range actions {
		if action.Success {
			successfulActions++
		}
	}

	lastThought := thoughts[len(thoughts)-1]

	return fmt.Sprintf("After %d reasoning steps and %d actions (%d successful), my analysis suggests: %s",
		len(thoughts), len(actions), successfulActions, lastThought.Content)
}

// ProgressAnalysis holds progress analysis results
type ProgressAnalysis struct {
	CompletionScore   float64  `json:"completion_score"`
	OverallConfidence float64  `json:"overall_confidence"`
	Summary           string   `json:"summary"`
	KeyFindings       []string `json:"key_findings"`
	RemainingTasks    []string `json:"remaining_tasks"`
}

// AnalyzeProgress analyzes progress toward completing the task
func (pa *ProgressAnalyzer) AnalyzeProgress(thoughts []Thought, actions []Action) ProgressAnalysis {
	analysis := ProgressAnalysis{
		KeyFindings:    make([]string, 0),
		RemainingTasks: make([]string, 0),
	}

	if len(thoughts) == 0 {
		return analysis
	}

	// Calculate average confidence
	totalConfidence := 0.0
	for _, thought := range thoughts {
		totalConfidence += thought.Confidence
	}
	analysis.OverallConfidence = totalConfidence / float64(len(thoughts))

	// Analyze confidence trend
	confidenceTrend := pa.calculateConfidenceTrend(thoughts)

	// Calculate completion score based on various factors
	completionFactors := []float64{
		analysis.OverallConfidence,
		confidenceTrend,
		pa.calculateActionSuccessRate(actions),
		pa.calculateContentQuality(thoughts),
	}

	total := 0.0
	for _, factor := range completionFactors {
		total += factor
	}
	analysis.CompletionScore = total / float64(len(completionFactors))

	// Generate summary
	lastThought := thoughts[len(thoughts)-1]
	analysis.Summary = fmt.Sprintf("Progress analysis: %s (Confidence: %.2f, Completion: %.2f)",
		lastThought.Content, analysis.OverallConfidence, analysis.CompletionScore)

	// Identify key findings from successful actions
	for _, action := range actions {
		if action.Success && action.Output != nil {
			analysis.KeyFindings = append(analysis.KeyFindings, fmt.Sprintf("%s: %v", action.Tool, action.Output))
		}
	}

	return analysis
}

// calculateConfidenceTrend calculates the trend in confidence over time
func (pa *ProgressAnalyzer) calculateConfidenceTrend(thoughts []Thought) float64 {
	if len(thoughts) < 2 {
		return 0.5
	}

	// Simple trend calculation: compare last half with first half
	midpoint := len(thoughts) / 2

	firstHalfAvg := 0.0
	for i := 0; i < midpoint; i++ {
		firstHalfAvg += thoughts[i].Confidence
	}
	firstHalfAvg /= float64(midpoint)

	secondHalfAvg := 0.0
	for i := midpoint; i < len(thoughts); i++ {
		secondHalfAvg += thoughts[i].Confidence
	}
	secondHalfAvg /= float64(len(thoughts) - midpoint)

	// Return normalized trend (0.5 = no change, 1.0 = strong positive trend)
	trend := (secondHalfAvg - firstHalfAvg) + 0.5
	if trend > 1.0 {
		trend = 1.0
	} else if trend < 0.0 {
		trend = 0.0
	}

	return trend
}

// calculateActionSuccessRate calculates the success rate of actions
func (pa *ProgressAnalyzer) calculateActionSuccessRate(actions []Action) float64 {
	if len(actions) == 0 {
		return 0.5
	}

	successCount := 0
	for _, action := range actions {
		if action.Success {
			successCount++
		}
	}

	return float64(successCount) / float64(len(actions))
}

// calculateContentQuality assesses the quality of thought content
func (pa *ProgressAnalyzer) calculateContentQuality(thoughts []Thought) float64 {
	if len(thoughts) == 0 {
		return 0.0
	}

	totalQuality := 0.0
	for _, thought := range thoughts {
		quality := 0.0

		// Length factor (reasonable length is good)
		if len(thought.Content) > 20 && len(thought.Content) < 500 {
			quality += 0.3
		}

		// Reasoning factor (presence of reasoning)
		if len(thought.Reasoning) > 10 {
			quality += 0.3
		}

		// Confidence factor
		quality += thought.Confidence * 0.4

		totalQuality += quality
	}

	return totalQuality / float64(len(thoughts))
}

// QualityAssessment holds quality assessment results
type QualityAssessment struct {
	OverallScore float64  `json:"overall_score"`
	Suggestions  []string `json:"suggestions"`
	Strengths    []string `json:"strengths"`
	Weaknesses   []string `json:"weaknesses"`
}

// AssessQuality assesses the quality of thoughts and actions
func (qa *QualityAssessor) AssessQuality(thoughts []Thought, actions []Action) QualityAssessment {
	assessment := QualityAssessment{
		Suggestions: make([]string, 0),
		Strengths:   make([]string, 0),
		Weaknesses:  make([]string, 0),
	}

	// Assess thought quality
	thoughtQuality := qa.assessThoughtQuality(thoughts)

	// Assess action quality
	actionQuality := qa.assessActionQuality(actions)

	// Calculate overall score
	assessment.OverallScore = (thoughtQuality + actionQuality) / 2

	// Generate suggestions based on assessment
	if thoughtQuality < 0.5 {
		assessment.Suggestions = append(assessment.Suggestions, "Improve reasoning depth and clarity")
		assessment.Weaknesses = append(assessment.Weaknesses, "Low thought quality")
	} else {
		assessment.Strengths = append(assessment.Strengths, "Good reasoning quality")
	}

	if actionQuality < 0.5 {
		assessment.Suggestions = append(assessment.Suggestions, "Consider alternative tools or approaches")
		assessment.Weaknesses = append(assessment.Weaknesses, "Low action success rate")
	} else {
		assessment.Strengths = append(assessment.Strengths, "Effective tool usage")
	}

	return assessment
}

// assessThoughtQuality assesses the quality of thoughts
func (qa *QualityAssessor) assessThoughtQuality(thoughts []Thought) float64 {
	if len(thoughts) == 0 {
		return 0.0
	}

	totalScore := 0.0
	for _, thought := range thoughts {
		score := 0.0

		// Content length and depth
		if len(thought.Content) > 30 {
			score += 0.3
		}

		// Reasoning presence
		if len(thought.Reasoning) > 10 {
			score += 0.3
		}

		// Confidence appropriateness
		score += thought.Confidence * 0.4

		totalScore += score
	}

	return totalScore / float64(len(thoughts))
}

// assessActionQuality assesses the quality of actions
func (qa *QualityAssessor) assessActionQuality(actions []Action) float64 {
	if len(actions) == 0 {
		return 0.5 // Neutral score if no actions
	}

	successRate := 0.0
	for _, action := range actions {
		if action.Success {
			successRate += 1.0
		}
	}
	successRate /= float64(len(actions))

	// Factor in action diversity (using different tools is good)
	toolSet := make(map[string]bool)
	for _, action := range actions {
		toolSet[action.Tool] = true
	}
	diversity := float64(len(toolSet)) / float64(len(actions))

	return (successRate*0.7 + diversity*0.3)
}
