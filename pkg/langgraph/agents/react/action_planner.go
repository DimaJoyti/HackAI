package react

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/tools"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// ActionPlanner handles action planning in the ReAct cycle
type ActionPlanner struct {
	logger         *logger.Logger
	toolSelector   *ToolSelector
	inputGenerator *InputGenerator
	planningRules  []PlanningRule
}

// PlanningRule defines rules for action planning
type PlanningRule struct {
	Name        string
	Description string
	Condition   func(thought Thought, availableTools map[string]tools.Tool) bool
	Action      func(thought Thought, availableTools map[string]tools.Tool) *Action
	Priority    int
}

// ToolSelector selects the most appropriate tool for a given thought
type ToolSelector struct {
	logger *logger.Logger
}

// InputGenerator generates appropriate inputs for tools
type InputGenerator struct {
	logger *logger.Logger
}

// NewActionPlanner creates a new action planner
func NewActionPlanner(logger *logger.Logger) *ActionPlanner {
	ap := &ActionPlanner{
		logger:         logger,
		toolSelector:   &ToolSelector{logger: logger},
		inputGenerator: &InputGenerator{logger: logger},
		planningRules:  make([]PlanningRule, 0),
	}

	// Initialize planning rules
	ap.initializePlanningRules()

	return ap
}

// initializePlanningRules sets up the planning rules
func (ap *ActionPlanner) initializePlanningRules() {
	rules := []PlanningRule{
		{
			Name:        "conclusion_rule",
			Description: "Don't plan action if thought indicates conclusion",
			Priority:    1,
			Condition: func(thought Thought, tools map[string]tools.Tool) bool {
				conclusionKeywords := []string{"conclusion", "final answer", "result is", "therefore", "in summary"}
				thoughtLower := strings.ToLower(thought.Content)
				for _, keyword := range conclusionKeywords {
					if strings.Contains(thoughtLower, keyword) {
						return true
					}
				}
				return false
			},
			Action: func(thought Thought, tools map[string]tools.Tool) *Action {
				return nil // No action needed
			},
		},
		{
			Name:        "high_confidence_rule",
			Description: "Don't plan action if confidence is very high and thought seems complete",
			Priority:    2,
			Condition: func(thought Thought, tools map[string]tools.Tool) bool {
				return thought.Confidence >= 0.9 && len(thought.Content) > 50
			},
			Action: func(thought Thought, tools map[string]tools.Tool) *Action {
				return nil // No action needed
			},
		},
		{
			Name:        "tool_selection_rule",
			Description: "Select appropriate tool based on thought content",
			Priority:    3,
			Condition: func(thought Thought, tools map[string]tools.Tool) bool {
				return len(tools) > 0
			},
			Action: func(thought Thought, tools map[string]tools.Tool) *Action {
				// This will be handled by the main planning logic
				return nil
			},
		},
	}

	ap.planningRules = rules
}

// Plan creates an action plan based on the current thought
func (ap *ActionPlanner) Plan(ctx context.Context, thought Thought, availableTools map[string]tools.Tool, input AgentInput) (*Action, error) {
	ap.logger.Debug("Planning action",
		"step", thought.Step,
		"thought_confidence", thought.Confidence,
		"available_tools", len(availableTools))

	// Apply planning rules in priority order
	for _, rule := range ap.planningRules {
		if rule.Condition(thought, availableTools) {
			action := rule.Action(thought, availableTools)
			if action == nil {
				ap.logger.Debug("Planning rule indicates no action needed",
					"rule", rule.Name,
					"step", thought.Step)
				return nil, nil
			}
		}
	}

	// If no rule prevented action, proceed with tool selection
	selectedTool := ap.toolSelector.SelectTool(thought, availableTools)
	if selectedTool == nil {
		ap.logger.Debug("No suitable tool found for thought",
			"step", thought.Step,
			"thought_content", thought.Content)
		return nil, nil
	}

	// Generate input for the selected tool
	toolInput, err := ap.inputGenerator.GenerateInput(thought, selectedTool, input)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tool input: %w", err)
	}

	action := &Action{
		Step:      thought.Step,
		Tool:      selectedTool.ID(),
		Input:     toolInput,
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"tool_name":        selectedTool.Name(),
			"tool_description": selectedTool.Description(),
			"selection_reason": ap.getSelectionReason(thought, selectedTool),
		},
	}

	ap.logger.Debug("Action planned",
		"step", thought.Step,
		"tool", selectedTool.ID(),
		"tool_name", selectedTool.Name())

	return action, nil
}

// SelectTool selects the most appropriate tool for the given thought
func (ts *ToolSelector) SelectTool(thought Thought, availableTools map[string]tools.Tool) tools.Tool {
	if len(availableTools) == 0 {
		return nil
	}

	// Score each tool based on relevance to the thought
	bestTool := tools.Tool(nil)
	bestScore := 0.0

	for _, tool := range availableTools {
		score := ts.calculateToolScore(thought, tool)
		if score > bestScore {
			bestScore = score
			bestTool = tool
		}
	}

	// Only return tool if score is above threshold
	if bestScore > 0.3 {
		return bestTool
	}

	return nil
}

// calculateToolScore calculates how well a tool matches the thought
func (ts *ToolSelector) calculateToolScore(thought Thought, tool tools.Tool) float64 {
	score := 0.0
	thoughtLower := strings.ToLower(thought.Content)
	toolNameLower := strings.ToLower(tool.Name())
	toolDescLower := strings.ToLower(tool.Description())

	// Check for direct tool name mentions
	if strings.Contains(thoughtLower, toolNameLower) {
		score += 0.8
	}

	// Check for keyword matches in tool description
	descWords := strings.Fields(toolDescLower)
	thoughtWords := strings.Fields(thoughtLower)

	matchCount := 0
	for _, descWord := range descWords {
		if len(descWord) > 3 { // Only consider meaningful words
			for _, thoughtWord := range thoughtWords {
				if descWord == thoughtWord {
					matchCount++
				}
			}
		}
	}

	if len(descWords) > 0 {
		score += float64(matchCount) / float64(len(descWords)) * 0.6
	}

	// Check for specific patterns
	score += ts.checkPatternMatches(thoughtLower, tool)

	return score
}

// checkPatternMatches checks for specific patterns that indicate tool usage
func (ts *ToolSelector) checkPatternMatches(thoughtLower string, tool tools.Tool) float64 {
	toolID := strings.ToLower(tool.ID())

	patterns := map[string][]string{
		"calculator":    {"calculate", "compute", "math", "number", "score", "sum"},
		"web_search":    {"search", "find", "look up", "google", "information"},
		"security_scan": {"scan", "security", "vulnerability", "check", "analyze"},
		"database":      {"query", "database", "data", "select", "insert", "update"},
		"file":          {"file", "read", "write", "save", "load", "document"},
		"api":           {"api", "request", "call", "endpoint", "service"},
		"report":        {"report", "generate", "create", "document", "summary"},
	}

	for toolType, keywords := range patterns {
		if strings.Contains(toolID, toolType) {
			for _, keyword := range keywords {
				if strings.Contains(thoughtLower, keyword) {
					return 0.4
				}
			}
		}
	}

	return 0.0
}

// GenerateInput generates appropriate input for a tool based on the thought
func (ig *InputGenerator) GenerateInput(thought Thought, tool tools.Tool, agentInput AgentInput) (map[string]interface{}, error) {
	input := make(map[string]interface{})

	// Extract relevant information from the thought
	thoughtContent := thought.Content

	// Add basic context
	input["query"] = thoughtContent
	input["step"] = thought.Step
	input["confidence"] = thought.Confidence

	// Add agent context
	if agentInput.Context != nil {
		for key, value := range agentInput.Context {
			input[key] = value
		}
	}

	// Tool-specific input generation
	toolID := strings.ToLower(tool.ID())

	switch {
	case strings.Contains(toolID, "calculator"):
		ig.generateCalculatorInput(input, thoughtContent)
	case strings.Contains(toolID, "search"):
		ig.generateSearchInput(input, thoughtContent)
	case strings.Contains(toolID, "security"):
		ig.generateSecurityInput(input, thoughtContent, agentInput)
	case strings.Contains(toolID, "database"):
		ig.generateDatabaseInput(input, thoughtContent)
	case strings.Contains(toolID, "api"):
		ig.generateAPIInput(input, thoughtContent)
	case strings.Contains(toolID, "report"):
		ig.generateReportInput(input, thoughtContent, agentInput)
	default:
		// Generic input generation
		ig.generateGenericInput(input, thoughtContent)
	}

	ig.logger.Debug("Generated tool input",
		"tool", tool.ID(),
		"input_keys", getMapKeys(input))

	return input, nil
}

// generateCalculatorInput generates input for calculator tools
func (ig *InputGenerator) generateCalculatorInput(input map[string]interface{}, content string) {
	// Extract numbers and operations from content
	input["expression"] = content
	input["operation"] = "calculate"
}

// generateSearchInput generates input for search tools
func (ig *InputGenerator) generateSearchInput(input map[string]interface{}, content string) {
	// Extract search terms
	searchTerms := ig.extractSearchTerms(content)
	input["search_terms"] = searchTerms
	input["max_results"] = 10
}

// generateSecurityInput generates input for security tools
func (ig *InputGenerator) generateSecurityInput(input map[string]interface{}, content string, agentInput AgentInput) {
	// Extract target from content or context
	if target, exists := agentInput.Context["target"]; exists {
		input["target"] = target
	} else {
		input["target"] = ig.extractTarget(content)
	}

	input["scan_type"] = "comprehensive"
	input["include_details"] = true
}

// generateDatabaseInput generates input for database tools
func (ig *InputGenerator) generateDatabaseInput(input map[string]interface{}, content string) {
	input["query_type"] = "select"
	input["table"] = "default"
}

// generateAPIInput generates input for API tools
func (ig *InputGenerator) generateAPIInput(input map[string]interface{}, content string) {
	input["method"] = "GET"
	input["endpoint"] = "/"
}

// generateReportInput generates input for report tools
func (ig *InputGenerator) generateReportInput(input map[string]interface{}, content string, agentInput AgentInput) {
	input["report_type"] = "summary"
	input["format"] = "text"
	input["include_details"] = true

	// Include all context for report generation
	if agentInput.Context != nil {
		input["context"] = agentInput.Context
	}
}

// generateGenericInput generates generic input for unknown tools
func (ig *InputGenerator) generateGenericInput(input map[string]interface{}, content string) {
	input["content"] = content
	input["action"] = "process"
}

// extractSearchTerms extracts search terms from content
func (ig *InputGenerator) extractSearchTerms(content string) []string {
	// Simple extraction - in practice, this could be more sophisticated
	words := strings.Fields(content)
	terms := make([]string, 0)

	for _, word := range words {
		if len(word) > 3 && !ig.isStopWord(word) {
			terms = append(terms, word)
		}
	}

	return terms
}

// extractTarget extracts target information from content
func (ig *InputGenerator) extractTarget(content string) string {
	// Look for URLs, IP addresses, or domain names
	words := strings.Fields(content)
	for _, word := range words {
		if strings.Contains(word, ".com") || strings.Contains(word, ".org") ||
			strings.Contains(word, ".net") || strings.Contains(word, "http") {
			return word
		}
	}
	return "unknown"
}

// isStopWord checks if a word is a stop word
func (ig *InputGenerator) isStopWord(word string) bool {
	stopWords := []string{"the", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by"}
	wordLower := strings.ToLower(word)
	for _, stopWord := range stopWords {
		if wordLower == stopWord {
			return true
		}
	}
	return false
}

// getSelectionReason returns the reason why a tool was selected
func (ap *ActionPlanner) getSelectionReason(thought Thought, tool tools.Tool) string {
	return fmt.Sprintf("Selected %s based on thought content analysis and tool capabilities", tool.Name())
}

// getMapKeys returns the keys of a map as a slice
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}
