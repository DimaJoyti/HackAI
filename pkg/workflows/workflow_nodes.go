package workflows

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// BaseNode provides common functionality for all workflow nodes
type BaseNode struct {
	ID          string                 `json:"id"`
	Type        NodeType               `json:"type"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Config      NodeConfig             `json:"config"`
	Metadata    map[string]interface{} `json:"metadata"`
	Logger      *logger.Logger         `json:"-"`
}

// GetID returns the node ID
func (bn *BaseNode) GetID() string {
	return bn.ID
}

// GetType returns the node type
func (bn *BaseNode) GetType() NodeType {
	return bn.Type
}

// GetName returns the node name
func (bn *BaseNode) GetName() string {
	return bn.Name
}

// GetDescription returns the node description
func (bn *BaseNode) GetDescription() string {
	return bn.Description
}

// GetConfig returns the node configuration
func (bn *BaseNode) GetConfig() NodeConfig {
	return bn.Config
}

// GetMetadata returns the node metadata
func (bn *BaseNode) GetMetadata() map[string]interface{} {
	return bn.Metadata
}

// Validate validates the node configuration
func (bn *BaseNode) Validate() error {
	if bn.ID == "" {
		return fmt.Errorf("node ID cannot be empty")
	}
	if bn.Name == "" {
		return fmt.Errorf("node name cannot be empty")
	}
	return nil
}

// AIProcessingNode processes data using AI models
type AIProcessingNode struct {
	BaseNode
	ModelType      string                 `json:"model_type"`
	ModelConfig    map[string]interface{} `json:"model_config"`
	PromptTemplate string                 `json:"prompt_template"`
}

// Execute executes the AI processing node
func (node *AIProcessingNode) Execute(ctx context.Context, input WorkflowData) (WorkflowData, error) {
	node.Logger.Debug("Executing AI processing node", "node_id", node.ID, "model_type", node.ModelType)

	// Simulate AI processing
	inputText := ""
	if content, ok := input.Content.(string); ok {
		inputText = content
	} else {
		inputText = fmt.Sprintf("%v", input.Content)
	}

	// Apply prompt template
	prompt := strings.ReplaceAll(node.PromptTemplate, "{input}", inputText)

	// Simulate AI model processing
	time.Sleep(time.Millisecond * 100) // Simulate processing time

	result := fmt.Sprintf("AI processed: %s using %s model", prompt, node.ModelType)

	return WorkflowData{
		ID:        fmt.Sprintf("ai_output_%d", time.Now().UnixNano()),
		Type:      "ai_result",
		Content:   result,
		Metadata:  map[string]interface{}{"model_type": node.ModelType, "processing_time": "100ms"},
		Timestamp: time.Now(),
	}, nil
}

// SecurityNode performs security checks and validations
type SecurityNode struct {
	BaseNode
	SecurityChecks []string               `json:"security_checks"`
	Thresholds     map[string]float64     `json:"thresholds"`
	SecurityConfig map[string]interface{} `json:"security_config"`
}

// Execute executes the security node
func (node *SecurityNode) Execute(ctx context.Context, input WorkflowData) (WorkflowData, error) {
	node.Logger.Debug("Executing security node", "node_id", node.ID, "checks", node.SecurityChecks)

	inputText := ""
	if content, ok := input.Content.(string); ok {
		inputText = content
	} else {
		inputText = fmt.Sprintf("%v", input.Content)
	}

	// Perform security checks
	securityResults := make(map[string]interface{})

	for _, check := range node.SecurityChecks {
		switch check {
		case "prompt_injection":
			score := node.checkPromptInjection(inputText)
			securityResults["prompt_injection_score"] = score
			if threshold, exists := node.Thresholds["prompt_injection"]; exists && score > threshold {
				return WorkflowData{}, fmt.Errorf("prompt injection detected with score %.2f", score)
			}
		case "content_filter":
			passed := node.checkContentFilter(inputText)
			securityResults["content_filter_passed"] = passed
			if !passed {
				return WorkflowData{}, fmt.Errorf("content filter check failed")
			}
		case "data_validation":
			valid := node.validateData(input)
			securityResults["data_validation_passed"] = valid
			if !valid {
				return WorkflowData{}, fmt.Errorf("data validation failed")
			}
		}
	}

	return WorkflowData{
		ID:        fmt.Sprintf("security_output_%d", time.Now().UnixNano()),
		Type:      "security_result",
		Content:   input.Content, // Pass through original content
		Metadata:  map[string]interface{}{"security_results": securityResults, "checks_performed": node.SecurityChecks},
		Timestamp: time.Now(),
	}, nil
}

// checkPromptInjection simulates prompt injection detection
func (node *SecurityNode) checkPromptInjection(text string) float64 {
	// Simple heuristic-based detection
	suspiciousPatterns := []string{"ignore", "override", "system", "admin", "bypass"}
	score := 0.0

	textLower := strings.ToLower(text)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(textLower, pattern) {
			score += 0.2
		}
	}

	return score
}

// checkContentFilter simulates content filtering
func (node *SecurityNode) checkContentFilter(text string) bool {
	// Simple content filter
	blockedWords := []string{"harmful", "dangerous", "illegal"}
	textLower := strings.ToLower(text)

	for _, word := range blockedWords {
		if strings.Contains(textLower, word) {
			return false
		}
	}

	return true
}

// validateData validates input data structure
func (node *SecurityNode) validateData(data WorkflowData) bool {
	// Simple validation
	return data.ID != "" && data.Type != "" && data.Content != nil
}

// DecisionNode makes routing decisions based on conditions
type DecisionNode struct {
	BaseNode
	Conditions  []DecisionCondition `json:"conditions"`
	DefaultPath string              `json:"default_path"`
}

// DecisionCondition represents a decision condition
type DecisionCondition struct {
	Expression string `json:"expression"`
	OutputPath string `json:"output_path"`
	Priority   int    `json:"priority"`
}

// Execute executes the decision node
func (node *DecisionNode) Execute(ctx context.Context, input WorkflowData) (WorkflowData, error) {
	node.Logger.Debug("Executing decision node", "node_id", node.ID, "conditions", len(node.Conditions))

	// Evaluate conditions
	selectedPath := node.DefaultPath

	for _, condition := range node.Conditions {
		if node.evaluateCondition(condition.Expression, input) {
			selectedPath = condition.OutputPath
			break
		}
	}

	return WorkflowData{
		ID:        fmt.Sprintf("decision_output_%d", time.Now().UnixNano()),
		Type:      "decision_result",
		Content:   input.Content, // Pass through original content
		Metadata:  map[string]interface{}{"selected_path": selectedPath, "decision_node": node.ID},
		Timestamp: time.Now(),
	}, nil
}

// evaluateCondition evaluates a decision condition
func (node *DecisionNode) evaluateCondition(expression string, data WorkflowData) bool {
	// Simple expression evaluation
	switch expression {
	case "has_content":
		return data.Content != nil
	case "is_string":
		_, ok := data.Content.(string)
		return ok
	case "is_secure":
		if securityResults, exists := data.Metadata["security_results"]; exists {
			if results, ok := securityResults.(map[string]interface{}); ok {
				if passed, exists := results["content_filter_passed"]; exists {
					if passedBool, ok := passed.(bool); ok {
						return passedBool
					}
				}
			}
		}
		return true
	default:
		return true
	}
}

// ParallelNode executes multiple branches in parallel
type ParallelNode struct {
	BaseNode
	Branches   []string      `json:"branches"`
	JoinPolicy string        `json:"join_policy"` // "all", "any", "first"
	Timeout    time.Duration `json:"timeout"`
}

// Execute executes the parallel node
func (node *ParallelNode) Execute(ctx context.Context, input WorkflowData) (WorkflowData, error) {
	node.Logger.Debug("Executing parallel node", "node_id", node.ID, "branches", len(node.Branches))

	// For now, just pass through the input
	// In a full implementation, this would coordinate parallel execution
	return WorkflowData{
		ID:        fmt.Sprintf("parallel_output_%d", time.Now().UnixNano()),
		Type:      "parallel_result",
		Content:   input.Content,
		Metadata:  map[string]interface{}{"branches": node.Branches, "join_policy": node.JoinPolicy},
		Timestamp: time.Now(),
	}, nil
}

// TransformNode transforms data between different formats
type TransformNode struct {
	BaseNode
	TransformType string                 `json:"transform_type"`
	Parameters    map[string]interface{} `json:"parameters"`
}

// Execute executes the transform node
func (node *TransformNode) Execute(ctx context.Context, input WorkflowData) (WorkflowData, error) {
	node.Logger.Debug("Executing transform node", "node_id", node.ID, "transform_type", node.TransformType)

	var transformedContent interface{}

	switch node.TransformType {
	case "to_uppercase":
		if text, ok := input.Content.(string); ok {
			transformedContent = strings.ToUpper(text)
		} else {
			transformedContent = input.Content
		}
	case "to_lowercase":
		if text, ok := input.Content.(string); ok {
			transformedContent = strings.ToLower(text)
		} else {
			transformedContent = input.Content
		}
	case "add_prefix":
		if prefix, exists := node.Parameters["prefix"]; exists {
			if text, ok := input.Content.(string); ok {
				transformedContent = fmt.Sprintf("%s%s", prefix, text)
			} else {
				transformedContent = input.Content
			}
		} else {
			transformedContent = input.Content
		}
	default:
		transformedContent = input.Content
	}

	return WorkflowData{
		ID:        fmt.Sprintf("transform_output_%d", time.Now().UnixNano()),
		Type:      "transform_result",
		Content:   transformedContent,
		Metadata:  map[string]interface{}{"transform_type": node.TransformType, "original_type": input.Type},
		Timestamp: time.Now(),
	}, nil
}

// ValidationNode validates data against schemas or rules
type ValidationNode struct {
	BaseNode
	ValidationRules []ValidationRule       `json:"validation_rules"`
	Schema          map[string]interface{} `json:"schema"`
	StrictMode      bool                   `json:"strict_mode"`
}

// ValidationRule represents a validation rule
type ValidationRule struct {
	Field         string        `json:"field"`
	Type          string        `json:"type"`
	Required      bool          `json:"required"`
	MinLength     int           `json:"min_length"`
	MaxLength     int           `json:"max_length"`
	Pattern       string        `json:"pattern"`
	AllowedValues []interface{} `json:"allowed_values"`
}

// Execute executes the validation node
func (node *ValidationNode) Execute(ctx context.Context, input WorkflowData) (WorkflowData, error) {
	node.Logger.Debug("Executing validation node", "node_id", node.ID, "rules", len(node.ValidationRules))

	// Perform validation
	validationResults := make(map[string]interface{})
	allValid := true

	for _, rule := range node.ValidationRules {
		valid := node.validateRule(rule, input)
		validationResults[rule.Field] = valid
		if !valid {
			allValid = false
			if node.StrictMode {
				return WorkflowData{}, fmt.Errorf("validation failed for field %s", rule.Field)
			}
		}
	}

	return WorkflowData{
		ID:        fmt.Sprintf("validation_output_%d", time.Now().UnixNano()),
		Type:      "validation_result",
		Content:   input.Content,
		Metadata:  map[string]interface{}{"validation_results": validationResults, "all_valid": allValid},
		Timestamp: time.Now(),
	}, nil
}

// validateRule validates a single rule
func (node *ValidationNode) validateRule(rule ValidationRule, data WorkflowData) bool {
	// Simple validation logic
	switch rule.Field {
	case "content":
		if rule.Required && data.Content == nil {
			return false
		}
		if text, ok := data.Content.(string); ok {
			if rule.MinLength > 0 && len(text) < rule.MinLength {
				return false
			}
			if rule.MaxLength > 0 && len(text) > rule.MaxLength {
				return false
			}
		}
	case "type":
		if rule.Required && data.Type == "" {
			return false
		}
		if len(rule.AllowedValues) > 0 {
			found := false
			for _, allowed := range rule.AllowedValues {
				if data.Type == allowed {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	return true
}
