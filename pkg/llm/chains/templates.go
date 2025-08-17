package chains

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/llm/providers"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var templateTracer = otel.Tracer("hackai/llm/chains/templates")

// TemplateManager provides template management for chains
type TemplateManager interface {
	// Template management
	CreateTemplate(ctx context.Context, template ChainTemplate) error
	UpdateTemplate(ctx context.Context, templateID string, template ChainTemplate) error
	DeleteTemplate(ctx context.Context, templateID string) error
	GetTemplate(ctx context.Context, templateID string) (ChainTemplate, error)
	ListTemplates(ctx context.Context, filter TemplateFilter) ([]ChainTemplate, error)

	// Template instantiation
	InstantiateFromTemplate(ctx context.Context, templateID string, config TemplateConfig) (llm.Chain, error)
	ValidateTemplate(ctx context.Context, template ChainTemplate) (ValidationResult, error)
	PreviewTemplate(ctx context.Context, templateID string, config TemplateConfig) (TemplatePreview, error)

	// Template versioning
	CreateTemplateVersion(ctx context.Context, templateID string, version string, template ChainTemplate) error
	GetTemplateVersion(ctx context.Context, templateID string, version string) (ChainTemplate, error)
	ListTemplateVersions(ctx context.Context, templateID string) ([]string, error)

	// Template sharing and marketplace
	PublishTemplate(ctx context.Context, templateID string, visibility string) error
	ImportTemplate(ctx context.Context, source string) (ChainTemplate, error)
	ExportTemplate(ctx context.Context, templateID string, format string) ([]byte, error)

	// Template analytics
	GetTemplateUsage(ctx context.Context, templateID string) (TemplateUsage, error)
	GetPopularTemplates(ctx context.Context, limit int) ([]ChainTemplate, error)
}

// DefaultTemplateManager implements the TemplateManager interface
type DefaultTemplateManager struct {
	templates        map[string]ChainTemplate
	templateVersions map[string]map[string]ChainTemplate // templateID -> version -> template
	templateUsage    map[string]*TemplateUsageData
	logger           *logger.Logger
	mutex            sync.RWMutex
}

// ChainTemplate represents a reusable chain template
type ChainTemplate struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Version     string        `json:"version"`
	Author      string        `json:"author"`
	Category    string        `json:"category"`
	Tags        []string      `json:"tags"`
	Type        llm.ChainType `json:"type"`

	// Template definition
	PromptTemplate string                `json:"prompt_template"`
	Parameters     []TemplateParameter   `json:"parameters"`
	Configuration  TemplateConfiguration `json:"configuration"`
	Dependencies   []string              `json:"dependencies"`

	// Metadata
	Visibility    string            `json:"visibility"` // public, private, organization
	License       string            `json:"license"`
	Documentation string            `json:"documentation"`
	Examples      []TemplateExample `json:"examples"`

	// Lifecycle
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	PublishedAt *time.Time `json:"published_at,omitempty"`

	// Usage tracking
	UsageCount  int64   `json:"usage_count"`
	Rating      float64 `json:"rating"`
	RatingCount int     `json:"rating_count"`
}

// TemplateParameter defines a configurable parameter in a template
type TemplateParameter struct {
	Name         string              `json:"name"`
	Type         string              `json:"type"` // string, number, boolean, array, object
	Description  string              `json:"description"`
	Required     bool                `json:"required"`
	DefaultValue interface{}         `json:"default_value"`
	Validation   ParameterValidation `json:"validation"`
	Examples     []interface{}       `json:"examples"`
}

// ParameterValidation defines validation rules for a parameter
type ParameterValidation struct {
	MinLength     *int          `json:"min_length,omitempty"`
	MaxLength     *int          `json:"max_length,omitempty"`
	MinValue      *float64      `json:"min_value,omitempty"`
	MaxValue      *float64      `json:"max_value,omitempty"`
	Pattern       string        `json:"pattern,omitempty"`
	AllowedValues []interface{} `json:"allowed_values,omitempty"`
}

// TemplateConfiguration defines the configuration structure for a template
type TemplateConfiguration struct {
	ProviderType   providers.ProviderType `json:"provider_type"`
	ModelName      string                 `json:"model_name"`
	Temperature    float64                `json:"temperature"`
	MaxTokens      int                    `json:"max_tokens"`
	TopP           float64                `json:"top_p"`
	TopK           int                    `json:"top_k"`
	StopSequences  []string               `json:"stop_sequences"`
	SystemPrompt   string                 `json:"system_prompt"`
	EnableMemory   bool                   `json:"enable_memory"`
	MemoryType     string                 `json:"memory_type"`
	CustomSettings map[string]interface{} `json:"custom_settings"`
}

// TemplateExample provides an example of how to use the template
type TemplateExample struct {
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Input          map[string]interface{} `json:"input"`
	ExpectedOutput string                 `json:"expected_output"`
}

// TemplateConfig provides configuration for template instantiation
type TemplateConfig struct {
	ChainID     string                 `json:"chain_id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	Overrides   TemplateConfiguration  `json:"overrides"`
}

// TemplateFilter provides filtering options for template queries
type TemplateFilter struct {
	Category   string   `json:"category"`
	Tags       []string `json:"tags"`
	Author     string   `json:"author"`
	Type       string   `json:"type"`
	Visibility string   `json:"visibility"`
	MinRating  float64  `json:"min_rating"`
	Limit      int      `json:"limit"`
	Offset     int      `json:"offset"`
	SortBy     string   `json:"sort_by"`    // name, created_at, usage_count, rating
	SortOrder  string   `json:"sort_order"` // asc, desc
}

// TemplatePreview provides a preview of what a template will generate
type TemplatePreview struct {
	TemplateID      string                `json:"template_id"`
	GeneratedPrompt string                `json:"generated_prompt"`
	Configuration   TemplateConfiguration `json:"configuration"`
	EstimatedTokens int                   `json:"estimated_tokens"`
	Warnings        []string              `json:"warnings"`
}

// TemplateUsage provides usage statistics for a template
type TemplateUsage struct {
	TemplateID        string                 `json:"template_id"`
	TotalUsage        int64                  `json:"total_usage"`
	UniqueUsers       int64                  `json:"unique_users"`
	UsageByDay        []UsageDataPoint       `json:"usage_by_day"`
	TopUsers          []UserUsage            `json:"top_users"`
	SuccessRate       float64                `json:"success_rate"`
	AverageRating     float64                `json:"average_rating"`
	PopularParameters map[string]interface{} `json:"popular_parameters"`
}

// TemplateUsageData stores internal usage tracking data
type TemplateUsageData struct {
	TemplateID   string
	TotalUsage   int64
	UniqueUsers  map[string]bool
	UsageHistory []UsageRecord
	Ratings      []Rating
	mutex        sync.RWMutex
}

// UsageDataPoint represents usage data for a specific time period
type UsageDataPoint struct {
	Date  time.Time `json:"date"`
	Count int64     `json:"count"`
}

// UserUsage represents usage by a specific user
type UserUsage struct {
	UserID string `json:"user_id"`
	Count  int64  `json:"count"`
}

// UsageRecord represents a single usage record
type UsageRecord struct {
	UserID     string                 `json:"user_id"`
	Timestamp  time.Time              `json:"timestamp"`
	Success    bool                   `json:"success"`
	Parameters map[string]interface{} `json:"parameters"`
}

// Rating represents a user rating for a template
type Rating struct {
	UserID    string    `json:"user_id"`
	Rating    float64   `json:"rating"`
	Comment   string    `json:"comment"`
	Timestamp time.Time `json:"timestamp"`
}

// NewDefaultTemplateManager creates a new default template manager
func NewDefaultTemplateManager(logger *logger.Logger) *DefaultTemplateManager {
	return &DefaultTemplateManager{
		templates:        make(map[string]ChainTemplate),
		templateVersions: make(map[string]map[string]ChainTemplate),
		templateUsage:    make(map[string]*TemplateUsageData),
		logger:           logger,
	}
}

// CreateTemplate creates a new chain template
func (tm *DefaultTemplateManager) CreateTemplate(ctx context.Context, template ChainTemplate) error {
	ctx, span := templateTracer.Start(ctx, "template_manager.create_template",
		trace.WithAttributes(
			attribute.String("template.id", template.ID),
			attribute.String("template.name", template.Name),
		),
	)
	defer span.End()

	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// Check if template already exists
	if _, exists := tm.templates[template.ID]; exists {
		err := fmt.Errorf("template %s already exists", template.ID)
		span.RecordError(err)
		return err
	}

	// Validate template
	validationResult, err := tm.ValidateTemplate(ctx, template)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("template validation failed: %w", err)
	}
	if !validationResult.Valid {
		err := fmt.Errorf("template validation failed: %v", validationResult.Errors)
		span.RecordError(err)
		return err
	}

	// Set timestamps
	now := time.Now()
	template.CreatedAt = now
	template.UpdatedAt = now
	template.UsageCount = 0
	template.Rating = 0.0
	template.RatingCount = 0

	// Store template
	tm.templates[template.ID] = template

	// Initialize versioning
	if tm.templateVersions[template.ID] == nil {
		tm.templateVersions[template.ID] = make(map[string]ChainTemplate)
	}
	tm.templateVersions[template.ID][template.Version] = template

	// Initialize usage tracking
	tm.templateUsage[template.ID] = &TemplateUsageData{
		TemplateID:   template.ID,
		TotalUsage:   0,
		UniqueUsers:  make(map[string]bool),
		UsageHistory: make([]UsageRecord, 0),
		Ratings:      make([]Rating, 0),
	}

	span.SetAttributes(
		attribute.String("template.version", template.Version),
		attribute.StringSlice("template.tags", template.Tags),
		attribute.String("template.category", template.Category),
		attribute.Bool("success", true),
	)

	tm.logger.Info("Template created",
		"template_id", template.ID,
		"template_name", template.Name,
		"version", template.Version,
		"author", template.Author,
	)

	return nil
}

// GetTemplate retrieves a template by ID
func (tm *DefaultTemplateManager) GetTemplate(ctx context.Context, templateID string) (ChainTemplate, error) {
	ctx, span := templateTracer.Start(ctx, "template_manager.get_template",
		trace.WithAttributes(attribute.String("template.id", templateID)),
	)
	defer span.End()

	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	template, exists := tm.templates[templateID]
	if !exists {
		err := fmt.Errorf("template %s not found", templateID)
		span.RecordError(err)
		return ChainTemplate{}, err
	}

	span.SetAttributes(
		attribute.String("template.name", template.Name),
		attribute.String("template.version", template.Version),
		attribute.Bool("success", true),
	)

	return template, nil
}

// InstantiateFromTemplate creates a chain instance from a template
func (tm *DefaultTemplateManager) InstantiateFromTemplate(ctx context.Context, templateID string, config TemplateConfig) (llm.Chain, error) {
	ctx, span := templateTracer.Start(ctx, "template_manager.instantiate_from_template",
		trace.WithAttributes(
			attribute.String("template.id", templateID),
			attribute.String("chain.id", config.ChainID),
		),
	)
	defer span.End()

	// Get template
	template, err := tm.GetTemplate(ctx, templateID)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}

	// Validate parameters
	if err := tm.validateParameters(template.Parameters, config.Parameters); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("parameter validation failed: %w", err)
	}

	// Generate prompt from template
	prompt, err := tm.generatePrompt(template.PromptTemplate, config.Parameters)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("prompt generation failed: %w", err)
	}

	// Create chain configuration
	chainConfig := template.Configuration
	if config.Overrides.ProviderType != "" {
		chainConfig.ProviderType = config.Overrides.ProviderType
	}
	if config.Overrides.ModelName != "" {
		chainConfig.ModelName = config.Overrides.ModelName
	}
	if config.Overrides.Temperature != 0 {
		chainConfig.Temperature = config.Overrides.Temperature
	}
	if config.Overrides.MaxTokens != 0 {
		chainConfig.MaxTokens = config.Overrides.MaxTokens
	}

	// Create a simple chain instance (this would be more sophisticated in production)
	// For now, we'll create a basic chain with the generated prompt
	chain := &TemplateChain{
		id:          config.ChainID,
		name:        config.Name,
		description: config.Description,
		template:    template,
		prompt:      prompt,
		config:      chainConfig,
		parameters:  config.Parameters,
	}

	// Record usage
	tm.recordUsage(templateID, "system", true, config.Parameters)

	span.SetAttributes(
		attribute.String("generated.prompt", prompt),
		attribute.Bool("success", true),
	)

	tm.logger.Info("Chain instantiated from template",
		"template_id", templateID,
		"chain_id", config.ChainID,
		"chain_name", config.Name,
	)

	return chain, nil
}

// ValidateTemplate validates a template
func (tm *DefaultTemplateManager) ValidateTemplate(ctx context.Context, template ChainTemplate) (ValidationResult, error) {
	result := ValidationResult{
		Valid:       true,
		Errors:      []ValidationError{},
		Warnings:    []ValidationWarning{},
		Score:       100.0,
		Suggestions: []string{},
	}

	// Validate basic fields
	if template.ID == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Type:      "template_validation",
			Message:   "Template ID is required",
			Field:     "id",
			Severity:  "error",
			Timestamp: time.Now(),
		})
		result.Score -= 20
	}

	if template.Name == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Type:      "template_validation",
			Message:   "Template name is required",
			Field:     "name",
			Severity:  "error",
			Timestamp: time.Now(),
		})
		result.Score -= 20
	}

	if template.PromptTemplate == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Type:      "template_validation",
			Message:   "Prompt template is required",
			Field:     "prompt_template",
			Severity:  "error",
			Timestamp: time.Now(),
		})
		result.Score -= 30
	}

	// Validate prompt template syntax
	if err := tm.validatePromptTemplate(template.PromptTemplate, template.Parameters); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Type:      "template_validation",
			Message:   fmt.Sprintf("Invalid prompt template: %v", err),
			Field:     "prompt_template",
			Severity:  "error",
			Timestamp: time.Now(),
		})
		result.Score -= 25
	}

	// Validate parameters
	for _, param := range template.Parameters {
		if param.Name == "" {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Type:      "template_validation",
				Message:   "Parameter name is empty",
				Field:     "parameters",
				Timestamp: time.Now(),
			})
			result.Score -= 5
		}
	}

	return result, nil
}

// Helper methods

// validateParameters validates that provided parameters match template requirements
func (tm *DefaultTemplateManager) validateParameters(templateParams []TemplateParameter, providedParams map[string]interface{}) error {
	for _, param := range templateParams {
		value, exists := providedParams[param.Name]

		// Check required parameters
		if param.Required && !exists {
			return fmt.Errorf("required parameter '%s' is missing", param.Name)
		}

		// Use default value if not provided
		if !exists && param.DefaultValue != nil {
			providedParams[param.Name] = param.DefaultValue
			continue
		}

		if exists {
			// Validate parameter type and constraints
			if err := tm.validateParameterValue(param, value); err != nil {
				return fmt.Errorf("parameter '%s' validation failed: %w", param.Name, err)
			}
		}
	}

	return nil
}

// validateParameterValue validates a single parameter value
func (tm *DefaultTemplateManager) validateParameterValue(param TemplateParameter, value interface{}) error {
	// Type validation (simplified)
	switch param.Type {
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("expected string, got %T", value)
		}
	case "number":
		if _, ok := value.(float64); !ok {
			if _, ok := value.(int); !ok {
				return fmt.Errorf("expected number, got %T", value)
			}
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("expected boolean, got %T", value)
		}
	}

	// Additional validation rules would go here
	return nil
}

// generatePrompt generates a prompt from template and parameters
func (tm *DefaultTemplateManager) generatePrompt(template string, parameters map[string]interface{}) (string, error) {
	prompt := template

	// Simple template substitution (in production, you'd use a proper template engine)
	for key, value := range parameters {
		placeholder := fmt.Sprintf("{{%s}}", key)
		valueStr := fmt.Sprintf("%v", value)
		prompt = strings.ReplaceAll(prompt, placeholder, valueStr)
	}

	return prompt, nil
}

// validatePromptTemplate validates the syntax of a prompt template
func (tm *DefaultTemplateManager) validatePromptTemplate(template string, parameters []TemplateParameter) error {
	// Check for unclosed placeholders
	openCount := strings.Count(template, "{{")
	closeCount := strings.Count(template, "}}")
	if openCount != closeCount {
		return fmt.Errorf("mismatched template placeholders")
	}

	// Check that all placeholders have corresponding parameters
	paramNames := make(map[string]bool)
	for _, param := range parameters {
		paramNames[param.Name] = true
	}

	// Extract placeholders (simplified)
	parts := strings.Split(template, "{{")
	for i := 1; i < len(parts); i++ {
		if closeIndex := strings.Index(parts[i], "}}"); closeIndex != -1 {
			paramName := strings.TrimSpace(parts[i][:closeIndex])
			if !paramNames[paramName] {
				return fmt.Errorf("placeholder '{{%s}}' has no corresponding parameter", paramName)
			}
		}
	}

	return nil
}

// recordUsage records template usage
func (tm *DefaultTemplateManager) recordUsage(templateID, userID string, success bool, parameters map[string]interface{}) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	usageData, exists := tm.templateUsage[templateID]
	if !exists {
		return
	}

	usageData.mutex.Lock()
	defer usageData.mutex.Unlock()

	usageData.TotalUsage++
	usageData.UniqueUsers[userID] = true

	record := UsageRecord{
		UserID:     userID,
		Timestamp:  time.Now(),
		Success:    success,
		Parameters: parameters,
	}
	usageData.UsageHistory = append(usageData.UsageHistory, record)

	// Keep only last 1000 usage records
	if len(usageData.UsageHistory) > 1000 {
		usageData.UsageHistory = usageData.UsageHistory[len(usageData.UsageHistory)-1000:]
	}

	// Update template usage count
	if template, exists := tm.templates[templateID]; exists {
		template.UsageCount = usageData.TotalUsage
		tm.templates[templateID] = template
	}
}

// TemplateChain represents a chain created from a template
type TemplateChain struct {
	id          string
	name        string
	description string
	template    ChainTemplate
	prompt      string
	config      TemplateConfiguration
	parameters  map[string]interface{}
}

// Implement the Chain interface for TemplateChain
func (tc *TemplateChain) ID() string          { return tc.id }
func (tc *TemplateChain) Name() string        { return tc.name }
func (tc *TemplateChain) Description() string { return tc.description }

func (tc *TemplateChain) Execute(ctx context.Context, input llm.ChainInput) (llm.ChainOutput, error) {
	// This would implement the actual execution logic
	// For now, return a mock response
	return llm.ChainOutput{
		"result":      fmt.Sprintf("Template chain executed with prompt: %s", tc.prompt),
		"template_id": tc.template.ID,
		"success":     true,
	}, nil
}

func (tc *TemplateChain) GetMemory() llm.Memory       { return nil }
func (tc *TemplateChain) SetMemory(memory llm.Memory) {}
func (tc *TemplateChain) Validate() error             { return nil }

// UpdateTemplate updates an existing template
func (tm *DefaultTemplateManager) UpdateTemplate(ctx context.Context, templateID string, template ChainTemplate) error {
	ctx, span := templateTracer.Start(ctx, "template_manager.update_template",
		trace.WithAttributes(attribute.String("template.id", templateID)),
	)
	defer span.End()

	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// Check if template exists
	if _, exists := tm.templates[templateID]; !exists {
		err := fmt.Errorf("template %s not found", templateID)
		span.RecordError(err)
		return err
	}

	// Validate updated template
	validationResult, err := tm.ValidateTemplate(ctx, template)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("template validation failed: %w", err)
	}
	if !validationResult.Valid {
		err := fmt.Errorf("template validation failed: %v", validationResult.Errors)
		span.RecordError(err)
		return err
	}

	// Update timestamps
	template.UpdatedAt = time.Now()
	template.ID = templateID // Ensure ID doesn't change

	// Store updated template
	tm.templates[templateID] = template

	span.SetAttributes(attribute.Bool("success", true))
	tm.logger.Info("Template updated", "template_id", templateID)

	return nil
}

// DeleteTemplate deletes a template
func (tm *DefaultTemplateManager) DeleteTemplate(ctx context.Context, templateID string) error {
	ctx, span := templateTracer.Start(ctx, "template_manager.delete_template",
		trace.WithAttributes(attribute.String("template.id", templateID)),
	)
	defer span.End()

	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// Check if template exists
	if _, exists := tm.templates[templateID]; !exists {
		err := fmt.Errorf("template %s not found", templateID)
		span.RecordError(err)
		return err
	}

	// Remove template and related data
	delete(tm.templates, templateID)
	delete(tm.templateVersions, templateID)
	delete(tm.templateUsage, templateID)

	span.SetAttributes(attribute.Bool("success", true))
	tm.logger.Info("Template deleted", "template_id", templateID)

	return nil
}

// ListTemplates lists templates with filtering
func (tm *DefaultTemplateManager) ListTemplates(ctx context.Context, filter TemplateFilter) ([]ChainTemplate, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	var results []ChainTemplate

	for _, template := range tm.templates {
		// Apply filters
		if filter.Category != "" && template.Category != filter.Category {
			continue
		}
		if filter.Author != "" && template.Author != filter.Author {
			continue
		}
		if filter.Visibility != "" && template.Visibility != filter.Visibility {
			continue
		}
		if filter.MinRating > 0 && template.Rating < filter.MinRating {
			continue
		}

		// Check tags
		if len(filter.Tags) > 0 {
			hasTag := false
			for _, filterTag := range filter.Tags {
				for _, templateTag := range template.Tags {
					if templateTag == filterTag {
						hasTag = true
						break
					}
				}
				if hasTag {
					break
				}
			}
			if !hasTag {
				continue
			}
		}

		results = append(results, template)
	}

	// Apply pagination
	if filter.Offset > 0 && filter.Offset < len(results) {
		results = results[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(results) {
		results = results[:filter.Limit]
	}

	return results, nil
}

// PreviewTemplate generates a preview of what a template will produce
func (tm *DefaultTemplateManager) PreviewTemplate(ctx context.Context, templateID string, config TemplateConfig) (TemplatePreview, error) {
	template, err := tm.GetTemplate(ctx, templateID)
	if err != nil {
		return TemplatePreview{}, err
	}

	// Validate parameters
	if err := tm.validateParameters(template.Parameters, config.Parameters); err != nil {
		return TemplatePreview{}, fmt.Errorf("parameter validation failed: %w", err)
	}

	// Generate prompt
	prompt, err := tm.generatePrompt(template.PromptTemplate, config.Parameters)
	if err != nil {
		return TemplatePreview{}, fmt.Errorf("prompt generation failed: %w", err)
	}

	// Estimate tokens (simplified)
	estimatedTokens := len(prompt) / 4 // Rough estimate

	// Generate warnings
	var warnings []string
	if len(prompt) > 4000 {
		warnings = append(warnings, "Generated prompt is very long and may exceed model limits")
	}

	return TemplatePreview{
		TemplateID:      templateID,
		GeneratedPrompt: prompt,
		Configuration:   template.Configuration,
		EstimatedTokens: estimatedTokens,
		Warnings:        warnings,
	}, nil
}

// CreateTemplateVersion creates a new version of a template
func (tm *DefaultTemplateManager) CreateTemplateVersion(ctx context.Context, templateID string, version string, template ChainTemplate) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	if tm.templateVersions[templateID] == nil {
		tm.templateVersions[templateID] = make(map[string]ChainTemplate)
	}

	template.Version = version
	tm.templateVersions[templateID][version] = template

	tm.logger.Info("Template version created", "template_id", templateID, "version", version)
	return nil
}

// GetTemplateVersion retrieves a specific version of a template
func (tm *DefaultTemplateManager) GetTemplateVersion(ctx context.Context, templateID string, version string) (ChainTemplate, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	versions, exists := tm.templateVersions[templateID]
	if !exists {
		return ChainTemplate{}, fmt.Errorf("template %s not found", templateID)
	}

	template, exists := versions[version]
	if !exists {
		return ChainTemplate{}, fmt.Errorf("version %s not found for template %s", version, templateID)
	}

	return template, nil
}

// ListTemplateVersions lists all versions of a template
func (tm *DefaultTemplateManager) ListTemplateVersions(ctx context.Context, templateID string) ([]string, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	versions, exists := tm.templateVersions[templateID]
	if !exists {
		return []string{}, nil
	}

	var versionList []string
	for version := range versions {
		versionList = append(versionList, version)
	}

	return versionList, nil
}

// PublishTemplate publishes a template with specified visibility
func (tm *DefaultTemplateManager) PublishTemplate(ctx context.Context, templateID string, visibility string) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	template, exists := tm.templates[templateID]
	if !exists {
		return fmt.Errorf("template %s not found", templateID)
	}

	template.Visibility = visibility
	now := time.Now()
	template.PublishedAt = &now
	tm.templates[templateID] = template

	tm.logger.Info("Template published", "template_id", templateID, "visibility", visibility)
	return nil
}

// ImportTemplate imports a template from an external source
func (tm *DefaultTemplateManager) ImportTemplate(ctx context.Context, source string) (ChainTemplate, error) {
	// This would implement template import logic
	// For now, return a placeholder
	return ChainTemplate{}, fmt.Errorf("template import not implemented")
}

// ExportTemplate exports a template in the specified format
func (tm *DefaultTemplateManager) ExportTemplate(ctx context.Context, templateID string, format string) ([]byte, error) {
	// This would implement template export logic
	// For now, return a placeholder
	return nil, fmt.Errorf("template export not implemented")
}

// GetTemplateUsage returns usage statistics for a template
func (tm *DefaultTemplateManager) GetTemplateUsage(ctx context.Context, templateID string) (TemplateUsage, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	usageData, exists := tm.templateUsage[templateID]
	if !exists {
		return TemplateUsage{}, fmt.Errorf("template %s not found", templateID)
	}

	usageData.mutex.RLock()
	defer usageData.mutex.RUnlock()

	// Calculate success rate
	successCount := int64(0)
	for _, record := range usageData.UsageHistory {
		if record.Success {
			successCount++
		}
	}

	successRate := float64(0)
	if len(usageData.UsageHistory) > 0 {
		successRate = float64(successCount) / float64(len(usageData.UsageHistory))
	}

	// Calculate average rating
	averageRating := float64(0)
	if len(usageData.Ratings) > 0 {
		totalRating := float64(0)
		for _, rating := range usageData.Ratings {
			totalRating += rating.Rating
		}
		averageRating = totalRating / float64(len(usageData.Ratings))
	}

	return TemplateUsage{
		TemplateID:    templateID,
		TotalUsage:    usageData.TotalUsage,
		UniqueUsers:   int64(len(usageData.UniqueUsers)),
		SuccessRate:   successRate,
		AverageRating: averageRating,
	}, nil
}

// GetPopularTemplates returns the most popular templates
func (tm *DefaultTemplateManager) GetPopularTemplates(ctx context.Context, limit int) ([]ChainTemplate, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	// Sort templates by usage count
	var templates []ChainTemplate
	for _, template := range tm.templates {
		templates = append(templates, template)
	}

	// Simple sorting by usage count (in production, you'd use a more sophisticated algorithm)
	for i := 0; i < len(templates)-1; i++ {
		for j := i + 1; j < len(templates); j++ {
			if templates[i].UsageCount < templates[j].UsageCount {
				templates[i], templates[j] = templates[j], templates[i]
			}
		}
	}

	// Apply limit
	if limit > 0 && limit < len(templates) {
		templates = templates[:limit]
	}

	return templates, nil
}
