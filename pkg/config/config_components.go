package config

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
)

// ConfigValidator validates configuration against schema
type ConfigValidator struct {
	validator   *validator.Validate
	schema      *ConfigSchema
	customRules map[string]validator.Func
	mutex       sync.RWMutex
}

// ConfigSchema defines the configuration schema
type ConfigSchema struct {
	Version    string                 `yaml:"version"`
	Properties map[string]PropertyDef `yaml:"properties"`
	Required   []string               `yaml:"required"`
}

// PropertyDef defines a configuration property
type PropertyDef struct {
	Type        string      `yaml:"type"`
	Description string      `yaml:"description"`
	Default     interface{} `yaml:"default"`
	Required    bool        `yaml:"required"`
	Validation  string      `yaml:"validation"`
	Enum        []string    `yaml:"enum,omitempty"`
	Min         *float64    `yaml:"min,omitempty"`
	Max         *float64    `yaml:"max,omitempty"`
	Pattern     string      `yaml:"pattern,omitempty"`
}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator(schemaPath string) (*ConfigValidator, error) {
	validator := &ConfigValidator{
		validator:   validator.New(),
		customRules: make(map[string]validator.Func),
	}

	// Load schema if provided
	if schemaPath != "" {
		schema, err := validator.loadSchema(schemaPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load schema: %w", err)
		}
		validator.schema = schema
	}

	// Register custom validation rules
	validator.registerCustomRules()

	return validator, nil
}

// loadSchema loads configuration schema from file
func (cv *ConfigValidator) loadSchema(schemaPath string) (*ConfigSchema, error) {
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read schema file: %w", err)
	}

	var schema ConfigSchema
	if err := yaml.Unmarshal(data, &schema); err != nil {
		return nil, fmt.Errorf("failed to parse schema: %w", err)
	}

	return &schema, nil
}

// registerCustomRules registers custom validation rules
func (cv *ConfigValidator) registerCustomRules() {
	// Register environment validation
	cv.validator.RegisterValidation("environment", cv.validateEnvironment)

	// Register URL validation
	cv.validator.RegisterValidation("url", cv.validateURL)

	// Register duration validation
	cv.validator.RegisterValidation("duration", cv.validateDuration)

	// Register port validation
	cv.validator.RegisterValidation("port", cv.validatePort)
}

// Validate validates configuration data against schema
func (cv *ConfigValidator) Validate(configData map[string]interface{}) error {
	cv.mutex.RLock()
	defer cv.mutex.RUnlock()

	if cv.schema == nil {
		// Basic validation without schema
		return cv.basicValidation(configData)
	}

	// Schema-based validation
	return cv.schemaValidation(configData)
}

// basicValidation performs basic validation without schema
func (cv *ConfigValidator) basicValidation(configData map[string]interface{}) error {
	// Check for required basic fields
	requiredFields := []string{"server", "database"}

	for _, field := range requiredFields {
		if _, exists := configData[field]; !exists {
			return fmt.Errorf("required field missing: %s", field)
		}
	}

	return nil
}

// schemaValidation performs schema-based validation
func (cv *ConfigValidator) schemaValidation(configData map[string]interface{}) error {
	// Check required fields
	for _, required := range cv.schema.Required {
		if _, exists := configData[required]; !exists {
			return fmt.Errorf("required field missing: %s", required)
		}
	}

	// Validate each property
	for key, value := range configData {
		if propDef, exists := cv.schema.Properties[key]; exists {
			if err := cv.validateProperty(key, value, propDef); err != nil {
				return fmt.Errorf("validation failed for %s: %w", key, err)
			}
		}
	}

	return nil
}

// validateProperty validates a single property
func (cv *ConfigValidator) validateProperty(key string, value interface{}, propDef PropertyDef) error {
	// Type validation
	if err := cv.validateType(value, propDef.Type); err != nil {
		return fmt.Errorf("type validation failed: %w", err)
	}

	// Enum validation
	if len(propDef.Enum) > 0 {
		if err := cv.validateEnum(value, propDef.Enum); err != nil {
			return fmt.Errorf("enum validation failed: %w", err)
		}
	}

	// Range validation
	if propDef.Min != nil || propDef.Max != nil {
		if err := cv.validateRange(value, propDef.Min, propDef.Max); err != nil {
			return fmt.Errorf("range validation failed: %w", err)
		}
	}

	return nil
}

// Custom validation functions
func (cv *ConfigValidator) validateEnvironment(fl validator.FieldLevel) bool {
	env := fl.Field().String()
	validEnvs := []string{"development", "staging", "production", "test"}

	for _, validEnv := range validEnvs {
		if env == validEnv {
			return true
		}
	}
	return false
}

func (cv *ConfigValidator) validateURL(fl validator.FieldLevel) bool {
	url := fl.Field().String()
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

func (cv *ConfigValidator) validateDuration(fl validator.FieldLevel) bool {
	duration := fl.Field().String()
	// Simple duration validation
	return strings.HasSuffix(duration, "s") || strings.HasSuffix(duration, "m") || strings.HasSuffix(duration, "h")
}

func (cv *ConfigValidator) validatePort(fl validator.FieldLevel) bool {
	port := fl.Field().Int()
	return port > 0 && port <= 65535
}

// Helper validation methods
func (cv *ConfigValidator) validateType(value interface{}, expectedType string) error {
	switch expectedType {
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("expected string, got %T", value)
		}
	case "int":
		if _, ok := value.(int); !ok {
			return fmt.Errorf("expected int, got %T", value)
		}
	case "bool":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("expected bool, got %T", value)
		}
	case "object":
		if _, ok := value.(map[string]interface{}); !ok {
			return fmt.Errorf("expected object, got %T", value)
		}
	case "array":
		if _, ok := value.([]interface{}); !ok {
			return fmt.Errorf("expected array, got %T", value)
		}
	}
	return nil
}

func (cv *ConfigValidator) validateEnum(value interface{}, enum []string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("enum validation requires string value")
	}

	for _, validValue := range enum {
		if str == validValue {
			return nil
		}
	}

	return fmt.Errorf("value %s not in allowed enum values: %v", str, enum)
}

func (cv *ConfigValidator) validateRange(value interface{}, min, max *float64) error {
	var numValue float64

	switch v := value.(type) {
	case int:
		numValue = float64(v)
	case float64:
		numValue = v
	case float32:
		numValue = float64(v)
	default:
		return fmt.Errorf("range validation requires numeric value")
	}

	if min != nil && numValue < *min {
		return fmt.Errorf("value %f is less than minimum %f", numValue, *min)
	}

	if max != nil && numValue > *max {
		return fmt.Errorf("value %f is greater than maximum %f", numValue, *max)
	}

	return nil
}

// EnvironmentManager manages environment-specific configurations
type EnvironmentManager struct {
	environment string
	namespace   string
	envVars     map[string]string
	mutex       sync.RWMutex
}

// NewEnvironmentManager creates a new environment manager
func NewEnvironmentManager(environment, namespace string) (*EnvironmentManager, error) {
	manager := &EnvironmentManager{
		environment: environment,
		namespace:   namespace,
		envVars:     make(map[string]string),
	}

	// Load environment variables
	manager.loadEnvironmentVariables()

	return manager, nil
}

// loadEnvironmentVariables loads environment variables
func (em *EnvironmentManager) loadEnvironmentVariables() {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	// Load all environment variables
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			em.envVars[parts[0]] = parts[1]
		}
	}
}

// GetEnvironmentVariables returns environment variables
func (em *EnvironmentManager) GetEnvironmentVariables() map[string]string {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	result := make(map[string]string)
	for k, v := range em.envVars {
		result[k] = v
	}
	return result
}

// GetEnvironmentVariable gets a specific environment variable
func (em *EnvironmentManager) GetEnvironmentVariable(key string) (string, bool) {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	value, exists := em.envVars[key]
	return value, exists
}

// SecretsManager manages secrets from various providers
type SecretsManager struct {
	provider    string
	environment string
	secrets     map[string]string
	mutex       sync.RWMutex
}

// NewSecretsManager creates a new secrets manager
func NewSecretsManager(provider, environment string) (*SecretsManager, error) {
	manager := &SecretsManager{
		provider:    provider,
		environment: environment,
		secrets:     make(map[string]string),
	}

	return manager, nil
}

// LoadSecrets loads secrets from the configured provider
func (sm *SecretsManager) LoadSecrets(ctx context.Context) (map[string]string, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	switch sm.provider {
	case "env":
		return sm.loadFromEnvironment()
	case "file":
		return sm.loadFromFile()
	case "vault":
		return sm.loadFromVault(ctx)
	case "k8s":
		return sm.loadFromKubernetes(ctx)
	default:
		return nil, fmt.Errorf("unsupported secrets provider: %s", sm.provider)
	}
}

// loadFromEnvironment loads secrets from environment variables
func (sm *SecretsManager) loadFromEnvironment() (map[string]string, error) {
	secrets := make(map[string]string)

	// Load secrets with specific prefixes
	secretPrefixes := []string{"SECRET_", "PASSWORD_", "KEY_", "TOKEN_"}

	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := parts[1]

		for _, prefix := range secretPrefixes {
			if strings.HasPrefix(key, prefix) {
				// Convert to config key format
				configKey := strings.ToLower(strings.TrimPrefix(key, prefix))
				configKey = strings.ReplaceAll(configKey, "_", ".")
				secrets[configKey] = value
				break
			}
		}
	}

	return secrets, nil
}

// loadFromFile loads secrets from file
func (sm *SecretsManager) loadFromFile() (map[string]string, error) {
	secretsFile := fmt.Sprintf("secrets/%s.yaml", sm.environment)

	data, err := os.ReadFile(secretsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]string), nil // No secrets file is OK
		}
		return nil, fmt.Errorf("failed to read secrets file: %w", err)
	}

	var secrets map[string]string
	if err := yaml.Unmarshal(data, &secrets); err != nil {
		return nil, fmt.Errorf("failed to parse secrets file: %w", err)
	}

	return secrets, nil
}

// loadFromVault loads secrets from HashiCorp Vault
func (sm *SecretsManager) loadFromVault(ctx context.Context) (map[string]string, error) {
	// Placeholder implementation for Vault integration
	// In a real implementation, this would use the Vault API
	return make(map[string]string), nil
}

// loadFromKubernetes loads secrets from Kubernetes secrets
func (sm *SecretsManager) loadFromKubernetes(ctx context.Context) (map[string]string, error) {
	// Placeholder implementation for Kubernetes secrets integration
	// In a real implementation, this would use the Kubernetes API
	return make(map[string]string), nil
}

// GetSecret gets a specific secret
func (sm *SecretsManager) GetSecret(key string) (string, bool) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	value, exists := sm.secrets[key]
	return value, exists
}

// SetSecret sets a secret value
func (sm *SecretsManager) SetSecret(key, value string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	sm.secrets[key] = value
}

// ValidationResult represents the result of configuration validation
type ValidationResult struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

// ValidateConfig validates the entire configuration
func ValidateConfig(config *Config) *ValidationResult {
	// Perform basic validation
	errors := make([]string, 0)
	warnings := make([]string, 0)

	// Basic validation checks
	if config.Server.Port == "" {
		errors = append(errors, "server.port is required")
	}
	if config.Database.Host == "" {
		errors = append(errors, "database.host is required")
	}
	if config.Database.Name == "" {
		errors = append(errors, "database.name is required")
	}
	if config.Redis.Host == "" {
		errors = append(errors, "redis.host is required")
	}
	if config.JWT.Secret == "" {
		errors = append(errors, "jwt.secret is required")
	}

	// Warnings
	if len(config.JWT.Secret) < 32 {
		warnings = append(warnings, "jwt.secret should be at least 32 characters")
	}

	return &ValidationResult{
		Valid:    len(errors) == 0,
		Errors:   errors,
		Warnings: warnings,
	}
}

// FeatureFlag represents a feature flag
type FeatureFlag struct {
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
}

// FeatureFlagsManager manages feature flags
type FeatureFlagsManager struct {
	flags map[string]FeatureFlag
	mutex sync.RWMutex
}

// NewFeatureFlagsManager creates a new feature flags manager
func NewFeatureFlagsManager() *FeatureFlagsManager {
	manager := &FeatureFlagsManager{
		flags: make(map[string]FeatureFlag),
	}

	// Initialize default flags
	manager.initializeDefaultFlags()

	return manager
}

// IsEnabled checks if a feature flag is enabled
func (ffm *FeatureFlagsManager) IsEnabled(flagName string) bool {
	ffm.mutex.RLock()
	defer ffm.mutex.RUnlock()

	flag, exists := ffm.flags[flagName]
	return exists && flag.Enabled
}

// SetFlag sets a feature flag
func (ffm *FeatureFlagsManager) SetFlag(flag FeatureFlag) {
	ffm.mutex.Lock()
	defer ffm.mutex.Unlock()

	ffm.flags[flag.Name] = flag
}

// initializeDefaultFlags initializes default feature flags
func (ffm *FeatureFlagsManager) initializeDefaultFlags() {
	defaultFlags := []FeatureFlag{
		{Name: "debug.mode", Enabled: false, Description: "Enable debug mode"},
		{Name: "security.enhanced.logging", Enabled: true, Description: "Enable enhanced security logging"},
		{Name: "ai.llm.proxy", Enabled: true, Description: "Enable LLM security proxy"},
		{Name: "monitoring.detailed.metrics", Enabled: true, Description: "Enable detailed metrics"},
		{Name: "cache.redis.enabled", Enabled: true, Description: "Enable Redis caching"},
	}

	for _, flag := range defaultFlags {
		ffm.flags[flag.Name] = flag
	}
}
