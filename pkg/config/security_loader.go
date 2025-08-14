package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SecurityConfigLoader loads and manages security configurations
type SecurityConfigLoader struct {
	baseConfigPath string
	environment    string
	overridesPath  string
}

// NewSecurityConfigLoader creates a new security configuration loader
func NewSecurityConfigLoader(baseConfigPath, environment string) *SecurityConfigLoader {
	return &SecurityConfigLoader{
		baseConfigPath: baseConfigPath,
		environment:    environment,
		overridesPath:  filepath.Join(filepath.Dir(baseConfigPath), fmt.Sprintf("overrides-%s.yaml", environment)),
	}
}

// LoadSecurityConfig loads security configuration with environment-specific overrides
func (scl *SecurityConfigLoader) LoadSecurityConfig() (*UnifiedSecurityConfig, error) {
	var config *UnifiedSecurityConfig

	// First, try to load from file
	if _, err := os.Stat(scl.baseConfigPath); err == nil {
		config, err = scl.loadFromFile(scl.baseConfigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load base config: %w", err)
		}
	} else {
		// If no file exists, use template based on environment
		profile := SecurityProfile(scl.environment)
		config = GetSecurityTemplate(profile)
	}

	// Apply environment-specific overrides from file
	if _, err := os.Stat(scl.overridesPath); err == nil {
		overrides, err := scl.loadOverridesFromFile(scl.overridesPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load overrides: %w", err)
		}
		config = scl.applyOverrides(config, overrides)
	}

	// Apply environment variable overrides
	config = scl.applyEnvironmentVariables(config)

	// Validate final configuration
	if err := scl.validateConfiguration(config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// loadFromFile loads configuration from a file
func (scl *SecurityConfigLoader) loadFromFile(path string) (*UnifiedSecurityConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config UnifiedSecurityConfig
	ext := filepath.Ext(path)

	switch ext {
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, &config)
	case ".json":
		err = json.Unmarshal(data, &config)
	default:
		return nil, fmt.Errorf("unsupported config file format: %s", ext)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// loadOverridesFromFile loads configuration overrides from a file
func (scl *SecurityConfigLoader) loadOverridesFromFile(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read overrides file: %w", err)
	}

	var overrides map[string]interface{}
	ext := filepath.Ext(path)

	switch ext {
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, &overrides)
	case ".json":
		err = json.Unmarshal(data, &overrides)
	default:
		return nil, fmt.Errorf("unsupported overrides file format: %s", ext)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse overrides file: %w", err)
	}

	return overrides, nil
}

// applyOverrides applies configuration overrides
func (scl *SecurityConfigLoader) applyOverrides(config *UnifiedSecurityConfig, overrides map[string]interface{}) *UnifiedSecurityConfig {
	// Convert config to map for easier manipulation
	configData, _ := json.Marshal(config)
	var configMap map[string]interface{}
	json.Unmarshal(configData, &configMap)

	// Apply overrides recursively
	scl.mergeMap(configMap, overrides)

	// Convert back to struct
	updatedData, _ := json.Marshal(configMap)
	var updatedConfig UnifiedSecurityConfig
	json.Unmarshal(updatedData, &updatedConfig)

	return &updatedConfig
}

// mergeMap recursively merges two maps
func (scl *SecurityConfigLoader) mergeMap(dst, src map[string]interface{}) {
	for key, value := range src {
		if srcMap, ok := value.(map[string]interface{}); ok {
			if dstMap, ok := dst[key].(map[string]interface{}); ok {
				scl.mergeMap(dstMap, srcMap)
			} else {
				dst[key] = srcMap
			}
		} else {
			dst[key] = value
		}
	}
}

// applyEnvironmentVariables applies environment variable overrides
func (scl *SecurityConfigLoader) applyEnvironmentVariables(config *UnifiedSecurityConfig) *UnifiedSecurityConfig {
	// Agentic Framework overrides
	if val := os.Getenv("SECURITY_AGENTIC_ENABLED"); val != "" {
		if enabled, err := strconv.ParseBool(val); err == nil {
			config.AgenticFramework.Enabled = enabled
		}
	}
	if val := os.Getenv("SECURITY_AGENTIC_THRESHOLD"); val != "" {
		if threshold, err := strconv.ParseFloat(val, 64); err == nil {
			config.AgenticFramework.ThreatResponseThreshold = threshold
		}
	}
	if val := os.Getenv("SECURITY_AGENTIC_AUTO_BLOCK"); val != "" {
		if autoBlock, err := strconv.ParseBool(val); err == nil {
			config.AgenticFramework.AutoBlockEnabled = autoBlock
		}
	}

	// AI Firewall overrides
	if val := os.Getenv("SECURITY_FIREWALL_ENABLED"); val != "" {
		if enabled, err := strconv.ParseBool(val); err == nil {
			config.AIFirewall.Enabled = enabled
		}
	}
	if val := os.Getenv("SECURITY_FIREWALL_BLOCK_THRESHOLD"); val != "" {
		if threshold, err := strconv.ParseFloat(val, 64); err == nil {
			config.AIFirewall.BlockThreshold = threshold
		}
	}
	if val := os.Getenv("SECURITY_FIREWALL_ALERT_THRESHOLD"); val != "" {
		if threshold, err := strconv.ParseFloat(val, 64); err == nil {
			config.AIFirewall.AlertThreshold = threshold
		}
	}

	// Input/Output Filter overrides
	if val := os.Getenv("SECURITY_FILTER_ENABLED"); val != "" {
		if enabled, err := strconv.ParseBool(val); err == nil {
			config.InputOutputFilter.Enabled = enabled
		}
	}
	if val := os.Getenv("SECURITY_FILTER_STRICT_MODE"); val != "" {
		if strict, err := strconv.ParseBool(val); err == nil {
			config.InputOutputFilter.StrictMode = strict
		}
	}
	if val := os.Getenv("SECURITY_FILTER_MAX_INPUT_LENGTH"); val != "" {
		if length, err := strconv.Atoi(val); err == nil {
			config.InputOutputFilter.MaxInputLength = length
		}
	}

	// Prompt Guard overrides
	if val := os.Getenv("SECURITY_PROMPT_GUARD_ENABLED"); val != "" {
		if enabled, err := strconv.ParseBool(val); err == nil {
			config.PromptGuard.Enabled = enabled
		}
	}
	if val := os.Getenv("SECURITY_PROMPT_GUARD_THRESHOLD"); val != "" {
		if threshold, err := strconv.ParseFloat(val, 64); err == nil {
			config.PromptGuard.ConfidenceThreshold = threshold
		}
	}

	// Web Layer overrides
	if val := os.Getenv("SECURITY_WEB_LAYER_ENABLED"); val != "" {
		if enabled, err := strconv.ParseBool(val); err == nil {
			config.WebLayer.Enabled = enabled
		}
	}
	if val := os.Getenv("SECURITY_WEB_LAYER_MAX_REQUEST_SIZE"); val != "" {
		if size, err := strconv.ParseInt(val, 10, 64); err == nil {
			config.WebLayer.MaxRequestSize = size
		}
	}
	if val := os.Getenv("SECURITY_WEB_LAYER_REQUEST_TIMEOUT"); val != "" {
		if timeout, err := time.ParseDuration(val); err == nil {
			config.WebLayer.RequestTimeout = timeout
		}
	}

	// CSP overrides
	if val := os.Getenv("SECURITY_CSP_ENABLED"); val != "" {
		if enabled, err := strconv.ParseBool(val); err == nil {
			config.WebLayer.CSP.Enabled = enabled
		}
	}
	if val := os.Getenv("SECURITY_CSP_POLICY"); val != "" {
		config.WebLayer.CSP.Policy = val
	}

	// HSTS overrides
	if val := os.Getenv("SECURITY_HSTS_ENABLED"); val != "" {
		if enabled, err := strconv.ParseBool(val); err == nil {
			config.WebLayer.HSTS.Enabled = enabled
		}
	}
	if val := os.Getenv("SECURITY_HSTS_MAX_AGE"); val != "" {
		if maxAge, err := strconv.Atoi(val); err == nil {
			config.WebLayer.HSTS.MaxAge = maxAge
		}
	}

	// Authentication overrides
	if val := os.Getenv("SECURITY_PASSWORD_MIN_LENGTH"); val != "" {
		if length, err := strconv.Atoi(val); err == nil {
			config.Authentication.PasswordPolicy.MinLength = length
		}
	}
	if val := os.Getenv("SECURITY_MFA_ENABLED"); val != "" {
		if enabled, err := strconv.ParseBool(val); err == nil {
			config.Authentication.MultiFactorAuth.Enabled = enabled
		}
	}
	if val := os.Getenv("SECURITY_MFA_REQUIRED"); val != "" {
		if required, err := strconv.ParseBool(val); err == nil {
			config.Authentication.MultiFactorAuth.Required = required
		}
	}

	// Session management overrides
	if val := os.Getenv("SECURITY_SESSION_TIMEOUT"); val != "" {
		if timeout, err := time.ParseDuration(val); err == nil {
			config.Authentication.SessionManagement.Timeout = timeout
		}
	}
	if val := os.Getenv("SECURITY_SESSION_SECURE_COOKIES"); val != "" {
		if secure, err := strconv.ParseBool(val); err == nil {
			config.Authentication.SessionManagement.SecureCookies = secure
		}
	}

	// Monitoring overrides
	if val := os.Getenv("SECURITY_MONITORING_ENABLED"); val != "" {
		if enabled, err := strconv.ParseBool(val); err == nil {
			config.Monitoring.Enabled = enabled
		}
	}
	if val := os.Getenv("SECURITY_METRICS_ENABLED"); val != "" {
		if enabled, err := strconv.ParseBool(val); err == nil {
			config.Monitoring.MetricsEnabled = enabled
		}
	}
	if val := os.Getenv("SECURITY_TRACING_ENABLED"); val != "" {
		if enabled, err := strconv.ParseBool(val); err == nil {
			config.Monitoring.TracingEnabled = enabled
		}
	}

	// Alerting overrides
	if val := os.Getenv("SECURITY_ALERTING_ENABLED"); val != "" {
		if enabled, err := strconv.ParseBool(val); err == nil {
			config.Alerting.Enabled = enabled
		}
	}

	// Logging overrides
	if val := os.Getenv("SECURITY_LOG_LEVEL"); val != "" {
		config.Logging.Level = val
	}
	if val := os.Getenv("SECURITY_LOG_FORMAT"); val != "" {
		config.Logging.Format = val
	}
	if val := os.Getenv("SECURITY_LOG_OUTPUT"); val != "" {
		config.Logging.Output = strings.Split(val, ",")
	}

	// Feature toggles overrides
	if val := os.Getenv("SECURITY_MAINTENANCE_MODE"); val != "" {
		if maintenance, err := strconv.ParseBool(val); err == nil {
			config.FeatureToggles.MaintenanceMode = maintenance
		}
	}
	if val := os.Getenv("SECURITY_DEBUG_MODE"); val != "" {
		if debug, err := strconv.ParseBool(val); err == nil {
			config.FeatureToggles.DebugMode = debug
		}
	}

	// Threat Intelligence overrides
	if val := os.Getenv("SECURITY_THREAT_INTEL_ENABLED"); val != "" {
		if enabled, err := strconv.ParseBool(val); err == nil {
			config.ThreatIntelligence.Enabled = enabled
		}
	}
	if val := os.Getenv("SECURITY_THREAT_INTEL_UPDATE_INTERVAL"); val != "" {
		if interval, err := time.ParseDuration(val); err == nil {
			config.ThreatIntelligence.UpdateInterval = interval
		}
	}
	if val := os.Getenv("SECURITY_THREAT_INTEL_SOURCES"); val != "" {
		config.ThreatIntelligence.Sources = strings.Split(val, ",")
	}

	return config
}

// validateConfiguration validates the loaded configuration
func (scl *SecurityConfigLoader) validateConfiguration(config *UnifiedSecurityConfig) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Validate version
	if config.Version == "" {
		return fmt.Errorf("configuration version is required")
	}

	// Validate environment
	if config.Environment == "" {
		return fmt.Errorf("configuration environment is required")
	}

	// Validate thresholds
	if config.AgenticFramework.ThreatResponseThreshold < 0 || config.AgenticFramework.ThreatResponseThreshold > 1 {
		return fmt.Errorf("agentic framework threat response threshold must be between 0 and 1")
	}

	if config.AIFirewall.BlockThreshold < 0 || config.AIFirewall.BlockThreshold > 1 {
		return fmt.Errorf("AI firewall block threshold must be between 0 and 1")
	}

	if config.AIFirewall.AlertThreshold < 0 || config.AIFirewall.AlertThreshold > 1 {
		return fmt.Errorf("AI firewall alert threshold must be between 0 and 1")
	}

	if config.PromptGuard.ConfidenceThreshold < 0 || config.PromptGuard.ConfidenceThreshold > 1 {
		return fmt.Errorf("prompt guard confidence threshold must be between 0 and 1")
	}

	// Validate lengths and sizes
	if config.InputOutputFilter.MaxInputLength < 0 {
		return fmt.Errorf("max input length cannot be negative")
	}

	if config.InputOutputFilter.MaxOutputLength < 0 {
		return fmt.Errorf("max output length cannot be negative")
	}

	if config.WebLayer.MaxRequestSize < 0 {
		return fmt.Errorf("max request size cannot be negative")
	}

	if config.PromptGuard.MaxPromptLength < 0 {
		return fmt.Errorf("max prompt length cannot be negative")
	}

	// Validate durations
	if config.AgenticFramework.ThreatRetentionDuration < 0 {
		return fmt.Errorf("threat retention duration cannot be negative")
	}

	if config.AgenticFramework.AlertCooldownPeriod < 0 {
		return fmt.Errorf("alert cooldown period cannot be negative")
	}

	if config.ThreatIntelligence.UpdateInterval < time.Minute {
		return fmt.Errorf("threat intelligence update interval must be at least 1 minute")
	}

	if config.WebLayer.RequestTimeout < time.Second {
		return fmt.Errorf("request timeout must be at least 1 second")
	}

	// Validate authentication settings
	if config.Authentication.PasswordPolicy.MinLength < 4 {
		return fmt.Errorf("minimum password length must be at least 4")
	}

	if config.Authentication.SessionManagement.Timeout < time.Minute {
		return fmt.Errorf("session timeout must be at least 1 minute")
	}

	if config.Authentication.AccountLockout.MaxFailedAttempts < 1 {
		return fmt.Errorf("max failed attempts must be at least 1")
	}

	// Validate HSTS settings
	if config.WebLayer.HSTS.Enabled && config.WebLayer.HSTS.MaxAge < 0 {
		return fmt.Errorf("HSTS max age cannot be negative when HSTS is enabled")
	}

	// Validate monitoring settings
	if config.Monitoring.SampleRate < 0 || config.Monitoring.SampleRate > 1 {
		return fmt.Errorf("monitoring sample rate must be between 0 and 1")
	}

	return nil
}

// SaveConfiguration saves configuration to file
func (scl *SecurityConfigLoader) SaveConfiguration(config *UnifiedSecurityConfig, path string) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	var data []byte
	var err error
	ext := filepath.Ext(path)

	switch ext {
	case ".yaml", ".yml":
		data, err = yaml.Marshal(config)
	case ".json":
		data, err = json.MarshalIndent(config, "", "  ")
	default:
		return fmt.Errorf("unsupported config file format: %s", ext)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GenerateConfigTemplate generates a configuration template for the specified environment
func (scl *SecurityConfigLoader) GenerateConfigTemplate(environment string, outputPath string) error {
	profile := SecurityProfile(environment)
	config := GetSecurityTemplate(profile)

	return scl.SaveConfiguration(config, outputPath)
}

// GetEnvironmentVariablesList returns a list of all supported environment variables
func (scl *SecurityConfigLoader) GetEnvironmentVariablesList() []string {
	return []string{
		"SECURITY_AGENTIC_ENABLED",
		"SECURITY_AGENTIC_THRESHOLD",
		"SECURITY_AGENTIC_AUTO_BLOCK",
		"SECURITY_FIREWALL_ENABLED",
		"SECURITY_FIREWALL_BLOCK_THRESHOLD",
		"SECURITY_FIREWALL_ALERT_THRESHOLD",
		"SECURITY_FILTER_ENABLED",
		"SECURITY_FILTER_STRICT_MODE",
		"SECURITY_FILTER_MAX_INPUT_LENGTH",
		"SECURITY_PROMPT_GUARD_ENABLED",
		"SECURITY_PROMPT_GUARD_THRESHOLD",
		"SECURITY_WEB_LAYER_ENABLED",
		"SECURITY_WEB_LAYER_MAX_REQUEST_SIZE",
		"SECURITY_WEB_LAYER_REQUEST_TIMEOUT",
		"SECURITY_CSP_ENABLED",
		"SECURITY_CSP_POLICY",
		"SECURITY_HSTS_ENABLED",
		"SECURITY_HSTS_MAX_AGE",
		"SECURITY_PASSWORD_MIN_LENGTH",
		"SECURITY_MFA_ENABLED",
		"SECURITY_MFA_REQUIRED",
		"SECURITY_SESSION_TIMEOUT",
		"SECURITY_SESSION_SECURE_COOKIES",
		"SECURITY_MONITORING_ENABLED",
		"SECURITY_METRICS_ENABLED",
		"SECURITY_TRACING_ENABLED",
		"SECURITY_ALERTING_ENABLED",
		"SECURITY_LOG_LEVEL",
		"SECURITY_LOG_FORMAT",
		"SECURITY_LOG_OUTPUT",
		"SECURITY_MAINTENANCE_MODE",
		"SECURITY_DEBUG_MODE",
		"SECURITY_THREAT_INTEL_ENABLED",
		"SECURITY_THREAT_INTEL_UPDATE_INTERVAL",
		"SECURITY_THREAT_INTEL_SOURCES",
	}
}
