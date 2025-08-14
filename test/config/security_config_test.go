package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockLogger implements the Logger interface for testing
type MockLogger struct {
	logs []LogEntry
}

type LogEntry struct {
	Level   string
	Message string
	Fields  []interface{}
}

func (m *MockLogger) Info(msg string, fields ...interface{}) {
	m.logs = append(m.logs, LogEntry{Level: "info", Message: msg, Fields: fields})
}

func (m *MockLogger) Error(msg string, fields ...interface{}) {
	m.logs = append(m.logs, LogEntry{Level: "error", Message: msg, Fields: fields})
}

func (m *MockLogger) Warn(msg string, fields ...interface{}) {
	m.logs = append(m.logs, LogEntry{Level: "warn", Message: msg, Fields: fields})
}

// MockConfigWatcher implements the ConfigWatcher interface for testing
type MockConfigWatcher struct {
	changeCount int
	lastConfig  *config.UnifiedSecurityConfig
}

func (m *MockConfigWatcher) OnConfigChange(cfg *config.UnifiedSecurityConfig) error {
	m.changeCount++
	m.lastConfig = cfg
	return nil
}

func TestSecurityConfigManager(t *testing.T) {
	// Create temporary directory for test configs
	tempDir, err := os.MkdirTemp("", "security_config_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "security.yaml")
	logger := &MockLogger{}

	t.Run("Create Security Config Manager", func(t *testing.T) {
		manager := config.NewSecurityConfigManager(configPath, logger)
		assert.NotNil(t, manager)
	})

	t.Run("Load Configuration from Template", func(t *testing.T) {
		manager := config.NewSecurityConfigManager(configPath, logger)

		// Create a test configuration file
		testConfig := config.GetSecurityTemplate(config.ProfileDevelopment)
		loader := config.NewSecurityConfigLoader(configPath, "development")
		err := loader.SaveConfiguration(testConfig, configPath)
		require.NoError(t, err)

		// Load configuration
		err = manager.LoadConfig()
		require.NoError(t, err)

		loadedConfig := manager.GetConfig()
		assert.NotNil(t, loadedConfig)
		assert.Equal(t, "development", loadedConfig.Environment)
		assert.True(t, loadedConfig.AgenticFramework.Enabled)
	})

	t.Run("Configuration Validation", func(t *testing.T) {
		manager := config.NewSecurityConfigManager(configPath, logger)

		// Test invalid configuration
		invalidConfig := &config.UnifiedSecurityConfig{
			Version:     "", // Missing version
			Environment: "test",
		}

		err := manager.UpdateConfig(invalidConfig)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "config version is required")
	})

	t.Run("Configuration Watchers", func(t *testing.T) {
		manager := config.NewSecurityConfigManager(configPath, logger)
		watcher := &MockConfigWatcher{}

		// Add watcher
		manager.AddWatcher(watcher)

		// Load initial config
		testConfig := config.GetSecurityTemplate(config.ProfileProduction)
		err := manager.UpdateConfig(testConfig)
		require.NoError(t, err)

		// Verify watcher was notified
		assert.Equal(t, 1, watcher.changeCount)
		assert.NotNil(t, watcher.lastConfig)
		assert.Equal(t, "production", watcher.lastConfig.Environment)

		// Remove watcher
		manager.RemoveWatcher(watcher)

		// Update config again
		testConfig.Version = "2.0.0"
		err = manager.UpdateConfig(testConfig)
		require.NoError(t, err)

		// Verify watcher was not notified again
		assert.Equal(t, 1, watcher.changeCount)
	})

	t.Run("Feature Toggle Updates", func(t *testing.T) {
		manager := config.NewSecurityConfigManager(configPath, logger)
		testConfig := config.GetSecurityTemplate(config.ProfileProduction)
		err := manager.UpdateConfig(testConfig)
		require.NoError(t, err)

		// Update feature toggle
		err = manager.UpdateFeatureToggle("advanced_threat_detection", false)
		require.NoError(t, err)

		updatedConfig := manager.GetConfig()
		assert.False(t, updatedConfig.FeatureToggles.SecurityFeatures["advanced_threat_detection"])
	})

	t.Run("Threshold Updates", func(t *testing.T) {
		manager := config.NewSecurityConfigManager(configPath, logger)
		testConfig := config.GetSecurityTemplate(config.ProfileProduction)
		err := manager.UpdateConfig(testConfig)
		require.NoError(t, err)

		// Update agentic framework threshold
		err = manager.UpdateThreshold("agentic_framework", "threat_response", 0.9)
		require.NoError(t, err)

		updatedConfig := manager.GetConfig()
		assert.Equal(t, 0.9, updatedConfig.AgenticFramework.ThreatResponseThreshold)

		// Update AI firewall threshold
		err = manager.UpdateThreshold("ai_firewall", "block", 0.8)
		require.NoError(t, err)

		updatedConfig = manager.GetConfig()
		assert.Equal(t, 0.8, updatedConfig.AIFirewall.BlockThreshold)

		// Test invalid threshold
		err = manager.UpdateThreshold("ai_firewall", "block", 1.5)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "threshold value must be between 0 and 1")
	})

	t.Run("Maintenance Mode", func(t *testing.T) {
		manager := config.NewSecurityConfigManager(configPath, logger)
		testConfig := config.GetSecurityTemplate(config.ProfileProduction)
		err := manager.UpdateConfig(testConfig)
		require.NoError(t, err)

		// Enable maintenance mode
		err = manager.EnableMaintenanceMode(true)
		require.NoError(t, err)

		updatedConfig := manager.GetConfig()
		assert.True(t, updatedConfig.FeatureToggles.MaintenanceMode)

		// Disable maintenance mode
		err = manager.EnableMaintenanceMode(false)
		require.NoError(t, err)

		updatedConfig = manager.GetConfig()
		assert.False(t, updatedConfig.FeatureToggles.MaintenanceMode)
	})

	t.Run("Configuration Summary", func(t *testing.T) {
		manager := config.NewSecurityConfigManager(configPath, logger)
		testConfig := config.GetSecurityTemplate(config.ProfileProduction)
		err := manager.UpdateConfig(testConfig)
		require.NoError(t, err)

		summary := manager.GetConfigSummary()
		assert.NotNil(t, summary)
		assert.Equal(t, "production", summary["environment"])
		assert.NotNil(t, summary["components"])
		assert.NotNil(t, summary["feature_toggles"])
	})

	t.Run("Save and Load Configuration", func(t *testing.T) {
		manager := config.NewSecurityConfigManager(configPath, logger)
		testConfig := config.GetSecurityTemplate(config.ProfileHighSecurity)

		// Update some values
		testConfig.AgenticFramework.ThreatResponseThreshold = 0.6
		testConfig.AIFirewall.BlockThreshold = 0.5

		err := manager.UpdateConfig(testConfig)
		require.NoError(t, err)

		// Save configuration
		err = manager.SaveConfig()
		require.NoError(t, err)

		// Create new manager and load
		newManager := config.NewSecurityConfigManager(configPath, logger)
		err = newManager.LoadConfig()
		require.NoError(t, err)

		loadedConfig := newManager.GetConfig()
		assert.Equal(t, 0.6, loadedConfig.AgenticFramework.ThreatResponseThreshold)
		assert.Equal(t, 0.5, loadedConfig.AIFirewall.BlockThreshold)
	})
}

func TestSecurityTemplates(t *testing.T) {
	t.Run("Development Template", func(t *testing.T) {
		config := config.GetSecurityTemplate(config.ProfileDevelopment)
		assert.NotNil(t, config)
		assert.Equal(t, "development", config.Environment)
		assert.True(t, config.AgenticFramework.Enabled)
		assert.False(t, config.AgenticFramework.AutoBlockEnabled) // Should be disabled in dev
		assert.False(t, config.ThreatIntelligence.Enabled)        // Should be disabled in dev
		assert.Equal(t, "basic", config.InputOutputFilter.SanitizationLevel)
	})

	t.Run("Production Template", func(t *testing.T) {
		config := config.GetSecurityTemplate(config.ProfileProduction)
		assert.NotNil(t, config)
		assert.Equal(t, "production", config.Environment)
		assert.True(t, config.AgenticFramework.Enabled)
		assert.True(t, config.AgenticFramework.AutoBlockEnabled)
		assert.True(t, config.ThreatIntelligence.Enabled)
		assert.Equal(t, "strict", config.InputOutputFilter.SanitizationLevel)
		assert.True(t, config.WebLayer.HSTS.Enabled)
	})

	t.Run("High Security Template", func(t *testing.T) {
		config := config.GetSecurityTemplate(config.ProfileHighSecurity)
		assert.NotNil(t, config)
		assert.Equal(t, "high_security", config.Environment)
		assert.Equal(t, 0.5, config.AgenticFramework.ThreatResponseThreshold) // Lower threshold = more sensitive
		assert.Equal(t, 0.5, config.AIFirewall.BlockThreshold)
		assert.Equal(t, 16, config.Authentication.PasswordPolicy.MinLength)
		assert.Equal(t, 3, config.Authentication.AccountLockout.MaxFailedAttempts)
	})

	t.Run("Compliance Template", func(t *testing.T) {
		config := config.GetSecurityTemplate(config.ProfileCompliance)
		assert.NotNil(t, config)
		assert.Equal(t, "compliance", config.Environment)
		assert.True(t, config.Compliance.GDPR.Enabled)
		assert.True(t, config.Compliance.HIPAA.Enabled)
		assert.True(t, config.Compliance.SOX.Enabled)
		assert.True(t, config.Compliance.PCI.Enabled)
		assert.True(t, config.Compliance.Auditing.Enabled)
		assert.True(t, config.Logging.AuditLogs)
		assert.True(t, config.Logging.Encryption)
	})
}

func TestSecurityConfigLoader(t *testing.T) {
	// Create temporary directory for test configs
	tempDir, err := os.MkdirTemp("", "security_loader_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "security.yaml")

	t.Run("Load from Template", func(t *testing.T) {
		loader := config.NewSecurityConfigLoader(configPath, "production")

		// Load configuration (should use template since file doesn't exist)
		cfg, err := loader.LoadSecurityConfig()
		require.NoError(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, "production", cfg.Environment)
	})

	t.Run("Environment Variable Overrides", func(t *testing.T) {
		// Set environment variables
		os.Setenv("SECURITY_AGENTIC_ENABLED", "false")
		os.Setenv("SECURITY_FIREWALL_BLOCK_THRESHOLD", "0.9")
		os.Setenv("SECURITY_LOG_LEVEL", "debug")
		defer func() {
			os.Unsetenv("SECURITY_AGENTIC_ENABLED")
			os.Unsetenv("SECURITY_FIREWALL_BLOCK_THRESHOLD")
			os.Unsetenv("SECURITY_LOG_LEVEL")
		}()

		loader := config.NewSecurityConfigLoader(configPath, "production")
		cfg, err := loader.LoadSecurityConfig()
		require.NoError(t, err)

		assert.False(t, cfg.AgenticFramework.Enabled)
		assert.Equal(t, 0.9, cfg.AIFirewall.BlockThreshold)
		assert.Equal(t, "debug", cfg.Logging.Level)
	})

	t.Run("Generate Configuration Template", func(t *testing.T) {
		loader := config.NewSecurityConfigLoader(configPath, "staging")
		outputPath := filepath.Join(tempDir, "staging-template.yaml")

		err := loader.GenerateConfigTemplate("staging", outputPath)
		require.NoError(t, err)

		// Verify file was created
		_, err = os.Stat(outputPath)
		assert.NoError(t, err)

		// Load and verify content
		cfg, err := loader.LoadSecurityConfig()
		require.NoError(t, err)
		assert.Equal(t, "staging", cfg.Environment)
	})

	t.Run("Environment Variables List", func(t *testing.T) {
		loader := config.NewSecurityConfigLoader(configPath, "production")
		envVars := loader.GetEnvironmentVariablesList()

		assert.NotEmpty(t, envVars)
		assert.Contains(t, envVars, "SECURITY_AGENTIC_ENABLED")
		assert.Contains(t, envVars, "SECURITY_FIREWALL_BLOCK_THRESHOLD")
		assert.Contains(t, envVars, "SECURITY_LOG_LEVEL")
	})

	t.Run("Configuration Validation", func(t *testing.T) {
		loader := config.NewSecurityConfigLoader(configPath, "production")

		// Create invalid config file
		invalidConfig := map[string]interface{}{
			"version":     "1.0.0",
			"environment": "test",
			"agentic_framework": map[string]interface{}{
				"threat_response_threshold": 1.5, // Invalid threshold
			},
		}

		data, _ := json.Marshal(invalidConfig)
		err := os.WriteFile(configPath, data, 0644)
		require.NoError(t, err)

		// Try to load - should fail validation
		_, err = loader.LoadSecurityConfig()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
	})
}

func TestConfigurationOverrides(t *testing.T) {
	// Create temporary directory for test configs
	tempDir, err := os.MkdirTemp("", "security_overrides_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "security.yaml")
	overridesPath := filepath.Join(tempDir, "overrides-test.yaml")

	t.Run("File-based Overrides", func(t *testing.T) {
		// Create base configuration
		baseConfig := config.GetSecurityTemplate(config.ProfileProduction)
		loader := config.NewSecurityConfigLoader(configPath, "test")
		err := loader.SaveConfiguration(baseConfig, configPath)
		require.NoError(t, err)

		// Create overrides file
		overrides := map[string]interface{}{
			"agentic_framework": map[string]interface{}{
				"threat_response_threshold": 0.9,
				"auto_block_enabled":        false,
			},
			"ai_firewall": map[string]interface{}{
				"block_threshold": 0.8,
			},
		}

		overrideData, _ := json.Marshal(overrides)
		err = os.WriteFile(overridesPath, overrideData, 0644)
		require.NoError(t, err)

		// Load configuration with overrides
		cfg, err := loader.LoadSecurityConfig()
		require.NoError(t, err)

		// Verify overrides were applied
		assert.Equal(t, 0.9, cfg.AgenticFramework.ThreatResponseThreshold)
		assert.False(t, cfg.AgenticFramework.AutoBlockEnabled)
		assert.Equal(t, 0.8, cfg.AIFirewall.BlockThreshold)
	})
}
