package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// AdvancedConfigManager provides comprehensive configuration management
type AdvancedConfigManager struct {
	id          string
	configPaths []string
	environment string
	namespace   string

	// Configuration instances
	configs      map[string]*viper.Viper
	mergedConfig *viper.Viper

	// Validation and schema
	validator *ConfigValidator
	schema    *ConfigSchema

	// Hot reload and watching
	watcher         *fsnotify.Watcher
	watchEnabled    bool
	reloadCallbacks []ConfigReloadCallback

	// Environment management
	envManager     *EnvironmentManager
	secretsManager *SecretsManager

	// Configuration state
	isInitialized bool
	lastReload    time.Time
	reloadCount   int

	// Concurrency control
	mutex  sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
}

// ConfigReloadCallback defines callback for configuration reload events
type ConfigReloadCallback func(oldConfig, newConfig *viper.Viper) error

// AdvancedConfigOptions configuration options for the manager
type AdvancedConfigOptions struct {
	ConfigPaths           []string      `yaml:"config_paths"`
	Environment           string        `yaml:"environment"`
	Namespace             string        `yaml:"namespace"`
	EnableHotReload       bool          `yaml:"enable_hot_reload"`
	EnableValidation      bool          `yaml:"enable_validation"`
	EnableSecrets         bool          `yaml:"enable_secrets"`
	EnableEnvironmentVars bool          `yaml:"enable_environment_vars"`
	ConfigFormat          string        `yaml:"config_format"`
	ValidationSchema      string        `yaml:"validation_schema"`
	SecretsProvider       string        `yaml:"secrets_provider"`
	ReloadInterval        time.Duration `yaml:"reload_interval"`
	WatchPaths            []string      `yaml:"watch_paths"`
}

// NewAdvancedConfigManager creates a new advanced configuration manager
func NewAdvancedConfigManager(options *AdvancedConfigOptions) (*AdvancedConfigManager, error) {
	if options == nil {
		options = DefaultAdvancedConfigOptions()
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &AdvancedConfigManager{
		id:              generateConfigID(),
		configPaths:     options.ConfigPaths,
		environment:     options.Environment,
		namespace:       options.Namespace,
		configs:         make(map[string]*viper.Viper),
		watchEnabled:    options.EnableHotReload,
		reloadCallbacks: make([]ConfigReloadCallback, 0),
		ctx:             ctx,
		cancel:          cancel,
	}

	// Initialize components
	if err := manager.initializeComponents(options); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}

	return manager, nil
}

// initializeComponents initializes all configuration components
func (acm *AdvancedConfigManager) initializeComponents(options *AdvancedConfigOptions) error {
	var err error

	// Initialize validator
	if options.EnableValidation {
		acm.validator, err = NewConfigValidator(options.ValidationSchema)
		if err != nil {
			return fmt.Errorf("failed to create config validator: %w", err)
		}
	}

	// Initialize environment manager
	acm.envManager, err = NewEnvironmentManager(acm.environment, acm.namespace)
	if err != nil {
		return fmt.Errorf("failed to create environment manager: %w", err)
	}

	// Initialize secrets manager
	if options.EnableSecrets {
		acm.secretsManager, err = NewSecretsManager(options.SecretsProvider, acm.environment)
		if err != nil {
			return fmt.Errorf("failed to create secrets manager: %w", err)
		}
	}

	// Initialize file watcher
	if options.EnableHotReload {
		acm.watcher, err = fsnotify.NewWatcher()
		if err != nil {
			return fmt.Errorf("failed to create file watcher: %w", err)
		}
	}

	return nil
}

// Initialize initializes the configuration manager
func (acm *AdvancedConfigManager) Initialize(ctx context.Context) error {
	acm.mutex.Lock()
	defer acm.mutex.Unlock()

	if acm.isInitialized {
		return fmt.Errorf("configuration manager already initialized")
	}

	// Load base configurations
	if err := acm.loadConfigurations(); err != nil {
		return fmt.Errorf("failed to load configurations: %w", err)
	}

	// Merge configurations
	if err := acm.mergeConfigurations(); err != nil {
		return fmt.Errorf("failed to merge configurations: %w", err)
	}

	// Apply environment variables
	if err := acm.applyEnvironmentVariables(); err != nil {
		return fmt.Errorf("failed to apply environment variables: %w", err)
	}

	// Load secrets
	if acm.secretsManager != nil {
		if err := acm.loadSecrets(ctx); err != nil {
			return fmt.Errorf("failed to load secrets: %w", err)
		}
	}

	// Validate configuration
	if acm.validator != nil {
		if err := acm.validateConfiguration(); err != nil {
			return fmt.Errorf("configuration validation failed: %w", err)
		}
	}

	// Start file watching
	if acm.watchEnabled {
		go acm.startFileWatching()
	}

	acm.isInitialized = true
	acm.lastReload = time.Now()

	return nil
}

// loadConfigurations loads all configuration files
func (acm *AdvancedConfigManager) loadConfigurations() error {
	for _, configPath := range acm.configPaths {
		// Determine config name from path
		configName := acm.getConfigName(configPath)

		// Create viper instance for this config
		v := viper.New()
		v.SetConfigFile(configPath)

		// Read configuration
		if err := v.ReadInConfig(); err != nil {
			if os.IsNotExist(err) {
				// Skip non-existent files
				continue
			}
			return fmt.Errorf("failed to read config %s: %w", configPath, err)
		}

		acm.configs[configName] = v
	}

	return nil
}

// mergeConfigurations merges all loaded configurations
func (acm *AdvancedConfigManager) mergeConfigurations() error {
	acm.mergedConfig = viper.New()

	// Define merge order (base configs first, environment-specific last)
	mergeOrder := []string{"base", "default", acm.environment, acm.namespace}

	for _, configName := range mergeOrder {
		if config, exists := acm.configs[configName]; exists {
			if err := acm.mergedConfig.MergeConfigMap(config.AllSettings()); err != nil {
				return fmt.Errorf("failed to merge config %s: %w", configName, err)
			}
		}
	}

	// Merge any remaining configs
	for name, config := range acm.configs {
		if !contains(mergeOrder, name) {
			if err := acm.mergedConfig.MergeConfigMap(config.AllSettings()); err != nil {
				return fmt.Errorf("failed to merge config %s: %w", name, err)
			}
		}
	}

	return nil
}

// applyEnvironmentVariables applies environment variable overrides
func (acm *AdvancedConfigManager) applyEnvironmentVariables() error {
	if acm.envManager == nil {
		return nil
	}

	envVars := acm.envManager.GetEnvironmentVariables()

	for key, value := range envVars {
		// Convert environment variable key to config key
		configKey := acm.envKeyToConfigKey(key)
		acm.mergedConfig.Set(configKey, value)
	}

	return nil
}

// loadSecrets loads secrets from the secrets manager
func (acm *AdvancedConfigManager) loadSecrets(ctx context.Context) error {
	if acm.secretsManager == nil {
		return nil
	}

	secrets, err := acm.secretsManager.LoadSecrets(ctx)
	if err != nil {
		return fmt.Errorf("failed to load secrets: %w", err)
	}

	for key, value := range secrets {
		acm.mergedConfig.Set(key, value)
	}

	return nil
}

// validateConfiguration validates the merged configuration
func (acm *AdvancedConfigManager) validateConfiguration() error {
	if acm.validator == nil {
		return nil
	}

	configData := acm.mergedConfig.AllSettings()
	return acm.validator.Validate(configData)
}

// startFileWatching starts watching configuration files for changes
func (acm *AdvancedConfigManager) startFileWatching() {
	if acm.watcher == nil {
		return
	}

	// Add config paths to watcher
	for _, configPath := range acm.configPaths {
		if err := acm.watcher.Add(configPath); err != nil {
			// Log error but continue
			continue
		}
	}

	// Watch for events
	for {
		select {
		case event, ok := <-acm.watcher.Events:
			if !ok {
				return
			}

			if event.Op&fsnotify.Write == fsnotify.Write {
				acm.handleConfigChange(event.Name)
			}

		case err, ok := <-acm.watcher.Errors:
			if !ok {
				return
			}
			// Log error but continue
			_ = err

		case <-acm.ctx.Done():
			return
		}
	}
}

// handleConfigChange handles configuration file changes
func (acm *AdvancedConfigManager) handleConfigChange(filename string) {
	acm.mutex.Lock()
	defer acm.mutex.Unlock()

	// Store old config for callbacks
	oldConfig := viper.New()
	oldConfig.MergeConfigMap(acm.mergedConfig.AllSettings())

	// Reload configurations
	if err := acm.reloadConfigurations(); err != nil {
		// Log error but don't fail
		return
	}

	// Execute reload callbacks
	for _, callback := range acm.reloadCallbacks {
		if err := callback(oldConfig, acm.mergedConfig); err != nil {
			// Log error but continue with other callbacks
		}
	}

	acm.lastReload = time.Now()
	acm.reloadCount++
}

// reloadConfigurations reloads all configurations
func (acm *AdvancedConfigManager) reloadConfigurations() error {
	// Clear existing configs
	acm.configs = make(map[string]*viper.Viper)

	// Reload all configurations
	if err := acm.loadConfigurations(); err != nil {
		return err
	}

	if err := acm.mergeConfigurations(); err != nil {
		return err
	}

	if err := acm.applyEnvironmentVariables(); err != nil {
		return err
	}

	if acm.validator != nil {
		if err := acm.validateConfiguration(); err != nil {
			return err
		}
	}

	return nil
}

// GetConfig returns the merged configuration
func (acm *AdvancedConfigManager) GetConfig() *viper.Viper {
	acm.mutex.RLock()
	defer acm.mutex.RUnlock()
	return acm.mergedConfig
}

// GetConfigValue gets a specific configuration value
func (acm *AdvancedConfigManager) GetConfigValue(key string) interface{} {
	acm.mutex.RLock()
	defer acm.mutex.RUnlock()
	return acm.mergedConfig.Get(key)
}

// SetConfigValue sets a configuration value
func (acm *AdvancedConfigManager) SetConfigValue(key string, value interface{}) {
	acm.mutex.Lock()
	defer acm.mutex.Unlock()
	acm.mergedConfig.Set(key, value)
}

// RegisterReloadCallback registers a callback for configuration reloads
func (acm *AdvancedConfigManager) RegisterReloadCallback(callback ConfigReloadCallback) {
	acm.mutex.Lock()
	defer acm.mutex.Unlock()
	acm.reloadCallbacks = append(acm.reloadCallbacks, callback)
}

// GetStatus returns the configuration manager status
func (acm *AdvancedConfigManager) GetStatus() map[string]interface{} {
	acm.mutex.RLock()
	defer acm.mutex.RUnlock()

	return map[string]interface{}{
		"id":             acm.id,
		"environment":    acm.environment,
		"namespace":      acm.namespace,
		"initialized":    acm.isInitialized,
		"configs_loaded": len(acm.configs),
		"watch_enabled":  acm.watchEnabled,
		"last_reload":    acm.lastReload,
		"reload_count":   acm.reloadCount,
	}
}

// Shutdown shuts down the configuration manager
func (acm *AdvancedConfigManager) Shutdown() error {
	acm.mutex.Lock()
	defer acm.mutex.Unlock()

	// Cancel context
	acm.cancel()

	// Close file watcher
	if acm.watcher != nil {
		acm.watcher.Close()
	}

	acm.isInitialized = false
	return nil
}

// Helper methods

// getConfigName extracts config name from file path
func (acm *AdvancedConfigManager) getConfigName(configPath string) string {
	filename := filepath.Base(configPath)
	ext := filepath.Ext(filename)
	return strings.TrimSuffix(filename, ext)
}

// envKeyToConfigKey converts environment variable key to config key
func (acm *AdvancedConfigManager) envKeyToConfigKey(envKey string) string {
	// Convert UPPER_CASE to lower.case
	key := strings.ToLower(envKey)
	key = strings.ReplaceAll(key, "_", ".")
	return key
}

// contains checks if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// generateConfigID generates a unique configuration ID
func generateConfigID() string {
	return fmt.Sprintf("config-%d", time.Now().UnixNano())
}

// DefaultAdvancedConfigOptions returns default configuration options
func DefaultAdvancedConfigOptions() *AdvancedConfigOptions {
	return &AdvancedConfigOptions{
		ConfigPaths: []string{
			"configs/config.yaml",
			"configs/config-development.yaml",
			"configs/config-production.yaml",
		},
		Environment:           "development",
		Namespace:             "default",
		EnableHotReload:       true,
		EnableValidation:      true,
		EnableSecrets:         true,
		EnableEnvironmentVars: true,
		ConfigFormat:          "yaml",
		ValidationSchema:      "configs/schema.yaml",
		SecretsProvider:       "env",
		ReloadInterval:        30 * time.Second,
		WatchPaths:            []string{"configs/"},
	}
}
