package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Environment represents the deployment environment
type Environment string

const (
	EnvironmentDevelopment Environment = "development"
	EnvironmentStaging     Environment = "staging"
	EnvironmentProduction  Environment = "production"
)

// EnvironmentConfig represents environment-specific configuration
type EnvironmentConfig struct {
	Environment Environment `yaml:"environment"`
	Config      *Config     `yaml:",inline"`
}

// LoadEnvironmentConfig loads configuration for the specified environment
func LoadEnvironmentConfig(env Environment) (*Config, error) {
	// Get the config directory path
	configDir := getConfigDirectory()

	// Load base configuration
	baseConfig, err := loadBaseConfig(configDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load base config: %w", err)
	}

	// Load environment-specific configuration
	envConfig, err := loadEnvironmentSpecificConfig(configDir, env)
	if err != nil {
		return nil, fmt.Errorf("failed to load environment config: %w", err)
	}

	// Merge configurations (environment overrides base)
	mergedConfig := mergeConfigs(baseConfig, envConfig)

	// Expand environment variables
	if err := expandEnvironmentVariables(mergedConfig); err != nil {
		return nil, fmt.Errorf("failed to expand environment variables: %w", err)
	}

	// Validate configuration
	if err := validateConfig(mergedConfig); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return mergedConfig, nil
}

// LoadConfigFromEnvironment loads configuration based on the ENVIRONMENT variable
func LoadConfigFromEnvironment() (*Config, error) {
	envStr := os.Getenv("ENVIRONMENT")
	if envStr == "" {
		envStr = "development" // Default to development
	}

	env := Environment(strings.ToLower(envStr))
	return LoadEnvironmentConfig(env)
}

// getConfigDirectory returns the configuration directory path
func getConfigDirectory() string {
	// Check for custom config directory
	if configDir := os.Getenv("CONFIG_DIR"); configDir != "" {
		return configDir
	}

	// Default to configs directory relative to project root
	return "configs"
}

// loadBaseConfig loads the base configuration template
func loadBaseConfig(configDir string) (*Config, error) {
	configPath := filepath.Join(configDir, "config.yaml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read base config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse base config: %w", err)
	}

	return &config, nil
}

// loadEnvironmentSpecificConfig loads environment-specific configuration
func loadEnvironmentSpecificConfig(configDir string, env Environment) (*Config, error) {
	configPath := filepath.Join(configDir, "environments", string(env)+".yaml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read environment config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse environment config: %w", err)
	}

	return &config, nil
}

// mergeConfigs merges environment configuration over base configuration
func mergeConfigs(base, env *Config) *Config {
	// Start with base configuration
	merged := *base

	// Override with environment-specific values
	if env.Server.Port != "" {
		merged.Server.Port = env.Server.Port
	}
	if env.Server.Host != "" {
		merged.Server.Host = env.Server.Host
	}
	if env.Server.ReadTimeout != 0 {
		merged.Server.ReadTimeout = env.Server.ReadTimeout
	}
	if env.Server.WriteTimeout != 0 {
		merged.Server.WriteTimeout = env.Server.WriteTimeout
	}
	if env.Server.IdleTimeout != 0 {
		merged.Server.IdleTimeout = env.Server.IdleTimeout
	}
	if env.Server.ShutdownTimeout != 0 {
		merged.Server.ShutdownTimeout = env.Server.ShutdownTimeout
	}

	// Database configuration
	if env.Database.Host != "" {
		merged.Database.Host = env.Database.Host
	}
	if env.Database.Port != "" {
		merged.Database.Port = env.Database.Port
	}
	if env.Database.Name != "" {
		merged.Database.Name = env.Database.Name
	}
	if env.Database.User != "" {
		merged.Database.User = env.Database.User
	}
	if env.Database.Password != "" {
		merged.Database.Password = env.Database.Password
	}
	if env.Database.SSLMode != "" {
		merged.Database.SSLMode = env.Database.SSLMode
	}
	if env.Database.MaxOpenConns != 0 {
		merged.Database.MaxOpenConns = env.Database.MaxOpenConns
	}
	if env.Database.MaxIdleConns != 0 {
		merged.Database.MaxIdleConns = env.Database.MaxIdleConns
	}
	if env.Database.ConnMaxLifetime != 0 {
		merged.Database.ConnMaxLifetime = env.Database.ConnMaxLifetime
	}
	if env.Database.ConnMaxIdleTime != 0 {
		merged.Database.ConnMaxIdleTime = env.Database.ConnMaxIdleTime
	}

	// Redis configuration
	if env.Redis.Host != "" {
		merged.Redis.Host = env.Redis.Host
	}
	if env.Redis.Port != "" {
		merged.Redis.Port = env.Redis.Port
	}
	if env.Redis.Password != "" {
		merged.Redis.Password = env.Redis.Password
	}
	if env.Redis.DB != 0 {
		merged.Redis.DB = env.Redis.DB
	}

	// JWT configuration
	if env.JWT.Secret != "" {
		merged.JWT.Secret = env.JWT.Secret
	}
	if env.JWT.Issuer != "" {
		merged.JWT.Issuer = env.JWT.Issuer
	}
	if env.JWT.Audience != "" {
		merged.JWT.Audience = env.JWT.Audience
	}
	if env.JWT.AccessTokenDuration != 0 {
		merged.JWT.AccessTokenDuration = env.JWT.AccessTokenDuration
	}
	if env.JWT.RefreshTokenDuration != 0 {
		merged.JWT.RefreshTokenDuration = env.JWT.RefreshTokenDuration
	}

	// Observability configuration
	if env.Observability.Logging.Level != "" {
		merged.Observability.Logging.Level = env.Observability.Logging.Level
	}
	if env.Observability.Logging.Format != "" {
		merged.Observability.Logging.Format = env.Observability.Logging.Format
	}
	if env.Observability.Logging.Output != "" {
		merged.Observability.Logging.Output = env.Observability.Logging.Output
	}

	return &merged
}

// expandEnvironmentVariables expands environment variables in configuration values
func expandEnvironmentVariables(config *Config) error {
	// Database
	config.Database.Host = expandEnvVar(config.Database.Host)
	config.Database.Port = expandEnvVar(config.Database.Port)
	config.Database.Name = expandEnvVar(config.Database.Name)
	config.Database.User = expandEnvVar(config.Database.User)
	config.Database.Password = expandEnvVar(config.Database.Password)

	// Redis
	config.Redis.Host = expandEnvVar(config.Redis.Host)
	config.Redis.Port = expandEnvVar(config.Redis.Port)
	config.Redis.Password = expandEnvVar(config.Redis.Password)

	// JWT
	config.JWT.Secret = expandEnvVar(config.JWT.Secret)

	return nil
}

// expandEnvVar expands environment variables in a string
func expandEnvVar(value string) string {
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		envVar := value[2 : len(value)-1]
		if envValue := os.Getenv(envVar); envValue != "" {
			return envValue
		}
	}
	return value
}

// validateConfig validates the configuration
func validateConfig(config *Config) error {
	// Validate server configuration
	if config.Server.Port == "" {
		return fmt.Errorf("server port cannot be empty")
	}
	if port, err := strconv.Atoi(config.Server.Port); err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("invalid server port: %s", config.Server.Port)
	}

	if config.Server.Host == "" {
		return fmt.Errorf("server host cannot be empty")
	}

	// Validate database configuration
	if config.Database.Host == "" {
		return fmt.Errorf("database host cannot be empty")
	}

	if config.Database.Name == "" {
		return fmt.Errorf("database name cannot be empty")
	}

	if config.Database.User == "" {
		return fmt.Errorf("database user cannot be empty")
	}

	// Validate JWT configuration
	if config.JWT.Secret == "" {
		return fmt.Errorf("JWT secret cannot be empty")
	}

	if len(config.JWT.Secret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 characters long")
	}

	// Validate timeouts
	if config.Server.ReadTimeout <= 0 {
		return fmt.Errorf("server read timeout must be positive")
	}

	if config.Server.WriteTimeout <= 0 {
		return fmt.Errorf("server write timeout must be positive")
	}

	return nil
}

// GetEnvironment returns the current environment
func GetEnvironment() Environment {
	envStr := os.Getenv("ENVIRONMENT")
	if envStr == "" {
		return EnvironmentDevelopment
	}
	return Environment(strings.ToLower(envStr))
}

// IsProduction returns true if running in production environment
func IsProduction() bool {
	return GetEnvironment() == EnvironmentProduction
}

// IsStaging returns true if running in staging environment
func IsStaging() bool {
	return GetEnvironment() == EnvironmentStaging
}

// IsDevelopment returns true if running in development environment
func IsDevelopment() bool {
	return GetEnvironment() == EnvironmentDevelopment
}

// DefaultConfigForEnvironment returns default configuration for the specified environment
func DefaultConfigForEnvironment(env Environment) *Config {
	config := &Config{
		Server: ServerConfig{
			Port:            "8080",
			Host:            "0.0.0.0",
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    30 * time.Second,
			IdleTimeout:     60 * time.Second,
			ShutdownTimeout: 30 * time.Second,
		},
		Database: DatabaseConfig{
			Host:            "localhost",
			Port:            "5432",
			Name:            "hackai",
			User:            "postgres",
			Password:        "password",
			SSLMode:         "disable",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 5 * time.Minute,
			ConnMaxIdleTime: 1 * time.Minute,
		},
		Redis: RedisConfig{
			Host:     "localhost",
			Port:     "6379",
			Password: "",
			DB:       0,
		},
		JWT: JWTConfig{
			Secret:               "default-secret-change-in-production",
			Issuer:               "hackai",
			Audience:             "hackai-users",
			AccessTokenDuration:  15 * time.Minute,
			RefreshTokenDuration: 24 * time.Hour,
			Algorithm:            "HS256",
		},
		Observability: ObservabilityConfig{
			Logging: LoggingConfig{
				Level:  "info",
				Format: "json",
				Output: "stdout",
			},
		},
	}

	// Environment-specific adjustments
	switch env {
	case EnvironmentDevelopment:
		config.Database.Name = "hackai_dev"
		config.Observability.Logging.Level = "debug"
		config.Observability.Logging.Format = "text"
	case EnvironmentStaging:
		config.Database.Name = "hackai_staging"
		config.Database.SSLMode = "require"
	case EnvironmentProduction:
		config.Database.Name = "hackai_production"
		config.Database.SSLMode = "require"
		config.Observability.Logging.Level = "warn"
	}

	return config
}
