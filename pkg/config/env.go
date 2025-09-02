package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// EnvConfig provides secure environment variable handling
type EnvConfig struct {
	requiredVars []string
	optionalVars map[string]string
}

// NewEnvConfig creates a new environment configuration handler
func NewEnvConfig() *EnvConfig {
	return &EnvConfig{
		requiredVars: make([]string, 0),
		optionalVars: make(map[string]string),
	}
}

// RequireEnv marks environment variables as required
func (e *EnvConfig) RequireEnv(vars ...string) *EnvConfig {
	e.requiredVars = append(e.requiredVars, vars...)
	return e
}

// OptionalEnv sets default values for optional environment variables
func (e *EnvConfig) OptionalEnv(key, defaultValue string) *EnvConfig {
	e.optionalVars[key] = defaultValue
	return e
}

// Validate checks that all required environment variables are set
func (e *EnvConfig) Validate() error {
	var missing []string
	
	for _, varName := range e.requiredVars {
		if value := os.Getenv(varName); value == "" {
			missing = append(missing, varName)
		}
	}
	
	if len(missing) > 0 {
		return fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}
	
	return nil
}

// GetString gets a string environment variable with optional default
func GetString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetRequiredString gets a required string environment variable
func GetRequiredString(key string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return "", fmt.Errorf("required environment variable %s is not set", key)
	}
	return value, nil
}

// GetInt gets an integer environment variable with optional default
func GetInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// GetBool gets a boolean environment variable with optional default
func GetBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// GetDuration gets a duration environment variable with optional default
func GetDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

// MaskSensitive masks sensitive values for logging
func MaskSensitive(value string) string {
	if len(value) <= 8 {
		return "***"
	}
	return value[:4] + "***" + value[len(value)-4:]
}

// ValidateSecretStrength validates that secrets meet minimum security requirements
func ValidateSecretStrength(secret string, minLength int) error {
	if len(secret) < minLength {
		return fmt.Errorf("secret must be at least %d characters long", minLength)
	}
	
	// Check for common weak patterns
	weakPatterns := []string{
		"password", "123456", "admin", "secret", "default",
		"changeme", "test", "demo", "example",
	}
	
	lowerSecret := strings.ToLower(secret)
	for _, pattern := range weakPatterns {
		if strings.Contains(lowerSecret, pattern) {
			return fmt.Errorf("secret contains weak pattern: %s", pattern)
		}
	}
	
	return nil
}

// LoadSecureConfig loads configuration with security validations
func LoadSecureConfig() error {
	env := NewEnvConfig()
	
	// Define required environment variables for production
	if os.Getenv("APP_ENV") == "production" {
		env.RequireEnv(
			"DB_PASSWORD",
			"JWT_SECRET",
			"ENCRYPTION_KEY",
		)
	}
	
	// Validate required variables
	if err := env.Validate(); err != nil {
		return fmt.Errorf("environment validation failed: %w", err)
	}
	
	// Validate secret strength for critical secrets
	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		if err := ValidateSecretStrength(jwtSecret, 32); err != nil {
			return fmt.Errorf("JWT_SECRET validation failed: %w", err)
		}
	}
	
	if encKey := os.Getenv("ENCRYPTION_KEY"); encKey != "" {
		if err := ValidateSecretStrength(encKey, 32); err != nil {
			return fmt.Errorf("ENCRYPTION_KEY validation failed: %w", err)
		}
	}
	
	return nil
}

// GetDatabaseConfig returns database configuration from environment variables
func GetDatabaseConfig() DatabaseConfig {
	return DatabaseConfig{
		Host:            GetString("DB_HOST", "localhost"),
		Port:            GetString("DB_PORT", "5432"),
		Name:            GetString("DB_NAME", "hackai"),
		User:            GetString("DB_USER", "postgres"),
		Password:        os.Getenv("DB_PASSWORD"), // Required, no default
		SSLMode:         GetString("DB_SSL_MODE", "disable"),
		MaxOpenConns:    GetInt("DB_MAX_OPEN_CONNS", 25),
		MaxIdleConns:    GetInt("DB_MAX_IDLE_CONNS", 5),
		ConnMaxLifetime: GetDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
		ConnMaxIdleTime: GetDuration("DB_CONN_MAX_IDLE_TIME", 1*time.Minute),
	}
}

// GetRedisConfig returns Redis configuration from environment variables
func GetRedisConfig() RedisConfig {
	return RedisConfig{
		Host:        GetString("REDIS_HOST", "localhost"),
		Port:        GetString("REDIS_PORT", "6379"),
		Password:    os.Getenv("REDIS_PASSWORD"), // Can be empty for local dev
		DB:          GetInt("REDIS_DB", 0),
		PoolSize:    GetInt("REDIS_POOL_SIZE", 10),
		MinIdleConns: GetInt("REDIS_MIN_IDLE_CONNS", 5),
		DialTimeout: GetDuration("REDIS_DIAL_TIMEOUT", 5*time.Second),
		ReadTimeout: GetDuration("REDIS_READ_TIMEOUT", 3*time.Second),
		WriteTimeout: GetDuration("REDIS_WRITE_TIMEOUT", 3*time.Second),
	}
}

// GetJWTConfig returns JWT configuration from environment variables
func GetJWTConfig() JWTConfig {
	return JWTConfig{
		Secret:               os.Getenv("JWT_SECRET"), // Required
		Issuer:               GetString("JWT_ISSUER", "hackai-llm-security-proxy"),
		Audience:             GetString("JWT_AUDIENCE", "hackai-users"),
		AccessTokenDuration:  GetDuration("JWT_ACCESS_TOKEN_DURATION", 15*time.Minute),
		RefreshTokenDuration: GetDuration("JWT_REFRESH_TOKEN_DURATION", 24*time.Hour),
		Algorithm:            GetString("JWT_ALGORITHM", "HS256"),
	}
}
