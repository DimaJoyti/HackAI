package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the application
type Config struct {
	Environment   string              `json:"environment" yaml:"environment"`
	Server        ServerConfig        `json:"server" yaml:"server"`
	Database      DatabaseConfig      `json:"database" yaml:"database"`
	Redis         RedisConfig         `json:"redis" yaml:"redis"`
	JWT           JWTConfig           `json:"jwt" yaml:"jwt"`
	Security      SecurityConfig      `json:"security" yaml:"security"`
	Observability ObservabilityConfig `json:"observability" yaml:"observability"`
	AI            AIConfig            `json:"ai" yaml:"ai"`
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Port            string          `json:"port"`
	Host            string          `json:"host"`
	ReadTimeout     time.Duration   `json:"read_timeout"`
	WriteTimeout    time.Duration   `json:"write_timeout"`
	IdleTimeout     time.Duration   `json:"idle_timeout"`
	ShutdownTimeout time.Duration   `json:"shutdown_timeout"`
	CORS            CORSConfig      `json:"cors"`
	RateLimit       RateLimitConfig `json:"rate_limit"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Host            string        `json:"host"`
	Port            string        `json:"port"`
	Name            string        `json:"name"`
	User            string        `json:"user"`
	Password        string        `json:"password"`
	SSLMode         string        `json:"ssl_mode"`
	MaxOpenConns    int           `json:"max_open_conns"`
	MaxIdleConns    int           `json:"max_idle_conns"`
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `json:"conn_max_idle_time"`
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Host            string         `json:"host" yaml:"host"`
	Port            int            `json:"port" yaml:"port"`
	Password        string         `json:"password" yaml:"password"`
	Database        int            `json:"database" yaml:"database"`
	PoolSize        int            `json:"pool_size" yaml:"pool_size"`
	MinIdleConns    int            `json:"min_idle_conns" yaml:"min_idle_conns"`
	MaxIdleConns    int            `json:"max_idle_conns" yaml:"max_idle_conns"`
	ConnMaxLifetime int            `json:"conn_max_lifetime" yaml:"conn_max_lifetime"`   // seconds
	ConnMaxIdleTime int            `json:"conn_max_idle_time" yaml:"conn_max_idle_time"` // seconds
	DialTimeout     int            `json:"dial_timeout" yaml:"dial_timeout"`             // seconds
	ReadTimeout     int            `json:"read_timeout" yaml:"read_timeout"`             // seconds
	WriteTimeout    int            `json:"write_timeout" yaml:"write_timeout"`           // seconds
	ClusterMode     bool           `json:"cluster_mode" yaml:"cluster_mode"`
	ClusterAddrs    []string       `json:"cluster_addrs" yaml:"cluster_addrs"`
	TLS             RedisTLSConfig `json:"tls" yaml:"tls"`
}

// RedisTLSConfig holds Redis TLS configuration
type RedisTLSConfig struct {
	Enabled            bool   `json:"enabled" yaml:"enabled"`
	ServerName         string `json:"server_name" yaml:"server_name"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify" yaml:"insecure_skip_verify"`
	CertFile           string `json:"cert_file" yaml:"cert_file"`
	KeyFile            string `json:"key_file" yaml:"key_file"`
	CAFile             string `json:"ca_file" yaml:"ca_file"`
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret               string        `json:"secret"`
	AccessTokenTTL       time.Duration `json:"access_token_ttl"`
	RefreshTokenTTL      time.Duration `json:"refresh_token_ttl"`
	AccessTokenDuration  time.Duration `json:"access_token_duration"`  // Alias for AccessTokenTTL
	RefreshTokenDuration time.Duration `json:"refresh_token_duration"` // Alias for RefreshTokenTTL
	Issuer               string        `json:"issuer"`
	Audience             string        `json:"audience"`
	Algorithm            string        `json:"algorithm"`
}

// SecurityConfig holds security configuration
type SecurityConfig struct {
	PasswordMinLength      int           `json:"password_min_length"`
	PasswordRequireUpper   bool          `json:"password_require_upper"`
	PasswordRequireLower   bool          `json:"password_require_lower"`
	PasswordRequireDigit   bool          `json:"password_require_digit"`
	PasswordRequireSpecial bool          `json:"password_require_special"`
	MaxLoginAttempts       int           `json:"max_login_attempts"`
	LoginAttemptWindow     time.Duration `json:"login_attempt_window"`
	SessionTimeout         time.Duration `json:"session_timeout"`
	TwoFactorRequired      bool          `json:"two_factor_required"`
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowedOrigins   []string `json:"allowed_origins"`
	AllowedMethods   []string `json:"allowed_methods"`
	AllowedHeaders   []string `json:"allowed_headers"`
	ExposedHeaders   []string `json:"exposed_headers"`
	AllowCredentials bool     `json:"allow_credentials"`
	MaxAge           int      `json:"max_age"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled   bool          `json:"enabled"`
	Requests  int           `json:"requests"`
	Window    time.Duration `json:"window"`
	SkipPaths []string      `json:"skip_paths"`
	SkipIPs   []string      `json:"skip_ips"`
}

// ObservabilityConfig holds observability configuration
type ObservabilityConfig struct {
	Enabled     bool                        `json:"enabled"`
	Tracing     TracingConfig               `json:"tracing"`
	Metrics     MetricsConfig               `json:"metrics"`
	Logging     LoggingConfig               `json:"logging"`
	HealthCheck HealthCheckConfig           `json:"health_check"`
	Profiling   ProfilingConfig             `json:"profiling"`
	Alerting    ObservabilityAlertingConfig `json:"alerting"`
	Dashboard   DashboardConfig             `json:"dashboard"`
}

// TracingConfig holds tracing configuration
type TracingConfig struct {
	Enabled     bool    `json:"enabled"`
	ServiceName string  `json:"service_name"`
	Endpoint    string  `json:"endpoint"`
	SampleRate  float64 `json:"sample_rate"`
}

// MetricsConfig holds metrics configuration
type MetricsConfig struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
	Port    string `json:"port"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Enabled    bool   `json:"enabled"`
	Level      string `json:"level"`
	Format     string `json:"format"` // json, text
	Output     string `json:"output"` // stdout, file
	FilePath   string `json:"file_path"`
	MaxSize    int    `json:"max_size"` // megabytes
	MaxBackups int    `json:"max_backups"`
	MaxAge     int    `json:"max_age"` // days
	Compress   bool   `json:"compress"`
}

// HealthCheckConfig holds health check configuration
type HealthCheckConfig struct {
	Enabled  bool   `json:"enabled"`
	Port     int    `json:"port"`
	Endpoint string `json:"endpoint"`
}

// ProfilingConfig holds profiling configuration
type ProfilingConfig struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
}

// ObservabilityAlertingConfig holds alerting configuration for observability
type ObservabilityAlertingConfig struct {
	Enabled         bool   `json:"enabled"`
	WebhookURL      string `json:"webhook_url"`
	EmailEnabled    bool   `json:"email_enabled"`
	SlackEnabled    bool   `json:"slack_enabled"`
	SlackWebhookURL string `json:"slack_webhook_url"`
}

// DashboardConfig holds dashboard configuration
type DashboardConfig struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
}

// AIConfig holds AI service configuration
type AIConfig struct {
	VulnerabilityScanner VulnScannerConfig     `json:"vulnerability_scanner"`
	NetworkAnalyzer      NetworkAnalyzerConfig `json:"network_analyzer"`
	ThreatIntelligence   ThreatIntelConfig     `json:"threat_intelligence"`
	LogAnalyzer          LogAnalyzerConfig     `json:"log_analyzer"`
}

// DefaultObservabilityConfig returns a default observability configuration
func DefaultObservabilityConfig() *ObservabilityConfig {
	return &ObservabilityConfig{
		Enabled: true,
		Tracing: TracingConfig{
			Enabled:     true,
			ServiceName: "hackai",
			Endpoint:    "http://localhost:14268/api/traces",
			SampleRate:  1.0,
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Path:    "/metrics",
			Port:    "9090",
		},
		Logging: LoggingConfig{
			Enabled: true,
			Level:   "info",
			Format:  "json",
			Output:  "stdout",
		},
		HealthCheck: HealthCheckConfig{
			Enabled:  true,
			Port:     8080,
			Endpoint: "/health",
		},
		Profiling: ProfilingConfig{
			Enabled: false,
			Port:    6060,
		},
		Alerting: ObservabilityAlertingConfig{
			Enabled: false,
		},
		Dashboard: DashboardConfig{
			Enabled: true,
			Port:    3000,
		},
	}
}

// VulnScannerConfig holds vulnerability scanner configuration
type VulnScannerConfig struct {
	Enabled         bool          `json:"enabled"`
	MaxConcurrent   int           `json:"max_concurrent"`
	DefaultTimeout  time.Duration `json:"default_timeout"`
	MaxScanDuration time.Duration `json:"max_scan_duration"`
	UserAgent       string        `json:"user_agent"`
	RateLimit       int           `json:"rate_limit"`
}

// NetworkAnalyzerConfig holds network analyzer configuration
type NetworkAnalyzerConfig struct {
	Enabled        bool          `json:"enabled"`
	MaxConcurrent  int           `json:"max_concurrent"`
	DefaultTimeout time.Duration `json:"default_timeout"`
	MaxHosts       int           `json:"max_hosts"`
	MaxPorts       int           `json:"max_ports"`
}

// ThreatIntelConfig holds threat intelligence configuration
type ThreatIntelConfig struct {
	Enabled        bool              `json:"enabled"`
	UpdateInterval time.Duration     `json:"update_interval"`
	Sources        []string          `json:"sources"`
	APIKeys        map[string]string `json:"api_keys"`
}

// LogAnalyzerConfig holds log analyzer configuration
type LogAnalyzerConfig struct {
	Enabled          bool     `json:"enabled"`
	MaxFileSize      int64    `json:"max_file_size"`
	SupportedFormats []string `json:"supported_formats"`
	MLModelPath      string   `json:"ml_model_path"`
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	// Validate secure configuration first
	if err := LoadSecureConfig(); err != nil {
		return nil, fmt.Errorf("security validation failed: %w", err)
	}

	config := &Config{
		Server: ServerConfig{
			Port:            getEnv("PORT", "8080"),
			Host:            getEnv("HOST", "0.0.0.0"),
			ReadTimeout:     getDurationEnv("READ_TIMEOUT", 30*time.Second),
			WriteTimeout:    getDurationEnv("WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:     getDurationEnv("IDLE_TIMEOUT", 120*time.Second),
			ShutdownTimeout: getDurationEnv("SHUTDOWN_TIMEOUT", 30*time.Second),
			CORS: CORSConfig{
				AllowedOrigins:   getSliceEnv("CORS_ALLOWED_ORIGINS", []string{"http://localhost:3000"}),
				AllowedMethods:   getSliceEnv("CORS_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
				AllowedHeaders:   getSliceEnv("CORS_ALLOWED_HEADERS", []string{"Content-Type", "Authorization"}),
				ExposedHeaders:   getSliceEnv("CORS_EXPOSED_HEADERS", []string{}),
				AllowCredentials: getBoolEnv("CORS_ALLOW_CREDENTIALS", true),
				MaxAge:           getIntEnv("CORS_MAX_AGE", 86400),
			},
			RateLimit: RateLimitConfig{
				Enabled:   getBoolEnv("RATE_LIMIT_ENABLED", true),
				Requests:  getIntEnv("RATE_LIMIT_REQUESTS", 100),
				Window:    getDurationEnv("RATE_LIMIT_WINDOW", time.Minute),
				SkipPaths: getSliceEnv("RATE_LIMIT_SKIP_PATHS", []string{"/health", "/metrics"}),
				SkipIPs:   getSliceEnv("RATE_LIMIT_SKIP_IPS", []string{}),
			},
		},
		Database: GetDatabaseConfig(),
		Redis:    GetRedisConfig(),
		JWT:      GetJWTConfig(),
		Security: SecurityConfig{
			PasswordMinLength:      getIntEnv("PASSWORD_MIN_LENGTH", 8),
			PasswordRequireUpper:   getBoolEnv("PASSWORD_REQUIRE_UPPER", true),
			PasswordRequireLower:   getBoolEnv("PASSWORD_REQUIRE_LOWER", true),
			PasswordRequireDigit:   getBoolEnv("PASSWORD_REQUIRE_DIGIT", true),
			PasswordRequireSpecial: getBoolEnv("PASSWORD_REQUIRE_SPECIAL", true),
			MaxLoginAttempts:       getIntEnv("MAX_LOGIN_ATTEMPTS", 5),
			LoginAttemptWindow:     getDurationEnv("LOGIN_ATTEMPT_WINDOW", 15*time.Minute),
			SessionTimeout:         getDurationEnv("SESSION_TIMEOUT", 24*time.Hour),
			TwoFactorRequired:      getBoolEnv("TWO_FACTOR_REQUIRED", false),
		},
		Observability: ObservabilityConfig{
			Tracing: TracingConfig{
				Enabled:     getBoolEnv("TRACING_ENABLED", true),
				ServiceName: getEnv("TRACING_SERVICE_NAME", "hackai"),
				Endpoint:    getEnv("JAEGER_ENDPOINT", "http://localhost:14268/api/traces"),
				SampleRate:  getFloat64Env("TRACING_SAMPLE_RATE", 1.0),
			},
			Metrics: MetricsConfig{
				Enabled: getBoolEnv("METRICS_ENABLED", true),
				Path:    getEnv("METRICS_PATH", "/metrics"),
				Port:    getEnv("METRICS_PORT", "9090"),
			},
			Logging: LoggingConfig{
				Level:      getEnv("LOG_LEVEL", "info"),
				Format:     getEnv("LOG_FORMAT", "json"),
				Output:     getEnv("LOG_OUTPUT", "stdout"),
				FilePath:   getEnv("LOG_FILE_PATH", "logs/app.log"),
				MaxSize:    getIntEnv("LOG_MAX_SIZE", 100),
				MaxBackups: getIntEnv("LOG_MAX_BACKUPS", 3),
				MaxAge:     getIntEnv("LOG_MAX_AGE", 28),
				Compress:   getBoolEnv("LOG_COMPRESS", true),
			},
		},
		AI: AIConfig{
			VulnerabilityScanner: VulnScannerConfig{
				Enabled:         getBoolEnv("VULN_SCANNER_ENABLED", true),
				MaxConcurrent:   getIntEnv("VULN_SCANNER_MAX_CONCURRENT", 5),
				DefaultTimeout:  getDurationEnv("VULN_SCANNER_DEFAULT_TIMEOUT", 30*time.Second),
				MaxScanDuration: getDurationEnv("VULN_SCANNER_MAX_DURATION", 30*time.Minute),
				UserAgent:       getEnv("VULN_SCANNER_USER_AGENT", "HackAI-Scanner/1.0"),
				RateLimit:       getIntEnv("VULN_SCANNER_RATE_LIMIT", 10),
			},
			NetworkAnalyzer: NetworkAnalyzerConfig{
				Enabled:        getBoolEnv("NETWORK_ANALYZER_ENABLED", true),
				MaxConcurrent:  getIntEnv("NETWORK_ANALYZER_MAX_CONCURRENT", 10),
				DefaultTimeout: getDurationEnv("NETWORK_ANALYZER_DEFAULT_TIMEOUT", 5*time.Second),
				MaxHosts:       getIntEnv("NETWORK_ANALYZER_MAX_HOSTS", 1000),
				MaxPorts:       getIntEnv("NETWORK_ANALYZER_MAX_PORTS", 65535),
			},
			ThreatIntelligence: ThreatIntelConfig{
				Enabled:        getBoolEnv("THREAT_INTEL_ENABLED", true),
				UpdateInterval: getDurationEnv("THREAT_INTEL_UPDATE_INTERVAL", 1*time.Hour),
				Sources:        getSliceEnv("THREAT_INTEL_SOURCES", []string{"virustotal", "alienvault"}),
				APIKeys:        getMapEnv("THREAT_INTEL_API_KEYS"),
			},
			LogAnalyzer: LogAnalyzerConfig{
				Enabled:          getBoolEnv("LOG_ANALYZER_ENABLED", true),
				MaxFileSize:      getInt64Env("LOG_ANALYZER_MAX_FILE_SIZE", 100*1024*1024), // 100MB
				SupportedFormats: getSliceEnv("LOG_ANALYZER_SUPPORTED_FORMATS", []string{"apache", "nginx", "syslog", "json"}),
				MLModelPath:      getEnv("LOG_ANALYZER_ML_MODEL_PATH", "models/log_analyzer.model"),
			},
		},
	}

	return config, nil
}

// GetDSN returns the database connection string
func (c *DatabaseConfig) GetDSN() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Name, c.SSLMode)
}

// GetRedisAddr returns the Redis address
func (c *RedisConfig) GetAddr() string {
	return fmt.Sprintf("%s:%s", c.Host, c.Port)
}

// Helper functions for environment variable parsing
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getInt64Env(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getFloat64Env(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
			return floatValue
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func getSliceEnv(key string, defaultValue []string) []string {
	// This is a simplified implementation
	// In production, you might want to parse comma-separated values
	if value := os.Getenv(key); value != "" {
		return []string{value}
	}
	return defaultValue
}

func getMapEnv(key string) map[string]string {
	// This is a simplified implementation
	// In production, you might want to parse JSON or key=value pairs
	result := make(map[string]string)
	if value := os.Getenv(key); value != "" {
		// Parse JSON or implement your preferred format
		// For now, return empty map
	}
	return result
}

// EnhancedConfigManager provides comprehensive configuration management
type EnhancedConfigManager struct {
	config          *Config
	envManager      *EnvironmentManager
	secretsManager  *SecretsManager
	featuresManager *FeatureFlagsManager
	configPath      string
}

// NewEnhancedConfigManager creates a new enhanced configuration manager
func NewEnhancedConfigManager(configPath string) (*EnhancedConfigManager, error) {
	if configPath == "" {
		configPath = "configs"
	}

	// Determine current environment
	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "development"
	}

	// Initialize environment manager
	envManager, err := NewEnvironmentManager(env, "hackai")
	if err != nil {
		return nil, fmt.Errorf("failed to create environment manager: %w", err)
	}

	// Initialize secrets manager
	encryptionKey := os.Getenv("CONFIG_ENCRYPTION_KEY")
	if encryptionKey == "" {
		encryptionKey = "default-key-for-development-only"
	}

	secretsManager, err := NewSecretsManager(encryptionKey, "hackai")
	if err != nil {
		return nil, fmt.Errorf("failed to create secrets manager: %w", err)
	}

	// Initialize feature flags manager
	featuresManager := NewFeatureFlagsManager()

	return &EnhancedConfigManager{
		envManager:      envManager,
		secretsManager:  secretsManager,
		featuresManager: featuresManager,
		configPath:      configPath,
	}, nil
}

// LoadEnhancedConfig loads configuration using the enhanced manager
func LoadEnhancedConfig() (*Config, *EnhancedConfigManager, error) {
	manager, err := NewEnhancedConfigManager("")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create config manager: %w", err)
	}

	config, err := manager.LoadConfig()
	if err != nil {
		return nil, nil, err
	}

	return config, manager, nil
}

// LoadConfig loads the complete configuration
func (ecm *EnhancedConfigManager) LoadConfig() (*Config, error) {
	// Load base configuration
	config, err := Load() // Use existing Load function
	if err != nil {
		return nil, fmt.Errorf("failed to load base config: %w", err)
	}

	// Apply environment settings (use the environment from OS)
	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "development"
	}
	config.Environment = env

	// Load secrets and apply them to configuration
	if err := ecm.applySecrets(config); err != nil {
		return nil, fmt.Errorf("failed to apply secrets: %w", err)
	}

	// Validate configuration
	result := ValidateConfig(config)
	if !result.Valid {
		return nil, fmt.Errorf("configuration validation failed: %d errors", len(result.Errors))
	}

	// Log warnings if any
	if len(result.Warnings) > 0 {
		fmt.Printf("Configuration warnings: %d warnings found\n", len(result.Warnings))
	}

	ecm.config = config
	return config, nil
}

// applySecrets applies secrets to configuration
func (ecm *EnhancedConfigManager) applySecrets(config *Config) error {
	// Apply database password
	if dbPassword, exists := ecm.secretsManager.GetSecret("database.password"); exists {
		config.Database.Password = dbPassword
	}

	// Apply Redis password
	if redisPassword, exists := ecm.secretsManager.GetSecret("redis.password"); exists {
		config.Redis.Password = redisPassword
	}

	// Apply JWT secret
	if jwtSecret, exists := ecm.secretsManager.GetSecret("jwt.secret"); exists {
		config.JWT.Secret = jwtSecret
	}

	// Apply other secrets as needed
	// Note: Add more secret applications based on your specific configuration structure

	return nil
}

// GetEnvironmentManager returns the environment manager
func (ecm *EnhancedConfigManager) GetEnvironmentManager() *EnvironmentManager {
	return ecm.envManager
}

// GetSecretsManager returns the secrets manager
func (ecm *EnhancedConfigManager) GetSecretsManager() *SecretsManager {
	return ecm.secretsManager
}

// GetFeatureFlagsManager returns the feature flags manager
func (ecm *EnhancedConfigManager) GetFeatureFlagsManager() *FeatureFlagsManager {
	return ecm.featuresManager
}

// IsFeatureEnabled checks if a feature flag is enabled
func (ecm *EnhancedConfigManager) IsFeatureEnabled(flagName string) bool {
	return ecm.featuresManager.IsEnabled(flagName)
}
