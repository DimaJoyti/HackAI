package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the application
type Config struct {
	Server   ServerConfig   `json:"server"`
	Database DatabaseConfig `json:"database"`
	Redis    RedisConfig    `json:"redis"`
	JWT      JWTConfig      `json:"jwt"`
	Security SecurityConfig `json:"security"`
	Observability ObservabilityConfig `json:"observability"`
	AI       AIConfig       `json:"ai"`
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Port            string        `json:"port"`
	Host            string        `json:"host"`
	ReadTimeout     time.Duration `json:"read_timeout"`
	WriteTimeout    time.Duration `json:"write_timeout"`
	IdleTimeout     time.Duration `json:"idle_timeout"`
	ShutdownTimeout time.Duration `json:"shutdown_timeout"`
	CORS            CORSConfig    `json:"cors"`
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
	Host         string        `json:"host"`
	Port         string        `json:"port"`
	Password     string        `json:"password"`
	DB           int           `json:"db"`
	PoolSize     int           `json:"pool_size"`
	MinIdleConns int           `json:"min_idle_conns"`
	DialTimeout  time.Duration `json:"dial_timeout"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
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
	PasswordMinLength    int           `json:"password_min_length"`
	PasswordRequireUpper bool          `json:"password_require_upper"`
	PasswordRequireLower bool          `json:"password_require_lower"`
	PasswordRequireDigit bool          `json:"password_require_digit"`
	PasswordRequireSpecial bool        `json:"password_require_special"`
	MaxLoginAttempts     int           `json:"max_login_attempts"`
	LoginAttemptWindow   time.Duration `json:"login_attempt_window"`
	SessionTimeout       time.Duration `json:"session_timeout"`
	TwoFactorRequired    bool          `json:"two_factor_required"`
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
	Enabled    bool          `json:"enabled"`
	Requests   int           `json:"requests"`
	Window     time.Duration `json:"window"`
	SkipPaths  []string      `json:"skip_paths"`
	SkipIPs    []string      `json:"skip_ips"`
}

// ObservabilityConfig holds observability configuration
type ObservabilityConfig struct {
	Tracing TracingConfig `json:"tracing"`
	Metrics MetricsConfig `json:"metrics"`
	Logging LoggingConfig `json:"logging"`
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
	Level      string `json:"level"`
	Format     string `json:"format"` // json, text
	Output     string `json:"output"` // stdout, file
	FilePath   string `json:"file_path"`
	MaxSize    int    `json:"max_size"`    // megabytes
	MaxBackups int    `json:"max_backups"`
	MaxAge     int    `json:"max_age"`     // days
	Compress   bool   `json:"compress"`
}

// AIConfig holds AI service configuration
type AIConfig struct {
	VulnerabilityScanner VulnScannerConfig `json:"vulnerability_scanner"`
	NetworkAnalyzer      NetworkAnalyzerConfig `json:"network_analyzer"`
	ThreatIntelligence   ThreatIntelConfig `json:"threat_intelligence"`
	LogAnalyzer          LogAnalyzerConfig `json:"log_analyzer"`
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
	Enabled         bool          `json:"enabled"`
	MaxConcurrent   int           `json:"max_concurrent"`
	DefaultTimeout  time.Duration `json:"default_timeout"`
	MaxHosts        int           `json:"max_hosts"`
	MaxPorts        int           `json:"max_ports"`
}

// ThreatIntelConfig holds threat intelligence configuration
type ThreatIntelConfig struct {
	Enabled       bool          `json:"enabled"`
	UpdateInterval time.Duration `json:"update_interval"`
	Sources       []string      `json:"sources"`
	APIKeys       map[string]string `json:"api_keys"`
}

// LogAnalyzerConfig holds log analyzer configuration
type LogAnalyzerConfig struct {
	Enabled       bool     `json:"enabled"`
	MaxFileSize   int64    `json:"max_file_size"`
	SupportedFormats []string `json:"supported_formats"`
	MLModelPath   string   `json:"ml_model_path"`
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
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
		Database: DatabaseConfig{
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnv("DB_PORT", "5432"),
			Name:            getEnv("DB_NAME", "hackai"),
			User:            getEnv("DB_USER", "hackai"),
			Password:        getEnv("DB_PASSWORD", "hackai_password"),
			SSLMode:         getEnv("DB_SSL_MODE", "disable"),
			MaxOpenConns:    getIntEnv("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getIntEnv("DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: getDurationEnv("DB_CONN_MAX_LIFETIME", 5*time.Minute),
			ConnMaxIdleTime: getDurationEnv("DB_CONN_MAX_IDLE_TIME", 5*time.Minute),
		},
		Redis: RedisConfig{
			Host:         getEnv("REDIS_HOST", "localhost"),
			Port:         getEnv("REDIS_PORT", "6379"),
			Password:     getEnv("REDIS_PASSWORD", ""),
			DB:           getIntEnv("REDIS_DB", 0),
			PoolSize:     getIntEnv("REDIS_POOL_SIZE", 10),
			MinIdleConns: getIntEnv("REDIS_MIN_IDLE_CONNS", 2),
			DialTimeout:  getDurationEnv("REDIS_DIAL_TIMEOUT", 5*time.Second),
			ReadTimeout:  getDurationEnv("REDIS_READ_TIMEOUT", 3*time.Second),
			WriteTimeout: getDurationEnv("REDIS_WRITE_TIMEOUT", 3*time.Second),
		},
		JWT: JWTConfig{
			Secret:          getEnv("JWT_SECRET", "your-super-secret-jwt-key-change-this-in-production"),
			AccessTokenTTL:  getDurationEnv("JWT_ACCESS_TOKEN_TTL", 15*time.Minute),
			RefreshTokenTTL: getDurationEnv("JWT_REFRESH_TOKEN_TTL", 7*24*time.Hour),
			Issuer:          getEnv("JWT_ISSUER", "hackai"),
			Audience:        getEnv("JWT_AUDIENCE", "hackai-users"),
		},
		Security: SecurityConfig{
			PasswordMinLength:    getIntEnv("PASSWORD_MIN_LENGTH", 8),
			PasswordRequireUpper: getBoolEnv("PASSWORD_REQUIRE_UPPER", true),
			PasswordRequireLower: getBoolEnv("PASSWORD_REQUIRE_LOWER", true),
			PasswordRequireDigit: getBoolEnv("PASSWORD_REQUIRE_DIGIT", true),
			PasswordRequireSpecial: getBoolEnv("PASSWORD_REQUIRE_SPECIAL", true),
			MaxLoginAttempts:     getIntEnv("MAX_LOGIN_ATTEMPTS", 5),
			LoginAttemptWindow:   getDurationEnv("LOGIN_ATTEMPT_WINDOW", 15*time.Minute),
			SessionTimeout:       getDurationEnv("SESSION_TIMEOUT", 24*time.Hour),
			TwoFactorRequired:    getBoolEnv("TWO_FACTOR_REQUIRED", false),
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
