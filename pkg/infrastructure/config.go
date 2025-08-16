package infrastructure

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// LLMInfrastructureConfig represents configuration for LLM infrastructure
type LLMInfrastructureConfig struct {
	// LLM Orchestration
	Orchestration OrchestrationConfig `json:"orchestration" yaml:"orchestration"`

	// Vector Database
	VectorDB VectorDBConfig `json:"vector_db" yaml:"vector_db"`

	// LLM Providers
	Providers ProvidersConfig `json:"providers" yaml:"providers"`

	// Memory Systems
	Memory MemoryConfig `json:"memory" yaml:"memory"`

	// Security
	Security LLMSecurityConfig `json:"security" yaml:"security"`

	// Rate Limiting
	RateLimit RateLimitConfig `json:"rate_limit" yaml:"rate_limit"`

	// Monitoring
	Monitoring MonitoringConfig `json:"monitoring" yaml:"monitoring"`
}

// OrchestrationConfig configures the LLM orchestration engine
type OrchestrationConfig struct {
	Enabled             bool          `json:"enabled" yaml:"enabled"`
	MaxConcurrentChains int           `json:"max_concurrent_chains" yaml:"max_concurrent_chains"`
	MaxConcurrentGraphs int           `json:"max_concurrent_graphs" yaml:"max_concurrent_graphs"`
	DefaultTimeout      time.Duration `json:"default_timeout" yaml:"default_timeout"`
	EnableMetrics       bool          `json:"enable_metrics" yaml:"enable_metrics"`
	EnableTracing       bool          `json:"enable_tracing" yaml:"enable_tracing"`
	PersistenceType     string        `json:"persistence_type" yaml:"persistence_type"`
	PersistencePath     string        `json:"persistence_path" yaml:"persistence_path"`
}

// VectorDBConfig configures vector database settings
type VectorDBConfig struct {
	Enabled        bool   `json:"enabled" yaml:"enabled"`
	Provider       string `json:"provider" yaml:"provider"` // postgres, pinecone, weaviate
	Dimensions     int    `json:"dimensions" yaml:"dimensions"`
	IndexType      string `json:"index_type" yaml:"index_type"`
	DistanceMetric string `json:"distance_metric" yaml:"distance_metric"`

	// PostgreSQL with pgvector
	PostgreSQL VectorPostgreSQLConfig `json:"postgresql" yaml:"postgresql"`
}

// VectorPostgreSQLConfig configures PostgreSQL vector settings
type VectorPostgreSQLConfig struct {
	Extension   string  `json:"extension" yaml:"extension"` // pgvector
	TablePrefix string  `json:"table_prefix" yaml:"table_prefix"`
	IndexMethod string  `json:"index_method" yaml:"index_method"` // ivfflat, hnsw
	Lists       int     `json:"lists" yaml:"lists"`
	ProbeRatio  float64 `json:"probe_ratio" yaml:"probe_ratio"`
}

// ProvidersConfig configures LLM providers
type ProvidersConfig struct {
	OpenAI    ProviderConfig `json:"openai" yaml:"openai"`
	Anthropic ProviderConfig `json:"anthropic" yaml:"anthropic"`
	Azure     ProviderConfig `json:"azure" yaml:"azure"`
	Local     ProviderConfig `json:"local" yaml:"local"`
}

// ProviderConfig configures individual LLM providers
type ProviderConfig struct {
	Enabled           bool          `json:"enabled" yaml:"enabled"`
	APIKey            string        `json:"api_key" yaml:"api_key"`
	BaseURL           string        `json:"base_url" yaml:"base_url"`
	Model             string        `json:"model" yaml:"model"`
	RequestsPerMinute int           `json:"requests_per_minute" yaml:"requests_per_minute"`
	TokensPerMinute   int           `json:"tokens_per_minute" yaml:"tokens_per_minute"`
	MaxConcurrent     int           `json:"max_concurrent" yaml:"max_concurrent"`
	Timeout           time.Duration `json:"timeout" yaml:"timeout"`
	MaxRetries        int           `json:"max_retries" yaml:"max_retries"`
}

// MemoryConfig configures memory systems
type MemoryConfig struct {
	VectorMemorySize   int           `json:"vector_memory_size" yaml:"vector_memory_size"`
	ConversationTTL    time.Duration `json:"conversation_ttl" yaml:"conversation_ttl"`
	EpisodeRetention   time.Duration `json:"episode_retention" yaml:"episode_retention"`
	FactRetention      time.Duration `json:"fact_retention" yaml:"fact_retention"`
	EnablePersistence  bool          `json:"enable_persistence" yaml:"enable_persistence"`
	PersistencePath    string        `json:"persistence_path" yaml:"persistence_path"`
	CacheSize          int           `json:"cache_size" yaml:"cache_size"`
	CompressionEnabled bool          `json:"compression_enabled" yaml:"compression_enabled"`
}

// LLMSecurityConfig configures security for LLM operations
type LLMSecurityConfig struct {
	EnableInputValidation  bool     `json:"enable_input_validation" yaml:"enable_input_validation"`
	EnableOutputFiltering  bool     `json:"enable_output_filtering" yaml:"enable_output_filtering"`
	MaxPromptLength        int      `json:"max_prompt_length" yaml:"max_prompt_length"`
	MaxResponseLength      int      `json:"max_response_length" yaml:"max_response_length"`
	BlockedPatterns        []string `json:"blocked_patterns" yaml:"blocked_patterns"`
	SensitiveDataDetection bool     `json:"sensitive_data_detection" yaml:"sensitive_data_detection"`
	AuditLogging           bool     `json:"audit_logging" yaml:"audit_logging"`
	EncryptionAtRest       bool     `json:"encryption_at_rest" yaml:"encryption_at_rest"`
	EncryptionInTransit    bool     `json:"encryption_in_transit" yaml:"encryption_in_transit"`
}

// RateLimitConfig configures rate limiting
type RateLimitConfig struct {
	Enabled           bool          `json:"enabled" yaml:"enabled"`
	RequestsPerSecond int           `json:"requests_per_second" yaml:"requests_per_second"`
	RequestsPerMinute int           `json:"requests_per_minute" yaml:"requests_per_minute"`
	RequestsPerHour   int           `json:"requests_per_hour" yaml:"requests_per_hour"`
	BurstSize         int           `json:"burst_size" yaml:"burst_size"`
	CleanupInterval   time.Duration `json:"cleanup_interval" yaml:"cleanup_interval"`

	// Per-user limits
	PerUserEnabled        bool `json:"per_user_enabled" yaml:"per_user_enabled"`
	PerUserRequestsPerMin int  `json:"per_user_requests_per_min" yaml:"per_user_requests_per_min"`

	// Per-IP limits
	PerIPEnabled        bool `json:"per_ip_enabled" yaml:"per_ip_enabled"`
	PerIPRequestsPerMin int  `json:"per_ip_requests_per_min" yaml:"per_ip_requests_per_min"`
}

// MonitoringConfig configures monitoring and observability
type MonitoringConfig struct {
	EnableMetrics   bool          `json:"enable_metrics" yaml:"enable_metrics"`
	EnableTracing   bool          `json:"enable_tracing" yaml:"enable_tracing"`
	EnableProfiling bool          `json:"enable_profiling" yaml:"enable_profiling"`
	MetricsInterval time.Duration `json:"metrics_interval" yaml:"metrics_interval"`
	HealthCheckPath string        `json:"health_check_path" yaml:"health_check_path"`
	MetricsPath     string        `json:"metrics_path" yaml:"metrics_path"`

	// Alerting
	AlertingEnabled bool            `json:"alerting_enabled" yaml:"alerting_enabled"`
	AlertWebhookURL string          `json:"alert_webhook_url" yaml:"alert_webhook_url"`
	AlertThresholds AlertThresholds `json:"alert_thresholds" yaml:"alert_thresholds"`
}

// AlertThresholds defines thresholds for alerting
type AlertThresholds struct {
	ErrorRate    float64       `json:"error_rate" yaml:"error_rate"`
	ResponseTime time.Duration `json:"response_time" yaml:"response_time"`
	QueueDepth   int           `json:"queue_depth" yaml:"queue_depth"`
	MemoryUsage  float64       `json:"memory_usage" yaml:"memory_usage"`
	CPUUsage     float64       `json:"cpu_usage" yaml:"cpu_usage"`
	DiskUsage    float64       `json:"disk_usage" yaml:"disk_usage"`
}

// LoadLLMInfrastructureConfig loads LLM infrastructure configuration from environment
func LoadLLMInfrastructureConfig() (*LLMInfrastructureConfig, error) {
	cfg := &LLMInfrastructureConfig{
		Orchestration: OrchestrationConfig{
			Enabled:             getBoolEnv("LLM_ORCHESTRATION_ENABLED", true),
			MaxConcurrentChains: getIntEnv("LLM_MAX_CONCURRENT_CHAINS", 100),
			MaxConcurrentGraphs: getIntEnv("LLM_MAX_CONCURRENT_GRAPHS", 50),
			DefaultTimeout:      getDurationEnv("LLM_DEFAULT_TIMEOUT", 5*time.Minute),
			EnableMetrics:       getBoolEnv("LLM_ENABLE_METRICS", true),
			EnableTracing:       getBoolEnv("LLM_ENABLE_TRACING", true),
			PersistenceType:     getEnv("LLM_PERSISTENCE_TYPE", "file"),
			PersistencePath:     getEnv("LLM_PERSISTENCE_PATH", "./data/llm_states"),
		},

		VectorDB: VectorDBConfig{
			Enabled:        getBoolEnv("VECTOR_DB_ENABLED", true),
			Provider:       getEnv("VECTOR_DB_PROVIDER", "postgres"),
			Dimensions:     getIntEnv("VECTOR_DB_DIMENSIONS", 1536),
			IndexType:      getEnv("VECTOR_DB_INDEX_TYPE", "ivfflat"),
			DistanceMetric: getEnv("VECTOR_DB_DISTANCE_METRIC", "cosine"),
			PostgreSQL: VectorPostgreSQLConfig{
				Extension:   getEnv("VECTOR_DB_PG_EXTENSION", "pgvector"),
				TablePrefix: getEnv("VECTOR_DB_PG_TABLE_PREFIX", "llm_"),
				IndexMethod: getEnv("VECTOR_DB_PG_INDEX_METHOD", "ivfflat"),
				Lists:       getIntEnv("VECTOR_DB_PG_LISTS", 100),
				ProbeRatio:  getFloatEnv("VECTOR_DB_PG_PROBE_RATIO", 0.1),
			},
		},

		Providers: ProvidersConfig{
			OpenAI: ProviderConfig{
				Enabled:           getBoolEnv("OPENAI_ENABLED", true),
				APIKey:            getEnv("OPENAI_API_KEY", ""),
				BaseURL:           getEnv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
				Model:             getEnv("OPENAI_MODEL", "gpt-4"),
				RequestsPerMinute: getIntEnv("OPENAI_REQUESTS_PER_MINUTE", 60),
				TokensPerMinute:   getIntEnv("OPENAI_TOKENS_PER_MINUTE", 100000),
				MaxConcurrent:     getIntEnv("OPENAI_MAX_CONCURRENT", 10),
				Timeout:           getDurationEnv("OPENAI_TIMEOUT", 30*time.Second),
				MaxRetries:        getIntEnv("OPENAI_MAX_RETRIES", 3),
			},
			Anthropic: ProviderConfig{
				Enabled:           getBoolEnv("ANTHROPIC_ENABLED", false),
				APIKey:            getEnv("ANTHROPIC_API_KEY", ""),
				BaseURL:           getEnv("ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
				Model:             getEnv("ANTHROPIC_MODEL", "claude-3-sonnet-20240229"),
				RequestsPerMinute: getIntEnv("ANTHROPIC_REQUESTS_PER_MINUTE", 60),
				TokensPerMinute:   getIntEnv("ANTHROPIC_TOKENS_PER_MINUTE", 100000),
				MaxConcurrent:     getIntEnv("ANTHROPIC_MAX_CONCURRENT", 10),
				Timeout:           getDurationEnv("ANTHROPIC_TIMEOUT", 30*time.Second),
				MaxRetries:        getIntEnv("ANTHROPIC_MAX_RETRIES", 3),
			},
		},

		Memory: MemoryConfig{
			VectorMemorySize:   getIntEnv("LLM_VECTOR_MEMORY_SIZE", 10000),
			ConversationTTL:    getDurationEnv("LLM_CONVERSATION_TTL", 24*time.Hour),
			EpisodeRetention:   getDurationEnv("LLM_EPISODE_RETENTION", 7*24*time.Hour),
			FactRetention:      getDurationEnv("LLM_FACT_RETENTION", 30*24*time.Hour),
			EnablePersistence:  getBoolEnv("LLM_MEMORY_PERSISTENCE", true),
			PersistencePath:    getEnv("LLM_MEMORY_PATH", "./data/llm_memory"),
			CacheSize:          getIntEnv("LLM_MEMORY_CACHE_SIZE", 1000),
			CompressionEnabled: getBoolEnv("LLM_MEMORY_COMPRESSION", true),
		},

		Security: LLMSecurityConfig{
			EnableInputValidation:  getBoolEnv("LLM_INPUT_VALIDATION", true),
			EnableOutputFiltering:  getBoolEnv("LLM_OUTPUT_FILTERING", true),
			MaxPromptLength:        getIntEnv("LLM_MAX_PROMPT_LENGTH", 10000),
			MaxResponseLength:      getIntEnv("LLM_MAX_RESPONSE_LENGTH", 50000),
			BlockedPatterns:        getSliceEnv("LLM_BLOCKED_PATTERNS", []string{}),
			SensitiveDataDetection: getBoolEnv("LLM_SENSITIVE_DATA_DETECTION", true),
			AuditLogging:           getBoolEnv("LLM_AUDIT_LOGGING", true),
			EncryptionAtRest:       getBoolEnv("LLM_ENCRYPTION_AT_REST", true),
			EncryptionInTransit:    getBoolEnv("LLM_ENCRYPTION_IN_TRANSIT", true),
		},

		RateLimit: RateLimitConfig{
			Enabled:               getBoolEnv("RATE_LIMIT_ENABLED", true),
			RequestsPerSecond:     getIntEnv("RATE_LIMIT_RPS", 10),
			RequestsPerMinute:     getIntEnv("RATE_LIMIT_RPM", 600),
			RequestsPerHour:       getIntEnv("RATE_LIMIT_RPH", 36000),
			BurstSize:             getIntEnv("RATE_LIMIT_BURST", 20),
			CleanupInterval:       getDurationEnv("RATE_LIMIT_CLEANUP", 1*time.Minute),
			PerUserEnabled:        getBoolEnv("RATE_LIMIT_PER_USER", true),
			PerUserRequestsPerMin: getIntEnv("RATE_LIMIT_USER_RPM", 100),
			PerIPEnabled:          getBoolEnv("RATE_LIMIT_PER_IP", true),
			PerIPRequestsPerMin:   getIntEnv("RATE_LIMIT_IP_RPM", 200),
		},

		Monitoring: MonitoringConfig{
			EnableMetrics:   getBoolEnv("MONITORING_METRICS", true),
			EnableTracing:   getBoolEnv("MONITORING_TRACING", true),
			EnableProfiling: getBoolEnv("MONITORING_PROFILING", false),
			MetricsInterval: getDurationEnv("MONITORING_INTERVAL", 30*time.Second),
			HealthCheckPath: getEnv("MONITORING_HEALTH_PATH", "/health"),
			MetricsPath:     getEnv("MONITORING_METRICS_PATH", "/metrics"),
			AlertingEnabled: getBoolEnv("MONITORING_ALERTING", false),
			AlertWebhookURL: getEnv("MONITORING_ALERT_WEBHOOK", ""),
			AlertThresholds: AlertThresholds{
				ErrorRate:    getFloatEnv("ALERT_ERROR_RATE", 0.05),
				ResponseTime: getDurationEnv("ALERT_RESPONSE_TIME", 5*time.Second),
				QueueDepth:   getIntEnv("ALERT_QUEUE_DEPTH", 100),
				MemoryUsage:  getFloatEnv("ALERT_MEMORY_USAGE", 0.8),
				CPUUsage:     getFloatEnv("ALERT_CPU_USAGE", 0.8),
				DiskUsage:    getFloatEnv("ALERT_DISK_USAGE", 0.9),
			},
		},
	}

	return cfg, nil
}

// Helper functions for environment variable parsing
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getFloatEnv(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseFloat(value, 64); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getSliceEnv(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}
