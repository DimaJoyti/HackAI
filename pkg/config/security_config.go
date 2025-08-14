package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// SecurityConfigManager manages security configuration with hot reloading
type SecurityConfigManager struct {
	config     *UnifiedSecurityConfig
	configPath string
	watchers   []ConfigWatcher
	mu         sync.RWMutex
	logger     Logger
}

// ConfigWatcher interface for configuration change notifications
type ConfigWatcher interface {
	OnConfigChange(config *UnifiedSecurityConfig) error
}

// Logger interface for configuration logging
type Logger interface {
	Info(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
}

// UnifiedSecurityConfig comprehensive security configuration
type UnifiedSecurityConfig struct {
	// Metadata
	Version     string    `json:"version" yaml:"version"`
	Environment string    `json:"environment" yaml:"environment"`
	UpdatedAt   time.Time `json:"updated_at" yaml:"updated_at"`

	// Core Security Components
	AgenticFramework   AgenticFrameworkConfig   `json:"agentic_framework" yaml:"agentic_framework"`
	AIFirewall         AIFirewallConfig         `json:"ai_firewall" yaml:"ai_firewall"`
	InputOutputFilter  InputOutputFilterConfig  `json:"input_output_filter" yaml:"input_output_filter"`
	PromptGuard        PromptGuardConfig        `json:"prompt_guard" yaml:"prompt_guard"`
	ThreatIntelligence ThreatIntelligenceConfig `json:"threat_intelligence" yaml:"threat_intelligence"`
	WebLayer           WebLayerConfig           `json:"web_layer" yaml:"web_layer"`

	// Security Policies
	Authentication AuthenticationConfig `json:"authentication" yaml:"authentication"`
	Authorization  AuthorizationConfig  `json:"authorization" yaml:"authorization"`
	Encryption     EncryptionConfig     `json:"encryption" yaml:"encryption"`
	Compliance     ComplianceConfig     `json:"compliance" yaml:"compliance"`

	// Monitoring & Alerting
	Monitoring MonitoringConfig      `json:"monitoring" yaml:"monitoring"`
	Alerting   AlertingConfig        `json:"alerting" yaml:"alerting"`
	Logging    SecurityLoggingConfig `json:"logging" yaml:"logging"`

	// Feature Toggles
	FeatureToggles FeatureTogglesConfig `json:"feature_toggles" yaml:"feature_toggles"`

	// Environment-specific Overrides
	Overrides map[string]interface{} `json:"overrides,omitempty" yaml:"overrides,omitempty"`
}

// AgenticFrameworkConfig configuration for agentic security framework
type AgenticFrameworkConfig struct {
	Enabled                 bool          `json:"enabled" yaml:"enabled"`
	RealTimeAnalysis        bool          `json:"real_time_analysis" yaml:"real_time_analysis"`
	ThreatResponseThreshold float64       `json:"threat_response_threshold" yaml:"threat_response_threshold"`
	AutoBlockEnabled        bool          `json:"auto_block_enabled" yaml:"auto_block_enabled"`
	LearningMode            bool          `json:"learning_mode" yaml:"learning_mode"`
	MaxConcurrentAnalysis   int           `json:"max_concurrent_analysis" yaml:"max_concurrent_analysis"`
	ThreatRetentionDuration time.Duration `json:"threat_retention_duration" yaml:"threat_retention_duration"`
	AlertCooldownPeriod     time.Duration `json:"alert_cooldown_period" yaml:"alert_cooldown_period"`
	ConfidenceThreshold     float64       `json:"confidence_threshold" yaml:"confidence_threshold"`
}

// AIFirewallConfig configuration for AI firewall
type AIFirewallConfig struct {
	Enabled             bool                 `json:"enabled" yaml:"enabled"`
	MLDetection         bool                 `json:"ml_detection" yaml:"ml_detection"`
	BehaviorAnalysis    bool                 `json:"behavior_analysis" yaml:"behavior_analysis"`
	AnomalyDetection    bool                 `json:"anomaly_detection" yaml:"anomaly_detection"`
	GeoBlocking         bool                 `json:"geo_blocking" yaml:"geo_blocking"`
	RateLimiting        bool                 `json:"rate_limiting" yaml:"rate_limiting"`
	BlockThreshold      float64              `json:"block_threshold" yaml:"block_threshold"`
	AlertThreshold      float64              `json:"alert_threshold" yaml:"alert_threshold"`
	Rules               []FirewallRuleConfig `json:"rules" yaml:"rules"`
	WhitelistedIPs      []string             `json:"whitelisted_ips" yaml:"whitelisted_ips"`
	BlacklistedIPs      []string             `json:"blacklisted_ips" yaml:"blacklisted_ips"`
	GeoBlockedCountries []string             `json:"geo_blocked_countries" yaml:"geo_blocked_countries"`
}

// FirewallRuleConfig configuration for firewall rules
type FirewallRuleConfig struct {
	ID          string  `json:"id" yaml:"id"`
	Name        string  `json:"name" yaml:"name"`
	Enabled     bool    `json:"enabled" yaml:"enabled"`
	Priority    int     `json:"priority" yaml:"priority"`
	Pattern     string  `json:"pattern" yaml:"pattern"`
	Action      string  `json:"action" yaml:"action"`
	Severity    string  `json:"severity" yaml:"severity"`
	Confidence  float64 `json:"confidence" yaml:"confidence"`
	Description string  `json:"description" yaml:"description"`
}

// InputOutputFilterConfig configuration for input/output filtering
type InputOutputFilterConfig struct {
	Enabled            bool     `json:"enabled" yaml:"enabled"`
	InputValidation    bool     `json:"input_validation" yaml:"input_validation"`
	OutputSanitization bool     `json:"output_sanitization" yaml:"output_sanitization"`
	ContentAnalysis    bool     `json:"content_analysis" yaml:"content_analysis"`
	ThreatScanning     bool     `json:"threat_scanning" yaml:"threat_scanning"`
	StrictMode         bool     `json:"strict_mode" yaml:"strict_mode"`
	MaxInputLength     int      `json:"max_input_length" yaml:"max_input_length"`
	MaxOutputLength    int      `json:"max_output_length" yaml:"max_output_length"`
	AllowedFileTypes   []string `json:"allowed_file_types" yaml:"allowed_file_types"`
	BlockedPatterns    []string `json:"blocked_patterns" yaml:"blocked_patterns"`
	SanitizationLevel  string   `json:"sanitization_level" yaml:"sanitization_level"`
	LogViolations      bool     `json:"log_violations" yaml:"log_violations"`
	BlockOnViolation   bool     `json:"block_on_violation" yaml:"block_on_violation"`
	EncodingDetection  bool     `json:"encoding_detection" yaml:"encoding_detection"`
	MalwareScanning    bool     `json:"malware_scanning" yaml:"malware_scanning"`
}

// PromptGuardConfig configuration for prompt injection protection
type PromptGuardConfig struct {
	Enabled                       bool    `json:"enabled" yaml:"enabled"`
	SemanticAnalysis              bool    `json:"semantic_analysis" yaml:"semantic_analysis"`
	ContextAnalysis               bool    `json:"context_analysis" yaml:"context_analysis"`
	StrictMode                    bool    `json:"strict_mode" yaml:"strict_mode"`
	ConfidenceThreshold           float64 `json:"confidence_threshold" yaml:"confidence_threshold"`
	MaxPromptLength               int     `json:"max_prompt_length" yaml:"max_prompt_length"`
	EnableLearning                bool    `json:"enable_learning" yaml:"enable_learning"`
	BlockSuspiciousPrompts        bool    `json:"block_suspicious_prompts" yaml:"block_suspicious_prompts"`
	LogAllAttempts                bool    `json:"log_all_attempts" yaml:"log_all_attempts"`
	RoleManipulationDetection     bool    `json:"role_manipulation_detection" yaml:"role_manipulation_detection"`
	InstructionInjectionDetection bool    `json:"instruction_injection_detection" yaml:"instruction_injection_detection"`
}

// ThreatIntelligenceConfig configuration for threat intelligence
type ThreatIntelligenceConfig struct {
	Enabled           bool              `json:"enabled" yaml:"enabled"`
	UpdateInterval    time.Duration     `json:"update_interval" yaml:"update_interval"`
	Sources           []string          `json:"sources" yaml:"sources"`
	APIKeys           map[string]string `json:"api_keys" yaml:"api_keys"`
	CacheTimeout      time.Duration     `json:"cache_timeout" yaml:"cache_timeout"`
	MaxCacheSize      int               `json:"max_cache_size" yaml:"max_cache_size"`
	IOCTypes          []string          `json:"ioc_types" yaml:"ioc_types"`
	ReputationScoring bool              `json:"reputation_scoring" yaml:"reputation_scoring"`
	AutoBlocking      bool              `json:"auto_blocking" yaml:"auto_blocking"`
}

// WebLayerConfig configuration for web layer security
type WebLayerConfig struct {
	Enabled         bool          `json:"enabled" yaml:"enabled"`
	SecurityHeaders bool          `json:"security_headers" yaml:"security_headers"`
	CSP             CSPConfig     `json:"csp" yaml:"csp"`
	HSTS            HSTSConfig    `json:"hsts" yaml:"hsts"`
	XFrameOptions   string        `json:"x_frame_options" yaml:"x_frame_options"`
	MaxRequestSize  int64         `json:"max_request_size" yaml:"max_request_size"`
	RequestTimeout  time.Duration `json:"request_timeout" yaml:"request_timeout"`
	RateLimiting    bool          `json:"rate_limiting" yaml:"rate_limiting"`
	SessionSecurity bool          `json:"session_security" yaml:"session_security"`
	CookieSecurity  bool          `json:"cookie_security" yaml:"cookie_security"`
	IPFiltering     bool          `json:"ip_filtering" yaml:"ip_filtering"`
	GeoBlocking     bool          `json:"geo_blocking" yaml:"geo_blocking"`
}

// CSPConfig Content Security Policy configuration
type CSPConfig struct {
	Enabled                 bool   `json:"enabled" yaml:"enabled"`
	Policy                  string `json:"policy" yaml:"policy"`
	ReportOnly              bool   `json:"report_only" yaml:"report_only"`
	ReportURI               string `json:"report_uri" yaml:"report_uri"`
	UpgradeInsecureRequests bool   `json:"upgrade_insecure_requests" yaml:"upgrade_insecure_requests"`
}

// HSTSConfig HTTP Strict Transport Security configuration
type HSTSConfig struct {
	Enabled           bool `json:"enabled" yaml:"enabled"`
	MaxAge            int  `json:"max_age" yaml:"max_age"`
	IncludeSubDomains bool `json:"include_subdomains" yaml:"include_subdomains"`
	Preload           bool `json:"preload" yaml:"preload"`
}

// AuthenticationConfig authentication security configuration
type AuthenticationConfig struct {
	PasswordPolicy    PasswordPolicyConfig    `json:"password_policy" yaml:"password_policy"`
	MultiFactorAuth   MultiFactorAuthConfig   `json:"multi_factor_auth" yaml:"multi_factor_auth"`
	SessionManagement SessionManagementConfig `json:"session_management" yaml:"session_management"`
	AccountLockout    AccountLockoutConfig    `json:"account_lockout" yaml:"account_lockout"`
	OAuth             OAuthConfig             `json:"oauth" yaml:"oauth"`
	SAML              SAMLConfig              `json:"saml" yaml:"saml"`
}

// PasswordPolicyConfig password policy configuration
type PasswordPolicyConfig struct {
	MinLength        int           `json:"min_length" yaml:"min_length"`
	RequireUppercase bool          `json:"require_uppercase" yaml:"require_uppercase"`
	RequireLowercase bool          `json:"require_lowercase" yaml:"require_lowercase"`
	RequireNumbers   bool          `json:"require_numbers" yaml:"require_numbers"`
	RequireSpecial   bool          `json:"require_special" yaml:"require_special"`
	HistoryCount     int           `json:"history_count" yaml:"history_count"`
	MaxAge           time.Duration `json:"max_age" yaml:"max_age"`
	MinAge           time.Duration `json:"min_age" yaml:"min_age"`
	ComplexityScore  int           `json:"complexity_score" yaml:"complexity_score"`
}

// MultiFactorAuthConfig multi-factor authentication configuration
type MultiFactorAuthConfig struct {
	Enabled       bool     `json:"enabled" yaml:"enabled"`
	Required      bool     `json:"required" yaml:"required"`
	Methods       []string `json:"methods" yaml:"methods"`
	TOTPIssuer    string   `json:"totp_issuer" yaml:"totp_issuer"`
	TOTPDigits    int      `json:"totp_digits" yaml:"totp_digits"`
	TOTPPeriod    int      `json:"totp_period" yaml:"totp_period"`
	BackupCodes   bool     `json:"backup_codes" yaml:"backup_codes"`
	SMSProvider   string   `json:"sms_provider" yaml:"sms_provider"`
	EmailProvider string   `json:"email_provider" yaml:"email_provider"`
}

// SessionManagementConfig session management configuration
type SessionManagementConfig struct {
	Timeout               time.Duration `json:"timeout" yaml:"timeout"`
	MaxConcurrentSessions int           `json:"max_concurrent_sessions" yaml:"max_concurrent_sessions"`
	SecureCookies         bool          `json:"secure_cookies" yaml:"secure_cookies"`
	HTTPOnlyCookies       bool          `json:"http_only_cookies" yaml:"http_only_cookies"`
	SameSiteCookies       string        `json:"same_site_cookies" yaml:"same_site_cookies"`
	SessionRotation       bool          `json:"session_rotation" yaml:"session_rotation"`
	IdleTimeout           time.Duration `json:"idle_timeout" yaml:"idle_timeout"`
}

// AccountLockoutConfig account lockout configuration
type AccountLockoutConfig struct {
	Enabled           bool          `json:"enabled" yaml:"enabled"`
	MaxFailedAttempts int           `json:"max_failed_attempts" yaml:"max_failed_attempts"`
	LockoutDuration   time.Duration `json:"lockout_duration" yaml:"lockout_duration"`
	ResetOnSuccess    bool          `json:"reset_on_success" yaml:"reset_on_success"`
	NotifyOnLockout   bool          `json:"notify_on_lockout" yaml:"notify_on_lockout"`
}

// OAuthConfig OAuth configuration
type OAuthConfig struct {
	Enabled   bool              `json:"enabled" yaml:"enabled"`
	Providers map[string]string `json:"providers" yaml:"providers"`
	Scopes    []string          `json:"scopes" yaml:"scopes"`
}

// SAMLConfig SAML configuration
type SAMLConfig struct {
	Enabled     bool   `json:"enabled" yaml:"enabled"`
	EntityID    string `json:"entity_id" yaml:"entity_id"`
	SSOURL      string `json:"sso_url" yaml:"sso_url"`
	Certificate string `json:"certificate" yaml:"certificate"`
}

// AuthorizationConfig authorization configuration
type AuthorizationConfig struct {
	RBAC        RBACConfig        `json:"rbac" yaml:"rbac"`
	ABAC        ABACConfig        `json:"abac" yaml:"abac"`
	Permissions PermissionsConfig `json:"permissions" yaml:"permissions"`
}

// RBACConfig Role-Based Access Control configuration
type RBACConfig struct {
	Enabled     bool              `json:"enabled" yaml:"enabled"`
	DefaultRole string            `json:"default_role" yaml:"default_role"`
	Roles       map[string]string `json:"roles" yaml:"roles"`
	Inheritance bool              `json:"inheritance" yaml:"inheritance"`
}

// ABACConfig Attribute-Based Access Control configuration
type ABACConfig struct {
	Enabled    bool              `json:"enabled" yaml:"enabled"`
	Policies   []string          `json:"policies" yaml:"policies"`
	Attributes map[string]string `json:"attributes" yaml:"attributes"`
}

// PermissionsConfig permissions configuration
type PermissionsConfig struct {
	Granular    bool     `json:"granular" yaml:"granular"`
	Resources   []string `json:"resources" yaml:"resources"`
	Actions     []string `json:"actions" yaml:"actions"`
	Inheritance bool     `json:"inheritance" yaml:"inheritance"`
}

// EncryptionConfig encryption configuration
type EncryptionConfig struct {
	DataAtRest    DataEncryptionConfig    `json:"data_at_rest" yaml:"data_at_rest"`
	DataInTransit TransitEncryptionConfig `json:"data_in_transit" yaml:"data_in_transit"`
	KeyManagement KeyManagementConfig     `json:"key_management" yaml:"key_management"`
}

// DataEncryptionConfig data encryption configuration
type DataEncryptionConfig struct {
	Enabled   bool   `json:"enabled" yaml:"enabled"`
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	KeySize   int    `json:"key_size" yaml:"key_size"`
	Mode      string `json:"mode" yaml:"mode"`
}

// TransitEncryptionConfig transit encryption configuration
type TransitEncryptionConfig struct {
	TLSVersion   string   `json:"tls_version" yaml:"tls_version"`
	CipherSuites []string `json:"cipher_suites" yaml:"cipher_suites"`
	HSTS         bool     `json:"hsts" yaml:"hsts"`
	CertPinning  bool     `json:"cert_pinning" yaml:"cert_pinning"`
}

// KeyManagementConfig key management configuration
type KeyManagementConfig struct {
	Provider         string        `json:"provider" yaml:"provider"`
	RotationInterval time.Duration `json:"rotation_interval" yaml:"rotation_interval"`
	BackupEnabled    bool          `json:"backup_enabled" yaml:"backup_enabled"`
	HSMEnabled       bool          `json:"hsm_enabled" yaml:"hsm_enabled"`
}

// ComplianceConfig compliance configuration
type ComplianceConfig struct {
	GDPR     GDPRConfig     `json:"gdpr" yaml:"gdpr"`
	HIPAA    HIPAAConfig    `json:"hipaa" yaml:"hipaa"`
	SOX      SOXConfig      `json:"sox" yaml:"sox"`
	PCI      PCIConfig      `json:"pci" yaml:"pci"`
	Auditing AuditingConfig `json:"auditing" yaml:"auditing"`
}

// GDPRConfig GDPR compliance configuration
type GDPRConfig struct {
	Enabled         bool          `json:"enabled" yaml:"enabled"`
	DataRetention   time.Duration `json:"data_retention" yaml:"data_retention"`
	ConsentRequired bool          `json:"consent_required" yaml:"consent_required"`
	RightToErasure  bool          `json:"right_to_erasure" yaml:"right_to_erasure"`
}

// HIPAAConfig HIPAA compliance configuration
type HIPAAConfig struct {
	Enabled       bool `json:"enabled" yaml:"enabled"`
	PHIProtection bool `json:"phi_protection" yaml:"phi_protection"`
	AuditLogging  bool `json:"audit_logging" yaml:"audit_logging"`
	Encryption    bool `json:"encryption" yaml:"encryption"`
}

// SOXConfig SOX compliance configuration
type SOXConfig struct {
	Enabled       bool `json:"enabled" yaml:"enabled"`
	AuditTrails   bool `json:"audit_trails" yaml:"audit_trails"`
	DataIntegrity bool `json:"data_integrity" yaml:"data_integrity"`
}

// PCIConfig PCI compliance configuration
type PCIConfig struct {
	Enabled         bool `json:"enabled" yaml:"enabled"`
	DataProtection  bool `json:"data_protection" yaml:"data_protection"`
	NetworkSecurity bool `json:"network_security" yaml:"network_security"`
}

// AuditingConfig auditing configuration
type AuditingConfig struct {
	Enabled         bool          `json:"enabled" yaml:"enabled"`
	LogLevel        string        `json:"log_level" yaml:"log_level"`
	RetentionPeriod time.Duration `json:"retention_period" yaml:"retention_period"`
	Destinations    []string      `json:"destinations" yaml:"destinations"`
}

// MonitoringConfig monitoring configuration
type MonitoringConfig struct {
	Enabled         bool              `json:"enabled" yaml:"enabled"`
	MetricsEnabled  bool              `json:"metrics_enabled" yaml:"metrics_enabled"`
	TracingEnabled  bool              `json:"tracing_enabled" yaml:"tracing_enabled"`
	HealthChecks    bool              `json:"health_checks" yaml:"health_checks"`
	Dashboards      bool              `json:"dashboards" yaml:"dashboards"`
	Exporters       []string          `json:"exporters" yaml:"exporters"`
	SampleRate      float64           `json:"sample_rate" yaml:"sample_rate"`
	RetentionPeriod time.Duration     `json:"retention_period" yaml:"retention_period"`
	Endpoints       map[string]string `json:"endpoints" yaml:"endpoints"`
}

// AlertingConfig alerting configuration
type AlertingConfig struct {
	Enabled     bool              `json:"enabled" yaml:"enabled"`
	Channels    []AlertChannel    `json:"channels" yaml:"channels"`
	Rules       []AlertRule       `json:"rules" yaml:"rules"`
	Escalation  EscalationConfig  `json:"escalation" yaml:"escalation"`
	Suppression SuppressionConfig `json:"suppression" yaml:"suppression"`
}

// AlertChannel alert channel configuration
type AlertChannel struct {
	Type     string            `json:"type" yaml:"type"`
	Enabled  bool              `json:"enabled" yaml:"enabled"`
	Config   map[string]string `json:"config" yaml:"config"`
	Severity []string          `json:"severity" yaml:"severity"`
}

// AlertRule alert rule configuration
type AlertRule struct {
	ID          string  `json:"id" yaml:"id"`
	Name        string  `json:"name" yaml:"name"`
	Enabled     bool    `json:"enabled" yaml:"enabled"`
	Condition   string  `json:"condition" yaml:"condition"`
	Threshold   float64 `json:"threshold" yaml:"threshold"`
	Severity    string  `json:"severity" yaml:"severity"`
	Description string  `json:"description" yaml:"description"`
}

// EscalationConfig escalation configuration
type EscalationConfig struct {
	Enabled bool              `json:"enabled" yaml:"enabled"`
	Levels  []EscalationLevel `json:"levels" yaml:"levels"`
}

// EscalationLevel escalation level configuration
type EscalationLevel struct {
	Level    int           `json:"level" yaml:"level"`
	Delay    time.Duration `json:"delay" yaml:"delay"`
	Channels []string      `json:"channels" yaml:"channels"`
}

// SuppressionConfig suppression configuration
type SuppressionConfig struct {
	Enabled   bool          `json:"enabled" yaml:"enabled"`
	Duration  time.Duration `json:"duration" yaml:"duration"`
	Rules     []string      `json:"rules" yaml:"rules"`
	Whitelist []string      `json:"whitelist" yaml:"whitelist"`
}

// SecurityLoggingConfig logging configuration for security
type SecurityLoggingConfig struct {
	Level           string        `json:"level" yaml:"level"`
	Format          string        `json:"format" yaml:"format"`
	Output          []string      `json:"output" yaml:"output"`
	SecurityEvents  bool          `json:"security_events" yaml:"security_events"`
	AuditLogs       bool          `json:"audit_logs" yaml:"audit_logs"`
	RetentionPeriod time.Duration `json:"retention_period" yaml:"retention_period"`
	Encryption      bool          `json:"encryption" yaml:"encryption"`
	Compression     bool          `json:"compression" yaml:"compression"`
}

// FeatureTogglesConfig feature toggles configuration
type FeatureTogglesConfig struct {
	SecurityFeatures     map[string]bool `json:"security_features" yaml:"security_features"`
	ExperimentalFeatures map[string]bool `json:"experimental_features" yaml:"experimental_features"`
	MaintenanceMode      bool            `json:"maintenance_mode" yaml:"maintenance_mode"`
	DebugMode            bool            `json:"debug_mode" yaml:"debug_mode"`
}

// NewSecurityConfigManager creates a new security configuration manager
func NewSecurityConfigManager(configPath string, logger Logger) *SecurityConfigManager {
	return &SecurityConfigManager{
		configPath: configPath,
		watchers:   make([]ConfigWatcher, 0),
		logger:     logger,
	}
}

// LoadConfig loads configuration from file
func (scm *SecurityConfigManager) LoadConfig() error {
	scm.mu.Lock()
	defer scm.mu.Unlock()

	data, err := os.ReadFile(scm.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config UnifiedSecurityConfig
	ext := filepath.Ext(scm.configPath)

	switch ext {
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, &config)
	case ".json":
		err = json.Unmarshal(data, &config)
	default:
		return fmt.Errorf("unsupported config file format: %s", ext)
	}

	if err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate configuration
	if err := scm.validateConfig(&config); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	scm.config = &config
	scm.config.UpdatedAt = time.Now()

	scm.logger.Info("Security configuration loaded successfully", "path", scm.configPath)
	return nil
}

// GetConfig returns current configuration (thread-safe)
func (scm *SecurityConfigManager) GetConfig() *UnifiedSecurityConfig {
	scm.mu.RLock()
	defer scm.mu.RUnlock()

	if scm.config == nil {
		return nil
	}

	// Return a copy to prevent external modifications
	configCopy := *scm.config
	return &configCopy
}

// UpdateConfig updates configuration and notifies watchers
func (scm *SecurityConfigManager) UpdateConfig(config *UnifiedSecurityConfig) error {
	scm.mu.Lock()
	defer scm.mu.Unlock()

	// Validate configuration
	if err := scm.validateConfig(config); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	config.UpdatedAt = time.Now()
	scm.config = config

	// Notify watchers
	for _, watcher := range scm.watchers {
		if err := watcher.OnConfigChange(config); err != nil {
			scm.logger.Error("Failed to notify config watcher", "error", err)
		}
	}

	scm.logger.Info("Security configuration updated successfully")
	return nil
}

// SaveConfig saves current configuration to file
func (scm *SecurityConfigManager) SaveConfig() error {
	scm.mu.RLock()
	config := scm.config
	scm.mu.RUnlock()

	if config == nil {
		return fmt.Errorf("no configuration to save")
	}

	var data []byte
	var err error
	ext := filepath.Ext(scm.configPath)

	switch ext {
	case ".yaml", ".yml":
		data, err = yaml.Marshal(config)
	case ".json":
		data, err = json.MarshalIndent(config, "", "  ")
	default:
		return fmt.Errorf("unsupported config file format: %s", ext)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(scm.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	scm.logger.Info("Security configuration saved successfully", "path", scm.configPath)
	return nil
}

// AddWatcher adds a configuration watcher
func (scm *SecurityConfigManager) AddWatcher(watcher ConfigWatcher) {
	scm.mu.Lock()
	defer scm.mu.Unlock()
	scm.watchers = append(scm.watchers, watcher)
}

// RemoveWatcher removes a configuration watcher
func (scm *SecurityConfigManager) RemoveWatcher(watcher ConfigWatcher) {
	scm.mu.Lock()
	defer scm.mu.Unlock()

	for i, w := range scm.watchers {
		if w == watcher {
			scm.watchers = append(scm.watchers[:i], scm.watchers[i+1:]...)
			break
		}
	}
}

// validateConfig validates the security configuration
func (scm *SecurityConfigManager) validateConfig(config *UnifiedSecurityConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	if config.Version == "" {
		return fmt.Errorf("config version is required")
	}

	if config.Environment == "" {
		return fmt.Errorf("config environment is required")
	}

	// Validate thresholds
	if config.AgenticFramework.ThreatResponseThreshold < 0 || config.AgenticFramework.ThreatResponseThreshold > 1 {
		return fmt.Errorf("agentic framework threat response threshold must be between 0 and 1")
	}

	if config.AIFirewall.BlockThreshold < 0 || config.AIFirewall.BlockThreshold > 1 {
		return fmt.Errorf("AI firewall block threshold must be between 0 and 1")
	}

	if config.PromptGuard.ConfidenceThreshold < 0 || config.PromptGuard.ConfidenceThreshold > 1 {
		return fmt.Errorf("prompt guard confidence threshold must be between 0 and 1")
	}

	// Validate durations
	if config.AgenticFramework.ThreatRetentionDuration < 0 {
		return fmt.Errorf("threat retention duration cannot be negative")
	}

	if config.ThreatIntelligence.UpdateInterval < time.Minute {
		return fmt.Errorf("threat intelligence update interval must be at least 1 minute")
	}

	// Validate authentication settings
	if config.Authentication.PasswordPolicy.MinLength < 4 {
		return fmt.Errorf("minimum password length must be at least 4")
	}

	if config.Authentication.SessionManagement.Timeout < time.Minute {
		return fmt.Errorf("session timeout must be at least 1 minute")
	}

	return nil
}

// StartConfigWatcher starts watching for configuration file changes
func (scm *SecurityConfigManager) StartConfigWatcher() error {
	// This is a simplified implementation
	// In production, you would use a proper file watcher like fsnotify
	go scm.watchConfigFile()
	return nil
}

// watchConfigFile watches for configuration file changes
func (scm *SecurityConfigManager) watchConfigFile() {
	// Simplified polling-based watcher
	// In production, use fsnotify or similar for efficient file watching
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	var lastModTime time.Time
	if stat, err := os.Stat(scm.configPath); err == nil {
		lastModTime = stat.ModTime()
	}

	for range ticker.C {
		stat, err := os.Stat(scm.configPath)
		if err != nil {
			continue
		}

		if stat.ModTime().After(lastModTime) {
			lastModTime = stat.ModTime()
			scm.logger.Info("Configuration file changed, reloading...")

			if err := scm.LoadConfig(); err != nil {
				scm.logger.Error("Failed to reload configuration", "error", err)
				continue
			}

			// Notify watchers
			scm.mu.RLock()
			config := scm.config
			watchers := scm.watchers
			scm.mu.RUnlock()

			for _, watcher := range watchers {
				if err := watcher.OnConfigChange(config); err != nil {
					scm.logger.Error("Failed to notify config watcher", "error", err)
				}
			}

			scm.logger.Info("Configuration reloaded successfully")
		}
	}
}

// UpdateFeatureToggle updates a specific feature toggle
func (scm *SecurityConfigManager) UpdateFeatureToggle(feature string, enabled bool) error {
	scm.mu.Lock()
	defer scm.mu.Unlock()

	if scm.config == nil {
		return fmt.Errorf("no configuration loaded")
	}

	if scm.config.FeatureToggles.SecurityFeatures == nil {
		scm.config.FeatureToggles.SecurityFeatures = make(map[string]bool)
	}

	scm.config.FeatureToggles.SecurityFeatures[feature] = enabled
	scm.config.UpdatedAt = time.Now()

	// Notify watchers
	for _, watcher := range scm.watchers {
		if err := watcher.OnConfigChange(scm.config); err != nil {
			scm.logger.Error("Failed to notify config watcher", "error", err)
		}
	}

	scm.logger.Info("Feature toggle updated", "feature", feature, "enabled", enabled)
	return nil
}

// UpdateThreshold updates a security threshold
func (scm *SecurityConfigManager) UpdateThreshold(component, threshold string, value float64) error {
	scm.mu.Lock()
	defer scm.mu.Unlock()

	if scm.config == nil {
		return fmt.Errorf("no configuration loaded")
	}

	if value < 0 || value > 1 {
		return fmt.Errorf("threshold value must be between 0 and 1")
	}

	switch component {
	case "agentic_framework":
		switch threshold {
		case "threat_response":
			scm.config.AgenticFramework.ThreatResponseThreshold = value
		case "confidence":
			scm.config.AgenticFramework.ConfidenceThreshold = value
		default:
			return fmt.Errorf("unknown agentic framework threshold: %s", threshold)
		}
	case "ai_firewall":
		switch threshold {
		case "block":
			scm.config.AIFirewall.BlockThreshold = value
		case "alert":
			scm.config.AIFirewall.AlertThreshold = value
		default:
			return fmt.Errorf("unknown AI firewall threshold: %s", threshold)
		}
	case "prompt_guard":
		switch threshold {
		case "confidence":
			scm.config.PromptGuard.ConfidenceThreshold = value
		default:
			return fmt.Errorf("unknown prompt guard threshold: %s", threshold)
		}
	default:
		return fmt.Errorf("unknown component: %s", component)
	}

	scm.config.UpdatedAt = time.Now()

	// Notify watchers
	for _, watcher := range scm.watchers {
		if err := watcher.OnConfigChange(scm.config); err != nil {
			scm.logger.Error("Failed to notify config watcher", "error", err)
		}
	}

	scm.logger.Info("Threshold updated", "component", component, "threshold", threshold, "value", value)
	return nil
}

// EnableMaintenanceMode enables or disables maintenance mode
func (scm *SecurityConfigManager) EnableMaintenanceMode(enabled bool) error {
	scm.mu.Lock()
	defer scm.mu.Unlock()

	if scm.config == nil {
		return fmt.Errorf("no configuration loaded")
	}

	scm.config.FeatureToggles.MaintenanceMode = enabled
	scm.config.UpdatedAt = time.Now()

	// Notify watchers
	for _, watcher := range scm.watchers {
		if err := watcher.OnConfigChange(scm.config); err != nil {
			scm.logger.Error("Failed to notify config watcher", "error", err)
		}
	}

	scm.logger.Info("Maintenance mode updated", "enabled", enabled)
	return nil
}

// GetConfigSummary returns a summary of current configuration
func (scm *SecurityConfigManager) GetConfigSummary() map[string]interface{} {
	scm.mu.RLock()
	defer scm.mu.RUnlock()

	if scm.config == nil {
		return map[string]interface{}{"error": "no configuration loaded"}
	}

	return map[string]interface{}{
		"version":     scm.config.Version,
		"environment": scm.config.Environment,
		"updated_at":  scm.config.UpdatedAt,
		"components": map[string]interface{}{
			"agentic_framework": map[string]interface{}{
				"enabled":                   scm.config.AgenticFramework.Enabled,
				"threat_response_threshold": scm.config.AgenticFramework.ThreatResponseThreshold,
				"auto_block_enabled":        scm.config.AgenticFramework.AutoBlockEnabled,
			},
			"ai_firewall": map[string]interface{}{
				"enabled":         scm.config.AIFirewall.Enabled,
				"block_threshold": scm.config.AIFirewall.BlockThreshold,
				"alert_threshold": scm.config.AIFirewall.AlertThreshold,
			},
			"input_output_filter": map[string]interface{}{
				"enabled":     scm.config.InputOutputFilter.Enabled,
				"strict_mode": scm.config.InputOutputFilter.StrictMode,
			},
			"prompt_guard": map[string]interface{}{
				"enabled":              scm.config.PromptGuard.Enabled,
				"confidence_threshold": scm.config.PromptGuard.ConfidenceThreshold,
			},
			"web_layer": map[string]interface{}{
				"enabled":          scm.config.WebLayer.Enabled,
				"security_headers": scm.config.WebLayer.SecurityHeaders,
				"csp_enabled":      scm.config.WebLayer.CSP.Enabled,
				"hsts_enabled":     scm.config.WebLayer.HSTS.Enabled,
			},
		},
		"feature_toggles": scm.config.FeatureToggles,
		"monitoring": map[string]interface{}{
			"enabled":         scm.config.Monitoring.Enabled,
			"metrics_enabled": scm.config.Monitoring.MetricsEnabled,
			"tracing_enabled": scm.config.Monitoring.TracingEnabled,
		},
		"alerting": map[string]interface{}{
			"enabled": scm.config.Alerting.Enabled,
		},
	}
}
