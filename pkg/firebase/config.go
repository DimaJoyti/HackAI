package firebase

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the Firebase configuration
type Config struct {
	Firebase FirebaseConfig `yaml:"firebase"`
	Common   CommonConfig   `yaml:"common"`
}

// FirebaseConfig contains Firebase-specific settings
type FirebaseConfig struct {
	ProjectID           string      `yaml:"project_id"`
	APIKey              string      `yaml:"api_key"`
	AuthDomain          string      `yaml:"auth_domain"`
	StorageBucket       string      `yaml:"storage_bucket"`
	MessagingSenderID   string      `yaml:"messaging_sender_id"`
	AppID               string      `yaml:"app_id"`
	MeasurementID       string      `yaml:"measurement_id"`
	Admin               AdminConfig `yaml:"admin"`
	Auth                AuthConfig  `yaml:"auth"`
}

// AdminConfig contains Firebase Admin SDK settings
type AdminConfig struct {
	ServiceAccountPath string `yaml:"service_account_path"`
	DatabaseURL        string `yaml:"database_url"`
}

// AuthConfig contains authentication settings
type AuthConfig struct {
	EnabledProviders []string           `yaml:"enabled_providers"`
	EmailPassword    EmailPasswordConfig `yaml:"email_password"`
	OAuthProviders   OAuthProvidersConfig `yaml:"oauth_providers"`
	PhoneAuth        PhoneAuthConfig     `yaml:"phone_auth"`
	MFA              MFAConfig          `yaml:"mfa"`
	Session          SessionConfig      `yaml:"session"`
	Security         SecurityConfig     `yaml:"security"`
}

// EmailPasswordConfig contains email/password authentication settings
type EmailPasswordConfig struct {
	Enabled              bool           `yaml:"enabled"`
	RequireEmailVerification bool       `yaml:"require_email_verification"`
	PasswordPolicy       PasswordPolicy `yaml:"password_policy"`
}

// PasswordPolicy defines password requirements
type PasswordPolicy struct {
	MinLength            int  `yaml:"min_length"`
	RequireUppercase     bool `yaml:"require_uppercase"`
	RequireLowercase     bool `yaml:"require_lowercase"`
	RequireNumbers       bool `yaml:"require_numbers"`
	RequireSpecialChars  bool `yaml:"require_special_chars"`
}

// OAuthProvidersConfig contains OAuth provider settings
type OAuthProvidersConfig struct {
	Google GoogleOAuthConfig `yaml:"google"`
	GitHub GitHubOAuthConfig `yaml:"github"`
}

// GoogleOAuthConfig contains Google OAuth settings
type GoogleOAuthConfig struct {
	Enabled      bool   `yaml:"enabled"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

// GitHubOAuthConfig contains GitHub OAuth settings
type GitHubOAuthConfig struct {
	Enabled      bool   `yaml:"enabled"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

// PhoneAuthConfig contains phone authentication settings
type PhoneAuthConfig struct {
	Enabled          bool              `yaml:"enabled"`
	TestPhoneNumbers map[string]string `yaml:"test_phone_numbers"`
}

// MFAConfig contains multi-factor authentication settings
type MFAConfig struct {
	Enabled          bool     `yaml:"enabled"`
	Enforcement      string   `yaml:"enforcement"`
	AllowedProviders []string `yaml:"allowed_providers"`
}

// SessionConfig contains session management settings
type SessionConfig struct {
	Timeout                           time.Duration `yaml:"timeout"`
	RefreshTokenTTL                   time.Duration `yaml:"refresh_token_ttl"`
	RevokeRefreshTokensOnPasswordChange bool        `yaml:"revoke_refresh_tokens_on_password_change"`
}

// SecurityConfig contains security settings
type SecurityConfig struct {
	EnableAnonymousUsers            bool `yaml:"enable_anonymous_users"`
	BlockFunctionsTrigger           bool `yaml:"block_functions_trigger"`
	EnableEmailEnumerationProtection bool `yaml:"enable_email_enumeration_protection"`
}

// CommonConfig contains common settings
type CommonConfig struct {
	Integration IntegrationConfig `yaml:"integration"`
	Monitoring  MonitoringConfig  `yaml:"monitoring"`
	RateLimiting RateLimitingConfig `yaml:"rate_limiting"`
}

// IntegrationConfig contains integration settings
type IntegrationConfig struct {
	DatabaseSync DatabaseSyncConfig `yaml:"database_sync"`
	CustomClaims CustomClaimsConfig `yaml:"custom_claims"`
	Webhooks     WebhooksConfig     `yaml:"webhooks"`
}

// DatabaseSyncConfig contains database synchronization settings
type DatabaseSyncConfig struct {
	Enabled      bool `yaml:"enabled"`
	SyncOnCreate bool `yaml:"sync_on_create"`
	SyncOnUpdate bool `yaml:"sync_on_update"`
	SyncOnDelete bool `yaml:"sync_on_delete"`
}

// CustomClaimsConfig contains custom claims settings
type CustomClaimsConfig struct {
	RoleClaim         string `yaml:"role_claim"`
	PermissionsClaim  string `yaml:"permissions_claim"`
	OrganizationClaim string `yaml:"organization_claim"`
}

// WebhooksConfig contains webhook settings
type WebhooksConfig struct {
	UserCreated string `yaml:"user_created"`
	UserUpdated string `yaml:"user_updated"`
	UserDeleted string `yaml:"user_deleted"`
}

// MonitoringConfig contains monitoring settings
type MonitoringConfig struct {
	EnableAuthLogging bool           `yaml:"enable_auth_logging"`
	LogLevel          string         `yaml:"log_level"`
	Metrics           MetricsConfig  `yaml:"metrics"`
}

// MetricsConfig contains metrics settings
type MetricsConfig struct {
	Enabled        bool          `yaml:"enabled"`
	ExportInterval time.Duration `yaml:"export_interval"`
}

// RateLimitingConfig contains rate limiting settings
type RateLimitingConfig struct {
	SignInAttempts  RateLimitConfig `yaml:"sign_in_attempts"`
	SignUpAttempts  RateLimitConfig `yaml:"sign_up_attempts"`
}

// RateLimitConfig contains rate limit settings
type RateLimitConfig struct {
	MaxAttempts     int           `yaml:"max_attempts"`
	Window          time.Duration `yaml:"window"`
	BlockDuration   time.Duration `yaml:"block_duration"`
}

// LoadConfig loads Firebase configuration from file
func LoadConfig(configPath string, environment string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse the YAML file
	var configs map[string]Config
	if err := yaml.Unmarshal(data, &configs); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Get environment-specific config
	envConfig, exists := configs[environment]
	if !exists {
		return nil, fmt.Errorf("configuration for environment '%s' not found", environment)
	}

	// Merge with common config if it exists
	if commonConfig, exists := configs["common"]; exists {
		envConfig.Common = commonConfig.Common
	}

	// Expand environment variables
	if err := expandEnvVars(&envConfig); err != nil {
		return nil, fmt.Errorf("failed to expand environment variables: %w", err)
	}

	return &envConfig, nil
}

// expandEnvVars expands environment variables in the configuration
func expandEnvVars(config *Config) error {
	config.Firebase.APIKey = os.ExpandEnv(config.Firebase.APIKey)
	config.Firebase.MessagingSenderID = os.ExpandEnv(config.Firebase.MessagingSenderID)
	config.Firebase.AppID = os.ExpandEnv(config.Firebase.AppID)
	config.Firebase.MeasurementID = os.ExpandEnv(config.Firebase.MeasurementID)
	
	config.Firebase.Auth.OAuthProviders.Google.ClientID = os.ExpandEnv(config.Firebase.Auth.OAuthProviders.Google.ClientID)
	config.Firebase.Auth.OAuthProviders.Google.ClientSecret = os.ExpandEnv(config.Firebase.Auth.OAuthProviders.Google.ClientSecret)
	config.Firebase.Auth.OAuthProviders.GitHub.ClientID = os.ExpandEnv(config.Firebase.Auth.OAuthProviders.GitHub.ClientID)
	config.Firebase.Auth.OAuthProviders.GitHub.ClientSecret = os.ExpandEnv(config.Firebase.Auth.OAuthProviders.GitHub.ClientSecret)
	
	config.Common.Integration.Webhooks.UserCreated = os.ExpandEnv(config.Common.Integration.Webhooks.UserCreated)
	config.Common.Integration.Webhooks.UserUpdated = os.ExpandEnv(config.Common.Integration.Webhooks.UserUpdated)
	config.Common.Integration.Webhooks.UserDeleted = os.ExpandEnv(config.Common.Integration.Webhooks.UserDeleted)

	return nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Firebase.ProjectID == "" {
		return fmt.Errorf("firebase project_id is required")
	}
	
	if c.Firebase.Admin.ServiceAccountPath == "" {
		return fmt.Errorf("firebase admin service_account_path is required")
	}
	
	// Check if service account file exists
	if _, err := os.Stat(c.Firebase.Admin.ServiceAccountPath); os.IsNotExist(err) {
		return fmt.Errorf("service account file not found: %s", c.Firebase.Admin.ServiceAccountPath)
	}
	
	return nil
}
