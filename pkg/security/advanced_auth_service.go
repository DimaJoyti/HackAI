package security

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// AdvancedAuthService provides enterprise-grade authentication and authorization
type AdvancedAuthService struct {
	id     string
	config *AdvancedAuthConfig
	logger *logger.Logger

	// Core authentication components
	jwtManager      *JWTManager
	passwordManager *PasswordManager
	mfaManager      *MFAManager
	sessionManager  *SessionManager

	// Security components
	rateLimiter       *AuthRateLimiter
	accountLockout    *AccountLockoutManager
	ipSecurityManager *IPSecurityManager
	deviceManager     *DeviceManager

	// Authorization components
	rbacManager       *RBACManager
	permissionManager *PermissionManager
	policyEngine      *PolicyEngine

	// Audit and monitoring
	auditLogger     *SecurityAuditLogger
	securityMonitor *SecurityMonitor
	threatDetector  *ThreatDetector

	// Storage and caching
	userStore    UserStore
	sessionStore SessionStore
	tokenStore   TokenStore

	// State management
	activeSessions map[string]*AuthSession
	activeTokens   map[string]*AuthToken
	securityEvents []*SecurityEvent

	// Concurrency control
	mutex  sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
}

// AdvancedAuthConfig configuration for advanced authentication
type AdvancedAuthConfig struct {
	// Service configuration
	ServiceName string `yaml:"service_name"`
	Environment string `yaml:"environment"`

	// JWT configuration
	JWT *JWTConfig `yaml:"jwt"`

	// Password policy
	PasswordPolicy *PasswordPolicyConfig `yaml:"password_policy"`

	// Multi-factor authentication
	MFA *MFAConfig `yaml:"mfa"`

	// Session management
	SessionConfig *SessionConfig `yaml:"session"`

	// Rate limiting
	RateLimit *RateLimitConfig `yaml:"rate_limit"`

	// Account lockout
	AccountLockout *AccountLockoutConfig `yaml:"account_lockout"`

	// IP security
	IPSecurity *IPSecurityConfig `yaml:"ip_security"`

	// Device management
	DeviceManagement *DeviceConfig `yaml:"device_management"`

	// Authorization
	Authorization *AuthorizationConfig `yaml:"authorization"`

	// Security monitoring
	SecurityMonitoring *SecurityMonitorConfig `yaml:"security_monitoring"`

	// Audit logging
	AuditLogging *AuditConfig `yaml:"audit_logging"`

	// Feature flags
	EnableMFA             bool `yaml:"enable_mfa"`
	EnableDeviceTracking  bool `yaml:"enable_device_tracking"`
	EnableIPRestrictions  bool `yaml:"enable_ip_restrictions"`
	EnableThreatDetection bool `yaml:"enable_threat_detection"`
	EnableAuditLogging    bool `yaml:"enable_audit_logging"`
	EnableRBAC            bool `yaml:"enable_rbac"`
	EnablePolicyEngine    bool `yaml:"enable_policy_engine"`
}

// JWTConfig JWT configuration
type JWTConfig struct {
	Secret                string        `yaml:"secret"`
	Issuer                string        `yaml:"issuer"`
	Audience              string        `yaml:"audience"`
	AccessTokenTTL        time.Duration `yaml:"access_token_ttl"`
	RefreshTokenTTL       time.Duration `yaml:"refresh_token_ttl"`
	Algorithm             string        `yaml:"algorithm"`
	EnableRefreshRotation bool          `yaml:"enable_refresh_rotation"`
	MaxRefreshTokens      int           `yaml:"max_refresh_tokens"`
}

// PasswordPolicyConfig password policy configuration
type PasswordPolicyConfig struct {
	MinLength             int           `yaml:"min_length"`
	MaxLength             int           `yaml:"max_length"`
	RequireUppercase      bool          `yaml:"require_uppercase"`
	RequireLowercase      bool          `yaml:"require_lowercase"`
	RequireNumbers        bool          `yaml:"require_numbers"`
	RequireSpecialChars   bool          `yaml:"require_special_chars"`
	ForbidCommonPasswords bool          `yaml:"forbid_common_passwords"`
	PasswordHistoryCount  int           `yaml:"password_history_count"`
	PasswordExpiry        time.Duration `yaml:"password_expiry"`
	HashAlgorithm         string        `yaml:"hash_algorithm"`
	HashCost              int           `yaml:"hash_cost"`
}

// MFAConfig multi-factor authentication configuration
type MFAConfig struct {
	EnableTOTP         bool          `yaml:"enable_totp"`
	EnableSMS          bool          `yaml:"enable_sms"`
	EnableEmail        bool          `yaml:"enable_email"`
	EnableWebAuthn     bool          `yaml:"enable_webauthn"`
	EnableBackupCodes  bool          `yaml:"enable_backup_codes"`
	TOTPIssuer         string        `yaml:"totp_issuer"`
	TOTPDigits         int           `yaml:"totp_digits"`
	TOTPPeriod         int           `yaml:"totp_period"`
	BackupCodeCount    int           `yaml:"backup_code_count"`
	BackupCodeLength   int           `yaml:"backup_code_length"`
	RequireMFAForAdmin bool          `yaml:"require_mfa_for_admin"`
	MFAGracePeriod     time.Duration `yaml:"mfa_grace_period"`
}

// SessionConfig session management configuration
type SessionConfig struct {
	DefaultTTL            time.Duration `yaml:"default_ttl"`
	MaxTTL                time.Duration `yaml:"max_ttl"`
	ExtendOnActivity      bool          `yaml:"extend_on_activity"`
	MaxConcurrentSessions int           `yaml:"max_concurrent_sessions"`
	SessionCookieName     string        `yaml:"session_cookie_name"`
	SessionCookieSecure   bool          `yaml:"session_cookie_secure"`
	SessionCookieHTTPOnly bool          `yaml:"session_cookie_http_only"`
	SessionCookieSameSite string        `yaml:"session_cookie_same_site"`
}

// RateLimitConfig rate limiting configuration
type RateLimitConfig struct {
	LoginAttempts         int           `yaml:"login_attempts"`
	LoginWindow           time.Duration `yaml:"login_window"`
	PasswordResetAttempts int           `yaml:"password_reset_attempts"`
	PasswordResetWindow   time.Duration `yaml:"password_reset_window"`
	TokenRefreshAttempts  int           `yaml:"token_refresh_attempts"`
	TokenRefreshWindow    time.Duration `yaml:"token_refresh_window"`
	GlobalRateLimit       int           `yaml:"global_rate_limit"`
	GlobalRateWindow      time.Duration `yaml:"global_rate_window"`
}

// AccountLockoutConfig account lockout configuration
type AccountLockoutConfig struct {
	MaxFailedAttempts  int           `yaml:"max_failed_attempts"`
	LockoutDuration    time.Duration `yaml:"lockout_duration"`
	ProgressiveLockout bool          `yaml:"progressive_lockout"`
	LockoutMultiplier  float64       `yaml:"lockout_multiplier"`
	MaxLockoutDuration time.Duration `yaml:"max_lockout_duration"`
	AutoUnlockEnabled  bool          `yaml:"auto_unlock_enabled"`
}

// IPSecurityConfig IP security configuration
type IPSecurityConfig struct {
	EnableWhitelist    bool     `yaml:"enable_whitelist"`
	EnableBlacklist    bool     `yaml:"enable_blacklist"`
	WhitelistedIPs     []string `yaml:"whitelisted_ips"`
	BlacklistedIPs     []string `yaml:"blacklisted_ips"`
	EnableGeoBlocking  bool     `yaml:"enable_geo_blocking"`
	AllowedCountries   []string `yaml:"allowed_countries"`
	BlockedCountries   []string `yaml:"blocked_countries"`
	EnableVPNDetection bool     `yaml:"enable_vpn_detection"`
	BlockVPNs          bool     `yaml:"block_vpns"`
}

// DeviceConfig device management configuration
type DeviceConfig struct {
	EnableDeviceTracking  bool          `yaml:"enable_device_tracking"`
	RequireDeviceApproval bool          `yaml:"require_device_approval"`
	DeviceApprovalTTL     time.Duration `yaml:"device_approval_ttl"`
	MaxDevicesPerUser     int           `yaml:"max_devices_per_user"`
	DeviceFingerprintAlgo string        `yaml:"device_fingerprint_algo"`
	TrustNewDevices       bool          `yaml:"trust_new_devices"`
}

// AuthorizationConfig authorization configuration
type AuthorizationConfig struct {
	EnableRBAC           bool          `yaml:"enable_rbac"`
	EnableABAC           bool          `yaml:"enable_abac"`
	DefaultRole          string        `yaml:"default_role"`
	AdminRole            string        `yaml:"admin_role"`
	SuperAdminRole       string        `yaml:"super_admin_role"`
	PermissionCacheTime  time.Duration `yaml:"permission_cache_time"`
	PolicyEvaluationMode string        `yaml:"policy_evaluation_mode"`
}

// SecurityMonitorConfig security monitoring configuration
type SecurityMonitorConfig struct {
	EnableThreatDetection  bool          `yaml:"enable_threat_detection"`
	EnableAnomalyDetection bool          `yaml:"enable_anomaly_detection"`
	ThreatScoreThreshold   float64       `yaml:"threat_score_threshold"`
	AnomalyThreshold       float64       `yaml:"anomaly_threshold"`
	MonitoringInterval     time.Duration `yaml:"monitoring_interval"`
	AlertingEnabled        bool          `yaml:"alerting_enabled"`
	AlertWebhookURL        string        `yaml:"alert_webhook_url"`
}

// AuditConfig audit logging configuration
type AuditConfig struct {
	EnableAuditLogging   bool          `yaml:"enable_audit_logging"`
	AuditLogLevel        string        `yaml:"audit_log_level"`
	AuditLogFormat       string        `yaml:"audit_log_format"`
	AuditLogRetention    time.Duration `yaml:"audit_log_retention"`
	AuditLogCompression  bool          `yaml:"audit_log_compression"`
	AuditLogEncryption   bool          `yaml:"audit_log_encryption"`
	IncludeSensitiveData bool          `yaml:"include_sensitive_data"`
}

// Core authentication types
type AuthSession struct {
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id"`
	DeviceID     string                 `json:"device_id"`
	IPAddress    string                 `json:"ip_address"`
	UserAgent    string                 `json:"user_agent"`
	CreatedAt    time.Time              `json:"created_at"`
	LastActivity time.Time              `json:"last_activity"`
	ExpiresAt    time.Time              `json:"expires_at"`
	IsActive     bool                   `json:"is_active"`
	MFAVerified  bool                   `json:"mfa_verified"`
	Permissions  []string               `json:"permissions"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// AuthToken represents an authentication token
type AuthToken struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"` // access, refresh, reset
	UserID    string                 `json:"user_id"`
	SessionID string                 `json:"session_id"`
	Token     string                 `json:"token"`
	CreatedAt time.Time              `json:"created_at"`
	ExpiresAt time.Time              `json:"expires_at"`
	IsRevoked bool                   `json:"is_revoked"`
	Scopes    []string               `json:"scopes"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// Note: SecurityEvent is defined in automated_security_orchestrator.go

// Storage interfaces
type UserStore interface {
	GetUser(ctx context.Context, userID string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	CreateUser(ctx context.Context, user *User) error
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, userID string) error
}

type SessionStore interface {
	CreateSession(ctx context.Context, session *AuthSession) error
	GetSession(ctx context.Context, sessionID string) (*AuthSession, error)
	UpdateSession(ctx context.Context, session *AuthSession) error
	DeleteSession(ctx context.Context, sessionID string) error
	GetUserSessions(ctx context.Context, userID string) ([]*AuthSession, error)
	CleanupExpiredSessions(ctx context.Context) error
}

type TokenStore interface {
	CreateToken(ctx context.Context, token *AuthToken) error
	GetToken(ctx context.Context, tokenID string) (*AuthToken, error)
	RevokeToken(ctx context.Context, tokenID string) error
	CleanupExpiredTokens(ctx context.Context) error
}

// User represents a user in the system
type User struct {
	ID                  string                 `json:"id"`
	Username            string                 `json:"username"`
	Email               string                 `json:"email"`
	PasswordHash        string                 `json:"password_hash"`
	PasswordHistory     []string               `json:"password_history"`
	PasswordChangedAt   time.Time              `json:"password_changed_at"`
	Role                string                 `json:"role"`
	Permissions         []string               `json:"permissions"`
	IsActive            bool                   `json:"is_active"`
	IsLocked            bool                   `json:"is_locked"`
	LockedUntil         *time.Time             `json:"locked_until"`
	FailedLoginAttempts int                    `json:"failed_login_attempts"`
	LastLoginAt         *time.Time             `json:"last_login_at"`
	LastLoginIP         string                 `json:"last_login_ip"`
	MFAEnabled          bool                   `json:"mfa_enabled"`
	MFASecret           string                 `json:"mfa_secret"`
	BackupCodes         []string               `json:"backup_codes"`
	TrustedDevices      []string               `json:"trusted_devices"`
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
	Metadata            map[string]interface{} `json:"metadata"`
}

// NewAdvancedAuthService creates a new advanced authentication service
func NewAdvancedAuthService(config *AdvancedAuthConfig, logger *logger.Logger, userStore UserStore, sessionStore SessionStore, tokenStore TokenStore) (*AdvancedAuthService, error) {
	if config == nil {
		config = DefaultAdvancedAuthConfig()
	}

	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	if userStore == nil {
		return nil, fmt.Errorf("user store is required")
	}

	if sessionStore == nil {
		return nil, fmt.Errorf("session store is required")
	}

	if tokenStore == nil {
		return nil, fmt.Errorf("token store is required")
	}

	ctx, cancel := context.WithCancel(context.Background())

	service := &AdvancedAuthService{
		id:             generateAuthServiceID(),
		config:         config,
		logger:         logger,
		userStore:      userStore,
		sessionStore:   sessionStore,
		tokenStore:     tokenStore,
		activeSessions: make(map[string]*AuthSession),
		activeTokens:   make(map[string]*AuthToken),
		securityEvents: make([]*SecurityEvent, 0),
		ctx:            ctx,
		cancel:         cancel,
	}

	// Initialize components
	if err := service.initializeComponents(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}

	logger.Info("Advanced authentication service created",
		"service_id", service.id,
		"service_name", config.ServiceName,
		"environment", config.Environment)

	return service, nil
}

// initializeComponents initializes all authentication components
func (aas *AdvancedAuthService) initializeComponents() error {
	var err error

	// Initialize JWT manager
	aas.jwtManager, err = NewJWTManager(aas.config.JWT, aas.logger)
	if err != nil {
		return fmt.Errorf("failed to create JWT manager: %w", err)
	}

	// Initialize password manager
	aas.passwordManager, err = NewPasswordManager(aas.config.PasswordPolicy, aas.logger)
	if err != nil {
		return fmt.Errorf("failed to create password manager: %w", err)
	}

	// Initialize MFA manager
	if aas.config.EnableMFA {
		aas.mfaManager, err = NewMFAManager(aas.config.MFA, aas.logger)
		if err != nil {
			return fmt.Errorf("failed to create MFA manager: %w", err)
		}
	}

	// Initialize session manager
	aas.sessionManager, err = NewSessionManager(aas.config.SessionConfig, aas.sessionStore, aas.logger)
	if err != nil {
		return fmt.Errorf("failed to create session manager: %w", err)
	}

	// Initialize rate limiter
	aas.rateLimiter, err = NewAuthRateLimiter(aas.config.RateLimit, aas.logger)
	if err != nil {
		return fmt.Errorf("failed to create rate limiter: %w", err)
	}

	// Initialize account lockout manager
	aas.accountLockout, err = NewAccountLockoutManager(aas.config.AccountLockout, aas.logger)
	if err != nil {
		return fmt.Errorf("failed to create account lockout manager: %w", err)
	}

	// Initialize IP security manager
	if aas.config.EnableIPRestrictions {
		aas.ipSecurityManager, err = NewIPSecurityManager(aas.config.IPSecurity, aas.logger)
		if err != nil {
			return fmt.Errorf("failed to create IP security manager: %w", err)
		}
	}

	// Initialize device manager
	if aas.config.EnableDeviceTracking {
		aas.deviceManager, err = NewDeviceManager(aas.config.DeviceManagement, aas.logger)
		if err != nil {
			return fmt.Errorf("failed to create device manager: %w", err)
		}
	}

	// Initialize RBAC manager
	if aas.config.EnableRBAC {
		aas.rbacManager, err = NewRBACManager(aas.config.Authorization, aas.logger)
		if err != nil {
			return fmt.Errorf("failed to create RBAC manager: %w", err)
		}
	}

	// Initialize permission manager
	aas.permissionManager, err = NewPermissionManager(aas.config.Authorization, aas.logger)
	if err != nil {
		return fmt.Errorf("failed to create permission manager: %w", err)
	}

	// Initialize policy engine
	if aas.config.EnablePolicyEngine {
		aas.policyEngine, err = NewPolicyEngine(aas.config.Authorization, aas.logger)
		if err != nil {
			return fmt.Errorf("failed to create policy engine: %w", err)
		}
	}

	// Initialize audit logger
	if aas.config.EnableAuditLogging {
		aas.auditLogger, err = NewSecurityAuditLogger(aas.config.AuditLogging, aas.logger)
		if err != nil {
			return fmt.Errorf("failed to create audit logger: %w", err)
		}
	}

	// Initialize security monitor
	aas.securityMonitor, err = NewSecurityMonitor(aas.config.SecurityMonitoring, aas.logger)
	if err != nil {
		return fmt.Errorf("failed to create security monitor: %w", err)
	}

	// Initialize threat detector
	if aas.config.EnableThreatDetection {
		aas.threatDetector, err = NewThreatDetector(aas.config.SecurityMonitoring, aas.logger)
		if err != nil {
			return fmt.Errorf("failed to create threat detector: %w", err)
		}
	}

	return nil
}

// generateAuthServiceID generates a unique authentication service ID
func generateAuthServiceID() string {
	return fmt.Sprintf("auth-service-%s", uuid.New().String()[:8])
}

// DefaultAdvancedAuthConfig returns default advanced authentication configuration
func DefaultAdvancedAuthConfig() *AdvancedAuthConfig {
	return &AdvancedAuthConfig{
		ServiceName:           "hackai-auth-service",
		Environment:           "development",
		EnableMFA:             true,
		EnableDeviceTracking:  true,
		EnableIPRestrictions:  true,
		EnableThreatDetection: true,
		EnableAuditLogging:    true,
		EnableRBAC:            true,
		EnablePolicyEngine:    true,
		JWT: &JWTConfig{
			Secret:                "change-me-in-production",
			Issuer:                "hackai-auth-service",
			Audience:              "hackai-users",
			AccessTokenTTL:        15 * time.Minute,
			RefreshTokenTTL:       24 * time.Hour,
			Algorithm:             "HS256",
			EnableRefreshRotation: true,
			MaxRefreshTokens:      5,
		},
		PasswordPolicy: &PasswordPolicyConfig{
			MinLength:             8,
			MaxLength:             128,
			RequireUppercase:      true,
			RequireLowercase:      true,
			RequireNumbers:        true,
			RequireSpecialChars:   true,
			ForbidCommonPasswords: true,
			PasswordHistoryCount:  5,
			PasswordExpiry:        90 * 24 * time.Hour,
			HashAlgorithm:         "bcrypt",
			HashCost:              12,
		},
		MFA: &MFAConfig{
			EnableTOTP:         true,
			EnableSMS:          false,
			EnableEmail:        true,
			EnableWebAuthn:     false,
			EnableBackupCodes:  true,
			TOTPIssuer:         "HackAI",
			TOTPDigits:         6,
			TOTPPeriod:         30,
			BackupCodeCount:    10,
			BackupCodeLength:   8,
			RequireMFAForAdmin: true,
			MFAGracePeriod:     24 * time.Hour,
		},
		SessionConfig: &SessionConfig{
			DefaultTTL:            24 * time.Hour,
			MaxTTL:                7 * 24 * time.Hour,
			ExtendOnActivity:      true,
			MaxConcurrentSessions: 5,
			SessionCookieName:     "hackai_session",
			SessionCookieSecure:   true,
			SessionCookieHTTPOnly: true,
			SessionCookieSameSite: "strict",
		},
		RateLimit: &RateLimitConfig{
			LoginAttempts:         5,
			LoginWindow:           15 * time.Minute,
			PasswordResetAttempts: 3,
			PasswordResetWindow:   time.Hour,
			TokenRefreshAttempts:  10,
			TokenRefreshWindow:    time.Hour,
			GlobalRateLimit:       100,
			GlobalRateWindow:      time.Minute,
		},
		AccountLockout: &AccountLockoutConfig{
			MaxFailedAttempts:  5,
			LockoutDuration:    15 * time.Minute,
			ProgressiveLockout: true,
			LockoutMultiplier:  2.0,
			MaxLockoutDuration: 24 * time.Hour,
			AutoUnlockEnabled:  true,
		},
		IPSecurity: &IPSecurityConfig{
			EnableWhitelist:    false,
			EnableBlacklist:    true,
			WhitelistedIPs:     []string{},
			BlacklistedIPs:     []string{},
			EnableGeoBlocking:  false,
			AllowedCountries:   []string{},
			BlockedCountries:   []string{},
			EnableVPNDetection: false,
			BlockVPNs:          false,
		},
		DeviceManagement: &DeviceConfig{
			EnableDeviceTracking:  true,
			RequireDeviceApproval: false,
			DeviceApprovalTTL:     30 * 24 * time.Hour,
			MaxDevicesPerUser:     10,
			DeviceFingerprintAlgo: "sha256",
			TrustNewDevices:       true,
		},
		Authorization: &AuthorizationConfig{
			EnableRBAC:           true,
			EnableABAC:           false,
			DefaultRole:          "user",
			AdminRole:            "admin",
			SuperAdminRole:       "super_admin",
			PermissionCacheTime:  5 * time.Minute,
			PolicyEvaluationMode: "strict",
		},
		SecurityMonitoring: &SecurityMonitorConfig{
			EnableThreatDetection:  true,
			EnableAnomalyDetection: true,
			ThreatScoreThreshold:   0.7,
			AnomalyThreshold:       0.8,
			MonitoringInterval:     time.Minute,
			AlertingEnabled:        true,
			AlertWebhookURL:        "",
		},
		AuditLogging: &AuditConfig{
			EnableAuditLogging:   true,
			AuditLogLevel:        "info",
			AuditLogFormat:       "json",
			AuditLogRetention:    90 * 24 * time.Hour,
			AuditLogCompression:  true,
			AuditLogEncryption:   true,
			IncludeSensitiveData: false,
		},
	}
}

// Authentication methods

// LoginRequest represents a login request
type LoginRequest struct {
	EmailOrUsername string `json:"email_or_username"`
	Password        string `json:"password"`
	MFACode         string `json:"mfa_code,omitempty"`
	DeviceID        string `json:"device_id,omitempty"`
	IPAddress       string `json:"ip_address"`
	UserAgent       string `json:"user_agent"`
	RememberMe      bool   `json:"remember_me"`
	TrustDevice     bool   `json:"trust_device"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Success      bool      `json:"success"`
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	SessionID    string    `json:"session_id,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	RequiresMFA  bool      `json:"requires_mfa"`
	MFAMethods   []string  `json:"mfa_methods,omitempty"`
	User         *UserInfo `json:"user,omitempty"`
	Error        string    `json:"error,omitempty"`
	ThreatScore  float64   `json:"threat_score,omitempty"`
}

// UserInfo represents user information
type UserInfo struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	Permissions []string   `json:"permissions"`
	LastLoginAt *time.Time `json:"last_login_at"`
	MFAEnabled  bool       `json:"mfa_enabled"`
}

// Login authenticates a user and creates a session
func (aas *AdvancedAuthService) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	aas.mutex.Lock()
	defer aas.mutex.Unlock()

	// Check rate limiting
	if aas.rateLimiter != nil {
		if !aas.rateLimiter.AllowLogin(req.IPAddress, req.EmailOrUsername) {
			aas.logSecurityEvent("login_rate_limited", "", req.IPAddress, req.UserAgent, map[string]interface{}{
				"email_or_username": req.EmailOrUsername,
			})
			return &LoginResponse{
				Success: false,
				Error:   "Rate limit exceeded. Please try again later.",
			}, nil
		}
	}

	// Check IP restrictions
	if aas.ipSecurityManager != nil {
		if !aas.ipSecurityManager.IsIPAllowed(req.IPAddress) {
			aas.logSecurityEvent("login_ip_blocked", "", req.IPAddress, req.UserAgent, map[string]interface{}{
				"email_or_username": req.EmailOrUsername,
			})
			return &LoginResponse{
				Success: false,
				Error:   "Access denied from this IP address.",
			}, nil
		}
	}

	// Get user
	var user *User
	var err error

	if strings.Contains(req.EmailOrUsername, "@") {
		user, err = aas.userStore.GetUserByEmail(ctx, req.EmailOrUsername)
	} else {
		user, err = aas.userStore.GetUserByUsername(ctx, req.EmailOrUsername)
	}

	if err != nil || user == nil {
		aas.logSecurityEvent("login_user_not_found", "", req.IPAddress, req.UserAgent, map[string]interface{}{
			"email_or_username": req.EmailOrUsername,
		})
		return &LoginResponse{
			Success: false,
			Error:   "Invalid credentials.",
		}, nil
	}

	// Check if account is locked
	if aas.accountLockout != nil {
		if aas.accountLockout.IsAccountLocked(user.ID) {
			aas.logSecurityEvent("login_account_locked", user.ID, req.IPAddress, req.UserAgent, nil)
			return &LoginResponse{
				Success: false,
				Error:   "Account is temporarily locked. Please try again later.",
			}, nil
		}
	}

	// Verify password
	if !aas.passwordManager.VerifyPassword(req.Password, user.PasswordHash) {
		// Record failed attempt
		if aas.accountLockout != nil {
			aas.accountLockout.RecordFailedAttempt(user.ID)
		}

		aas.logSecurityEvent("login_invalid_password", user.ID, req.IPAddress, req.UserAgent, nil)
		return &LoginResponse{
			Success: false,
			Error:   "Invalid credentials.",
		}, nil
	}

	// Check if MFA is required
	if user.MFAEnabled && req.MFACode == "" {
		return &LoginResponse{
			Success:     false,
			RequiresMFA: true,
			MFAMethods:  aas.getMFAMethods(user),
			Error:       "Multi-factor authentication required.",
		}, nil
	}

	// Verify MFA if provided
	if user.MFAEnabled && req.MFACode != "" {
		if aas.mfaManager == nil {
			return &LoginResponse{
				Success: false,
				Error:   "MFA verification unavailable.",
			}, nil
		}

		if !aas.mfaManager.VerifyTOTP(user.MFASecret, req.MFACode) {
			aas.logSecurityEvent("login_invalid_mfa", user.ID, req.IPAddress, req.UserAgent, nil)
			return &LoginResponse{
				Success: false,
				Error:   "Invalid MFA code.",
			}, nil
		}
	}

	// Calculate threat score
	threatScore := aas.calculateThreatScore(req, user)

	// Check threat score
	if threatScore >= aas.config.SecurityMonitoring.ThreatScoreThreshold {
		aas.logSecurityEvent("login_high_threat_score", user.ID, req.IPAddress, req.UserAgent, map[string]interface{}{
			"threat_score": threatScore,
		})

		// Optionally block high-threat logins
		if threatScore >= 0.9 {
			return &LoginResponse{
				Success: false,
				Error:   "Login blocked due to security concerns.",
			}, nil
		}
	}

	// Clear failed attempts on successful authentication
	if aas.accountLockout != nil {
		aas.accountLockout.ClearFailedAttempts(user.ID)
	}

	// Create session
	session, err := aas.createSession(ctx, user, req)
	if err != nil {
		aas.logger.Error("Failed to create session", "error", err, "user_id", user.ID)
		return &LoginResponse{
			Success: false,
			Error:   "Failed to create session.",
		}, nil
	}

	// Generate tokens
	accessToken, refreshToken, err := aas.generateTokens(ctx, user, session)
	if err != nil {
		aas.logger.Error("Failed to generate tokens", "error", err, "user_id", user.ID)
		return &LoginResponse{
			Success: false,
			Error:   "Failed to generate tokens.",
		}, nil
	}

	// Update user last login
	user.LastLoginAt = &session.CreatedAt
	user.LastLoginIP = req.IPAddress
	if err := aas.userStore.UpdateUser(ctx, user); err != nil {
		aas.logger.Warn("Failed to update user last login", "error", err, "user_id", user.ID)
	}

	// Log successful login
	aas.logSecurityEvent("login_success", user.ID, req.IPAddress, req.UserAgent, map[string]interface{}{
		"session_id":   session.ID,
		"threat_score": threatScore,
	})

	return &LoginResponse{
		Success:      true,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		SessionID:    session.ID,
		ExpiresAt:    session.ExpiresAt,
		User: &UserInfo{
			ID:          user.ID,
			Username:    user.Username,
			Email:       user.Email,
			Role:        user.Role,
			Permissions: user.Permissions,
			LastLoginAt: user.LastLoginAt,
			MFAEnabled:  user.MFAEnabled,
		},
		ThreatScore: threatScore,
	}, nil
}

// Logout terminates a user session
func (aas *AdvancedAuthService) Logout(ctx context.Context, sessionID string) error {
	aas.mutex.Lock()
	defer aas.mutex.Unlock()

	// Get session
	session, err := aas.sessionStore.GetSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	if session == nil {
		return fmt.Errorf("session not found")
	}

	// Deactivate session
	session.IsActive = false
	if err := aas.sessionStore.UpdateSession(ctx, session); err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	// Remove from active sessions
	delete(aas.activeSessions, sessionID)

	// Revoke associated tokens
	// This would typically involve querying tokens by session ID
	// For now, we'll just log the logout

	aas.logSecurityEvent("logout_success", session.UserID, "", "", map[string]interface{}{
		"session_id": sessionID,
	})

	return nil
}

// ValidateToken validates an access token
func (aas *AdvancedAuthService) ValidateToken(ctx context.Context, token string) (*TokenValidationResult, error) {
	// Validate JWT token
	claims, err := aas.jwtManager.ValidateToken(token)
	if err != nil {
		return &TokenValidationResult{
			Valid: false,
			Error: "Invalid token",
		}, nil
	}

	// Check if token is revoked
	if aas.isTokenRevoked(token) {
		return &TokenValidationResult{
			Valid: false,
			Error: "Token revoked",
		}, nil
	}

	// Get user
	user, err := aas.userStore.GetUser(ctx, claims.UserID)
	if err != nil || user == nil {
		return &TokenValidationResult{
			Valid: false,
			Error: "User not found",
		}, nil
	}

	// Check if user is active
	if !user.IsActive || user.IsLocked {
		return &TokenValidationResult{
			Valid: false,
			Error: "User account inactive",
		}, nil
	}

	return &TokenValidationResult{
		Valid:       true,
		UserID:      user.ID,
		Username:    user.Username,
		Email:       user.Email,
		Role:        user.Role,
		Permissions: user.Permissions,
		Claims:      claims,
	}, nil
}

// TokenValidationResult represents token validation result
type TokenValidationResult struct {
	Valid       bool       `json:"valid"`
	UserID      string     `json:"user_id,omitempty"`
	Username    string     `json:"username,omitempty"`
	Email       string     `json:"email,omitempty"`
	Role        string     `json:"role,omitempty"`
	Permissions []string   `json:"permissions,omitempty"`
	Claims      *JWTClaims `json:"claims,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// Helper methods

// createSession creates a new authentication session
func (aas *AdvancedAuthService) createSession(ctx context.Context, user *User, req *LoginRequest) (*AuthSession, error) {
	sessionID := generateSessionID()
	now := time.Now()

	var expiresAt time.Time
	if req.RememberMe {
		expiresAt = now.Add(aas.config.SessionConfig.MaxTTL)
	} else {
		expiresAt = now.Add(aas.config.SessionConfig.DefaultTTL)
	}

	session := &AuthSession{
		ID:           sessionID,
		UserID:       user.ID,
		DeviceID:     req.DeviceID,
		IPAddress:    req.IPAddress,
		UserAgent:    req.UserAgent,
		CreatedAt:    now,
		LastActivity: now,
		ExpiresAt:    expiresAt,
		IsActive:     true,
		MFAVerified:  user.MFAEnabled && req.MFACode != "",
		Permissions:  user.Permissions,
		Metadata:     make(map[string]interface{}),
	}

	// Store session
	if err := aas.sessionStore.CreateSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	// Add to active sessions
	aas.activeSessions[sessionID] = session

	return session, nil
}

// generateTokens generates access and refresh tokens
func (aas *AdvancedAuthService) generateTokens(ctx context.Context, user *User, session *AuthSession) (string, string, error) {
	// Generate access token
	accessToken, err := aas.jwtManager.GenerateAccessToken(user, session)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := aas.jwtManager.GenerateRefreshToken(user, session)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// calculateThreatScore calculates threat score for login attempt
func (aas *AdvancedAuthService) calculateThreatScore(req *LoginRequest, user *User) float64 {
	if aas.threatDetector == nil {
		return 0.0
	}

	return aas.threatDetector.CalculateLoginThreatScore(req, user)
}

// getMFAMethods returns available MFA methods for user
func (aas *AdvancedAuthService) getMFAMethods(user *User) []string {
	methods := []string{}

	if aas.config.MFA.EnableTOTP && user.MFASecret != "" {
		methods = append(methods, "totp")
	}

	if aas.config.MFA.EnableEmail {
		methods = append(methods, "email")
	}

	if aas.config.MFA.EnableSMS {
		methods = append(methods, "sms")
	}

	if aas.config.MFA.EnableBackupCodes && len(user.BackupCodes) > 0 {
		methods = append(methods, "backup_codes")
	}

	return methods
}

// isTokenRevoked checks if a token is revoked
func (aas *AdvancedAuthService) isTokenRevoked(token string) bool {
	// This would typically check against a revocation list
	// For now, we'll return false
	return false
}

// logSecurityEvent logs a security event
func (aas *AdvancedAuthService) logSecurityEvent(eventType, userID, ipAddress, userAgent string, metadata map[string]interface{}) {
	event := &SecurityEvent{
		ID:          uuid.New().String(),
		Type:        eventType,
		UserID:      userID,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		Timestamp:   time.Now(),
		Severity:    "info",
		Description: fmt.Sprintf("Security event: %s", eventType),
		Metadata:    metadata,
		Resolved:    false,
	}

	// Determine severity based on event type
	switch eventType {
	case "login_rate_limited", "login_ip_blocked", "login_account_locked":
		event.Severity = "warning"
	case "login_invalid_password", "login_invalid_mfa":
		event.Severity = "warning"
	case "login_high_threat_score":
		event.Severity = "critical"
	case "login_success", "logout_success":
		event.Severity = "info"
	}

	aas.securityEvents = append(aas.securityEvents, event)

	// Log to audit logger if available
	if aas.auditLogger != nil {
		aas.auditLogger.LogSecurityEvent(event)
	}

	// Log to standard logger
	aas.logger.Info("Security event",
		"event_type", eventType,
		"user_id", userID,
		"ip_address", ipAddress,
		"severity", event.Severity)
}

// generateSessionID generates a secure session ID
func generateSessionID() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to UUID if crypto/rand fails
		return uuid.New().String()
	}
	return base64.URLEncoding.EncodeToString(bytes)
}
