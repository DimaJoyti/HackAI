package auth

import (
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
)

// LoginRequest represents a login request
type LoginRequest struct {
	EmailOrUsername string      `json:"email_or_username" validate:"required"`
	Username        string      `json:"username,omitempty"`
	Password        string      `json:"password" validate:"required"`
	MFACode         string      `json:"mfa_code,omitempty"`
	TOTPCode        string      `json:"totp_code,omitempty"`
	DeviceInfo      *DeviceInfo `json:"device_info,omitempty"`
	DeviceID        string      `json:"device_id,omitempty"`
	RememberMe      bool        `json:"remember_me"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Success      bool          `json:"success"`
	Message      string        `json:"message"`
	User         *domain.User  `json:"user,omitempty"`
	UserResponse *UserResponse `json:"user_response,omitempty"`
	AccessToken  string        `json:"access_token,omitempty"`
	RefreshToken string        `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time     `json:"expires_at,omitempty"`
	TokenType    string        `json:"token_type,omitempty"`
	SessionID    interface{}   `json:"session_id,omitempty"` // Can be string or uuid.UUID
	RequiresMFA  bool          `json:"requires_mfa"`
	RequiresTOTP bool          `json:"requires_totp"`
	CSRFToken    string        `json:"csrf_token,omitempty"`
	Permissions  []string      `json:"permissions,omitempty"`
}

// UserResponse represents user information in responses
type UserResponse struct {
	ID               uuid.UUID       `json:"id"`
	Username         string          `json:"username"`
	Email            string          `json:"email"`
	Role             domain.UserRole `json:"role"`
	TwoFactorEnabled bool            `json:"two_factor_enabled"`
	LastLoginAt      *time.Time      `json:"last_login_at"`
	CreatedAt        time.Time       `json:"created_at"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	// From auth_service.go version
	MaxLoginAttempts int           `json:"max_login_attempts"`
	LockoutDuration  time.Duration `json:"lockout_duration"`
	SessionTimeout   time.Duration `json:"session_timeout"`
	RequireMFA       bool          `json:"require_mfa"`
	PasswordPolicy   *PasswordPolicy `json:"password_policy"`

	// From security.go version
	MinPasswordLength     int           `json:"min_password_length"`
	RequireUppercase      bool          `json:"require_uppercase"`
	RequireLowercase      bool          `json:"require_lowercase"`
	RequireNumbers        bool          `json:"require_numbers"`
	RequireSpecialChars   bool          `json:"require_special_chars"`
	PasswordHistoryCount  int           `json:"password_history_count"`
	MaxFailedAttempts     int           `json:"max_failed_attempts"`
	MaxConcurrentSessions int           `json:"max_concurrent_sessions"`
	LoginRateLimit        int           `json:"login_rate_limit"`
	LoginRateWindow       time.Duration `json:"login_rate_window"`
	TOTPIssuer            string        `json:"totp_issuer"`
	TOTPDigits            int           `json:"totp_digits"`
	TOTPPeriod            int           `json:"totp_period"`
	AllowedIPRanges       []string      `json:"allowed_ip_ranges"`
	BlockedIPRanges       []string      `json:"blocked_ip_ranges"`
	EnableCSRF            bool          `json:"enable_csrf"`
	CSRFTokenLength       int           `json:"csrf_token_length"`
}

// PasswordPolicy represents password policy configuration
type PasswordPolicy struct {
	MinLength        int           `json:"min_length"`
	RequireUppercase bool          `json:"require_uppercase"`
	RequireLowercase bool          `json:"require_lowercase"`
	RequireNumbers   bool          `json:"require_numbers"`
	RequireSpecial   bool          `json:"require_special"`
	MaxAge           time.Duration `json:"max_age"`
	HistoryCount     int           `json:"history_count"`
}

// DeviceInfo represents device information
type DeviceInfo struct {
	DeviceID    string `json:"device_id"`
	DeviceName  string `json:"device_name"`
	DeviceType  string `json:"device_type"`
	OS          string `json:"os"`
	Browser     string `json:"browser"`
	IPAddress   string `json:"ip_address"`
	UserAgent   string `json:"user_agent"`
	Fingerprint string `json:"fingerprint"`
}

// LogoutRequest represents a logout request
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	LogoutAll    bool   `json:"logout_all"`
}

// OAuth2LoginRequest represents an OAuth2 login request
type OAuth2LoginRequest struct {
	Provider   string      `json:"provider"`
	Code       string      `json:"code"`
	State      string      `json:"state"`
	DeviceInfo *DeviceInfo `json:"device_info,omitempty"`
}

// AuthenticationRequest represents internal authentication request
type AuthenticationRequest struct {
	EmailOrUsername string `json:"email_or_username"`
	Password        string `json:"password"`
	TOTPCode        string `json:"totp_code,omitempty"`
	IPAddress       string `json:"ip_address"`
	UserAgent       string `json:"user_agent"`
	DeviceID        string `json:"device_id,omitempty"`
	RememberMe      bool   `json:"remember_me"`
}

// AuthenticationResponse represents internal authentication response  
type AuthenticationResponse struct {
	User         *domain.User `json:"user"`
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	ExpiresAt    time.Time    `json:"expires_at"`
	SessionID    uuid.UUID    `json:"session_id"`
	RequiresTOTP bool         `json:"requires_totp"`
	CSRFToken    string       `json:"csrf_token"`
}