package firebase

import (
	"time"
)

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	UID           string                 `json:"uid,omitempty"`
	Email         string                 `json:"email"`
	Password      string                 `json:"password,omitempty"`
	DisplayName   string                 `json:"display_name,omitempty"`
	PhoneNumber   string                 `json:"phone_number,omitempty"`
	EmailVerified bool                   `json:"email_verified"`
	Disabled      bool                   `json:"disabled"`
	CustomClaims  map[string]interface{} `json:"custom_claims,omitempty"`

	// Additional fields for database sync
	Username     string `json:"username,omitempty"`
	FirstName    string `json:"first_name,omitempty"`
	LastName     string `json:"last_name,omitempty"`
	Role         string `json:"role,omitempty"`
	Organization string `json:"organization,omitempty"`
}

// UpdateUserRequest represents a request to update a user
type UpdateUserRequest struct {
	Email         *string                `json:"email,omitempty"`
	Password      *string                `json:"password,omitempty"`
	DisplayName   *string                `json:"display_name,omitempty"`
	PhoneNumber   *string                `json:"phone_number,omitempty"`
	EmailVerified *bool                  `json:"email_verified,omitempty"`
	Disabled      *bool                  `json:"disabled,omitempty"`
	CustomClaims  map[string]interface{} `json:"custom_claims,omitempty"`

	// Additional fields for database sync
	Username     *string `json:"username,omitempty"`
	FirstName    *string `json:"first_name,omitempty"`
	LastName     *string `json:"last_name,omitempty"`
	Role         *string `json:"role,omitempty"`
	Organization *string `json:"organization,omitempty"`
}

// UserResponse represents a user response
type UserResponse struct {
	UID           string                 `json:"uid"`
	Email         string                 `json:"email"`
	DisplayName   string                 `json:"display_name"`
	PhoneNumber   string                 `json:"phone_number"`
	EmailVerified bool                   `json:"email_verified"`
	Disabled      bool                   `json:"disabled"`
	CreatedAt     int64                  `json:"created_at"`
	LastLoginAt   int64                  `json:"last_login_at"`
	CustomClaims  map[string]interface{} `json:"custom_claims"`

	// Additional fields from database
	Username     string `json:"username,omitempty"`
	FirstName    string `json:"first_name,omitempty"`
	LastName     string `json:"last_name,omitempty"`
	Role         string `json:"role,omitempty"`
	Organization string `json:"organization,omitempty"`
}

// ListUsersResponse represents a response for listing users
type ListUsersResponse struct {
	Users         []*UserResponse `json:"users"`
	NextPageToken string          `json:"next_page_token,omitempty"`
}

// AuthenticationRequest represents a Firebase authentication request
type AuthenticationRequest struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// AuthenticationResponse represents a Firebase authentication response
type AuthenticationResponse struct {
	User         *UserResponse `json:"user"`
	AccessToken  string        `json:"access_token,omitempty"`
	RefreshToken string        `json:"refresh_token,omitempty"`
	ExpiresIn    int64         `json:"expires_in,omitempty"`
}

// TokenValidationRequest represents a token validation request
type TokenValidationRequest struct {
	IDToken string `json:"id_token"`
}

// TokenValidationResponse represents a token validation response
type TokenValidationResponse struct {
	Valid     bool                   `json:"valid"`
	UID       string                 `json:"uid,omitempty"`
	Email     string                 `json:"email,omitempty"`
	Claims    map[string]interface{} `json:"claims,omitempty"`
	ExpiresAt int64                  `json:"expires_at,omitempty"`
	IssuedAt  int64                  `json:"issued_at,omitempty"`
	AuthTime  int64                  `json:"auth_time,omitempty"`
	Issuer    string                 `json:"issuer,omitempty"`
	Audience  string                 `json:"audience,omitempty"`
	Subject   string                 `json:"subject,omitempty"`
}

// CustomTokenRequest represents a custom token creation request
type CustomTokenRequest struct {
	UID    string                 `json:"uid"`
	Claims map[string]interface{} `json:"claims,omitempty"`
}

// CustomTokenResponse represents a custom token creation response
type CustomTokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"`
}

// SetClaimsRequest represents a request to set custom claims
type SetClaimsRequest struct {
	UID    string                 `json:"uid"`
	Claims map[string]interface{} `json:"claims"`
}

// RevokeTokensRequest represents a request to revoke refresh tokens
type RevokeTokensRequest struct {
	UID string `json:"uid"`
}

// UserSyncEvent represents a user synchronization event
type UserSyncEvent struct {
	Type      string                 `json:"type"` // create, update, delete
	UID       string                 `json:"uid"`
	Email     string                 `json:"email,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// WebhookPayload represents a webhook payload
type WebhookPayload struct {
	Event     string                 `json:"event"`
	User      *UserResponse          `json:"user,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// HealthCheckResponse represents a health check response
type HealthCheckResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version,omitempty"`
	Firebase  struct {
		Connected bool   `json:"connected"`
		ProjectID string `json:"project_id"`
	} `json:"firebase"`
	Database struct {
		Connected bool `json:"connected"`
	} `json:"database"`
}

// MetricsResponse represents metrics response
type MetricsResponse struct {
	TotalUsers           int64 `json:"total_users"`
	ActiveUsers          int64 `json:"active_users"`
	NewUsersToday        int64 `json:"new_users_today"`
	AuthenticationsToday int64 `json:"authentications_today"`
	ErrorsToday          int64 `json:"errors_today"`
}

// BatchOperationRequest represents a batch operation request
type BatchOperationRequest struct {
	Operation string        `json:"operation"` // create, update, delete
	Users     []interface{} `json:"users"`
}

// BatchOperationResponse represents a batch operation response
type BatchOperationResponse struct {
	Success []string `json:"success"`
	Failed  []struct {
		UID   string `json:"uid"`
		Error string `json:"error"`
	} `json:"failed"`
	Total int `json:"total"`
}

// PasswordResetRequest represents a password reset request
type PasswordResetRequest struct {
	Email string `json:"email"`
}

// EmailVerificationRequest represents an email verification request
type EmailVerificationRequest struct {
	UID string `json:"uid"`
}

// PhoneVerificationRequest represents a phone verification request
type PhoneVerificationRequest struct {
	PhoneNumber string `json:"phone_number"`
}

// MFAEnrollmentRequest represents an MFA enrollment request
type MFAEnrollmentRequest struct {
	UID      string `json:"uid"`
	Provider string `json:"provider"` // phone, totp
}

// SessionInfo represents session information
type SessionInfo struct {
	UID         string    `json:"uid"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Role        string    `json:"role"`
	Permissions []string  `json:"permissions"`
	LoginTime   time.Time `json:"login_time"`
	ExpiresAt   time.Time `json:"expires_at"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
}

// AuditLogEntry represents an audit log entry
type AuditLogEntry struct {
	ID        string                 `json:"id"`
	Event     string                 `json:"event"`
	UID       string                 `json:"uid"`
	Email     string                 `json:"email"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
	Success   bool                   `json:"success"`
	Error     string                 `json:"error,omitempty"`
}

// RateLimitInfo represents rate limit information
type RateLimitInfo struct {
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	ResetTime time.Time `json:"reset_time"`
	Blocked   bool      `json:"blocked"`
}

// ConfigValidationResult represents configuration validation result
type ConfigValidationResult struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
}

// ServiceStatus represents service status
type ServiceStatus struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"` // healthy, unhealthy, degraded
	LastCheck time.Time `json:"last_check"`
	Error     string    `json:"error,omitempty"`
}

// SystemInfo represents system information
type SystemInfo struct {
	Version     string          `json:"version"`
	Environment string          `json:"environment"`
	Uptime      time.Duration   `json:"uptime"`
	Services    []ServiceStatus `json:"services"`
}
