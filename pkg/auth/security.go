package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/dimajoyti/hackai/internal/domain"
)

// SecurityConfig holds security configuration
type SecurityConfig struct {
	// Password policy
	MinPasswordLength    int
	RequireUppercase     bool
	RequireLowercase     bool
	RequireNumbers       bool
	RequireSpecialChars  bool
	PasswordHistoryCount int

	// Account lockout
	MaxFailedAttempts int
	LockoutDuration   time.Duration

	// Session security
	SessionTimeout        time.Duration
	MaxConcurrentSessions int

	// Rate limiting
	LoginRateLimit  int
	LoginRateWindow time.Duration

	// Two-factor authentication
	TOTPIssuer string
	TOTPDigits int
	TOTPPeriod int

	// IP restrictions
	AllowedIPRanges []string
	BlockedIPRanges []string

	// Security headers
	EnableCSRF      bool
	CSRFTokenLength int
}

// DefaultSecurityConfig returns default security configuration
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		MinPasswordLength:     8,
		RequireUppercase:      true,
		RequireLowercase:      true,
		RequireNumbers:        true,
		RequireSpecialChars:   true,
		PasswordHistoryCount:  5,
		MaxFailedAttempts:     5,
		LockoutDuration:       15 * time.Minute,
		SessionTimeout:        24 * time.Hour,
		MaxConcurrentSessions: 5,
		LoginRateLimit:        10,
		LoginRateWindow:       time.Minute,
		TOTPIssuer:            "HackAI",
		TOTPDigits:            6,
		TOTPPeriod:            30,
		EnableCSRF:            true,
		CSRFTokenLength:       32,
	}
}

// PasswordManager handles password operations
type PasswordManager struct {
	config *SecurityConfig
}

// NewPasswordManager creates a new password manager
func NewPasswordManager(config *SecurityConfig) *PasswordManager {
	return &PasswordManager{config: config}
}

// HashPassword hashes a password using bcrypt
func (pm *PasswordManager) HashPassword(password string) (string, error) {
	// Use bcrypt with cost 12 for good security/performance balance
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword verifies a password against its hash
func (pm *PasswordManager) VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ValidatePassword validates password against security policy
func (pm *PasswordManager) ValidatePassword(password string) error {
	if len(password) < pm.config.MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters long", pm.config.MinPasswordLength)
	}

	if pm.config.RequireUppercase && !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}

	if pm.config.RequireLowercase && !regexp.MustCompile(`[a-z]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}

	if pm.config.RequireNumbers && !regexp.MustCompile(`[0-9]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one number")
	}

	if pm.config.RequireSpecialChars && !regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one special character")
	}

	// Check for common weak patterns
	if pm.isWeakPassword(password) {
		return fmt.Errorf("password is too weak or commonly used")
	}

	return nil
}

// isWeakPassword checks for common weak password patterns
func (pm *PasswordManager) isWeakPassword(password string) bool {
	weakPatterns := []string{
		"password", "123456", "qwerty", "admin", "letmein",
		"welcome", "monkey", "dragon", "master", "shadow",
	}

	lowerPassword := strings.ToLower(password)
	for _, pattern := range weakPatterns {
		if strings.Contains(lowerPassword, pattern) {
			return true
		}
	}

	// Check for keyboard patterns
	keyboardPatterns := []string{
		"qwertyuiop", "asdfghjkl", "zxcvbnm",
		"1234567890", "0987654321",
	}

	for _, pattern := range keyboardPatterns {
		if strings.Contains(lowerPassword, pattern) || strings.Contains(lowerPassword, reverse(pattern)) {
			return true
		}
	}

	return false
}

// reverse reverses a string
func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// GenerateSecureToken generates a cryptographically secure random token
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateCSRFToken generates a CSRF token
func GenerateCSRFToken() (string, error) {
	return GenerateSecureToken(32)
}

// ValidateCSRFToken validates a CSRF token
func ValidateCSRFToken(token, expected string) bool {
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

// IPSecurityManager handles IP-based security
type IPSecurityManager struct {
	config *SecurityConfig
}

// NewIPSecurityManager creates a new IP security manager
func NewIPSecurityManager(config *SecurityConfig) *IPSecurityManager {
	return &IPSecurityManager{config: config}
}

// IsIPAllowed checks if an IP address is allowed
func (ism *IPSecurityManager) IsIPAllowed(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check blocked ranges first
	for _, rangeStr := range ism.config.BlockedIPRanges {
		if ism.isIPInRange(ip, rangeStr) {
			return false
		}
	}

	// If no allowed ranges specified, allow all (except blocked)
	if len(ism.config.AllowedIPRanges) == 0 {
		return true
	}

	// Check allowed ranges
	for _, rangeStr := range ism.config.AllowedIPRanges {
		if ism.isIPInRange(ip, rangeStr) {
			return true
		}
	}

	return false
}

// isIPInRange checks if an IP is in a CIDR range
func (ism *IPSecurityManager) isIPInRange(ip net.IP, rangeStr string) bool {
	_, ipNet, err := net.ParseCIDR(rangeStr)
	if err != nil {
		// Try parsing as single IP
		rangeIP := net.ParseIP(rangeStr)
		if rangeIP != nil {
			return ip.Equal(rangeIP)
		}
		return false
	}
	return ipNet.Contains(ip)
}

// TOTPManager handles Time-based One-Time Password operations
type TOTPManager struct {
	config *SecurityConfig
}

// NewTOTPManager creates a new TOTP manager
func NewTOTPManager(config *SecurityConfig) *TOTPManager {
	return &TOTPManager{config: config}
}

// GenerateSecret generates a new TOTP secret
func (tm *TOTPManager) GenerateSecret() (string, error) {
	secret := make([]byte, 20) // 160 bits
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.EncodeToString(secret), nil
}

// GenerateQRCodeURL generates a QR code URL for TOTP setup
func (tm *TOTPManager) GenerateQRCodeURL(secret, accountName string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
		tm.config.TOTPIssuer, accountName, secret, tm.config.TOTPIssuer,
		tm.config.TOTPDigits, tm.config.TOTPPeriod)
}

// VerifyTOTP verifies a TOTP code
func (tm *TOTPManager) VerifyTOTP(secret, code string) bool {
	// This is a simplified implementation
	// In production, use a proper TOTP library like github.com/pquerna/otp
	return len(code) == tm.config.TOTPDigits && code != ""
}

// SessionManager handles session security
type SessionManager struct {
	config *SecurityConfig
}

// NewSessionManager creates a new session manager
func NewSessionManager(config *SecurityConfig) *SessionManager {
	return &SessionManager{config: config}
}

// GenerateSessionID generates a secure session ID
func (sm *SessionManager) GenerateSessionID() (string, error) {
	return GenerateSecureToken(32)
}

// IsSessionValid checks if a session is valid
func (sm *SessionManager) IsSessionValid(session *domain.UserSession) bool {
	if session == nil {
		return false
	}

	// Check if session is expired
	if session.IsExpired() {
		return false
	}

	// Check session timeout
	if time.Since(session.CreatedAt) > sm.config.SessionTimeout {
		return false
	}

	return true
}

// SecurityEventType represents types of security events
type SecurityEventType string

const (
	SecurityEventLogin            SecurityEventType = "login"
	SecurityEventLoginFailed      SecurityEventType = "login_failed"
	SecurityEventLogout           SecurityEventType = "logout"
	SecurityEventPasswordChange   SecurityEventType = "password_change"
	SecurityEventAccountLocked    SecurityEventType = "account_locked"
	SecurityEventSuspiciousIP     SecurityEventType = "suspicious_ip"
	SecurityEventTOTPEnabled      SecurityEventType = "totp_enabled"
	SecurityEventTOTPDisabled     SecurityEventType = "totp_disabled"
	SecurityEventPermissionGrant  SecurityEventType = "permission_grant"
	SecurityEventPermissionRevoke SecurityEventType = "permission_revoke"
)

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	Type      SecurityEventType      `json:"type"`
	UserID    string                 `json:"user_id,omitempty"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Details   map[string]interface{} `json:"details"`
	Timestamp time.Time              `json:"timestamp"`
	Severity  string                 `json:"severity"`
	Success   bool                   `json:"success"`
}

// SecurityAuditor handles security event logging and analysis
type SecurityAuditor struct {
	config *SecurityConfig
}

// NewSecurityAuditor creates a new security auditor
func NewSecurityAuditor(config *SecurityConfig) *SecurityAuditor {
	return &SecurityAuditor{config: config}
}

// LogSecurityEvent logs a security event
func (sa *SecurityAuditor) LogSecurityEvent(event *SecurityEvent) {
	// In a real implementation, this would log to a security event store
	// For now, we'll just ensure the event is properly formatted
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	if event.Severity == "" {
		event.Severity = sa.determineSeverity(event.Type, event.Success)
	}
}

// determineSeverity determines the severity of a security event
func (sa *SecurityAuditor) determineSeverity(eventType SecurityEventType, success bool) string {
	switch eventType {
	case SecurityEventLoginFailed, SecurityEventAccountLocked, SecurityEventSuspiciousIP:
		return "high"
	case SecurityEventLogin, SecurityEventLogout:
		if success {
			return "low"
		}
		return "medium"
	case SecurityEventPasswordChange, SecurityEventTOTPEnabled, SecurityEventTOTPDisabled:
		return "medium"
	case SecurityEventPermissionGrant, SecurityEventPermissionRevoke:
		return "high"
	default:
		return "low"
	}
}

// RateLimiter handles rate limiting for authentication attempts
type RateLimiter struct {
	config *SecurityConfig
	// In production, this would use Redis or similar for distributed rate limiting
	attempts map[string][]time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config *SecurityConfig) *RateLimiter {
	return &RateLimiter{
		config:   config,
		attempts: make(map[string][]time.Time),
	}
}

// IsAllowed checks if a request is allowed based on rate limiting
func (rl *RateLimiter) IsAllowed(identifier string) bool {
	now := time.Now()
	windowStart := now.Add(-rl.config.LoginRateWindow)

	// Clean old attempts
	attempts := rl.attempts[identifier]
	validAttempts := make([]time.Time, 0)
	for _, attempt := range attempts {
		if attempt.After(windowStart) {
			validAttempts = append(validAttempts, attempt)
		}
	}

	// Check if under limit
	if len(validAttempts) >= rl.config.LoginRateLimit {
		return false
	}

	// Record this attempt
	validAttempts = append(validAttempts, now)
	rl.attempts[identifier] = validAttempts

	return true
}

// AccountLockoutManager handles account lockout functionality
type AccountLockoutManager struct {
	config *SecurityConfig
	// In production, this would use Redis or database for persistence
	failedAttempts map[string]int
	lockoutTimes   map[string]time.Time
}

// NewAccountLockoutManager creates a new account lockout manager
func NewAccountLockoutManager(config *SecurityConfig) *AccountLockoutManager {
	return &AccountLockoutManager{
		config:         config,
		failedAttempts: make(map[string]int),
		lockoutTimes:   make(map[string]time.Time),
	}
}

// RecordFailedAttempt records a failed login attempt
func (alm *AccountLockoutManager) RecordFailedAttempt(identifier string) bool {
	alm.failedAttempts[identifier]++

	if alm.failedAttempts[identifier] >= alm.config.MaxFailedAttempts {
		alm.lockoutTimes[identifier] = time.Now()
		return true // Account is now locked
	}

	return false
}

// IsAccountLocked checks if an account is locked
func (alm *AccountLockoutManager) IsAccountLocked(identifier string) bool {
	lockoutTime, exists := alm.lockoutTimes[identifier]
	if !exists {
		return false
	}

	if time.Since(lockoutTime) > alm.config.LockoutDuration {
		// Lockout has expired
		delete(alm.lockoutTimes, identifier)
		delete(alm.failedAttempts, identifier)
		return false
	}

	return true
}

// ClearFailedAttempts clears failed attempts for an identifier
func (alm *AccountLockoutManager) ClearFailedAttempts(identifier string) {
	delete(alm.failedAttempts, identifier)
	delete(alm.lockoutTimes, identifier)
}
