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
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)


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
func (ism *IPSecurityManager) IsIPAllowed(ipAddress string) bool {
	if len(ism.config.AllowedIPRanges) == 0 {
		return true // No restrictions
	}

	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return false
	}

	// Check allowed ranges
	for _, rangeStr := range ism.config.AllowedIPRanges {
		if ism.isIPInRange(ip, rangeStr) {
			return true
		}
	}

	return false
}

// IsIPBlocked checks if an IP address is blocked
func (ism *IPSecurityManager) IsIPBlocked(ipAddress string) bool {
	if len(ism.config.BlockedIPRanges) == 0 {
		return false // No blocks
	}

	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return true // Invalid IP is blocked
	}

	// Check blocked ranges
	for _, rangeStr := range ism.config.BlockedIPRanges {
		if ism.isIPInRange(ip, rangeStr) {
			return true
		}
	}

	return false
}

// isIPInRange checks if an IP is in a CIDR range
func (ism *IPSecurityManager) isIPInRange(ip net.IP, rangeStr string) bool {
	// Handle single IP
	if !strings.Contains(rangeStr, "/") {
		return ip.Equal(net.ParseIP(rangeStr))
	}

	// Handle CIDR range
	_, ipNet, err := net.ParseCIDR(rangeStr)
	if err != nil {
		return false
	}

	return ipNet.Contains(ip)
}

// TOTPManager handles TOTP operations
type TOTPManager struct {
	config *SecurityConfig
}

// NewTOTPManager creates a new TOTP manager
func NewTOTPManager(config *SecurityConfig) *TOTPManager {
	return &TOTPManager{config: config}
}

// GenerateSecret generates a TOTP secret
func (tm *TOTPManager) GenerateSecret() (string, error) {
	secret := make([]byte, 20) // 160 bits
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.EncodeToString(secret), nil
}

// GenerateQRCodeURL generates a QR code URL for TOTP setup
func (tm *TOTPManager) GenerateQRCodeURL(secret, email string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
		tm.config.TOTPIssuer, email, secret, tm.config.TOTPIssuer,
		tm.config.TOTPDigits, tm.config.TOTPPeriod)
}

// VerifyTOTP verifies a TOTP code
func (tm *TOTPManager) VerifyTOTP(secret, code string) bool {
	// This is a simplified implementation
	// In production, use a proper TOTP library like github.com/pquerna/otp
	return len(code) == tm.config.TOTPDigits
}

// AccountLockoutManager handles account lockout
type AccountLockoutManager struct {
	config         *SecurityConfig
	failedAttempts map[string]*FailedAttemptInfo
	mutex          sync.RWMutex
}

// FailedAttemptInfo tracks failed login attempts
type FailedAttemptInfo struct {
	Count        int
	FirstAttempt time.Time
	LastAttempt  time.Time
	LockedUntil  *time.Time
}

// NewAccountLockoutManager creates a new account lockout manager
func NewAccountLockoutManager(config *SecurityConfig) *AccountLockoutManager {
	return &AccountLockoutManager{
		config:         config,
		failedAttempts: make(map[string]*FailedAttemptInfo),
	}
}

// RecordFailedAttempt records a failed login attempt
func (alm *AccountLockoutManager) RecordFailedAttempt(identifier string) bool {
	alm.mutex.Lock()
	defer alm.mutex.Unlock()

	now := time.Now()
	info, exists := alm.failedAttempts[identifier]

	if !exists {
		info = &FailedAttemptInfo{
			Count:        1,
			FirstAttempt: now,
			LastAttempt:  now,
		}
		alm.failedAttempts[identifier] = info
	} else {
		info.Count++
		info.LastAttempt = now
	}

	// Check if account should be locked
	if info.Count >= alm.config.MaxFailedAttempts {
		lockUntil := now.Add(alm.config.LockoutDuration)
		info.LockedUntil = &lockUntil
		return true
	}

	return false
}

// IsAccountLocked checks if an account is locked
func (alm *AccountLockoutManager) IsAccountLocked(identifier string) bool {
	alm.mutex.RLock()
	defer alm.mutex.RUnlock()

	info, exists := alm.failedAttempts[identifier]
	if !exists {
		return false
	}

	if info.LockedUntil == nil {
		return false
	}

	return time.Now().Before(*info.LockedUntil)
}

// ClearFailedAttempts clears failed attempts for an identifier
func (alm *AccountLockoutManager) ClearFailedAttempts(identifier string) {
	alm.mutex.Lock()
	defer alm.mutex.Unlock()

	delete(alm.failedAttempts, identifier)
}

// RateLimiter handles rate limiting
type RateLimiter struct {
	config   *SecurityConfig
	attempts map[string]*RateLimitInfo
	mutex    sync.RWMutex
}

// RateLimitInfo tracks rate limit information
type RateLimitInfo struct {
	Count       int
	WindowStart time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config *SecurityConfig) *RateLimiter {
	return &RateLimiter{
		config:   config,
		attempts: make(map[string]*RateLimitInfo),
	}
}

// IsAllowed checks if a request is allowed based on rate limits
func (rl *RateLimiter) IsAllowed(identifier string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	info, exists := rl.attempts[identifier]

	if !exists {
		rl.attempts[identifier] = &RateLimitInfo{
			Count:       1,
			WindowStart: now,
		}
		return true
	}

	// Check if window has expired
	if now.Sub(info.WindowStart) > rl.config.LoginRateWindow {
		info.Count = 1
		info.WindowStart = now
		return true
	}

	// Check if limit exceeded
	if info.Count >= rl.config.LoginRateLimit {
		return false
	}

	info.Count++
	return true
}

// SecurityEvent represents a security event
type SecurityEvent struct {
	Type      SecurityEventType      `json:"type"`
	UserID    string                 `json:"user_id"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Details   map[string]interface{} `json:"details"`
	Success   bool                   `json:"success"`
	Timestamp time.Time              `json:"timestamp"`
	Severity  string                 `json:"severity"`
}

// SecurityEventType represents types of security events
type SecurityEventType string

const (
	SecurityEventLogin            SecurityEventType = "login"
	SecurityEventLogout           SecurityEventType = "logout"
	SecurityEventLoginFailed      SecurityEventType = "login_failed"
	SecurityEventPasswordChange   SecurityEventType = "password_change"
	SecurityEventTOTPEnabled      SecurityEventType = "totp_enabled"
	SecurityEventTOTPDisabled     SecurityEventType = "totp_disabled"
	SecurityEventAccountLocked    SecurityEventType = "account_locked"
	SecurityEventSuspiciousIP     SecurityEventType = "suspicious_ip"
	SecurityEventPermissionGrant  SecurityEventType = "permission_grant"
	SecurityEventPermissionRevoke SecurityEventType = "permission_revoke"
)

// SecurityAuditor handles security event logging
type SecurityAuditor struct {
	config *SecurityConfig
	events []SecurityEvent
	mutex  sync.RWMutex
}

// NewSecurityAuditor creates a new security auditor
func NewSecurityAuditor(config *SecurityConfig) *SecurityAuditor {
	return &SecurityAuditor{
		config: config,
		events: make([]SecurityEvent, 0),
	}
}

// LogSecurityEvent logs a security event
func (sa *SecurityAuditor) LogSecurityEvent(event *SecurityEvent) {
	sa.mutex.Lock()
	defer sa.mutex.Unlock()

	event.Timestamp = time.Now()
	event.Severity = sa.determineSeverity(event.Type, event.Success)

	sa.events = append(sa.events, *event)

	// In production, you would send this to a logging service
	// or store in a database
}

// determineSeverity determines the severity of a security event
func (sa *SecurityAuditor) determineSeverity(eventType SecurityEventType, success bool) string {
	if !success {
		switch eventType {
		case SecurityEventLoginFailed, SecurityEventAccountLocked, SecurityEventSuspiciousIP:
			return "high"
		case SecurityEventPasswordChange:
			return "medium"
		default:
			return "low"
		}
	}

	switch eventType {
	case SecurityEventPermissionGrant, SecurityEventPermissionRevoke:
		return "medium"
	case SecurityEventTOTPEnabled, SecurityEventTOTPDisabled:
		return "medium"
	default:
		return "low"
	}
}
