package security

import (
	// "context" // unused
	// "crypto/hmac" // unused
	"crypto/rand"
	// "crypto/sha256" // unused
	// "encoding/base32" // unused
	// "encoding/base64" // unused
	"fmt"
	"net"
	"regexp"
	// "strings" // unused
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// JWTManager handles JWT token operations
type JWTManager struct {
	config *JWTConfig
	logger *logger.Logger
}

// JWTClaims represents JWT claims
type JWTClaims struct {
	UserID    string   `json:"user_id"`
	Username  string   `json:"username"`
	Email     string   `json:"email"`
	Role      string   `json:"role"`
	SessionID string   `json:"session_id"`
	Scopes    []string `json:"scopes"`
	jwt.RegisteredClaims
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(config *JWTConfig, logger *logger.Logger) (*JWTManager, error) {
	if config == nil {
		return nil, fmt.Errorf("JWT config is required")
	}
	
	return &JWTManager{
		config: config,
		logger: logger,
	}, nil
}

// GenerateAccessToken generates an access token
func (jm *JWTManager) GenerateAccessToken(user *User, session *AuthSession) (string, error) {
	now := time.Now()
	claims := &JWTClaims{
		UserID:    user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Role:      user.Role,
		SessionID: session.ID,
		Scopes:    []string{"read", "write"},
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Subject:   user.ID,
			Issuer:    jm.config.Issuer,
			Audience:  []string{jm.config.Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(jm.config.AccessTokenTTL)),
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jm.config.Secret))
}

// GenerateRefreshToken generates a refresh token
func (jm *JWTManager) GenerateRefreshToken(user *User, session *AuthSession) (string, error) {
	now := time.Now()
	claims := &JWTClaims{
		UserID:    user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Role:      user.Role,
		SessionID: session.ID,
		Scopes:    []string{"refresh"},
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Subject:   user.ID,
			Issuer:    jm.config.Issuer,
			Audience:  []string{jm.config.Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(jm.config.RefreshTokenTTL)),
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jm.config.Secret))
}

// ValidateToken validates a JWT token
func (jm *JWTManager) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jm.config.Secret), nil
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	
	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	
	return claims, nil
}

// PasswordManager handles password operations
type PasswordManager struct {
	config *PasswordPolicyConfig
	logger *logger.Logger
}

// NewPasswordManager creates a new password manager
func NewPasswordManager(config *PasswordPolicyConfig, logger *logger.Logger) (*PasswordManager, error) {
	if config == nil {
		return nil, fmt.Errorf("password policy config is required")
	}
	
	return &PasswordManager{
		config: config,
		logger: logger,
	}, nil
}

// HashPassword hashes a password using bcrypt
func (pm *PasswordManager) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), pm.config.HashCost)
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

// ValidatePassword validates password against policy
func (pm *PasswordManager) ValidatePassword(password string) error {
	if len(password) < pm.config.MinLength {
		return fmt.Errorf("password must be at least %d characters long", pm.config.MinLength)
	}
	
	if len(password) > pm.config.MaxLength {
		return fmt.Errorf("password must be no more than %d characters long", pm.config.MaxLength)
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
	
	if pm.config.RequireSpecialChars && !regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one special character")
	}
	
	return nil
}

// MFAManager handles multi-factor authentication
type MFAManager struct {
	config *MFAConfig
	logger *logger.Logger
}

// NewMFAManager creates a new MFA manager
func NewMFAManager(config *MFAConfig, logger *logger.Logger) (*MFAManager, error) {
	if config == nil {
		return nil, fmt.Errorf("MFA config is required")
	}
	
	return &MFAManager{
		config: config,
		logger: logger,
	}, nil
}

// GenerateTOTPSecret generates a new TOTP secret
func (mm *MFAManager) GenerateTOTPSecret(userEmail string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      mm.config.TOTPIssuer,
		AccountName: userEmail,
		Period:      uint(mm.config.TOTPPeriod),
		Digits:      otp.Digits(mm.config.TOTPDigits),
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}
	
	return key.Secret(), key.URL(), nil
}

// VerifyTOTP verifies a TOTP code
func (mm *MFAManager) VerifyTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}

// GenerateBackupCodes generates backup codes
func (mm *MFAManager) GenerateBackupCodes() ([]string, error) {
	codes := make([]string, mm.config.BackupCodeCount)
	
	for i := 0; i < mm.config.BackupCodeCount; i++ {
		code, err := generateRandomCode(mm.config.BackupCodeLength)
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		codes[i] = code
	}
	
	return codes, nil
}

// SessionManager handles session operations
type SessionManager struct {
	config       *SessionConfig
	sessionStore SessionStore
	logger       *logger.Logger
}

// NewSessionManager creates a new session manager
func NewSessionManager(config *SessionConfig, sessionStore SessionStore, logger *logger.Logger) (*SessionManager, error) {
	if config == nil {
		return nil, fmt.Errorf("session config is required")
	}
	
	if sessionStore == nil {
		return nil, fmt.Errorf("session store is required")
	}
	
	return &SessionManager{
		config:       config,
		sessionStore: sessionStore,
		logger:       logger,
	}, nil
}

// AuthRateLimiter handles authentication rate limiting
type AuthRateLimiter struct {
	config    *RateLimitConfig
	logger    *logger.Logger
	attempts  map[string]*RateLimitEntry
	mutex     sync.RWMutex
}

// RateLimitEntry represents a rate limit entry
type RateLimitEntry struct {
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
}

// NewAuthRateLimiter creates a new authentication rate limiter
func NewAuthRateLimiter(config *RateLimitConfig, logger *logger.Logger) (*AuthRateLimiter, error) {
	if config == nil {
		return nil, fmt.Errorf("rate limit config is required")
	}
	
	return &AuthRateLimiter{
		config:   config,
		logger:   logger,
		attempts: make(map[string]*RateLimitEntry),
	}, nil
}

// AllowLogin checks if login is allowed for IP/username combination
func (arl *AuthRateLimiter) AllowLogin(ipAddress, username string) bool {
	arl.mutex.Lock()
	defer arl.mutex.Unlock()
	
	key := fmt.Sprintf("%s:%s", ipAddress, username)
	now := time.Now()
	
	entry, exists := arl.attempts[key]
	if !exists {
		arl.attempts[key] = &RateLimitEntry{
			Count:     1,
			FirstSeen: now,
			LastSeen:  now,
		}
		return true
	}
	
	// Check if window has expired
	if now.Sub(entry.FirstSeen) > arl.config.LoginWindow {
		entry.Count = 1
		entry.FirstSeen = now
		entry.LastSeen = now
		return true
	}
	
	// Check if limit exceeded
	if entry.Count >= arl.config.LoginAttempts {
		return false
	}
	
	entry.Count++
	entry.LastSeen = now
	return true
}

// AccountLockoutManager handles account lockout
type AccountLockoutManager struct {
	config   *AccountLockoutConfig
	logger   *logger.Logger
	lockouts map[string]*LockoutEntry
	mutex    sync.RWMutex
}

// LockoutEntry represents a lockout entry
type LockoutEntry struct {
	FailedAttempts int
	LockedUntil    *time.Time
	LockoutCount   int
}

// NewAccountLockoutManager creates a new account lockout manager
func NewAccountLockoutManager(config *AccountLockoutConfig, logger *logger.Logger) (*AccountLockoutManager, error) {
	if config == nil {
		return nil, fmt.Errorf("account lockout config is required")
	}
	
	return &AccountLockoutManager{
		config:   config,
		logger:   logger,
		lockouts: make(map[string]*LockoutEntry),
	}, nil
}

// IsAccountLocked checks if an account is locked
func (alm *AccountLockoutManager) IsAccountLocked(userID string) bool {
	alm.mutex.RLock()
	defer alm.mutex.RUnlock()
	
	entry, exists := alm.lockouts[userID]
	if !exists {
		return false
	}
	
	if entry.LockedUntil != nil && time.Now().Before(*entry.LockedUntil) {
		return true
	}
	
	return false
}

// RecordFailedAttempt records a failed login attempt
func (alm *AccountLockoutManager) RecordFailedAttempt(userID string) {
	alm.mutex.Lock()
	defer alm.mutex.Unlock()
	
	entry, exists := alm.lockouts[userID]
	if !exists {
		entry = &LockoutEntry{
			FailedAttempts: 0,
			LockoutCount:   0,
		}
		alm.lockouts[userID] = entry
	}
	
	entry.FailedAttempts++
	
	if entry.FailedAttempts >= alm.config.MaxFailedAttempts {
		// Calculate lockout duration
		duration := alm.config.LockoutDuration
		if alm.config.ProgressiveLockout {
			multiplier := 1.0
			for i := 0; i < entry.LockoutCount; i++ {
				multiplier *= alm.config.LockoutMultiplier
			}
			duration = time.Duration(float64(duration) * multiplier)
			
			// Cap at max lockout duration
			if duration > alm.config.MaxLockoutDuration {
				duration = alm.config.MaxLockoutDuration
			}
		}
		
		lockedUntil := time.Now().Add(duration)
		entry.LockedUntil = &lockedUntil
		entry.LockoutCount++
		entry.FailedAttempts = 0
		
		alm.logger.Warn("Account locked due to failed attempts",
			"user_id", userID,
			"lockout_duration", duration,
			"lockout_count", entry.LockoutCount)
	}
}

// ClearFailedAttempts clears failed attempts for a user
func (alm *AccountLockoutManager) ClearFailedAttempts(userID string) {
	alm.mutex.Lock()
	defer alm.mutex.Unlock()
	
	if entry, exists := alm.lockouts[userID]; exists {
		entry.FailedAttempts = 0
		entry.LockedUntil = nil
	}
}

// IPSecurityManager handles IP-based security
type IPSecurityManager struct {
	config *IPSecurityConfig
	logger *logger.Logger
}

// NewIPSecurityManager creates a new IP security manager
func NewIPSecurityManager(config *IPSecurityConfig, logger *logger.Logger) (*IPSecurityManager, error) {
	if config == nil {
		return nil, fmt.Errorf("IP security config is required")
	}
	
	return &IPSecurityManager{
		config: config,
		logger: logger,
	}, nil
}

// IsIPAllowed checks if an IP address is allowed
func (ism *IPSecurityManager) IsIPAllowed(ipAddress string) bool {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return false
	}
	
	// Check blacklist first
	if ism.config.EnableBlacklist {
		for _, blockedIP := range ism.config.BlacklistedIPs {
			if blockedIP == ipAddress {
				return false
			}
		}
	}
	
	// Check whitelist if enabled
	if ism.config.EnableWhitelist {
		for _, allowedIP := range ism.config.WhitelistedIPs {
			if allowedIP == ipAddress {
				return true
			}
		}
		return false // If whitelist is enabled, only whitelisted IPs are allowed
	}
	
	return true
}

// Helper functions

// generateRandomCode generates a random code of specified length
func generateRandomCode(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	
	// Convert to alphanumeric string
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}
	
	return string(bytes), nil
}
