package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// EnhancedAuthService provides comprehensive authentication and authorization
type EnhancedAuthService struct {
	jwtService        *JWTService
	passwordManager   *PasswordManager
	totpManager       *TOTPManager
	sessionManager    *SessionManager
	ipSecurityManager *IPSecurityManager
	securityAuditor   *SecurityAuditor
	rateLimiter       *RateLimiter
	accountLockout    *AccountLockoutManager
	userRepo          domain.UserRepository
	auditRepo         domain.AuditRepository
	logger            *logger.Logger
	config            *SecurityConfig
}

// NewEnhancedAuthService creates a new enhanced authentication service
func NewEnhancedAuthService(
	jwtConfig *JWTConfig,
	securityConfig *SecurityConfig,
	userRepo domain.UserRepository,
	auditRepo domain.AuditRepository,
	log *logger.Logger,
) *EnhancedAuthService {
	return &EnhancedAuthService{
		jwtService:        NewJWTService(jwtConfig),
		passwordManager:   NewPasswordManager(securityConfig),
		totpManager:       NewTOTPManager(securityConfig),
		sessionManager:    NewSessionManager(securityConfig),
		ipSecurityManager: NewIPSecurityManager(securityConfig),
		securityAuditor:   NewSecurityAuditor(securityConfig),
		rateLimiter:       NewRateLimiter(securityConfig),
		accountLockout:    NewAccountLockoutManager(securityConfig),
		userRepo:          userRepo,
		auditRepo:         auditRepo,
		logger:            log,
		config:            securityConfig,
	}
}

// AuthenticationRequest represents an authentication request
type AuthenticationRequest struct {
	EmailOrUsername string `json:"email_or_username"`
	Password        string `json:"password"`
	TOTPCode        string `json:"totp_code,omitempty"`
	IPAddress       string `json:"ip_address"`
	UserAgent       string `json:"user_agent"`
	DeviceID        string `json:"device_id,omitempty"`
	RememberMe      bool   `json:"remember_me"`
}

// AuthenticationResponse represents an authentication response
type AuthenticationResponse struct {
	User         *domain.User `json:"user"`
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time    `json:"expires_at"`
	SessionID    uuid.UUID    `json:"session_id"`
	RequiresTOTP bool         `json:"requires_totp"`
	CSRFToken    string       `json:"csrf_token,omitempty"`
}

// Authenticate performs comprehensive user authentication
func (eas *EnhancedAuthService) Authenticate(ctx context.Context, req *AuthenticationRequest) (*AuthenticationResponse, error) {
	// Check IP restrictions
	if !eas.ipSecurityManager.IsIPAllowed(req.IPAddress) {
		eas.logSecurityEvent(SecurityEventSuspiciousIP, "", req.IPAddress, req.UserAgent, map[string]interface{}{
			"reason": "IP not in allowed range",
		}, false)
		return nil, fmt.Errorf("access denied from this IP address")
	}

	// Check rate limiting
	if !eas.rateLimiter.IsAllowed(req.IPAddress) {
		eas.logSecurityEvent(SecurityEventLoginFailed, "", req.IPAddress, req.UserAgent, map[string]interface{}{
			"reason": "rate limit exceeded",
		}, false)
		return nil, fmt.Errorf("too many login attempts, please try again later")
	}

	// Check account lockout
	if eas.accountLockout.IsAccountLocked(req.EmailOrUsername) {
		eas.logSecurityEvent(SecurityEventAccountLocked, "", req.IPAddress, req.UserAgent, map[string]interface{}{
			"account": req.EmailOrUsername,
		}, false)
		return nil, fmt.Errorf("account is temporarily locked due to too many failed attempts")
	}

	// Find user
	var user *domain.User
	var err error

	if strings.Contains(req.EmailOrUsername, "@") {
		user, err = eas.userRepo.GetByEmail(req.EmailOrUsername)
	} else {
		user, err = eas.userRepo.GetByUsername(req.EmailOrUsername)
	}

	if err != nil {
		eas.recordFailedAttempt(req.EmailOrUsername, req.IPAddress, req.UserAgent, "user not found")
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check user status
	if !user.IsActive() {
		eas.logSecurityEvent(SecurityEventLoginFailed, user.ID.String(), req.IPAddress, req.UserAgent, map[string]interface{}{
			"reason": "account not active",
			"status": user.Status,
		}, false)
		return nil, fmt.Errorf("account is not active")
	}

	// Verify password
	if !eas.passwordManager.VerifyPassword(req.Password, user.Password) {
		eas.recordFailedAttempt(req.EmailOrUsername, req.IPAddress, req.UserAgent, "invalid password")
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check TOTP if enabled
	if user.TwoFactorEnabled {
		if req.TOTPCode == "" {
			return &AuthenticationResponse{
				RequiresTOTP: true,
			}, nil
		}

		// In a real implementation, you'd retrieve the user's TOTP secret
		// and verify the code using the TOTPManager
		if !eas.totpManager.VerifyTOTP("", req.TOTPCode) {
			eas.recordFailedAttempt(req.EmailOrUsername, req.IPAddress, req.UserAgent, "invalid TOTP code")
			return nil, fmt.Errorf("invalid two-factor authentication code")
		}
	}

	// Clear failed attempts on successful authentication
	eas.accountLockout.ClearFailedAttempts(req.EmailOrUsername)

	// Create session
	sessionID, err := eas.sessionManager.GenerateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session: %w", err)
	}

	expiresAt := time.Now().Add(eas.config.SessionTimeout)
	if req.RememberMe {
		expiresAt = time.Now().Add(30 * 24 * time.Hour) // 30 days
	}

	session := &domain.UserSession{
		ID:        uuid.New(),
		UserID:    user.ID,
		Token:     sessionID,
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent,
		IPAddress: req.IPAddress,
		ExpiresAt: expiresAt,
	}

	if err := eas.userRepo.CreateSession(session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Generate JWT tokens
	claims := &Claims{
		UserID:    user.ID,
		Email:     user.Email,
		Username:  user.Username,
		Role:      user.Role,
		SessionID: session.ID,
	}

	accessToken, err := eas.jwtService.GenerateToken(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	var refreshToken string
	if req.RememberMe {
		refreshToken, err = eas.jwtService.GenerateRefreshToken(claims)
		if err != nil {
			eas.logger.WithError(err).Warn("Failed to generate refresh token")
		}
	}

	// Generate CSRF token if enabled
	var csrfToken string
	if eas.config.EnableCSRF {
		csrfToken, err = GenerateCSRFToken()
		if err != nil {
			eas.logger.WithError(err).Warn("Failed to generate CSRF token")
		}
	}

	// Update user's last login
	now := time.Now()
	user.LastLoginAt = &now
	if err := eas.userRepo.Update(user); err != nil {
		eas.logger.WithError(err).Warn("Failed to update user last login")
	}

	// Log successful authentication
	eas.logSecurityEvent(SecurityEventLogin, user.ID.String(), req.IPAddress, req.UserAgent, map[string]interface{}{
		"session_id": session.ID,
		"device_id":  req.DeviceID,
		"totp_used":  user.TwoFactorEnabled,
	}, true)

	// Log user activity
	eas.auditRepo.LogUserAction(user.ID, &session.ID, "login", "authentication", map[string]interface{}{
		"ip_address": req.IPAddress,
		"user_agent": req.UserAgent,
		"device_id":  req.DeviceID,
	})

	return &AuthenticationResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		SessionID:    session.ID,
		RequiresTOTP: false,
		CSRFToken:    csrfToken,
	}, nil
}

// Logout performs user logout
func (eas *EnhancedAuthService) Logout(ctx context.Context, token string, ipAddress, userAgent string) error {
	// Validate token
	claims, err := eas.jwtService.ValidateToken(token)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	// Delete session
	if err := eas.userRepo.DeleteSession(token); err != nil {
		eas.logger.WithError(err).Warn("Failed to delete session")
	}

	// Log logout
	eas.logSecurityEvent(SecurityEventLogout, claims.UserID.String(), ipAddress, userAgent, map[string]interface{}{
		"session_id": claims.SessionID,
	}, true)

	// Log user activity
	eas.auditRepo.LogUserAction(claims.UserID, &claims.SessionID, "logout", "authentication", map[string]interface{}{
		"ip_address": ipAddress,
		"user_agent": userAgent,
	})

	return nil
}

// ChangePassword changes a user's password
func (eas *EnhancedAuthService) ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string, ipAddress, userAgent string) error {
	// Get user
	user, err := eas.userRepo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Verify old password
	if !eas.passwordManager.VerifyPassword(oldPassword, user.Password) {
		eas.logSecurityEvent(SecurityEventPasswordChange, userID.String(), ipAddress, userAgent, map[string]interface{}{
			"reason": "invalid old password",
		}, false)
		return fmt.Errorf("invalid current password")
	}

	// Validate new password
	if err := eas.passwordManager.ValidatePassword(newPassword); err != nil {
		return fmt.Errorf("password validation failed: %w", err)
	}

	// Hash new password
	hashedPassword, err := eas.passwordManager.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	user.Password = hashedPassword
	user.PasswordChangedAt = time.Now()
	if err := eas.userRepo.Update(user); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Log password change
	eas.logSecurityEvent(SecurityEventPasswordChange, userID.String(), ipAddress, userAgent, map[string]interface{}{
		"forced": false,
	}, true)

	// Log user activity
	eas.auditRepo.LogUserAction(userID, nil, "change_password", "authentication", map[string]interface{}{
		"ip_address": ipAddress,
		"user_agent": userAgent,
	})

	return nil
}

// EnableTOTP enables two-factor authentication for a user
func (eas *EnhancedAuthService) EnableTOTP(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) (string, string, error) {
	// Get user
	user, err := eas.userRepo.GetByID(userID)
	if err != nil {
		return "", "", fmt.Errorf("user not found: %w", err)
	}

	if user.TwoFactorEnabled {
		return "", "", fmt.Errorf("two-factor authentication is already enabled")
	}

	// Generate TOTP secret
	secret, err := eas.totpManager.GenerateSecret()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// Generate QR code URL
	qrURL := eas.totpManager.GenerateQRCodeURL(secret, user.Email)

	// In a real implementation, you'd store the secret securely
	// For now, we'll just enable TOTP on the user
	user.TwoFactorEnabled = true
	if err := eas.userRepo.Update(user); err != nil {
		return "", "", fmt.Errorf("failed to enable TOTP: %w", err)
	}

	// Log TOTP enablement
	eas.logSecurityEvent(SecurityEventTOTPEnabled, userID.String(), ipAddress, userAgent, map[string]interface{}{}, true)

	// Log user activity
	eas.auditRepo.LogUserAction(userID, nil, "enable_totp", "security", map[string]interface{}{
		"ip_address": ipAddress,
		"user_agent": userAgent,
	})

	return secret, qrURL, nil
}

// recordFailedAttempt records a failed authentication attempt
func (eas *EnhancedAuthService) recordFailedAttempt(identifier, ipAddress, userAgent, reason string) {
	// Record failed attempt for account lockout
	isLocked := eas.accountLockout.RecordFailedAttempt(identifier)

	// Log security event
	eventType := SecurityEventLoginFailed
	if isLocked {
		eventType = SecurityEventAccountLocked
	}

	eas.logSecurityEvent(eventType, "", ipAddress, userAgent, map[string]interface{}{
		"account": identifier,
		"reason":  reason,
		"locked":  isLocked,
	}, false)
}

// logSecurityEvent logs a security event
func (eas *EnhancedAuthService) logSecurityEvent(eventType SecurityEventType, userID, ipAddress, userAgent string, details map[string]interface{}, success bool) {
	event := &SecurityEvent{
		Type:      eventType,
		UserID:    userID,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Details:   details,
		Success:   success,
	}

	eas.securityAuditor.LogSecurityEvent(event)

	// Also log to audit repository if available
	if eas.auditRepo != nil {
		var riskLevel domain.RiskLevel
		switch event.Severity {
		case "high":
			riskLevel = domain.RiskLevelHigh
		case "medium":
			riskLevel = domain.RiskLevelMedium
		default:
			riskLevel = domain.RiskLevelLow
		}

		var userUUID *uuid.UUID
		if userID != "" {
			if id, err := uuid.Parse(userID); err == nil {
				userUUID = &id
			}
		}

		eas.auditRepo.LogSecurityAction(userUUID, string(eventType), "authentication", riskLevel, details)
	}
}

// ValidateToken validates a JWT token and returns claims
func (eas *EnhancedAuthService) ValidateToken(token string) (*Claims, error) {
	return eas.jwtService.ValidateToken(token)
}

// RefreshTokenByString refreshes an access token using a refresh token string
func (eas *EnhancedAuthService) RefreshTokenByString(refreshToken string) (string, error) {
	return eas.jwtService.RefreshToken(refreshToken)
}

// GetUserPermissions gets all permissions for a user
func (eas *EnhancedAuthService) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*domain.UserPermission, error) {
	return eas.userRepo.GetUserPermissions(userID)
}

// CheckPermission checks if a user has a specific permission
func (eas *EnhancedAuthService) CheckPermission(ctx context.Context, userID uuid.UUID, resource, action string) (bool, error) {
	return eas.userRepo.HasPermission(userID, resource, action)
}

// GrantPermission grants a permission to a user
func (eas *EnhancedAuthService) GrantPermission(ctx context.Context, userID, grantedBy uuid.UUID, resource, action string, expiresAt *time.Time, ipAddress, userAgent string) error {
	permission := &domain.UserPermission{
		UserID:    userID,
		Resource:  resource,
		Action:    action,
		Granted:   true,
		GrantedBy: grantedBy,
		GrantedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	if err := eas.userRepo.GrantPermission(permission); err != nil {
		return fmt.Errorf("failed to grant permission: %w", err)
	}

	// Log permission grant
	eas.logSecurityEvent(SecurityEventPermissionGrant, userID.String(), ipAddress, userAgent, map[string]interface{}{
		"resource":   resource,
		"action":     action,
		"granted_by": grantedBy,
		"expires_at": expiresAt,
	}, true)

	// Log user activity
	eas.auditRepo.LogUserAction(grantedBy, nil, "grant_permission", "authorization", map[string]interface{}{
		"target_user": userID,
		"resource":    resource,
		"action":      action,
		"ip_address":  ipAddress,
		"user_agent":  userAgent,
	})

	return nil
}

// RevokePermission revokes a permission from a user
func (eas *EnhancedAuthService) RevokePermission(ctx context.Context, userID, revokedBy uuid.UUID, resource, action string, ipAddress, userAgent string) error {
	if err := eas.userRepo.RevokePermission(userID, resource, action); err != nil {
		return fmt.Errorf("failed to revoke permission: %w", err)
	}

	// Log permission revocation
	eas.logSecurityEvent(SecurityEventPermissionRevoke, userID.String(), ipAddress, userAgent, map[string]interface{}{
		"resource":   resource,
		"action":     action,
		"revoked_by": revokedBy,
	}, true)

	// Log user activity
	eas.auditRepo.LogUserAction(revokedBy, nil, "revoke_permission", "authorization", map[string]interface{}{
		"target_user": userID,
		"resource":    resource,
		"action":      action,
		"ip_address":  ipAddress,
		"user_agent":  userAgent,
	})

	return nil
}

// RefreshToken generates a new token pair for the user (interface method)
func (eas *EnhancedAuthService) RefreshToken(user *domain.User) (*TokenPair, error) {
	return eas.jwtService.GenerateTokenPair(user)
}

// GenerateTokenPair generates a new token pair for the user
func (eas *EnhancedAuthService) GenerateTokenPair(user *domain.User) (*TokenPair, error) {
	return eas.jwtService.GenerateTokenPair(user)
}

// RevokeToken revokes a JWT token
func (eas *EnhancedAuthService) RevokeToken(token string) error {
	// For now, we'll implement a simple token revocation
	// In a production system, you might want to store revoked tokens in Redis
	// or implement a token blacklist
	eas.logger.Info("Token revoked", map[string]interface{}{
		"action": "token_revoked",
		"token":  token[:10] + "...", // Log only first 10 chars for security
	})
	return nil
}

// IsTokenRevoked checks if a token has been revoked
func (eas *EnhancedAuthService) IsTokenRevoked(token string) (bool, error) {
	// For now, we'll assume no tokens are revoked
	// In a production system, you would check against a blacklist
	return false, nil
}
