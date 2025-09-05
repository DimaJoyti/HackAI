package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/firebase"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// AuthMiddleware provides Firebase authentication middleware
type AuthMiddleware struct {
	firebaseService *firebase.Service
	logger          *logger.Logger
	config          *AuthConfig
}

// AuthConfig contains authentication middleware configuration
type AuthConfig struct {
	RequiredClaims   []string          `json:"required_claims"`
	AllowedRoles     []string          `json:"allowed_roles"`
	SkipPaths        []string          `json:"skip_paths"`
	TokenHeader      string            `json:"token_header"`
	TokenPrefix      string            `json:"token_prefix"`
	CookieName       string            `json:"cookie_name"`
	SessionTimeout   time.Duration     `json:"session_timeout"`
	RefreshThreshold time.Duration     `json:"refresh_threshold"`
	CustomValidators []CustomValidator `json:"-"`
}

// CustomValidator defines a custom token validation function
type CustomValidator func(ctx context.Context, token *TokenInfo) error

// TokenInfo contains validated token information
type TokenInfo struct {
	UID           string                 `json:"uid"`
	Email         string                 `json:"email"`
	EmailVerified bool                   `json:"email_verified"`
	Claims        map[string]interface{} `json:"claims"`
	IssuedAt      time.Time              `json:"issued_at"`
	ExpiresAt     time.Time              `json:"expires_at"`
	AuthTime      time.Time              `json:"auth_time"`
}

// UserContext contains authenticated user context
type UserContext struct {
	UID           string                 `json:"uid"`
	Email         string                 `json:"email"`
	DisplayName   string                 `json:"display_name"`
	EmailVerified bool                   `json:"email_verified"`
	Role          string                 `json:"role"`
	Permissions   []string               `json:"permissions"`
	Claims        map[string]interface{} `json:"claims"`
	SessionID     string                 `json:"session_id"`
	LoginTime     time.Time              `json:"login_time"`
	LastActivity  time.Time              `json:"last_activity"`
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(firebaseService *firebase.Service, logger *logger.Logger, config *AuthConfig) *AuthMiddleware {
	if config == nil {
		config = &AuthConfig{
			TokenHeader:      "Authorization",
			TokenPrefix:      "Bearer ",
			CookieName:       "auth_token",
			SessionTimeout:   24 * time.Hour,
			RefreshThreshold: time.Hour,
		}
	}

	return &AuthMiddleware{
		firebaseService: firebaseService,
		logger:          logger,
		config:          config,
	}
}

// Authenticate provides authentication middleware
func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for certain paths
		if m.shouldSkipAuth(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Extract token from request
		token, err := m.extractToken(r)
		if err != nil {
			m.logger.WithError(err).Warn("Failed to extract authentication token")
			m.writeUnauthorizedResponse(w, "Authentication required")
			return
		}

		// Validate token with Firebase
		tokenInfo, err := m.validateToken(r.Context(), token)
		if err != nil {
			m.logger.WithError(err).Warn("Token validation failed")
			m.writeUnauthorizedResponse(w, "Invalid authentication token")
			return
		}

		// Check token expiration and refresh if needed
		if m.shouldRefreshToken(tokenInfo) {
			m.logger.Info("Token refresh recommended", map[string]interface{}{
				"uid":        tokenInfo.UID,
				"expires_at": tokenInfo.ExpiresAt,
			})
			// Add refresh header
			w.Header().Set("X-Token-Refresh-Required", "true")
		}

		// Run custom validators
		if err := m.runCustomValidators(r.Context(), tokenInfo); err != nil {
			m.logger.WithError(err).Warn("Custom validation failed")
			m.writeUnauthorizedResponse(w, "Access denied")
			return
		}

		// Create user context
		userCtx, err := m.createUserContext(r.Context(), tokenInfo)
		if err != nil {
			m.logger.WithError(err).Error("Failed to create user context")
			m.writeInternalErrorResponse(w, "Authentication error")
			return
		}

		// Check role-based access
		if !m.hasRequiredRole(userCtx) {
			m.logger.Warn("Insufficient role permissions", map[string]interface{}{
				"uid":            userCtx.UID,
				"user_role":      userCtx.Role,
				"required_roles": m.config.AllowedRoles,
			})
			m.writeForbiddenResponse(w, "Insufficient permissions")
			return
		}

		// Add user context to request
		ctx := context.WithValue(r.Context(), "user", userCtx)
		ctx = context.WithValue(ctx, "token_info", tokenInfo)

		// Log successful authentication
		m.logAuthenticationEvent(r, userCtx, true, "")

		// Update last activity
		m.updateLastActivity(ctx, userCtx)

		// Continue to next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole creates middleware that requires specific roles
func (m *AuthMiddleware) RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userCtx := GetUserFromContext(r.Context())
			if userCtx == nil {
				m.writeUnauthorizedResponse(w, "Authentication required")
				return
			}

			hasRole := false
			for _, role := range roles {
				if userCtx.Role == role {
					hasRole = true
					break
				}
			}

			if !hasRole {
				m.logger.Warn("Role access denied", map[string]interface{}{
					"uid":            userCtx.UID,
					"user_role":      userCtx.Role,
					"required_roles": roles,
				})
				m.writeForbiddenResponse(w, "Insufficient role permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission creates middleware that requires specific permissions
func (m *AuthMiddleware) RequirePermission(permissions ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userCtx := GetUserFromContext(r.Context())
			if userCtx == nil {
				m.writeUnauthorizedResponse(w, "Authentication required")
				return
			}

			hasPermission := false
			for _, permission := range permissions {
				for _, userPerm := range userCtx.Permissions {
					if userPerm == permission {
						hasPermission = true
						break
					}
				}
				if hasPermission {
					break
				}
			}

			if !hasPermission {
				m.logger.Warn("Permission access denied", map[string]interface{}{
					"uid":                  userCtx.UID,
					"user_permissions":     userCtx.Permissions,
					"required_permissions": permissions,
				})
				m.writeForbiddenResponse(w, "Insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Helper methods

// shouldSkipAuth checks if authentication should be skipped for a path
func (m *AuthMiddleware) shouldSkipAuth(path string) bool {
	for _, skipPath := range m.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// extractToken extracts the authentication token from the request
func (m *AuthMiddleware) extractToken(r *http.Request) (string, error) {
	// Try Authorization header first
	authHeader := r.Header.Get(m.config.TokenHeader)
	if authHeader != "" {
		if strings.HasPrefix(authHeader, m.config.TokenPrefix) {
			return strings.TrimPrefix(authHeader, m.config.TokenPrefix), nil
		}
		return authHeader, nil
	}

	// Try cookie if configured
	if m.config.CookieName != "" {
		cookie, err := r.Cookie(m.config.CookieName)
		if err == nil {
			return cookie.Value, nil
		}
	}

	return "", fmt.Errorf("no authentication token found")
}

// validateToken validates the token with Firebase
func (m *AuthMiddleware) validateToken(ctx context.Context, token string) (*TokenInfo, error) {
	firebaseToken, err := m.firebaseService.VerifyIDToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	tokenInfo := &TokenInfo{
		UID:           firebaseToken.UID,
		Email:         getStringClaim(firebaseToken.Claims, "email"),
		EmailVerified: getBoolClaim(firebaseToken.Claims, "email_verified"),
		Claims:        firebaseToken.Claims,
		IssuedAt:      time.Unix(firebaseToken.IssuedAt, 0),
		ExpiresAt:     time.Unix(firebaseToken.Expires, 0),
		AuthTime:      time.Unix(firebaseToken.AuthTime, 0),
	}

	return tokenInfo, nil
}

// shouldRefreshToken checks if the token should be refreshed
func (m *AuthMiddleware) shouldRefreshToken(tokenInfo *TokenInfo) bool {
	return time.Until(tokenInfo.ExpiresAt) < m.config.RefreshThreshold
}

// runCustomValidators runs custom token validators
func (m *AuthMiddleware) runCustomValidators(ctx context.Context, tokenInfo *TokenInfo) error {
	for _, validator := range m.config.CustomValidators {
		if err := validator(ctx, tokenInfo); err != nil {
			return err
		}
	}
	return nil
}

// createUserContext creates a user context from token info
func (m *AuthMiddleware) createUserContext(ctx context.Context, tokenInfo *TokenInfo) (*UserContext, error) {
	// Get additional user information from Firebase
	user, err := m.firebaseService.GetUser(ctx, tokenInfo.UID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	userCtx := &UserContext{
		UID:           tokenInfo.UID,
		Email:         tokenInfo.Email,
		DisplayName:   user.DisplayName,
		EmailVerified: tokenInfo.EmailVerified,
		Role:          getStringClaim(tokenInfo.Claims, "role"),
		Permissions:   getStringSliceClaim(tokenInfo.Claims, "permissions"),
		Claims:        tokenInfo.Claims,
		SessionID:     generateSessionID(),
		LoginTime:     tokenInfo.AuthTime,
		LastActivity:  time.Now(),
	}

	return userCtx, nil
}

// hasRequiredRole checks if the user has the required role
func (m *AuthMiddleware) hasRequiredRole(userCtx *UserContext) bool {
	if len(m.config.AllowedRoles) == 0 {
		return true // No role restrictions
	}

	for _, allowedRole := range m.config.AllowedRoles {
		if userCtx.Role == allowedRole {
			return true
		}
	}

	return false
}

// logAuthenticationEvent logs an authentication event
func (m *AuthMiddleware) logAuthenticationEvent(r *http.Request, userCtx *UserContext, success bool, errorMsg string) {
	logData := map[string]interface{}{
		"event":      "authentication",
		"success":    success,
		"uid":        userCtx.UID,
		"email":      userCtx.Email,
		"ip_address": getClientIP(r),
		"user_agent": r.UserAgent(),
		"path":       r.URL.Path,
		"method":     r.Method,
		"timestamp":  time.Now().Unix(),
	}

	if !success && errorMsg != "" {
		logData["error"] = errorMsg
	}

	if success {
		m.logger.Info("Authentication successful", logData)
	} else {
		m.logger.Warn("Authentication failed", logData)
	}
}

// updateLastActivity updates the user's last activity timestamp
func (m *AuthMiddleware) updateLastActivity(ctx context.Context, userCtx *UserContext) {
	// In a real implementation, this would update the user's last activity in the database
	// using Firebase MCP tools
	go func() {
		// Async update to avoid blocking the request
		// This would call Firebase MCP to update user activity
	}()
}

// Response helpers

func (m *AuthMiddleware) writeUnauthorizedResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, `{"error": "%s", "code": "UNAUTHORIZED"}`, message)
}

func (m *AuthMiddleware) writeForbiddenResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `{"error": "%s", "code": "FORBIDDEN"}`, message)
}

func (m *AuthMiddleware) writeInternalErrorResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, `{"error": "%s", "code": "INTERNAL_ERROR"}`, message)
}

// Utility functions

// GetUserFromContext extracts the user context from the request context
func GetUserFromContext(ctx context.Context) *UserContext {
	if user, ok := ctx.Value("user").(*UserContext); ok {
		return user
	}
	return nil
}

// GetTokenInfoFromContext extracts the token info from the request context
func GetTokenInfoFromContext(ctx context.Context) *TokenInfo {
	if tokenInfo, ok := ctx.Value("token_info").(*TokenInfo); ok {
		return tokenInfo
	}
	return nil
}

// Helper functions for claim extraction
func getStringClaim(claims map[string]interface{}, key string) string {
	if val, ok := claims[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getBoolClaim(claims map[string]interface{}, key string) bool {
	if val, ok := claims[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

func getStringSliceClaim(claims map[string]interface{}, key string) []string {
	if val, ok := claims[key]; ok {
		if slice, ok := val.([]interface{}); ok {
			var result []string
			for _, item := range slice {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			return result
		}
	}
	return []string{}
}

func generateSessionID() string {
	return fmt.Sprintf("session_%d", time.Now().UnixNano())
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}

	return ip
}
