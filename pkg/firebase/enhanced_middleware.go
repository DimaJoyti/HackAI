package firebase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"firebase.google.com/go/v4/auth"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var middlewareTracer = otel.Tracer("hackai/firebase/enhanced_middleware")

// EnhancedMiddleware provides Firebase authentication middleware with enhanced security
type EnhancedMiddleware struct {
	service       *EnhancedService
	logger        *logger.Logger
	config        *MiddlewareConfig
	rateLimiter   *RateLimiter
	securityRules *SecurityRules
}

// MiddlewareConfig configures the Firebase middleware
type MiddlewareConfig struct {
	RequireEmailVerification bool          `yaml:"require_email_verification"`
	AllowedOrigins          []string      `yaml:"allowed_origins"`
	TokenCacheTTL           time.Duration `yaml:"token_cache_ttl"`
	RateLimitRequests       int           `yaml:"rate_limit_requests"`
	RateLimitWindow         time.Duration `yaml:"rate_limit_window"`
	EnableSecurityHeaders   bool          `yaml:"enable_security_headers"`
	EnableAuditLogging      bool          `yaml:"enable_audit_logging"`
}

// SecurityRules defines security rules for Firebase authentication
type SecurityRules struct {
	RequiredClaims    map[string]interface{} `yaml:"required_claims"`
	ForbiddenClaims   map[string]interface{} `yaml:"forbidden_claims"`
	MinTokenAge       time.Duration          `yaml:"min_token_age"`
	MaxTokenAge       time.Duration          `yaml:"max_token_age"`
	AllowedIssuers    []string              `yaml:"allowed_issuers"`
	RequiredAudience  []string              `yaml:"required_audience"`
}

// RateLimiter implements rate limiting for authentication requests
type RateLimiter struct {
	requests map[string][]time.Time
	maxReqs  int
	window   time.Duration
}

// AuthContext contains authentication context information
type AuthContext struct {
	User          *UserResponse          `json:"user"`
	Token         *auth.Token           `json:"token"`
	Claims        map[string]interface{} `json:"claims"`
	RequestID     string                `json:"request_id"`
	IPAddress     string                `json:"ip_address"`
	UserAgent     string                `json:"user_agent"`
	Timestamp     time.Time             `json:"timestamp"`
	IsVerified    bool                  `json:"is_verified"`
	SecurityScore float64               `json:"security_score"`
}

// NewEnhancedMiddleware creates a new enhanced Firebase middleware
func NewEnhancedMiddleware(service *EnhancedService, logger *logger.Logger, config *MiddlewareConfig) *EnhancedMiddleware {
	if config == nil {
		config = &MiddlewareConfig{
			RequireEmailVerification: true,
			TokenCacheTTL:           5 * time.Minute,
			RateLimitRequests:       100,
			RateLimitWindow:         time.Hour,
			EnableSecurityHeaders:   true,
			EnableAuditLogging:      true,
		}
	}

	return &EnhancedMiddleware{
		service: service,
		logger:  logger,
		config:  config,
		rateLimiter: &RateLimiter{
			requests: make(map[string][]time.Time),
			maxReqs:  config.RateLimitRequests,
			window:   config.RateLimitWindow,
		},
		securityRules: &SecurityRules{
			MinTokenAge:      time.Minute,
			MaxTokenAge:      time.Hour,
			AllowedIssuers:   []string{"https://securetoken.google.com/" + service.config.Firebase.ProjectID},
			RequiredAudience: []string{service.config.Firebase.ProjectID},
		},
	}
}

// AuthRequiredWithSecurity middleware that requires Firebase authentication with enhanced security
func (m *EnhancedMiddleware) AuthRequiredWithSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := middlewareTracer.Start(r.Context(), "firebase.AuthRequiredWithSecurity")
		defer span.End()

		// Add security headers
		if m.config.EnableSecurityHeaders {
			m.addSecurityHeaders(w)
		}

		// Rate limiting
		if !m.checkRateLimit(r) {
			m.writeErrorResponse(w, http.StatusTooManyRequests, "Rate limit exceeded", nil)
			return
		}

		// Extract and validate token
		token, err := m.extractToken(r)
		if err != nil {
			span.RecordError(err)
			m.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", err)
			return
		}

		// Verify the token with enhanced validation
		authCtx, err := m.verifyTokenWithSecurity(ctx, token, r)
		if err != nil {
			span.RecordError(err)
			m.writeErrorResponse(w, http.StatusUnauthorized, "Invalid token", err)
			return
		}

		// Apply security rules
		if err := m.applySecurityRules(authCtx); err != nil {
			span.RecordError(err)
			m.writeErrorResponse(w, http.StatusForbidden, "Security rules violation", err)
			return
		}

		// Check email verification if required
		if m.config.RequireEmailVerification && !authCtx.IsVerified {
			m.writeErrorResponse(w, http.StatusForbidden, "Email verification required", nil)
			return
		}

		// Add authentication context to request
		ctx = context.WithValue(ctx, UserContextKey, authCtx.User)
		ctx = context.WithValue(ctx, TokenContextKey, authCtx.Token)
		ctx = context.WithValue(ctx, ClaimsContextKey, authCtx.Claims)
		ctx = context.WithValue(ctx, "auth_context", authCtx)

		// Audit logging
		if m.config.EnableAuditLogging {
			m.logAuthEvent("authentication_success", authCtx, r)
		}

		span.SetAttributes(
			attribute.String("firebase.user_id", authCtx.User.UID),
			attribute.String("firebase.user_email", authCtx.User.Email),
			attribute.Bool("firebase.email_verified", authCtx.IsVerified),
			attribute.Float64("firebase.security_score", authCtx.SecurityScore),
		)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// verifyTokenWithSecurity verifies token with enhanced security checks
func (m *EnhancedMiddleware) verifyTokenWithSecurity(ctx context.Context, token string, r *http.Request) (*AuthContext, error) {
	// Verify the Firebase token
	firebaseToken, err := m.service.VerifyIDTokenWithContext(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// Get user information
	user, err := m.service.authClient.GetUser(ctx, firebaseToken.UID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Check if user is disabled
	if user.Disabled {
		return nil, fmt.Errorf("account disabled")
	}

	// Calculate security score
	securityScore := m.calculateSecurityScore(firebaseToken, r)

	authCtx := &AuthContext{
		User: &UserResponse{
			UID:           user.UID,
			Email:         user.Email,
			DisplayName:   user.DisplayName,
			EmailVerified: user.EmailVerified,
			PhoneNumber:   user.PhoneNumber,
			Disabled:      user.Disabled,
			CreatedAt:     user.UserMetadata.CreationTimestamp,
			LastLoginAt:   user.UserMetadata.LastLogInTimestamp,
		},
		Token:         firebaseToken,
		Claims:        firebaseToken.Claims,
		RequestID:     r.Header.Get("X-Request-ID"),
		IPAddress:     getEnhancedClientIP(r),
		UserAgent:     r.UserAgent(),
		Timestamp:     time.Now(),
		IsVerified:    user.EmailVerified,
		SecurityScore: securityScore,
	}

	return authCtx, nil
}

// calculateSecurityScore calculates a security score based on various factors
func (m *EnhancedMiddleware) calculateSecurityScore(token *auth.Token, r *http.Request) float64 {
	score := 1.0

	// Check token age
	tokenAge := time.Since(time.Unix(token.IssuedAt, 0))
	if tokenAge > time.Hour {
		score -= 0.2
	}

	// Check if email is verified
	if emailVerified, ok := token.Claims["email_verified"].(bool); ok && !emailVerified {
		score -= 0.3
	}

	// Check for suspicious user agent
	userAgent := r.UserAgent()
	if userAgent == "" || strings.Contains(strings.ToLower(userAgent), "bot") {
		score -= 0.2
	}

	// Check for known good IP patterns (this is a simplified example)
	clientIP := getEnhancedClientIP(r)
	if strings.HasPrefix(clientIP, "127.") || strings.HasPrefix(clientIP, "192.168.") {
		score += 0.1 // Local development
	}

	// Ensure score is between 0 and 1
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}

	return score
}

// applySecurityRules applies security rules to the authentication context
func (m *EnhancedMiddleware) applySecurityRules(authCtx *AuthContext) error {
	// Check minimum security score
	if authCtx.SecurityScore < 0.5 {
		return fmt.Errorf("security score too low: %f", authCtx.SecurityScore)
	}

	// Check token age
	tokenAge := time.Since(time.Unix(authCtx.Token.IssuedAt, 0))
	if tokenAge < m.securityRules.MinTokenAge {
		return fmt.Errorf("token too new: %v", tokenAge)
	}
	if tokenAge > m.securityRules.MaxTokenAge {
		return fmt.Errorf("token too old: %v", tokenAge)
	}

	// Check issuer
	validIssuer := false
	for _, allowedIssuer := range m.securityRules.AllowedIssuers {
		if authCtx.Token.Issuer == allowedIssuer {
			validIssuer = true
			break
		}
	}
	if !validIssuer {
		return fmt.Errorf("invalid issuer: %s", authCtx.Token.Issuer)
	}

	// Check audience
	validAudience := false
	for _, requiredAud := range m.securityRules.RequiredAudience {
		if authCtx.Token.Audience == requiredAud {
			validAudience = true
			break
		}
	}
	if !validAudience {
		return fmt.Errorf("invalid audience: %v", authCtx.Token.Audience)
	}

	return nil
}

// checkRateLimit checks if the request is within rate limits
func (m *EnhancedMiddleware) checkRateLimit(r *http.Request) bool {
	clientIP := getEnhancedClientIP(r)
	now := time.Now()

	// Clean old requests
	if requests, exists := m.rateLimiter.requests[clientIP]; exists {
		var validRequests []time.Time
		for _, reqTime := range requests {
			if now.Sub(reqTime) < m.rateLimiter.window {
				validRequests = append(validRequests, reqTime)
			}
		}
		m.rateLimiter.requests[clientIP] = validRequests
	}

	// Check if under limit
	if len(m.rateLimiter.requests[clientIP]) >= m.rateLimiter.maxReqs {
		return false
	}

	// Add current request
	m.rateLimiter.requests[clientIP] = append(m.rateLimiter.requests[clientIP], now)
	return true
}

// addSecurityHeaders adds security headers to the response
func (m *EnhancedMiddleware) addSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

// logAuthEvent logs authentication events for audit purposes
func (m *EnhancedMiddleware) logAuthEvent(event string, authCtx *AuthContext, r *http.Request) {
	m.logger.Info("Firebase auth event", map[string]interface{}{
		"event":          event,
		"user_id":        authCtx.User.UID,
		"user_email":     authCtx.User.Email,
		"ip_address":     authCtx.IPAddress,
		"user_agent":     authCtx.UserAgent,
		"request_id":     authCtx.RequestID,
		"security_score": authCtx.SecurityScore,
		"email_verified": authCtx.IsVerified,
		"timestamp":      authCtx.Timestamp,
		"path":           r.URL.Path,
		"method":         r.Method,
	})
}

// extractToken extracts the Firebase token from the request
func (m *EnhancedMiddleware) extractToken(r *http.Request) (string, error) {
	// Check Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && parts[0] == "Bearer" {
			return parts[1], nil
		}
	}

	// Check cookie
	if cookie, err := r.Cookie("firebase_token"); err == nil {
		return cookie.Value, nil
	}

	return "", fmt.Errorf("no authentication token found")
}

// writeErrorResponse writes an error response
func (m *EnhancedMiddleware) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := map[string]interface{}{
		"error":     message,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"status":    statusCode,
	}

	if err != nil && m.logger != nil {
		m.logger.WithError(err).Error("Firebase middleware error", map[string]interface{}{
			"status_code": statusCode,
			"message":     message,
		})
	}

	json.NewEncoder(w).Encode(response)
}

// getEnhancedClientIP extracts the client IP address from the request
func getEnhancedClientIP(r *http.Request) string {
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
