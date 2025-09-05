package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/dimajoyti/hackai/pkg/firebase"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// FirebaseMCPMiddleware provides comprehensive Firebase MCP middleware stack
type FirebaseMCPMiddleware struct {
	authMiddleware     *AuthMiddleware
	securityMiddleware *SecurityMiddleware
	logger             *logger.Logger
}

// FirebaseMCPConfig contains configuration for Firebase MCP middleware
type FirebaseMCPConfig struct {
	Auth     *AuthConfig     `json:"auth"`
	Security *SecurityConfig `json:"security"`
}

// NewFirebaseMCPMiddleware creates a new Firebase MCP middleware stack
func NewFirebaseMCPMiddleware(firebaseService *firebase.Service, logger *logger.Logger, config *FirebaseMCPConfig) *FirebaseMCPMiddleware {
	if config == nil {
		config = &FirebaseMCPConfig{
			Auth: &AuthConfig{
				RequiredClaims: []string{"email_verified"},
				AllowedRoles:   []string{"user", "admin"},
				SkipPaths: []string{
					"/health",
					"/api/auth/login",
					"/api/auth/register",
					"/api/auth/refresh",
					"/api/firebase/auth/google",
				},
				TokenHeader:      "Authorization",
				TokenPrefix:      "Bearer ",
				CookieName:       "auth_token",
				SessionTimeout:   24 * time.Hour,
				RefreshThreshold: time.Hour,
			},
			Security: &SecurityConfig{
				RateLimit: &RateLimitConfig{
					RequestsPerSecond: 100,
					BurstSize:         200,
					WindowSize:        time.Minute,
					CleanupInterval:   5 * time.Minute,
					SkipPaths: []string{
						"/health",
						"/metrics",
					},
					CustomLimits: map[string]struct {
						RequestsPerSecond int `json:"requests_per_second"`
						BurstSize         int `json:"burst_size"`
					}{
						"/api/auth/": {
							RequestsPerSecond: 10,
							BurstSize:         20,
						},
						"/api/firebase/auth/": {
							RequestsPerSecond: 10,
							BurstSize:         20,
						},
					},
				},
				CSRF: &CSRFConfig{
					Enabled:        true,
					TokenLength:    32,
					CookieName:     "csrf_token",
					HeaderName:     "X-CSRF-Token",
					FieldName:      "csrf_token",
					CookieSecure:   true,
					CookieHTTPOnly: true,
					CookieSameSite: http.SameSiteStrictMode,
					TokenLifetime:  24 * time.Hour,
					SkipPaths: []string{
						"/api/auth/login",
						"/api/auth/register",
						"/api/firebase/auth/google",
						"/health",
					},
					SafeMethods: []string{"GET", "HEAD", "OPTIONS"},
				},
				Headers: &HeadersConfig{
					ContentTypeNosniff:      true,
					FrameOptions:            "DENY",
					ContentSecurityPolicy:   "default-src 'self'; script-src 'self' 'unsafe-inline' https://apis.google.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com",
					StrictTransportSecurity: "max-age=31536000; includeSubDomains",
					ReferrerPolicy:          "strict-origin-when-cross-origin",
					PermissionsPolicy:       "geolocation=(), microphone=(), camera=()",
				},
			},
		}
	}

	authMiddleware := NewAuthMiddleware(firebaseService, logger, config.Auth)
	securityMiddleware := NewSecurityMiddleware(logger, config.Security)

	return &FirebaseMCPMiddleware{
		authMiddleware:     authMiddleware,
		securityMiddleware: securityMiddleware,
		logger:             logger,
	}
}

// CreateMiddlewareStack creates a complete middleware stack for Firebase MCP
func (m *FirebaseMCPMiddleware) CreateMiddlewareStack() []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{
		// Request ID and logging (first)
		RequestID,
		Logging(m.logger),

		// Security headers (early)
		m.securityMiddleware.SecurityHeaders,

		// Recovery (early to catch all panics)
		Recovery(m.logger),

		// Rate limiting (before authentication to prevent abuse)
		m.securityMiddleware.RateLimit,

		// CSRF protection (before authentication)
		m.securityMiddleware.CSRFProtection,

		// Audit logging (before authentication to log all attempts)
		m.securityMiddleware.AuditLogger,

		// Authentication (main auth check)
		m.authMiddleware.Authenticate,
	}
}

// CreatePublicMiddlewareStack creates a middleware stack for public endpoints
func (m *FirebaseMCPMiddleware) CreatePublicMiddlewareStack() []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{
		// Request ID and logging
		RequestID,
		Logging(m.logger),

		// Security headers
		m.securityMiddleware.SecurityHeaders,

		// Recovery
		Recovery(m.logger),

		// Rate limiting (more permissive for public endpoints)
		m.securityMiddleware.RateLimit,

		// Audit logging
		m.securityMiddleware.AuditLogger,
	}
}

// CreateAuthMiddlewareStack creates a middleware stack for authentication endpoints
func (m *FirebaseMCPMiddleware) CreateAuthMiddlewareStack() []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{
		// Request ID and logging
		RequestID,
		Logging(m.logger),

		// Security headers
		m.securityMiddleware.SecurityHeaders,

		// Recovery
		Recovery(m.logger),

		// Stricter rate limiting for auth endpoints
		m.securityMiddleware.RateLimit,

		// CSRF protection (important for auth endpoints)
		m.securityMiddleware.CSRFProtection,

		// Audit logging (critical for auth endpoints)
		m.securityMiddleware.AuditLogger,
	}
}

// RequireRole creates role-based authorization middleware
func (m *FirebaseMCPMiddleware) RequireRole(roles ...string) func(http.Handler) http.Handler {
	return m.authMiddleware.RequireRole(roles...)
}

// RequirePermission creates permission-based authorization middleware
func (m *FirebaseMCPMiddleware) RequirePermission(permissions ...string) func(http.Handler) http.Handler {
	return m.authMiddleware.RequirePermission(permissions...)
}

// RequireEmailVerified creates middleware that requires email verification
func (m *FirebaseMCPMiddleware) RequireEmailVerified() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userCtx := GetUserFromContext(r.Context())
			if userCtx == nil {
				m.authMiddleware.writeUnauthorizedResponse(w, "Authentication required")
				return
			}

			if !userCtx.EmailVerified {
				m.authMiddleware.writeForbiddenResponse(w, "Email verification required")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireActiveUser creates middleware that requires an active user account
func (m *FirebaseMCPMiddleware) RequireActiveUser() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userCtx := GetUserFromContext(r.Context())
			if userCtx == nil {
				m.authMiddleware.writeUnauthorizedResponse(w, "Authentication required")
				return
			}

			// Check if user account is active (this would be a custom claim or database check)
			if active, ok := userCtx.Claims["active"].(bool); ok && !active {
				m.authMiddleware.writeForbiddenResponse(w, "Account is inactive")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// AddCustomValidator adds a custom token validator
func (m *FirebaseMCPMiddleware) AddCustomValidator(validator CustomValidator) {
	m.authMiddleware.config.CustomValidators = append(m.authMiddleware.config.CustomValidators, validator)
}

// Example custom validators

// RequireGoogleProvider creates a validator that requires Google authentication
func RequireGoogleProvider() CustomValidator {
	return func(ctx context.Context, token *TokenInfo) error {
		if provider, ok := token.Claims["firebase"].(map[string]interface{})["sign_in_provider"].(string); ok {
			if provider != "google.com" {
				return fmt.Errorf("Google authentication required")
			}
		}
		return nil
	}
}

// RequireRecentAuth creates a validator that requires recent authentication
func RequireRecentAuth(maxAge time.Duration) CustomValidator {
	return func(ctx context.Context, token *TokenInfo) error {
		if time.Since(token.AuthTime) > maxAge {
			return fmt.Errorf("recent authentication required")
		}
		return nil
	}
}

// RequireCustomClaim creates a validator that requires a specific custom claim
func RequireCustomClaim(claimName string, expectedValue interface{}) CustomValidator {
	return func(ctx context.Context, token *TokenInfo) error {
		if value, ok := token.Claims[claimName]; ok {
			if value != expectedValue {
				return fmt.Errorf("invalid %s claim", claimName)
			}
		} else {
			return fmt.Errorf("missing %s claim", claimName)
		}
		return nil
	}
}

// Utility functions for middleware configuration

// WithRateLimit configures rate limiting
func WithRateLimit(requestsPerSecond, burstSize int) func(*FirebaseMCPConfig) {
	return func(config *FirebaseMCPConfig) {
		if config.Security == nil {
			config.Security = &SecurityConfig{}
		}
		if config.Security.RateLimit == nil {
			config.Security.RateLimit = &RateLimitConfig{}
		}
		config.Security.RateLimit.RequestsPerSecond = requestsPerSecond
		config.Security.RateLimit.BurstSize = burstSize
	}
}

// WithCSRF configures CSRF protection
func WithCSRF(enabled bool) func(*FirebaseMCPConfig) {
	return func(config *FirebaseMCPConfig) {
		if config.Security == nil {
			config.Security = &SecurityConfig{}
		}
		if config.Security.CSRF == nil {
			config.Security.CSRF = &CSRFConfig{}
		}
		config.Security.CSRF.Enabled = enabled
	}
}

// WithRequiredRoles configures required roles
func WithRequiredRoles(roles ...string) func(*FirebaseMCPConfig) {
	return func(config *FirebaseMCPConfig) {
		if config.Auth == nil {
			config.Auth = &AuthConfig{}
		}
		config.Auth.AllowedRoles = roles
	}
}

// WithSkipPaths configures paths to skip authentication
func WithSkipPaths(paths ...string) func(*FirebaseMCPConfig) {
	return func(config *FirebaseMCPConfig) {
		if config.Auth == nil {
			config.Auth = &AuthConfig{}
		}
		config.Auth.SkipPaths = append(config.Auth.SkipPaths, paths...)
	}
}

// ApplyConfig applies configuration options to a config
func ApplyConfig(config *FirebaseMCPConfig, options ...func(*FirebaseMCPConfig)) *FirebaseMCPConfig {
	for _, option := range options {
		option(config)
	}
	return config
}

// Example usage:
/*
// Create Firebase MCP middleware with custom configuration
config := ApplyConfig(&FirebaseMCPConfig{},
	WithRateLimit(50, 100),
	WithCSRF(true),
	WithRequiredRoles("user", "admin"),
	WithSkipPaths("/api/public", "/health"),
)

firebaseService := firebase.NewService(...)
logger := logger.New("middleware", "info")
middleware := NewFirebaseMCPMiddleware(firebaseService, logger, config)

// Add custom validators
middleware.AddCustomValidator(RequireGoogleProvider())
middleware.AddCustomValidator(RequireRecentAuth(30 * time.Minute))

// Create middleware stacks
publicStack := middleware.CreatePublicMiddlewareStack()
authStack := middleware.CreateAuthMiddlewareStack()
protectedStack := middleware.CreateMiddlewareStack()

// Use with HTTP router
router := mux.NewRouter()

// Public endpoints
publicRouter := router.PathPrefix("/api/public").Subrouter()
for _, mw := range publicStack {
	publicRouter.Use(mw)
}

// Auth endpoints
authRouter := router.PathPrefix("/api/auth").Subrouter()
for _, mw := range authStack {
	authRouter.Use(mw)
}

// Protected endpoints
protectedRouter := router.PathPrefix("/api/protected").Subrouter()
for _, mw := range protectedStack {
	protectedRouter.Use(mw)
}

// Role-specific endpoints
adminRouter := protectedRouter.PathPrefix("/admin").Subrouter()
adminRouter.Use(middleware.RequireRole("admin"))

// Permission-specific endpoints
userManagementRouter := protectedRouter.PathPrefix("/users").Subrouter()
userManagementRouter.Use(middleware.RequirePermission("user:read", "user:write"))
*/
