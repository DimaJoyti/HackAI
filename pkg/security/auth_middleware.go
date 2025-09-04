package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var authTracer = otel.Tracer("hackai/security/auth_middleware")

// AuthMiddleware provides comprehensive authentication and authorization middleware
type AuthMiddleware struct {
	id                    string
	config                *AuthMiddlewareConfig
	logger                *logger.Logger
	authService           *AdvancedAuthService
	
	// Security components
	rateLimiter           *AuthRateLimiter
	ipSecurityManager     *IPSecurityManager
	deviceManager         *DeviceManager
	rbacManager           *RBACManager
	
	// Monitoring
	securityMonitor       *SecurityMonitor
	auditLogger           *SecurityAuditLogger
}

// AuthMiddlewareConfig configuration for authentication middleware
type AuthMiddlewareConfig struct {
	// Authentication settings
	RequireAuthentication bool                   `yaml:"require_authentication"`
	AllowAnonymous        []string               `yaml:"allow_anonymous"`
	RequireMFA            []string               `yaml:"require_mfa"`
	
	// Authorization settings
	EnableRBAC            bool                   `yaml:"enable_rbac"`
	EnablePermissionCheck bool                   `yaml:"enable_permission_check"`
	DefaultPermissions    []string               `yaml:"default_permissions"`
	
	// Security settings
	EnableRateLimiting    bool                   `yaml:"enable_rate_limiting"`
	EnableIPRestrictions  bool                   `yaml:"enable_ip_restrictions"`
	EnableDeviceTracking  bool                   `yaml:"enable_device_tracking"`
	EnableThreatDetection bool                   `yaml:"enable_threat_detection"`
	
	// Token settings
	TokenHeader           string                 `yaml:"token_header"`
	TokenPrefix           string                 `yaml:"token_prefix"`
	CookieName            string                 `yaml:"cookie_name"`
	
	// CORS settings
	EnableCORS            bool                   `yaml:"enable_cors"`
	AllowedOrigins        []string               `yaml:"allowed_origins"`
	AllowedMethods        []string               `yaml:"allowed_methods"`
	AllowedHeaders        []string               `yaml:"allowed_headers"`
	AllowCredentials      bool                   `yaml:"allow_credentials"`
	
	// Security headers
	EnableSecurityHeaders bool                   `yaml:"enable_security_headers"`
	CSPPolicy             string                 `yaml:"csp_policy"`
	HSTSMaxAge            int                    `yaml:"hsts_max_age"`
	
	// Monitoring
	EnableAuditLogging    bool                   `yaml:"enable_audit_logging"`
	EnableMetrics         bool                   `yaml:"enable_metrics"`
}

// AuthContext represents authentication context
type AuthContext struct {
	UserID                string                 `json:"user_id"`
	Username              string                 `json:"username"`
	Email                 string                 `json:"email"`
	Role                  string                 `json:"role"`
	Permissions           []string               `json:"permissions"`
	SessionID             string                 `json:"session_id"`
	DeviceID              string                 `json:"device_id"`
	IPAddress             string                 `json:"ip_address"`
	UserAgent             string                 `json:"user_agent"`
	IsAuthenticated       bool                   `json:"is_authenticated"`
	IsMFAVerified         bool                   `json:"is_mfa_verified"`
	ThreatScore           float64                `json:"threat_score"`
	RequestID             string                 `json:"request_id"`
	Timestamp             time.Time              `json:"timestamp"`
	Metadata              map[string]interface{} `json:"metadata"`
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(config *AuthMiddlewareConfig, authService *AdvancedAuthService, logger *logger.Logger) (*AuthMiddleware, error) {
	if config == nil {
		config = DefaultAuthMiddlewareConfig()
	}
	
	if authService == nil {
		return nil, fmt.Errorf("auth service is required")
	}
	
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	
	middleware := &AuthMiddleware{
		id:          generateMiddlewareID(),
		config:      config,
		logger:      logger,
		authService: authService,
	}
	
	// Initialize components from auth service
	middleware.rateLimiter = authService.rateLimiter
	middleware.ipSecurityManager = authService.ipSecurityManager
	middleware.deviceManager = authService.deviceManager
	middleware.rbacManager = authService.rbacManager
	middleware.securityMonitor = authService.securityMonitor
	middleware.auditLogger = authService.auditLogger
	
	logger.Info("Authentication middleware created",
		"middleware_id", middleware.id,
		"require_auth", config.RequireAuthentication,
		"enable_rbac", config.EnableRBAC)
	
	return middleware, nil
}

// Handler returns the HTTP middleware handler
func (am *AuthMiddleware) Handler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := authTracer.Start(r.Context(), "auth_middleware",
				trace.WithAttributes(
					attribute.String("middleware.id", am.id),
					attribute.String("http.method", r.Method),
					attribute.String("http.path", r.URL.Path),
				),
			)
			defer span.End()
			
			// Create auth context
			authCtx := &AuthContext{
				IPAddress:       getClientIP(r),
				UserAgent:       r.UserAgent(),
				RequestID:       getRequestID(r),
				Timestamp:       time.Now(),
				IsAuthenticated: false,
				IsMFAVerified:   false,
				Metadata:        make(map[string]interface{}),
			}
			
			// Add security headers
			if am.config.EnableSecurityHeaders {
				am.addSecurityHeaders(w)
			}
			
			// Handle CORS
			if am.config.EnableCORS {
				am.handleCORS(w, r)
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusOK)
					return
				}
			}
			
			// Check if path allows anonymous access
			if am.isAnonymousAllowed(r.URL.Path) {
				ctx = context.WithValue(ctx, "auth_context", authCtx)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			
			// Rate limiting
			if am.config.EnableRateLimiting && am.rateLimiter != nil {
				if !am.rateLimiter.AllowLogin(authCtx.IPAddress, "") {
					am.handleAuthError(w, r, "Rate limit exceeded", http.StatusTooManyRequests, authCtx)
					return
				}
			}
			
			// IP restrictions
			if am.config.EnableIPRestrictions && am.ipSecurityManager != nil {
				if !am.ipSecurityManager.IsIPAllowed(authCtx.IPAddress) {
					am.handleAuthError(w, r, "IP address not allowed", http.StatusForbidden, authCtx)
					return
				}
			}
			
			// Extract and validate token
			token := am.extractToken(r)
			if token == "" {
				if am.config.RequireAuthentication {
					am.handleAuthError(w, r, "Authentication required", http.StatusUnauthorized, authCtx)
					return
				}
				ctx = context.WithValue(ctx, "auth_context", authCtx)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			
			// Validate token
			tokenResult, err := am.authService.ValidateToken(ctx, token)
			if err != nil || !tokenResult.Valid {
				am.handleAuthError(w, r, "Invalid token", http.StatusUnauthorized, authCtx)
				return
			}
			
			// Update auth context with user information
			authCtx.UserID = tokenResult.UserID
			authCtx.Username = tokenResult.Username
			authCtx.Email = tokenResult.Email
			authCtx.Role = tokenResult.Role
			authCtx.Permissions = tokenResult.Permissions
			authCtx.IsAuthenticated = true
			
			// Device tracking
			if am.config.EnableDeviceTracking && am.deviceManager != nil {
				device, err := am.deviceManager.RegisterDevice(authCtx.UserID, authCtx.UserAgent, authCtx.IPAddress)
				if err != nil {
					am.logger.Warn("Failed to register device", "error", err, "user_id", authCtx.UserID)
				} else {
					authCtx.DeviceID = device.ID
				}
			}
			
			// Check MFA requirement
			if am.requiresMFA(r.URL.Path) && !authCtx.IsMFAVerified {
				am.handleAuthError(w, r, "MFA verification required", http.StatusForbidden, authCtx)
				return
			}
			
			// Authorization check
			if am.config.EnableRBAC && am.rbacManager != nil {
				if !am.checkPermissions(r, authCtx) {
					am.handleAuthError(w, r, "Insufficient permissions", http.StatusForbidden, authCtx)
					return
				}
			}
			
			// Threat detection
			if am.config.EnableThreatDetection {
				authCtx.ThreatScore = am.calculateThreatScore(r, authCtx)
				if authCtx.ThreatScore >= 0.8 {
					am.handleAuthError(w, r, "High threat score detected", http.StatusForbidden, authCtx)
					return
				}
			}
			
			// Audit logging
			if am.config.EnableAuditLogging && am.auditLogger != nil {
				am.logAuthEvent("request_authenticated", authCtx, r)
			}
			
			// Add auth context to request context
			ctx = context.WithValue(ctx, "auth_context", authCtx)
			
			span.SetAttributes(
				attribute.String("auth.user_id", authCtx.UserID),
				attribute.String("auth.role", authCtx.Role),
				attribute.Bool("auth.authenticated", authCtx.IsAuthenticated),
				attribute.Float64("auth.threat_score", authCtx.ThreatScore),
			)
			
			// Continue to next handler
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractToken extracts authentication token from request
func (am *AuthMiddleware) extractToken(r *http.Request) string {
	// Try Authorization header first
	authHeader := r.Header.Get(am.config.TokenHeader)
	if authHeader != "" {
		if strings.HasPrefix(authHeader, am.config.TokenPrefix+" ") {
			return strings.TrimPrefix(authHeader, am.config.TokenPrefix+" ")
		}
	}
	
	// Try cookie
	if am.config.CookieName != "" {
		if cookie, err := r.Cookie(am.config.CookieName); err == nil {
			return cookie.Value
		}
	}
	
	// Try query parameter (less secure, for specific use cases)
	return r.URL.Query().Get("token")
}

// isAnonymousAllowed checks if path allows anonymous access
func (am *AuthMiddleware) isAnonymousAllowed(path string) bool {
	for _, allowedPath := range am.config.AllowAnonymous {
		if strings.HasPrefix(path, allowedPath) {
			return true
		}
	}
	return false
}

// requiresMFA checks if path requires MFA
func (am *AuthMiddleware) requiresMFA(path string) bool {
	for _, mfaPath := range am.config.RequireMFA {
		if strings.HasPrefix(path, mfaPath) {
			return true
		}
	}
	return false
}

// checkPermissions checks if user has required permissions
func (am *AuthMiddleware) checkPermissions(r *http.Request, authCtx *AuthContext) bool {
	// Extract required permission from path and method
	permission := fmt.Sprintf("%s:%s", strings.ToLower(r.Method), r.URL.Path)
	
	// Check if user has permission
	for _, userPerm := range authCtx.Permissions {
		if userPerm == "*" || userPerm == permission {
			return true
		}
	}
	
	// Check role-based permissions
	if am.rbacManager != nil {
		return am.rbacManager.HasPermission(authCtx.Role, permission)
	}
	
	return false
}

// calculateThreatScore calculates threat score for request
func (am *AuthMiddleware) calculateThreatScore(r *http.Request, authCtx *AuthContext) float64 {
	score := 0.0
	
	// Time-based analysis
	hour := time.Now().Hour()
	if hour >= 2 && hour <= 6 {
		score += 0.2
	}
	
	// Request pattern analysis
	if strings.Contains(r.URL.Path, "admin") && authCtx.Role != "admin" {
		score += 0.3
	}
	
	// User agent analysis
	if len(authCtx.UserAgent) < 10 {
		score += 0.4
	}
	
	return score
}

// addSecurityHeaders adds security headers to response
func (am *AuthMiddleware) addSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	
	if am.config.CSPPolicy != "" {
		w.Header().Set("Content-Security-Policy", am.config.CSPPolicy)
	}
	
	if am.config.HSTSMaxAge > 0 {
		w.Header().Set("Strict-Transport-Security", fmt.Sprintf("max-age=%d; includeSubDomains", am.config.HSTSMaxAge))
	}
}

// handleCORS handles CORS headers
func (am *AuthMiddleware) handleCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	
	// Check if origin is allowed
	allowed := false
	for _, allowedOrigin := range am.config.AllowedOrigins {
		if allowedOrigin == "*" || allowedOrigin == origin {
			allowed = true
			break
		}
	}
	
	if allowed {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(am.config.AllowedMethods, ", "))
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(am.config.AllowedHeaders, ", "))
		
		if am.config.AllowCredentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
	}
}

// handleAuthError handles authentication/authorization errors
func (am *AuthMiddleware) handleAuthError(w http.ResponseWriter, r *http.Request, message string, statusCode int, authCtx *AuthContext) {
	// Log security event
	if am.auditLogger != nil {
		am.logAuthEvent("auth_error", authCtx, r)
	}
	
	// Record security event
	if am.securityMonitor != nil {
		event := &SecurityEvent{
			ID:          generateEventID(),
			Type:        "auth_error",
			UserID:      authCtx.UserID,
			IPAddress:   authCtx.IPAddress,
			UserAgent:   authCtx.UserAgent,
			Timestamp:   time.Now(),
			Severity:    "warning",
			Description: message,
			ThreatScore: authCtx.ThreatScore,
			Metadata: map[string]interface{}{
				"status_code": statusCode,
				"path":        r.URL.Path,
				"method":      r.Method,
			},
		}
		am.securityMonitor.RecordEvent(event)
	}
	
	// Return error response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	errorResponse := map[string]interface{}{
		"error":   message,
		"code":    statusCode,
		"path":    r.URL.Path,
		"method":  r.Method,
		"timestamp": time.Now().Format(time.RFC3339),
	}
	
	json.NewEncoder(w).Encode(errorResponse)
}

// logAuthEvent logs an authentication event
func (am *AuthMiddleware) logAuthEvent(eventType string, authCtx *AuthContext, r *http.Request) {
	event := &SecurityEvent{
		ID:          generateEventID(),
		Type:        eventType,
		UserID:      authCtx.UserID,
		IPAddress:   authCtx.IPAddress,
		UserAgent:   authCtx.UserAgent,
		Timestamp:   time.Now(),
		Severity:    "info",
		Description: fmt.Sprintf("Authentication event: %s", eventType),
		ThreatScore: authCtx.ThreatScore,
		Metadata: map[string]interface{}{
			"path":   r.URL.Path,
			"method": r.Method,
		},
	}
	
	am.auditLogger.LogSecurityEvent(event)
}

// Helper functions

// getClientIP extracts client IP address from request
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

// getRequestID extracts or generates request ID
func getRequestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-ID"); id != "" {
		return id
	}
	return generateEventID()
}

// generateMiddlewareID generates a unique middleware ID
func generateMiddlewareID() string {
	return fmt.Sprintf("auth-middleware-%s", generateEventID()[:8])
}

// generateEventID generates a unique event ID
func generateEventID() string {
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), strings.Replace(uuid.New().String(), "-", "", -1)[:8])
}

// DefaultAuthMiddlewareConfig returns default middleware configuration
func DefaultAuthMiddlewareConfig() *AuthMiddlewareConfig {
	return &AuthMiddlewareConfig{
		RequireAuthentication: true,
		AllowAnonymous:        []string{"/health", "/metrics", "/login", "/register"},
		RequireMFA:            []string{"/admin", "/api/admin"},
		EnableRBAC:            true,
		EnablePermissionCheck: true,
		DefaultPermissions:    []string{"read:profile"},
		EnableRateLimiting:    true,
		EnableIPRestrictions:  false,
		EnableDeviceTracking:  true,
		EnableThreatDetection: true,
		TokenHeader:           "Authorization",
		TokenPrefix:           "Bearer",
		CookieName:            "auth_token",
		EnableCORS:            true,
		AllowedOrigins:        []string{"*"},
		AllowedMethods:        []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:        []string{"Content-Type", "Authorization", "X-Requested-With"},
		AllowCredentials:      true,
		EnableSecurityHeaders: true,
		CSPPolicy:             "default-src 'self'",
		HSTSMaxAge:            31536000, // 1 year
		EnableAuditLogging:    true,
		EnableMetrics:         true,
	}
}
