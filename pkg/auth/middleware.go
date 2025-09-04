package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// ContextKey represents a context key type
type ContextKey string

const (
	// UserContextKey is the context key for user information
	UserContextKey ContextKey = "user"
	// ClaimsContextKey is the context key for JWT claims
	ClaimsContextKey ContextKey = "claims"
	// SessionContextKey is the context key for session information
	SessionContextKey ContextKey = "session"
	// PermissionsContextKey is the context key for user permissions
	PermissionsContextKey ContextKey = "permissions"
)

// AuthMiddleware provides authentication middleware
type AuthMiddleware struct {
	authService AuthService
	rbacManager *RBACManager
	logger      *logger.Logger
	config      *SecurityConfig
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(authService AuthService, rbacManager *RBACManager, logger *logger.Logger, config *SecurityConfig) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
		rbacManager: rbacManager,
		logger:      logger,
		config:      config,
	}
}

// RequireAuth middleware that requires authentication
func (am *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			am.respondWithError(w, http.StatusUnauthorized, "Authorization header required")
			return
		}

		token, err := ExtractTokenFromHeader(authHeader)
		if err != nil {
			am.respondWithError(w, http.StatusUnauthorized, "Invalid authorization header format")
			return
		}

		// Validate token
		claims, err := am.authService.ValidateToken(token)
		if err != nil {
			am.logger.WithError(err).Warn("Invalid token provided")
			am.respondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
			return
		}

		// Check if token is revoked
		if revoked, err := am.authService.IsTokenRevoked(token); err != nil {
			am.logger.WithError(err).Error("Failed to check token revocation status")
			am.respondWithError(w, http.StatusInternalServerError, "Authentication service error")
			return
		} else if revoked {
			am.respondWithError(w, http.StatusUnauthorized, "Token has been revoked")
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)

		// Log authentication success
		am.logger.WithFields(logger.Fields{
			"user_id":    claims.UserID,
			"username":   claims.Username,
			"session_id": claims.SessionID,
			"endpoint":   r.URL.Path,
			"method":     r.Method,
		}).Debug("User authenticated successfully")

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole middleware that requires a specific role
func (am *AuthMiddleware) RequireRole(role domain.UserRole) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(ClaimsContextKey).(*Claims)
			if !ok {
				am.respondWithError(w, http.StatusUnauthorized, "Authentication required")
				return
			}

			if !claims.CanAccess(role) {
				am.logger.WithFields(logger.Fields{
					"user_id":       claims.UserID,
					"user_role":     claims.Role,
					"required_role": role,
					"endpoint":      r.URL.Path,
				}).Warn("Access denied: insufficient role")
				am.respondWithError(w, http.StatusForbidden, "Insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission middleware that requires a specific permission
func (am *AuthMiddleware) RequirePermission(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(ClaimsContextKey).(*Claims)
			if !ok {
				am.respondWithError(w, http.StatusUnauthorized, "Authentication required")
				return
			}

			// Check permission
			hasPermission := am.rbacManager.HasPermission(claims.UserID, resource, action)

			if !hasPermission {
				am.logger.WithFields(logger.Fields{
					"user_id":  claims.UserID,
					"resource": resource,
					"action":   action,
					"endpoint": r.URL.Path,
				}).Warn("Access denied: missing permission")
				am.respondWithError(w, http.StatusForbidden, "Permission denied")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// OptionalAuth middleware that optionally authenticates users
func (am *AuthMiddleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// No authentication provided, continue without user context
			next.ServeHTTP(w, r)
			return
		}

		token, err := ExtractTokenFromHeader(authHeader)
		if err != nil {
			// Invalid header format, continue without user context
			next.ServeHTTP(w, r)
			return
		}

		// Try to validate token
		claims, err := am.authService.ValidateToken(token)
		if err != nil {
			// Invalid token, continue without user context
			next.ServeHTTP(w, r)
			return
		}

		// Check if token is revoked
		if revoked, err := am.authService.IsTokenRevoked(token); err != nil || revoked {
			// Token revoked or error checking, continue without user context
			next.ServeHTTP(w, r)
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RateLimitMiddleware provides rate limiting
func (am *AuthMiddleware) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)

		// Create a simple rate limiter (in production, use Redis or similar)
		// For now, we'll just log the attempt
		am.logger.WithFields(logger.Fields{
			"client_ip": clientIP,
			"endpoint":  r.URL.Path,
			"method":    r.Method,
		}).Debug("Rate limit check")

		next.ServeHTTP(w, r)
	})
}

// CSRFMiddleware provides CSRF protection
func (am *AuthMiddleware) CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !am.config.EnableCSRF {
			next.ServeHTTP(w, r)
			return
		}

		// Skip CSRF check for GET, HEAD, OPTIONS requests
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		// Get CSRF token from header or form
		csrfToken := r.Header.Get("X-CSRF-Token")
		if csrfToken == "" {
			csrfToken = r.FormValue("csrf_token")
		}

		if csrfToken == "" {
			am.respondWithError(w, http.StatusForbidden, "CSRF token required")
			return
		}

		// In a real implementation, you'd validate the CSRF token
		// against a stored value (session, cookie, etc.)
		// For now, we'll just check if it's not empty
		if len(csrfToken) < 16 {
			am.respondWithError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// SecurityHeadersMiddleware adds security headers
func (am *AuthMiddleware) SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware logs authentication events
func (am *AuthMiddleware) LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		clientIP := getClientIP(r)
		userAgent := r.Header.Get("User-Agent")

		// Create a response writer wrapper to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)

		// Get user info from context if available
		var userID string
		var username string
		if claims, ok := r.Context().Value(ClaimsContextKey).(*Claims); ok {
			userID = claims.UserID.String()
			username = claims.Username
		}

		am.logger.WithFields(logger.Fields{
			"method":      r.Method,
			"path":        r.URL.Path,
			"status_code": wrapped.statusCode,
			"duration_ms": duration.Milliseconds(),
			"client_ip":   clientIP,
			"user_agent":  userAgent,
			"user_id":     userID,
			"username":    username,
		}).Info("HTTP request processed")
	})
}

// respondWithError sends an error response
func (am *AuthMiddleware) respondWithError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := map[string]interface{}{
		"error":     message,
		"status":    statusCode,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(response)
}

// getClientIP extracts the real client IP address
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
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

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// GetUserFromContext extracts user claims from request context
func GetUserFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(ClaimsContextKey).(*Claims)
	return claims, ok
}

// GetUserIDFromContext extracts user ID from request context
func GetUserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	if claims, ok := GetUserFromContext(ctx); ok {
		return claims.UserID, true
	}
	return uuid.Nil, false
}

// RequireUserID middleware that ensures the user can only access their own resources
func (am *AuthMiddleware) RequireUserID(userIDParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(ClaimsContextKey).(*Claims)
			if !ok {
				am.respondWithError(w, http.StatusUnauthorized, "Authentication required")
				return
			}

			// Extract user ID from URL parameter
			requestedUserID := r.URL.Query().Get(userIDParam)
			if requestedUserID == "" {
				// Try to get from path parameters (this would need a router that supports it)
				requestedUserID = r.Header.Get("X-User-ID") // Fallback
			}

			if requestedUserID == "" {
				am.respondWithError(w, http.StatusBadRequest, "User ID parameter required")
				return
			}

			requestedUUID, err := uuid.Parse(requestedUserID)
			if err != nil {
				am.respondWithError(w, http.StatusBadRequest, "Invalid user ID format")
				return
			}

			// Check if user is accessing their own resource or is admin
			if claims.UserID != requestedUUID && !claims.IsAdmin() {
				am.logger.WithFields(logger.Fields{
					"user_id":           claims.UserID,
					"requested_user_id": requestedUUID,
					"endpoint":          r.URL.Path,
				}).Warn("Access denied: user trying to access another user's resource")
				am.respondWithError(w, http.StatusForbidden, "Access denied")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
