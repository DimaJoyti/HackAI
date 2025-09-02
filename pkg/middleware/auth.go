package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/auth"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// AuthMiddleware provides authentication and authorization middleware
type AuthMiddleware struct {
	authService auth.AuthService
	logger      *logger.Logger
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(authService auth.AuthService, log *logger.Logger) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
		logger:      log,
	}
}

// Authentication middleware that validates JWT tokens
func (am *AuthMiddleware) Authentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			am.writeErrorResponse(w, http.StatusUnauthorized, "Authorization header required")
			return
		}

		token, err := auth.ExtractTokenFromHeader(authHeader)
		if err != nil {
			am.writeErrorResponse(w, http.StatusUnauthorized, "Invalid authorization header format")
			return
		}

		// Validate token
		claims, err := am.authService.ValidateToken(token)
		if err != nil {
			am.logger.WithError(err).Debug("Token validation failed")
			am.writeErrorResponse(w, http.StatusUnauthorized, "Invalid or expired token")
			return
		}

		// Check if token is revoked
		if revoked, err := am.authService.IsTokenRevoked(token); err != nil {
			am.logger.WithError(err).Error("Failed to check token revocation status")
			am.writeErrorResponse(w, http.StatusInternalServerError, "Authentication service error")
			return
		} else if revoked {
			am.writeErrorResponse(w, http.StatusUnauthorized, "Token has been revoked")
			return
		}

		// Add user information to request context
		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
		ctx = context.WithValue(ctx, "username", claims.Username)
		ctx = context.WithValue(ctx, "email", claims.Email)
		ctx = context.WithValue(ctx, "role", claims.Role)
		ctx = context.WithValue(ctx, "session_id", claims.SessionID)
		ctx = context.WithValue(ctx, "claims", claims)

		// Continue to next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole middleware that requires a specific role
func (am *AuthMiddleware) RequireRole(role domain.UserRole) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value("claims").(*auth.Claims)
			if !ok {
				am.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
				return
			}

			if !claims.CanAccess(role) {
				am.logger.WithFields(map[string]interface{}{
					"user_id":       claims.UserID,
					"user_role":     claims.Role,
					"required_role": role,
					"path":          r.URL.Path,
				}).Warn("Access denied: insufficient role")
				am.writeErrorResponse(w, http.StatusForbidden, "Insufficient permissions")
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
			userID, ok := r.Context().Value("user_id").(uuid.UUID)
			if !ok {
				am.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
				return
			}

			// Check permission (this would typically use a permission service)
			// For now, we'll implement basic role-based checks
			claims, ok := r.Context().Value("claims").(*auth.Claims)
			if !ok {
				am.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
				return
			}

			// Basic permission check based on role and resource
			if !am.hasPermission(claims, resource, action) {
				am.logger.WithFields(map[string]interface{}{
					"user_id":  userID,
					"resource": resource,
					"action":   action,
					"path":     r.URL.Path,
				}).Warn("Access denied: insufficient permissions")
				am.writeErrorResponse(w, http.StatusForbidden, "Insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin middleware that requires admin role
func (am *AuthMiddleware) RequireAdmin(next http.Handler) http.Handler {
	return am.RequireRole(domain.UserRoleAdmin)(next)
}

// RequireModerator middleware that requires moderator or admin role
func (am *AuthMiddleware) RequireModerator(next http.Handler) http.Handler {
	return am.RequireRole(domain.UserRoleModerator)(next)
}

// OptionalAuth middleware that optionally validates authentication
func (am *AuthMiddleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// No authentication provided, continue without user context
			next.ServeHTTP(w, r)
			return
		}

		token, err := auth.ExtractTokenFromHeader(authHeader)
		if err != nil {
			// Invalid header format, continue without user context
			next.ServeHTTP(w, r)
			return
		}

		// Validate token
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

		// Add user information to request context
		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
		ctx = context.WithValue(ctx, "username", claims.Username)
		ctx = context.WithValue(ctx, "email", claims.Email)
		ctx = context.WithValue(ctx, "role", claims.Role)
		ctx = context.WithValue(ctx, "session_id", claims.SessionID)
		ctx = context.WithValue(ctx, "claims", claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// SessionTimeout middleware that checks session timeout
func (am *AuthMiddleware) SessionTimeout(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value("claims").(*auth.Claims)
			if !ok {
				am.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
				return
			}

			// Check if session has timed out
			if time.Since(claims.IssuedAt.Time) > timeout {
				am.logger.WithFields(map[string]interface{}{
					"user_id":   claims.UserID,
					"issued_at": claims.IssuedAt.Time,
					"timeout":   timeout,
				}).Warn("Session timeout")
				am.writeErrorResponse(w, http.StatusUnauthorized, "Session has timed out")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// IPWhitelist middleware that restricts access to specific IP addresses
func (am *AuthMiddleware) IPWhitelist(allowedIPs []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := getClientIP(r)

			if !am.isIPAllowed(clientIP, allowedIPs) {
				am.logger.WithFields(map[string]interface{}{
					"client_ip":   clientIP,
					"allowed_ips": allowedIPs,
					"path":        r.URL.Path,
				}).Warn("Access denied: IP not in whitelist")
				am.writeErrorResponse(w, http.StatusForbidden, "Access denied from this IP address")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// AuditLog middleware that logs all authenticated requests
func (am *AuthMiddleware) AuditLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response writer wrapper to capture status code
		wrapper := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Process request
		next.ServeHTTP(wrapper, r)

		// Log the request
		duration := time.Since(start)

		userID, _ := r.Context().Value("user_id").(uuid.UUID)
		username, _ := r.Context().Value("username").(string)

		am.logger.WithFields(map[string]interface{}{
			"user_id":     userID,
			"username":    username,
			"method":      r.Method,
			"path":        r.URL.Path,
			"status_code": wrapper.statusCode,
			"duration_ms": duration.Milliseconds(),
			"ip_address":  getClientIP(r),
			"user_agent":  r.UserAgent(),
		}).Info("API request")
	})
}

// hasPermission checks if a user has permission for a resource and action
func (am *AuthMiddleware) hasPermission(claims *auth.Claims, resource, action string) bool {
	// Basic role-based permission system
	// In a real implementation, this would query a permission service or database

	switch claims.Role {
	case domain.UserRoleAdmin:
		return true // Admins have all permissions
	case domain.UserRoleModerator:
		// Moderators have most permissions except user management
		if resource == "users" && (action == "create" || action == "delete") {
			return false
		}
		return true
	case domain.UserRoleUser:
		// Regular users have limited permissions
		switch resource {
		case "scans":
			return action == "create" || action == "read"
		case "reports":
			return action == "read"
		case "profile":
			return true
		default:
			return false
		}
	case domain.UserRoleGuest:
		// Guests have very limited permissions
		return resource == "public" && action == "read"
	default:
		return false
	}
}

// isIPAllowed checks if an IP address is in the allowed list
func (am *AuthMiddleware) isIPAllowed(clientIP string, allowedIPs []string) bool {
	if len(allowedIPs) == 0 {
		return true // No restrictions if list is empty
	}

	for _, allowedIP := range allowedIPs {
		if clientIP == allowedIP {
			return true
		}
		// Could add CIDR range support here
	}
	return false
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	if ip := strings.Split(r.RemoteAddr, ":"); len(ip) > 0 {
		return ip[0]
	}

	return r.RemoteAddr
}

// writeErrorResponse writes a JSON error response
func (am *AuthMiddleware) writeErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := fmt.Sprintf(`{"error": "%s", "status": %d}`, message, statusCode)
	w.Write([]byte(response))
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

// AuthContext provides helper functions to extract auth info from context
type AuthContext struct{}

// GetUserID extracts user ID from request context
func (AuthContext) GetUserID(ctx context.Context) (uuid.UUID, bool) {
	userID, ok := ctx.Value("user_id").(uuid.UUID)
	return userID, ok
}

// GetUsername extracts username from request context
func (AuthContext) GetUsername(ctx context.Context) (string, bool) {
	username, ok := ctx.Value("username").(string)
	return username, ok
}

// GetUserRole extracts user role from request context
func (AuthContext) GetUserRole(ctx context.Context) (domain.UserRole, bool) {
	role, ok := ctx.Value("role").(domain.UserRole)
	return role, ok
}

// GetClaims extracts JWT claims from request context
func (AuthContext) GetClaims(ctx context.Context) (*auth.Claims, bool) {
	claims, ok := ctx.Value("claims").(*auth.Claims)
	return claims, ok
}

// IsAuthenticated checks if the request is authenticated
func (AuthContext) IsAuthenticated(ctx context.Context) bool {
	_, ok := ctx.Value("user_id").(uuid.UUID)
	return ok
}

// HasRole checks if the authenticated user has the specified role
func (ac AuthContext) HasRole(ctx context.Context, role domain.UserRole) bool {
	claims, ok := ac.GetClaims(ctx)
	if !ok {
		return false
	}
	return claims.CanAccess(role)
}

// IsAdmin checks if the authenticated user is an admin
func (ac AuthContext) IsAdmin(ctx context.Context) bool {
	return ac.HasRole(ctx, domain.UserRoleAdmin)
}

// IsModerator checks if the authenticated user is a moderator or admin
func (ac AuthContext) IsModerator(ctx context.Context) bool {
	return ac.HasRole(ctx, domain.UserRoleModerator)
}
