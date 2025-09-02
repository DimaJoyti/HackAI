package firebase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"firebase.google.com/go/v4/auth"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// ContextKey represents a context key type
type ContextKey string

const (
	// UserContextKey is the context key for the authenticated user
	UserContextKey ContextKey = "firebase_user"
	// TokenContextKey is the context key for the Firebase token
	TokenContextKey ContextKey = "firebase_token"
	// ClaimsContextKey is the context key for custom claims
	ClaimsContextKey ContextKey = "firebase_claims"
)

// Middleware provides Firebase authentication middleware
type Middleware struct {
	service *Service
	logger  *logger.Logger
}

// NewMiddleware creates a new Firebase middleware
func NewMiddleware(service *Service, logger *logger.Logger) *Middleware {
	return &Middleware{
		service: service,
		logger:  logger,
	}
}

// AuthRequired middleware that requires Firebase authentication
func (m *Middleware) AuthRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := m.extractToken(r)
		if err != nil {
			m.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", err)
			return
		}

		// Verify the token
		firebaseToken, err := m.service.VerifyIDToken(r.Context(), token)
		if err != nil {
			m.writeErrorResponse(w, http.StatusUnauthorized, "Invalid token", err)
			return
		}

		// Get user information
		user, err := m.service.GetUser(r.Context(), firebaseToken.UID)
		if err != nil {
			m.writeErrorResponse(w, http.StatusUnauthorized, "User not found", err)
			return
		}

		// Check if user is disabled
		if user.Disabled {
			m.writeErrorResponse(w, http.StatusForbidden, "Account disabled", nil)
			return
		}

		// Add user and token to context
		ctx := context.WithValue(r.Context(), UserContextKey, user)
		ctx = context.WithValue(ctx, TokenContextKey, firebaseToken)
		ctx = context.WithValue(ctx, ClaimsContextKey, firebaseToken.Claims)

		// Log authentication
		m.logger.Info("User authenticated", map[string]interface{}{
			"uid":        firebaseToken.UID,
			"email":      user.Email,
			"ip_address": getClientIP(r),
			"user_agent": r.UserAgent(),
		})

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuthOptional middleware that optionally authenticates users
func (m *Middleware) AuthOptional(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := m.extractToken(r)
		if err != nil {
			// No token provided, continue without authentication
			next.ServeHTTP(w, r)
			return
		}

		// Verify the token
		firebaseToken, err := m.service.VerifyIDToken(r.Context(), token)
		if err != nil {
			// Invalid token, continue without authentication
			next.ServeHTTP(w, r)
			return
		}

		// Get user information
		user, err := m.service.GetUser(r.Context(), firebaseToken.UID)
		if err != nil {
			// User not found, continue without authentication
			next.ServeHTTP(w, r)
			return
		}

		// Check if user is disabled
		if user.Disabled {
			// User disabled, continue without authentication
			next.ServeHTTP(w, r)
			return
		}

		// Add user and token to context
		ctx := context.WithValue(r.Context(), UserContextKey, user)
		ctx = context.WithValue(ctx, TokenContextKey, firebaseToken)
		ctx = context.WithValue(ctx, ClaimsContextKey, firebaseToken.Claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole middleware that requires a specific role
func (m *Middleware) RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				m.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", nil)
				return
			}

			// Check if user has any of the required roles
			hasRole := false
			for _, role := range roles {
				if user.Role == role {
					hasRole = true
					break
				}
			}

			if !hasRole {
				m.writeErrorResponse(w, http.StatusForbidden, "Insufficient permissions", nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireClaim middleware that requires a specific custom claim
func (m *Middleware) RequireClaim(claimKey string, claimValues ...interface{}) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaimsFromContext(r.Context())
			if claims == nil {
				m.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", nil)
				return
			}

			claimValue, exists := claims[claimKey]
			if !exists {
				m.writeErrorResponse(w, http.StatusForbidden, "Required claim not found", nil)
				return
			}

			// Check if claim value matches any of the required values
			hasValidClaim := false
			for _, requiredValue := range claimValues {
				if claimValue == requiredValue {
					hasValidClaim = true
					break
				}
			}

			if !hasValidClaim {
				m.writeErrorResponse(w, http.StatusForbidden, "Invalid claim value", nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitByUser middleware that applies rate limiting per user
func (m *Middleware) RateLimitByUser(maxRequests int, window time.Duration) func(http.Handler) http.Handler {
	// This is a simplified rate limiter - in production, use Redis or similar
	userRequests := make(map[string][]time.Time)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				// No user, apply IP-based rate limiting
				next.ServeHTTP(w, r)
				return
			}

			now := time.Now()
			userID := user.UID

			// Clean old requests
			if requests, exists := userRequests[userID]; exists {
				var validRequests []time.Time
				for _, reqTime := range requests {
					if now.Sub(reqTime) < window {
						validRequests = append(validRequests, reqTime)
					}
				}
				userRequests[userID] = validRequests
			}

			// Check rate limit
			if len(userRequests[userID]) >= maxRequests {
				m.writeErrorResponse(w, http.StatusTooManyRequests, "Rate limit exceeded", nil)
				return
			}

			// Add current request
			userRequests[userID] = append(userRequests[userID], now)

			next.ServeHTTP(w, r)
		})
	}
}

// extractToken extracts the Firebase ID token from the request
func (m *Middleware) extractToken(r *http.Request) (string, error) {
	// Check Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return parts[1], nil
		}
	}

	// Check query parameter
	token := r.URL.Query().Get("token")
	if token != "" {
		return token, nil
	}

	// Check cookie
	cookie, err := r.Cookie("firebase_token")
	if err == nil && cookie.Value != "" {
		return cookie.Value, nil
	}

	return "", fmt.Errorf("no token found")
}

// writeErrorResponse writes an error response
func (m *Middleware) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	errorResponse := ErrorResponse{
		Error:   message,
		Message: message,
	}

	if err != nil {
		errorResponse.Message = err.Error()
		m.logger.WithError(err).Error("Authentication error")
	}

	json.NewEncoder(w).Encode(errorResponse)
}

// getClientIP gets the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return strings.TrimSpace(xri)
	}

	// Use remote address
	ip := r.RemoteAddr
	if strings.Contains(ip, ":") {
		ip = strings.Split(ip, ":")[0]
	}

	return ip
}

// Helper functions to extract data from context

// GetUserFromContext extracts the authenticated user from context
func GetUserFromContext(ctx context.Context) *UserResponse {
	user, ok := ctx.Value(UserContextKey).(*UserResponse)
	if !ok {
		return nil
	}
	return user
}

// GetTokenFromContext extracts the Firebase token from context
func GetTokenFromContext(ctx context.Context) *auth.Token {
	token, ok := ctx.Value(TokenContextKey).(*auth.Token)
	if !ok {
		return nil
	}
	return token
}

// GetClaimsFromContext extracts the custom claims from context
func GetClaimsFromContext(ctx context.Context) map[string]interface{} {
	claims, ok := ctx.Value(ClaimsContextKey).(map[string]interface{})
	if !ok {
		return nil
	}
	return claims
}

// GetUserIDFromContext extracts the user ID from context
func GetUserIDFromContext(ctx context.Context) string {
	user := GetUserFromContext(ctx)
	if user == nil {
		return ""
	}
	return user.UID
}

// GetUserRoleFromContext extracts the user role from context
func GetUserRoleFromContext(ctx context.Context) string {
	user := GetUserFromContext(ctx)
	if user == nil {
		return ""
	}
	return user.Role
}

// IsAuthenticated checks if the request is authenticated
func IsAuthenticated(ctx context.Context) bool {
	return GetUserFromContext(ctx) != nil
}

// HasRole checks if the authenticated user has a specific role
func HasRole(ctx context.Context, role string) bool {
	user := GetUserFromContext(ctx)
	if user == nil {
		return false
	}
	return user.Role == role
}

// HasClaim checks if the authenticated user has a specific claim
func HasClaim(ctx context.Context, claimKey string, claimValue interface{}) bool {
	claims := GetClaimsFromContext(ctx)
	if claims == nil {
		return false
	}

	value, exists := claims[claimKey]
	if !exists {
		return false
	}

	return value == claimValue
}
