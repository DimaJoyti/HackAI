package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// AuthHandlers provides HTTP handlers for authentication
type AuthHandlers struct {
	authService    *EnhancedAuthService
	sessionManager *SessionManager
	rbacManager    *RBACManager
	logger         *logger.Logger
}

// NewAuthHandlers creates new authentication handlers
func NewAuthHandlers(authService *EnhancedAuthService, sessionManager *SessionManager, rbacManager *RBACManager, logger *logger.Logger) *AuthHandlers {
	return &AuthHandlers{
		authService:    authService,
		sessionManager: sessionManager,
		rbacManager:    rbacManager,
		logger:         logger,
	}
}


// Login handles user login
func (ah *AuthHandlers) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ah.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Get client information
	clientIP := getClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	// Create authentication request
	authReq := &AuthenticationRequest{
		EmailOrUsername: req.EmailOrUsername,
		Password:        req.Password,
		TOTPCode:        req.TOTPCode,
		IPAddress:       clientIP,
		UserAgent:       userAgent,
		DeviceID:        req.DeviceID,
		RememberMe:      req.RememberMe,
	}

	// Authenticate user
	authResp, err := ah.authService.Authenticate(r.Context(), authReq)
	if err != nil {
		ah.logger.WithError(err).WithFields(logger.Fields{
			"email_or_username": req.EmailOrUsername,
			"ip_address":        clientIP,
		}).Warn("Authentication failed")
		ah.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Handle TOTP requirement
	if authResp.RequiresTOTP {
		ah.respondWithJSON(w, http.StatusOK, LoginResponse{
			Success:      false,
			Message:      "Two-factor authentication required",
			RequiresTOTP: true,
		})
		return
	}

	// Get user permissions
	permissions := ah.rbacManager.GetUserPermissions(authResp.User.ID)
	permissionStrings := make([]string, len(permissions))
	for i, perm := range permissions {
		permissionStrings[i] = fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
	}

	// Successful login response
	response := LoginResponse{
		Success:      true,
		Message:      "Login successful",
		UserResponse: ah.mapUserToResponse(authResp.User),
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
		ExpiresAt:    authResp.ExpiresAt,
		SessionID:    authResp.SessionID,
		RequiresTOTP: false,
		CSRFToken:    authResp.CSRFToken,
		Permissions:  permissionStrings,
	}

	ah.respondWithJSON(w, http.StatusOK, response)
}

// Logout handles user logout
func (ah *AuthHandlers) Logout(w http.ResponseWriter, r *http.Request) {
	// Extract token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		ah.respondWithError(w, http.StatusBadRequest, "Authorization header required")
		return
	}

	token, err := ExtractTokenFromHeader(authHeader)
	if err != nil {
		ah.respondWithError(w, http.StatusBadRequest, "Invalid authorization header format")
		return
	}

	// Get client information
	clientIP := getClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	// Logout user
	if err := ah.authService.Logout(r.Context(), token, clientIP, userAgent); err != nil {
		ah.logger.WithError(err).Warn("Logout failed")
		ah.respondWithError(w, http.StatusInternalServerError, "Logout failed")
		return
	}

	ah.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Logout successful",
	})
}

// RefreshToken handles token refresh
func (ah *AuthHandlers) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ah.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Refresh token
	newAccessToken, err := ah.authService.RefreshTokenByString(req.RefreshToken)
	if err != nil {
		ah.logger.WithError(err).Warn("Token refresh failed")
		ah.respondWithError(w, http.StatusUnauthorized, "Invalid refresh token")
		return
	}

	ah.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"access_token": newAccessToken,
		"expires_at":   time.Now().Add(24 * time.Hour), // Should match JWT config
	})
}

// GetProfile returns the current user's profile
func (ah *AuthHandlers) GetProfile(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserFromContext(r.Context())
	if !ok {
		ah.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Get user permissions
	permissions := ah.rbacManager.GetUserPermissions(claims.UserID)
	permissionStrings := make([]string, len(permissions))
	for i, perm := range permissions {
		permissionStrings[i] = fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
	}

	// Get user roles
	roles := ah.rbacManager.GetUserRoles(claims.UserID)
	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.Name
	}

	// Get user sessions
	sessions := ah.sessionManager.GetUserSessions(claims.UserID)

	response := map[string]interface{}{
		"user": map[string]interface{}{
			"id":       claims.UserID,
			"username": claims.Username,
			"email":    claims.Email,
			"role":     claims.Role,
		},
		"permissions":     permissionStrings,
		"roles":           roleNames,
		"active_sessions": len(sessions),
		"session_id":      claims.SessionID,
	}

	ah.respondWithJSON(w, http.StatusOK, response)
}

// ChangePassword handles password change
func (ah *AuthHandlers) ChangePassword(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserFromContext(r.Context())
	if !ok {
		ah.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password" validate:"required"`
		NewPassword     string `json:"new_password" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ah.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Get client information
	clientIP := getClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	// Change password
	if err := ah.authService.ChangePassword(r.Context(), claims.UserID, req.CurrentPassword, req.NewPassword, clientIP, userAgent); err != nil {
		ah.logger.WithError(err).WithFields(logger.Fields{
			"user_id": claims.UserID,
		}).Warn("Password change failed")
		ah.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	ah.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Password changed successfully",
	})
}

// EnableTOTP handles TOTP enablement
func (ah *AuthHandlers) EnableTOTP(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserFromContext(r.Context())
	if !ok {
		ah.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Get client information
	clientIP := getClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	// Enable TOTP
	secret, qrURL, err := ah.authService.EnableTOTP(r.Context(), claims.UserID, clientIP, userAgent)
	if err != nil {
		ah.logger.WithError(err).WithFields(logger.Fields{
			"user_id": claims.UserID,
		}).Warn("TOTP enablement failed")
		ah.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	ah.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Two-factor authentication enabled",
		"secret":  secret,
		"qr_url":  qrURL,
	})
}

// GetSessions returns user's active sessions
func (ah *AuthHandlers) GetSessions(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserFromContext(r.Context())
	if !ok {
		ah.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	sessions := ah.sessionManager.GetUserSessions(claims.UserID)

	ah.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"sessions": sessions,
		"count":    len(sessions),
	})
}

// RevokeSession revokes a specific session
func (ah *AuthHandlers) RevokeSession(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserFromContext(r.Context())
	if !ok {
		ah.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		ah.respondWithError(w, http.StatusBadRequest, "Session ID required")
		return
	}

	// Verify session belongs to user
	session, err := ah.sessionManager.GetSession(sessionID)
	if err != nil {
		ah.respondWithError(w, http.StatusNotFound, "Session not found")
		return
	}

	if session.UserID != claims.UserID && !claims.IsAdmin() {
		ah.respondWithError(w, http.StatusForbidden, "Access denied")
		return
	}

	// Revoke session
	if err := ah.sessionManager.InvalidateSession(sessionID); err != nil {
		ah.logger.WithError(err).Error("Failed to revoke session")
		ah.respondWithError(w, http.StatusInternalServerError, "Failed to revoke session")
		return
	}

	ah.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Session revoked successfully",
	})
}

// CheckPermissions checks user permissions
func (ah *AuthHandlers) CheckPermissions(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserFromContext(r.Context())
	if !ok {
		ah.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var req struct {
		Permissions []string `json:"permissions" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ah.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Check permissions
	results := ah.rbacManager.CheckMultiplePermissions(claims.UserID, req.Permissions)

	ah.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"results": results,
	})
}

// GetRoles returns available roles (admin only)
func (ah *AuthHandlers) GetRoles(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserFromContext(r.Context())
	if !ok {
		ah.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	if !claims.IsAdmin() {
		ah.respondWithError(w, http.StatusForbidden, "Admin access required")
		return
	}

	roles := ah.rbacManager.GetAllRoles()

	ah.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"roles": roles,
		"count": len(roles),
	})
}

// Helper methods

func (ah *AuthHandlers) mapUserToResponse(user *domain.User) *UserResponse {
	return &UserResponse{
		ID:               user.ID,
		Username:         user.Username,
		Email:            user.Email,
		Role:             user.Role,
		TwoFactorEnabled: user.TwoFactorEnabled,
		LastLoginAt:      user.LastLoginAt,
		CreatedAt:        user.CreatedAt,
	}
}

func (ah *AuthHandlers) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func (ah *AuthHandlers) respondWithError(w http.ResponseWriter, statusCode int, message string) {
	ah.respondWithJSON(w, statusCode, map[string]interface{}{
		"success":   false,
		"error":     message,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// RegisterRoutes registers authentication routes
func (ah *AuthHandlers) RegisterRoutes(mux *http.ServeMux, authMiddleware *AuthMiddleware) {
	// Public routes
	mux.HandleFunc("POST /auth/login", ah.Login)
	mux.HandleFunc("POST /auth/refresh", ah.RefreshToken)

	// Protected routes
	mux.Handle("POST /auth/logout", authMiddleware.RequireAuth(http.HandlerFunc(ah.Logout)))
	mux.Handle("GET /auth/profile", authMiddleware.RequireAuth(http.HandlerFunc(ah.GetProfile)))
	mux.Handle("POST /auth/change-password", authMiddleware.RequireAuth(http.HandlerFunc(ah.ChangePassword)))
	mux.Handle("POST /auth/enable-totp", authMiddleware.RequireAuth(http.HandlerFunc(ah.EnableTOTP)))
	mux.Handle("GET /auth/sessions", authMiddleware.RequireAuth(http.HandlerFunc(ah.GetSessions)))
	mux.Handle("DELETE /auth/sessions", authMiddleware.RequireAuth(http.HandlerFunc(ah.RevokeSession)))
	mux.Handle("POST /auth/check-permissions", authMiddleware.RequireAuth(http.HandlerFunc(ah.CheckPermissions)))

	// Admin routes
	mux.Handle("GET /auth/roles", authMiddleware.RequireAuth(authMiddleware.RequireRole(domain.UserRoleAdmin)(http.HandlerFunc(ah.GetRoles))))
}
