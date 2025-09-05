package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/auth"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// AuthHandler handles authentication HTTP requests
type AuthHandler struct {
	authService *auth.EnhancedAuthService
	logger      *logger.Logger
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(authService *auth.EnhancedAuthService, log *logger.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		logger:      log,
	}
}

// LoginRequest represents a login request
type LoginRequest struct {
	EmailOrUsername string `json:"email_or_username"`
	Password        string `json:"password"`
	TOTPCode        string `json:"totp_code,omitempty"`
	DeviceID        string `json:"device_id,omitempty"`
	RememberMe      bool   `json:"remember_me"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	User         *UserResponse `json:"user"`
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time     `json:"expires_at"`
	SessionID    uuid.UUID     `json:"session_id"`
	RequiresTOTP bool          `json:"requires_totp"`
	CSRFToken    string        `json:"csrf_token,omitempty"`
}

// UserResponse represents user information in responses
type UserResponse struct {
	ID               uuid.UUID       `json:"id"`
	Username         string          `json:"username"`
	Email            string          `json:"email"`
	FirstName        string          `json:"first_name"`
	LastName         string          `json:"last_name"`
	Role             domain.UserRole `json:"role"`
	Status           string          `json:"status"`
	TwoFactorEnabled bool            `json:"two_factor_enabled"`
	LastLoginAt      *time.Time      `json:"last_login_at"`
	CreatedAt        time.Time       `json:"created_at"`
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// EnableTOTPResponse represents the response for enabling TOTP
type EnableTOTPResponse struct {
	Secret string `json:"secret"`
	QRCode string `json:"qr_code_url"`
}

// Login handles POST /api/v1/auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate required fields
	if req.EmailOrUsername == "" || req.Password == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Email/username and password are required", nil)
		return
	}

	// Create authentication request
	authReq := &auth.AuthenticationRequest{
		EmailOrUsername: req.EmailOrUsername,
		Password:        req.Password,
		TOTPCode:        req.TOTPCode,
		IPAddress:       getClientIP(r),
		UserAgent:       r.UserAgent(),
		DeviceID:        req.DeviceID,
		RememberMe:      req.RememberMe,
	}

	// Authenticate user
	authResp, err := h.authService.Authenticate(r.Context(), authReq)
	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"email_or_username": req.EmailOrUsername,
			"ip_address":        authReq.IPAddress,
		}).Warn("Authentication failed")
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authentication failed", err)
		return
	}

	// Handle TOTP requirement
	if authResp.RequiresTOTP {
		h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"requires_totp": true,
			"message":       "Two-factor authentication code required",
		})
		return
	}

	// Convert user to response format
	userResp := &UserResponse{
		ID:               authResp.User.ID,
		Username:         authResp.User.Username,
		Email:            authResp.User.Email,
		FirstName:        authResp.User.FirstName,
		LastName:         authResp.User.LastName,
		Role:             authResp.User.Role,
		Status:           string(authResp.User.Status),
		TwoFactorEnabled: authResp.User.TwoFactorEnabled,
		LastLoginAt:      authResp.User.LastLoginAt,
		CreatedAt:        authResp.User.CreatedAt,
	}

	response := &LoginResponse{
		User:         userResp,
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
		ExpiresAt:    authResp.ExpiresAt,
		SessionID:    authResp.SessionID,
		RequiresTOTP: false,
		CSRFToken:    authResp.CSRFToken,
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// Logout handles POST /api/v1/auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Extract token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Authorization header required", nil)
		return
	}

	token, err := auth.ExtractTokenFromHeader(authHeader)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid authorization header format", err)
		return
	}

	// Logout user
	if err := h.authService.Logout(r.Context(), token, getClientIP(r), r.UserAgent()); err != nil {
		h.logger.WithError(err).Error("Logout failed")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Logout failed", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{
		"message": "Successfully logged out",
	})
}

// RefreshToken handles POST /api/v1/auth/refresh
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.RefreshToken == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Refresh token is required", nil)
		return
	}

	// Refresh token
	newAccessToken, err := h.authService.RefreshTokenByString(req.RefreshToken)
	if err != nil {
		h.logger.WithError(err).Warn("Token refresh failed")
		h.writeErrorResponse(w, http.StatusUnauthorized, "Invalid refresh token", err)
		return
	}

	response := map[string]interface{}{
		"access_token": newAccessToken,
		"token_type":   "Bearer",
		"expires_in":   3600, // 1 hour in seconds
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GetProfile handles GET /api/v1/auth/profile
func (h *AuthHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	// Get user from JWT claims in context
	claims, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Invalid authentication", nil)
		return
	}

	userResp := &UserResponse{
		ID:       claims.UserID,
		Username: claims.Username,
		Email:    claims.Email,
		Role:     claims.Role,
	}

	h.writeJSONResponse(w, http.StatusOK, userResp)
}

// ChangePassword handles POST /api/v1/auth/change-password
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.GetUserIDFromContext(r.Context())
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Current password and new password are required", nil)
		return
	}

	// Change password
	if err := h.authService.ChangePassword(r.Context(), userID, req.CurrentPassword, req.NewPassword, getClientIP(r), r.UserAgent()); err != nil {
		h.logger.WithError(err).WithField("user_id", userID).Warn("Password change failed")
		h.writeErrorResponse(w, http.StatusBadRequest, "Password change failed", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{
		"message": "Password changed successfully",
	})
}

// EnableTOTP handles POST /api/v1/auth/enable-totp
func (h *AuthHandler) EnableTOTP(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.GetUserIDFromContext(r.Context())
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	// Enable TOTP
	secret, qrURL, err := h.authService.EnableTOTP(r.Context(), userID, getClientIP(r), r.UserAgent())
	if err != nil {
		h.logger.WithError(err).WithField("user_id", userID).Error("TOTP enablement failed")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to enable two-factor authentication", err)
		return
	}

	response := &EnableTOTPResponse{
		Secret: secret,
		QRCode: qrURL,
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GetPermissions handles GET /api/v1/auth/permissions
func (h *AuthHandler) GetPermissions(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.GetUserIDFromContext(r.Context())
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	// Get user permissions
	permissions, err := h.authService.GetUserPermissions(r.Context(), userID)
	if err != nil {
		h.logger.WithError(err).WithField("user_id", userID).Error("Failed to get user permissions")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get permissions", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"permissions": permissions,
	})
}

// ValidateToken handles POST /api/v1/auth/validate
func (h *AuthHandler) ValidateToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.Token == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Token is required", nil)
		return
	}

	// Validate token
	claims, err := h.authService.ValidateToken(req.Token)
	if err != nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Invalid token", err)
		return
	}

	response := map[string]interface{}{
		"valid":      true,
		"user_id":    claims.UserID,
		"username":   claims.Username,
		"email":      claims.Email,
		"role":       claims.Role,
		"expires_at": claims.ExpiresAt.Time,
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// Helper methods

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

// writeJSONResponse writes a JSON response
func (h *AuthHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.WithError(err).Error("Failed to encode JSON response")
	}
}

// writeErrorResponse writes a JSON error response
func (h *AuthHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	response := map[string]interface{}{
		"error":  message,
		"status": statusCode,
	}

	if err != nil {
		h.logger.WithError(err).Error(message)
		response["details"] = err.Error()
	}

	h.writeJSONResponse(w, statusCode, response)
}
