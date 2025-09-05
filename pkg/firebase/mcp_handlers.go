package firebase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// MCPHandlers provides HTTP handlers for Firebase MCP operations
type MCPHandlers struct {
	mcpService *MCPService
	logger     *logger.Logger
}

// NewMCPHandlers creates new Firebase MCP handlers
func NewMCPHandlers(mcpService *MCPService, logger *logger.Logger) *MCPHandlers {
	return &MCPHandlers{
		mcpService: mcpService,
		logger:     logger,
	}
}

// GoogleAuthHandler handles Google authentication requests
func (h *MCPHandlers) GoogleAuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse request body
	var req GoogleAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WithError(err).Error("Failed to parse Google auth request")
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if req.IDToken == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "ID token is required")
		return
	}

	// Add request context
	ctx := context.WithValue(r.Context(), "ip", getClientIP(r))
	ctx = context.WithValue(ctx, "user_agent", r.UserAgent())

	// Authenticate with Google
	response, err := h.mcpService.AuthenticateWithGoogle(ctx, &req)
	if err != nil {
		h.logger.WithError(err).Error("Google authentication failed")
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authentication failed")
		return
	}

	// Write successful response
	h.writeJSONResponse(w, http.StatusOK, response)
}

// RefreshTokenHandler handles token refresh requests
func (h *MCPHandlers) RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse request body
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.RefreshToken == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Refresh token is required")
		return
	}

	// Refresh token
	tokens, err := h.mcpService.RefreshGoogleToken(r.Context(), req.RefreshToken)
	if err != nil {
		h.logger.WithError(err).Error("Token refresh failed")
		h.writeErrorResponse(w, http.StatusUnauthorized, "Token refresh failed")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, tokens)
}

// ValidateTokenHandler handles token validation requests
func (h *MCPHandlers) ValidateTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse request body
	var req TokenValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.IDToken == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "ID token is required")
		return
	}

	// Validate token
	response, err := h.mcpService.ValidateGoogleToken(r.Context(), req.IDToken)
	if err != nil {
		h.logger.WithError(err).Error("Token validation failed")
		h.writeErrorResponse(w, http.StatusUnauthorized, "Token validation failed")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GetUserProfileHandler handles user profile requests
func (h *MCPHandlers) GetUserProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get access token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authorization header required")
		return
	}

	accessToken := strings.TrimPrefix(authHeader, "Bearer ")
	if accessToken == authHeader {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Invalid authorization header format")
		return
	}

	// Get user profile
	profile, err := h.mcpService.GetGoogleUserProfile(r.Context(), accessToken)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get user profile")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get user profile")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, profile)
}

// RevokeTokenHandler handles token revocation requests
func (h *MCPHandlers) RevokeTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse request body
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Token == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Token is required")
		return
	}

	// Revoke token
	if err := h.mcpService.RevokeGoogleToken(r.Context(), req.Token); err != nil {
		h.logger.WithError(err).Error("Token revocation failed")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Token revocation failed")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"status": "success"})
}

// ListUsersHandler handles user listing requests
func (h *MCPHandlers) ListUsersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	limit := 10 // default
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	pageToken := r.URL.Query().Get("page_token")

	// Create MCP client for user operations
	mcpClient := NewMCPClient(h.mcpService.config, h.logger)

	// List users
	users, nextPageToken, err := mcpClient.ListUsers(r.Context(), limit, pageToken)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list users")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list users")
		return
	}

	response := map[string]interface{}{
		"users":           users,
		"next_page_token": nextPageToken,
		"total":           len(users),
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// SearchUsersHandler handles user search requests
func (h *MCPHandlers) SearchUsersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse query parameters
	searchTerm := r.URL.Query().Get("q")
	if searchTerm == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Search term is required")
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 10 // default
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	// Create MCP client for user operations
	mcpClient := NewMCPClient(h.mcpService.config, h.logger)

	// Search users
	users, err := mcpClient.SearchUsers(r.Context(), searchTerm, limit)
	if err != nil {
		h.logger.WithError(err).Error("Failed to search users")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to search users")
		return
	}

	response := map[string]interface{}{
		"users":       users,
		"search_term": searchTerm,
		"total":       len(users),
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GetUserSessionsHandler handles user session listing requests
func (h *MCPHandlers) GetUserSessionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user ID from URL path
	userID := strings.TrimPrefix(r.URL.Path, "/api/firebase/users/")
	userID = strings.TrimSuffix(userID, "/sessions")

	if userID == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "User ID is required")
		return
	}

	// Create MCP client for session operations
	mcpClient := NewMCPClient(h.mcpService.config, h.logger)

	// Get user sessions
	sessions, err := mcpClient.GetUserSessions(r.Context(), userID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get user sessions")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get user sessions")
		return
	}

	response := map[string]interface{}{
		"user_id":  userID,
		"sessions": sessions,
		"total":    len(sessions),
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// HealthCheckHandler handles health check requests
func (h *MCPHandlers) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	response := &HealthCheckResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0",
		Firebase: struct {
			Connected bool   `json:"connected"`
			ProjectID string `json:"project_id"`
		}{
			Connected: true,
			ProjectID: h.mcpService.config.Firebase.ProjectID,
		},
		Database: struct {
			Connected bool `json:"connected"`
		}{
			Connected: true,
		},
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// Helper methods

// writeJSONResponse writes a JSON response
func (h *MCPHandlers) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.WithError(err).Error("Failed to encode JSON response")
	}
}

// writeErrorResponse writes an error response
func (h *MCPHandlers) writeErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	errorResponse := &ErrorResponse{
		Error:   message,
		Code:    fmt.Sprintf("HTTP_%d", statusCode),
		Message: message,
	}

	h.writeJSONResponse(w, statusCode, errorResponse)
}

