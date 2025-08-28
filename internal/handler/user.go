package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/middleware"
)

// UserHandler handles user management HTTP requests
type UserHandler struct {
	userUseCase domain.UserUseCase
	authContext middleware.AuthContext
	logger      *logger.Logger
}

// NewUserHandler creates a new user handler
func NewUserHandler(userUseCase domain.UserUseCase, log *logger.Logger) *UserHandler {
	return &UserHandler{
		userUseCase: userUseCase,
		authContext: middleware.AuthContext{},
		logger:      log,
	}
}

// UpdateProfileRequest represents the request body for updating user profile
type UpdateProfileRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Bio       string `json:"bio"`
	Company   string `json:"company"`
	Location  string `json:"location"`
	Website   string `json:"website"`
	Avatar    string `json:"avatar"`
}

// UpdateRoleRequest represents the request body for updating user role
type UpdateRoleRequest struct {
	Role string `json:"role"`
}

// UpdateStatusRequest represents the request body for updating user status
type UpdateStatusRequest struct {
	Status string `json:"status"`
}

// UserListResponse represents the response for listing users
type UserListResponse struct {
	Users  []*UserResponse `json:"users"`
	Total  int             `json:"total"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
}

// UpdateProfile handles PUT /api/v1/auth/profile
func (h *UserHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.authContext.GetUserID(r.Context())
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	var req UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Convert request to updates map
	updates := make(map[string]interface{})
	if req.FirstName != "" {
		updates["first_name"] = req.FirstName
	}
	if req.LastName != "" {
		updates["last_name"] = req.LastName
	}
	if req.Bio != "" {
		updates["bio"] = req.Bio
	}
	if req.Company != "" {
		updates["company"] = req.Company
	}
	if req.Location != "" {
		updates["location"] = req.Location
	}
	if req.Website != "" {
		updates["website"] = req.Website
	}
	if req.Avatar != "" {
		updates["avatar"] = req.Avatar
	}

	// Update profile
	user, err := h.userUseCase.UpdateProfile(userID, updates)
	if err != nil {
		h.logger.WithError(err).WithField("user_id", userID).Error("Failed to update profile")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update profile", err)
		return
	}

	// Convert to response
	userResp := h.convertUserToResponse(user)
	h.writeJSONResponse(w, http.StatusOK, userResp)
}

// ListUsers handles GET /api/v1/users
func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 20 // default
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	offset := 0 // default
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	// Get users
	users, err := h.userUseCase.ListUsers(limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list users")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list users", err)
		return
	}

	// Convert to response
	userResponses := make([]*UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = h.convertUserToResponse(user)
	}

	response := &UserListResponse{
		Users:  userResponses,
		Total:  len(userResponses),
		Limit:  limit,
		Offset: offset,
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// SearchUsers handles GET /api/v1/users/search
func (h *UserHandler) SearchUsers(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	query := r.URL.Query().Get("q")
	if query == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Search query is required", nil)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 20 // default
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	offset := 0 // default
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	// Search users
	users, err := h.userUseCase.SearchUsers(query, limit, offset)
	if err != nil {
		h.logger.WithError(err).WithField("query", query).Error("Failed to search users")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to search users", err)
		return
	}

	// Convert to response
	userResponses := make([]*UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = h.convertUserToResponse(user)
	}

	response := &UserListResponse{
		Users:  userResponses,
		Total:  len(userResponses),
		Limit:  limit,
		Offset: offset,
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// UpdateUserRole handles PUT /api/v1/users/{id}/role
func (h *UserHandler) UpdateUserRole(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from path
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 5 {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid user ID", nil)
		return
	}

	userID, err := uuid.Parse(pathParts[4])
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid user ID format", err)
		return
	}

	var req UpdateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate role
	var role domain.UserRole
	switch req.Role {
	case "admin":
		role = domain.UserRoleAdmin
	case "moderator":
		role = domain.UserRoleModerator
	case "user":
		role = domain.UserRoleUser
	case "guest":
		role = domain.UserRoleGuest
	default:
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid role", nil)
		return
	}

	// Update role
	if err := h.userUseCase.UpdateUserRole(userID, role); err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"user_id": userID,
			"role":    req.Role,
		}).Error("Failed to update user role")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update user role", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "User role updated successfully",
		"user_id": userID,
		"role":    req.Role,
	})
}

// UpdateUserStatus handles PUT /api/v1/users/{id}/status
func (h *UserHandler) UpdateUserStatus(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from path
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 5 {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid user ID", nil)
		return
	}

	userID, err := uuid.Parse(pathParts[4])
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid user ID format", err)
		return
	}

	var req UpdateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate status
	var status domain.UserStatus
	switch req.Status {
	case "active":
		status = domain.UserStatusActive
	case "inactive":
		status = domain.UserStatusInactive
	case "suspended":
		status = domain.UserStatusSuspended
	case "pending":
		status = domain.UserStatusPending
	default:
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid status", nil)
		return
	}

	// Update status
	if err := h.userUseCase.UpdateUserStatus(userID, status); err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"user_id": userID,
			"status":  req.Status,
		}).Error("Failed to update user status")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update user status", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "User status updated successfully",
		"user_id": userID,
		"status":  req.Status,
	})
}

// Helper methods

func (h *UserHandler) convertUserToResponse(user *domain.User) *UserResponse {
	return &UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      user.Role,
		Status:    string(user.Status),
		CreatedAt: user.CreatedAt,
	}
}

func (h *UserHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func (h *UserHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	response := map[string]interface{}{
		"error":   true,
		"message": message,
	}
	
	if err != nil {
		h.logger.WithError(err).Error(message)
		response["details"] = err.Error()
	}
	
	json.NewEncoder(w).Encode(response)
}
