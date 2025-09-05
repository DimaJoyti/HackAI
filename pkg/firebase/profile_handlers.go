package firebase

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// ProfileHandlers provides HTTP handlers for profile management
type ProfileHandlers struct {
	profileService *ProfileService
	rbacService    *RBACService
	logger         *logger.Logger
}

// NewProfileHandlers creates new profile handlers
func NewProfileHandlers(profileService *ProfileService, rbacService *RBACService, logger *logger.Logger) *ProfileHandlers {
	return &ProfileHandlers{
		profileService: profileService,
		rbacService:    rbacService,
		logger:         logger,
	}
}

// GetProfileHandler handles profile retrieval requests
func (h *ProfileHandlers) GetProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user from context
	userCtx := GetUserFromContext(r.Context())
	if userCtx == nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Get user ID from URL or use current user
	userID := strings.TrimPrefix(r.URL.Path, "/api/firebase/profile/")
	if userID == "" || userID == "me" {
		userID = userCtx.UID
	}

	// Check if user can access this profile
	if userID != userCtx.UID {
		// Check if user has permission to read other profiles
		accessRequest := &AccessRequest{
			UserID:   userCtx.UID,
			Resource: "profile",
			Action:   "read_others",
		}
		
		accessResult, err := h.rbacService.CheckAccess(r.Context(), accessRequest)
		if err != nil || !accessResult.Allowed {
			h.writeErrorResponse(w, http.StatusForbidden, "Access denied")
			return
		}
	}

	// Get profile
	profile, err := h.profileService.GetUserProfile(r.Context(), userID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get user profile")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get profile")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, profile)
}

// UpdateProfileHandler handles profile update requests
func (h *ProfileHandlers) UpdateProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPatch {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user from context
	userCtx := GetUserFromContext(r.Context())
	if userCtx == nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Get user ID from URL or use current user
	userID := strings.TrimPrefix(r.URL.Path, "/api/firebase/profile/")
	if userID == "" || userID == "me" {
		userID = userCtx.UID
	}

	// Check if user can update this profile
	if userID != userCtx.UID {
		// Check if user has permission to update other profiles
		accessRequest := &AccessRequest{
			UserID:   userCtx.UID,
			Resource: "profile",
			Action:   "write_others",
		}
		
		accessResult, err := h.rbacService.CheckAccess(r.Context(), accessRequest)
		if err != nil || !accessResult.Allowed {
			h.writeErrorResponse(w, http.StatusForbidden, "Access denied")
			return
		}
	}

	// Parse request body
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Remove sensitive fields that shouldn't be updated directly
	delete(updates, "uid")
	delete(updates, "email")
	delete(updates, "created_at")
	delete(updates, "role")
	delete(updates, "permissions")
	delete(updates, "custom_claims")

	// Update profile
	profile, err := h.profileService.UpdateUserProfile(r.Context(), userID, updates)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update user profile")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update profile")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, profile)
}

// SyncGoogleProfileHandler handles Google profile sync requests
func (h *ProfileHandlers) SyncGoogleProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user from context
	userCtx := GetUserFromContext(r.Context())
	if userCtx == nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request body
	var googleUserInfo map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&googleUserInfo); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Sync Google profile
	err := h.profileService.SyncGoogleProfile(r.Context(), userCtx.UID, googleUserInfo)
	if err != nil {
		h.logger.WithError(err).Error("Failed to sync Google profile")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to sync Google profile")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"status": "success"})
}

// UpdateSettingsHandler handles user settings update requests
func (h *ProfileHandlers) UpdateSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user from context
	userCtx := GetUserFromContext(r.Context())
	if userCtx == nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request body
	var settings ProfileSettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Update settings
	err := h.profileService.UpdateUserSettings(r.Context(), userCtx.UID, &settings)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update user settings")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update settings")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"status": "success"})
}

// AssignRoleHandler handles role assignment requests
func (h *ProfileHandlers) AssignRoleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user from context
	userCtx := GetUserFromContext(r.Context())
	if userCtx == nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Check if user has permission to assign roles
	accessRequest := &AccessRequest{
		UserID:   userCtx.UID,
		Resource: "role",
		Action:   "assign",
	}
	
	accessResult, err := h.rbacService.CheckAccess(r.Context(), accessRequest)
	if err != nil || !accessResult.Allowed {
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied")
		return
	}

	// Parse request body
	var request struct {
		UserID    string     `json:"user_id"`
		RoleID    string     `json:"role_id"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Assign role
	err = h.rbacService.AssignRole(r.Context(), request.UserID, request.RoleID, userCtx.UID, request.ExpiresAt)
	if err != nil {
		h.logger.WithError(err).Error("Failed to assign role")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to assign role")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"status": "success"})
}

// CheckAccessHandler handles access control check requests
func (h *ProfileHandlers) CheckAccessHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user from context
	userCtx := GetUserFromContext(r.Context())
	if userCtx == nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request body
	var accessRequest AccessRequest
	if err := json.NewDecoder(r.Body).Decode(&accessRequest); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Use current user if not specified
	if accessRequest.UserID == "" {
		accessRequest.UserID = userCtx.UID
	}

	// Check if user can check access for others
	if accessRequest.UserID != userCtx.UID {
		adminAccessRequest := &AccessRequest{
			UserID:   userCtx.UID,
			Resource: "system",
			Action:   "read",
		}
		
		adminAccessResult, err := h.rbacService.CheckAccess(r.Context(), adminAccessRequest)
		if err != nil || !adminAccessResult.Allowed {
			h.writeErrorResponse(w, http.StatusForbidden, "Access denied")
			return
		}
	}

	// Check access
	result, err := h.rbacService.CheckAccess(r.Context(), &accessRequest)
	if err != nil {
		h.logger.WithError(err).Error("Failed to check access")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to check access")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, result)
}

// ListRolesHandler handles role listing requests
func (h *ProfileHandlers) ListRolesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user from context
	userCtx := GetUserFromContext(r.Context())
	if userCtx == nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Check if user has permission to read roles
	accessRequest := &AccessRequest{
		UserID:   userCtx.UID,
		Resource: "role",
		Action:   "read",
	}
	
	accessResult, err := h.rbacService.CheckAccess(r.Context(), accessRequest)
	if err != nil || !accessResult.Allowed {
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied")
		return
	}

	// List roles
	roles, err := h.rbacService.ListRoles(r.Context())
	if err != nil {
		h.logger.WithError(err).Error("Failed to list roles")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list roles")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"roles": roles,
		"total": len(roles),
	})
}

// ListPermissionsHandler handles permission listing requests
func (h *ProfileHandlers) ListPermissionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user from context
	userCtx := GetUserFromContext(r.Context())
	if userCtx == nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Check if user has permission to read permissions
	accessRequest := &AccessRequest{
		UserID:   userCtx.UID,
		Resource: "role",
		Action:   "read",
	}
	
	accessResult, err := h.rbacService.CheckAccess(r.Context(), accessRequest)
	if err != nil || !accessResult.Allowed {
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied")
		return
	}

	// List permissions
	permissions, err := h.rbacService.ListPermissions(r.Context())
	if err != nil {
		h.logger.WithError(err).Error("Failed to list permissions")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list permissions")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"permissions": permissions,
		"total":       len(permissions),
	})
}

// ActivateUserHandler handles user activation requests
func (h *ProfileHandlers) ActivateUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user from context
	userCtx := GetUserFromContext(r.Context())
	if userCtx == nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Check if user has permission to activate users
	accessRequest := &AccessRequest{
		UserID:   userCtx.UID,
		Resource: "user",
		Action:   "activate",
	}
	
	accessResult, err := h.rbacService.CheckAccess(r.Context(), accessRequest)
	if err != nil || !accessResult.Allowed {
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied")
		return
	}

	// Get user ID from URL
	userID := strings.TrimPrefix(r.URL.Path, "/api/firebase/profile/")
	userID = strings.TrimSuffix(userID, "/activate")

	// Activate user
	err = h.profileService.ActivateUser(r.Context(), userID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to activate user")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to activate user")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"status": "success"})
}

// SuspendUserHandler handles user suspension requests
func (h *ProfileHandlers) SuspendUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user from context
	userCtx := GetUserFromContext(r.Context())
	if userCtx == nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Check if user has permission to suspend users
	accessRequest := &AccessRequest{
		UserID:   userCtx.UID,
		Resource: "user",
		Action:   "suspend",
	}
	
	accessResult, err := h.rbacService.CheckAccess(r.Context(), accessRequest)
	if err != nil || !accessResult.Allowed {
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied")
		return
	}

	// Parse request body
	var request struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Get user ID from URL
	userID := strings.TrimPrefix(r.URL.Path, "/api/firebase/profile/")
	userID = strings.TrimSuffix(userID, "/suspend")

	// Suspend user
	err = h.profileService.SuspendUser(r.Context(), userID, request.Reason)
	if err != nil {
		h.logger.WithError(err).Error("Failed to suspend user")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to suspend user")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"status": "success"})
}

// Helper methods

// writeJSONResponse writes a JSON response
func (h *ProfileHandlers) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.WithError(err).Error("Failed to encode JSON response")
	}
}

// writeErrorResponse writes an error response
func (h *ProfileHandlers) writeErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	errorResponse := &ErrorResponse{
		Error:   message,
		Code:    fmt.Sprintf("HTTP_%d", statusCode),
		Message: message,
	}
	
	h.writeJSONResponse(w, statusCode, errorResponse)
}
