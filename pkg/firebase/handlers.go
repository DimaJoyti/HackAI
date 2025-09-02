package firebase

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// Handler provides HTTP handlers for Firebase operations
type Handler struct {
	service *Service
	logger  *logger.Logger
}

// NewHandler creates a new Firebase handler
func NewHandler(service *Service, logger *logger.Logger) *Handler {
	return &Handler{
		service: service,
		logger:  logger,
	}
}

// RegisterRoutes registers Firebase routes
func (h *Handler) RegisterRoutes(router *mux.Router) {
	// Authentication routes
	auth := router.PathPrefix("/auth/firebase").Subrouter()
	auth.HandleFunc("/verify", h.VerifyToken).Methods("POST")
	auth.HandleFunc("/custom-token", h.CreateCustomToken).Methods("POST")
	auth.HandleFunc("/revoke-tokens", h.RevokeTokens).Methods("POST")

	// User management routes
	users := router.PathPrefix("/firebase/users").Subrouter()
	users.HandleFunc("", h.CreateUser).Methods("POST")
	users.HandleFunc("", h.ListUsers).Methods("GET")
	users.HandleFunc("/{uid}", h.GetUser).Methods("GET")
	users.HandleFunc("/{uid}", h.UpdateUser).Methods("PUT")
	users.HandleFunc("/{uid}", h.DeleteUser).Methods("DELETE")
	users.HandleFunc("/{uid}/claims", h.SetClaims).Methods("POST")
	users.HandleFunc("/email/{email}", h.GetUserByEmail).Methods("GET")

	// Sync routes
	sync := router.PathPrefix("/firebase/sync").Subrouter()
	sync.HandleFunc("/user/{uid}/to-database", h.SyncUserToDatabase).Methods("POST")
	sync.HandleFunc("/user/{user_id}/to-firebase", h.SyncUserToFirebase).Methods("POST")
	sync.HandleFunc("/batch/to-firebase", h.BatchSyncToFirebase).Methods("POST")

	// Admin routes
	admin := router.PathPrefix("/firebase/admin").Subrouter()
	admin.HandleFunc("/health", h.HealthCheck).Methods("GET")
	admin.HandleFunc("/metrics", h.GetMetrics).Methods("GET")
}

// VerifyToken verifies a Firebase ID token
func (h *Handler) VerifyToken(w http.ResponseWriter, r *http.Request) {
	var req TokenValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	token, err := h.service.VerifyIDToken(r.Context(), req.IDToken)
	if err != nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Invalid token", err)
		return
	}

	response := &TokenValidationResponse{
		Valid:     true,
		UID:       token.UID,
		Email:     token.Claims["email"].(string),
		Claims:    token.Claims,
		ExpiresAt: token.Expires,
		IssuedAt:  token.IssuedAt,
		AuthTime:  token.AuthTime,
		Issuer:    token.Issuer,
		Audience:  token.Audience,
		Subject:   token.Subject,
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// CreateCustomToken creates a custom Firebase token
func (h *Handler) CreateCustomToken(w http.ResponseWriter, r *http.Request) {
	var req CustomTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	token, err := h.service.CreateCustomToken(r.Context(), req.UID, req.Claims)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create custom token", err)
		return
	}

	response := &CustomTokenResponse{
		Token:     token,
		ExpiresIn: 3600, // 1 hour
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// RevokeTokens revokes all refresh tokens for a user
func (h *Handler) RevokeTokens(w http.ResponseWriter, r *http.Request) {
	var req RevokeTokensRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := h.service.RevokeRefreshTokens(r.Context(), req.UID); err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to revoke tokens", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{
		"message": "Tokens revoked successfully",
	})
}

// CreateUser creates a new Firebase user
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	user, err := h.service.CreateUser(r.Context(), &req)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create user", err)
		return
	}

	h.writeJSONResponse(w, http.StatusCreated, user)
}

// GetUser retrieves a user by UID
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	uid := vars["uid"]

	user, err := h.service.GetUser(r.Context(), uid)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "User not found", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, user)
}

// GetUserByEmail retrieves a user by email
func (h *Handler) GetUserByEmail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	email := vars["email"]

	user, err := h.service.GetUserByEmail(r.Context(), email)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "User not found", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, user)
}

// UpdateUser updates a Firebase user
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	uid := vars["uid"]

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	user, err := h.service.UpdateUser(r.Context(), uid, &req)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update user", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, user)
}

// DeleteUser deletes a Firebase user
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	uid := vars["uid"]

	if err := h.service.DeleteUser(r.Context(), uid); err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete user", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{
		"message": "User deleted successfully",
	})
}

// SetClaims sets custom claims for a user
func (h *Handler) SetClaims(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	uid := vars["uid"]

	var req SetClaimsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := h.service.SetCustomUserClaims(r.Context(), uid, req.Claims); err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to set claims", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{
		"message": "Claims set successfully",
	})
}

// ListUsers lists Firebase users with pagination
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	maxResults := 10
	if mr := r.URL.Query().Get("max_results"); mr != "" {
		if parsed, err := strconv.Atoi(mr); err == nil && parsed > 0 && parsed <= 100 {
			maxResults = parsed
		}
	}

	pageToken := r.URL.Query().Get("page_token")

	users, err := h.service.ListUsers(r.Context(), maxResults, pageToken)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list users", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, users)
}

// SyncUserToDatabase syncs a Firebase user to the database
func (h *Handler) SyncUserToDatabase(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	uid := vars["uid"]

	if err := h.service.SyncFirebaseUserToDatabase(r.Context(), uid); err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to sync user to database", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{
		"message": "User synced to database successfully",
	})
}

// SyncUserToFirebase syncs a database user to Firebase
func (h *Handler) SyncUserToFirebase(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["user_id"]

	// Parse UUID
	userID, err := parseUUID(userIDStr)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid user ID", err)
		return
	}

	if err := h.service.SyncDatabaseUserToFirebase(r.Context(), userID); err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to sync user to Firebase", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{
		"message": "User synced to Firebase successfully",
	})
}

// BatchSyncToFirebase syncs multiple database users to Firebase
func (h *Handler) BatchSyncToFirebase(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserIDs []string `json:"user_ids"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Parse UUIDs
	var userIDs []uuid.UUID
	for _, idStr := range req.UserIDs {
		id, err := parseUUID(idStr)
		if err != nil {
			h.writeErrorResponse(w, http.StatusBadRequest, "Invalid user ID: "+idStr, err)
			return
		}
		userIDs = append(userIDs, id)
	}

	result, err := h.service.BatchSyncUsersToFirebase(r.Context(), userIDs)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to batch sync users", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, result)
}

// HealthCheck performs a health check
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	response := &HealthCheckResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0",
	}

	// Test Firebase connection
	_, err := h.service.authClient.GetUser(r.Context(), "test")
	response.Firebase.Connected = err == nil || err.Error() != "connection error"
	response.Firebase.ProjectID = h.service.config.Firebase.ProjectID

	// Test database connection (if available)
	response.Database.Connected = h.service.userRepo != nil

	if !response.Firebase.Connected || !response.Database.Connected {
		response.Status = "degraded"
	}

	statusCode := http.StatusOK
	if response.Status != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	h.writeJSONResponse(w, statusCode, response)
}

// GetMetrics returns service metrics
func (h *Handler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	// This is a simplified metrics implementation
	// In production, integrate with Prometheus or similar
	response := &MetricsResponse{
		TotalUsers:           0, // Would query from database
		ActiveUsers:          0, // Would query from database
		NewUsersToday:        0, // Would query from database
		AuthenticationsToday: 0, // Would query from logs/metrics
		ErrorsToday:          0, // Would query from logs/metrics
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// Helper methods

func (h *Handler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func (h *Handler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	errorResponse := ErrorResponse{
		Error:   message,
		Message: message,
	}

	if err != nil {
		errorResponse.Message = err.Error()
		h.logger.WithError(err).Error("Handler error")
	}

	json.NewEncoder(w).Encode(errorResponse)
}

// parseUUID parses a string into a UUID
func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}
