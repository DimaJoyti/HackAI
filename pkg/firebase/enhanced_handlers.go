package firebase

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var handlerTracer = otel.Tracer("hackai/firebase/enhanced_handlers")

// EnhancedHandler provides HTTP handlers for enhanced Firebase operations
type EnhancedHandler struct {
	service *EnhancedService
	logger  *logger.Logger
}

// NewEnhancedHandler creates a new enhanced Firebase handler
func NewEnhancedHandler(service *EnhancedService, logger *logger.Logger) *EnhancedHandler {
	return &EnhancedHandler{
		service: service,
		logger:  logger,
	}
}

// RegisterRoutes registers Firebase routes
func (h *EnhancedHandler) RegisterRoutes(router *mux.Router) {
	// Authentication routes
	auth := router.PathPrefix("/auth/firebase").Subrouter()
	auth.HandleFunc("/verify", h.VerifyToken).Methods("POST")
	auth.HandleFunc("/custom-token", h.CreateCustomToken).Methods("POST")
	auth.HandleFunc("/revoke-tokens", h.RevokeTokens).Methods("POST")

	// User management routes
	users := router.PathPrefix("/users").Subrouter()
	users.HandleFunc("", h.CreateUser).Methods("POST")
	users.HandleFunc("/{uid}", h.GetUser).Methods("GET")
	users.HandleFunc("/{uid}", h.UpdateUser).Methods("PUT")
	users.HandleFunc("/{uid}", h.DeleteUser).Methods("DELETE")
	users.HandleFunc("", h.ListUsers).Methods("GET")

	// Claims management
	claims := router.PathPrefix("/claims").Subrouter()
	claims.HandleFunc("/{uid}", h.SetClaims).Methods("POST")
	claims.HandleFunc("/{uid}", h.GetClaims).Methods("GET")

	// Health and metrics
	router.HandleFunc("/health", h.HealthCheck).Methods("GET")
	router.HandleFunc("/metrics", h.GetMetrics).Methods("GET")
	router.HandleFunc("/status", h.GetStatus).Methods("GET")
}

// VerifyToken verifies a Firebase ID token
func (h *EnhancedHandler) VerifyToken(w http.ResponseWriter, r *http.Request) {
	ctx, span := handlerTracer.Start(r.Context(), "firebase.VerifyToken")
	defer span.End()

	var req TokenValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	token, err := h.service.VerifyIDTokenWithContext(ctx, req.IDToken)
	if err != nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Invalid token", err)
		return
	}

	response := &TokenValidationResponse{
		Valid:     true,
		UID:       token.UID,
		Email:     getStringClaim(token.Claims, "email"),
		Claims:    token.Claims,
		ExpiresAt: token.Expires,
		IssuedAt:  token.IssuedAt,
		AuthTime:  token.AuthTime,
		Issuer:    token.Issuer,
		Audience:  token.Audience,
		Subject:   token.Subject,
	}

	span.SetAttributes(
		attribute.String("firebase.user_id", token.UID),
		attribute.String("firebase.email", getStringClaim(token.Claims, "email")),
		attribute.Bool("firebase.email_verified", getBoolClaim(token.Claims, "email_verified")),
	)

	h.writeJSONResponse(w, http.StatusOK, response)
}

// CreateUser creates a new Firebase user
func (h *EnhancedHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	ctx, span := handlerTracer.Start(r.Context(), "firebase.CreateUser")
	defer span.End()

	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	user, err := h.service.CreateUserWithEnhancedLogging(ctx, &req)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create user", err)
		return
	}

	span.SetAttributes(
		attribute.String("firebase.created_user_id", user.UID),
		attribute.String("firebase.created_user_email", user.Email),
	)

	h.writeJSONResponse(w, http.StatusCreated, user)
}

// GetUser retrieves a user by UID
func (h *EnhancedHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	ctx, span := handlerTracer.Start(r.Context(), "firebase.GetUser")
	defer span.End()

	vars := mux.Vars(r)
	uid := vars["uid"]

	if uid == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "UID is required", nil)
		return
	}

	user, err := h.service.GetUser(ctx, uid)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "User not found", err)
		return
	}

	span.SetAttributes(
		attribute.String("firebase.user_id", user.UID),
		attribute.String("firebase.user_email", user.Email),
	)

	h.writeJSONResponse(w, http.StatusOK, user)
}

// HealthCheck performs a comprehensive health check
func (h *EnhancedHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	_, span := handlerTracer.Start(r.Context(), "firebase.HealthCheck")
	defer span.End()

	healthStatus := h.service.GetHealthStatus()
	
	response := &HealthCheckResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "2.0.0",
	}

	response.Firebase.Connected = healthStatus.IsHealthy
	response.Firebase.ProjectID = healthStatus.ProjectID
	response.Database.Connected = healthStatus.DatabaseEnabled

	if !healthStatus.IsHealthy {
		response.Status = "degraded"
	}

	statusCode := http.StatusOK
	if response.Status != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	span.SetAttributes(
		attribute.String("firebase.health_status", response.Status),
		attribute.Bool("firebase.connected", response.Firebase.Connected),
		attribute.Bool("database.connected", response.Database.Connected),
	)

	h.writeJSONResponse(w, statusCode, response)
}

// GetMetrics returns service metrics
func (h *EnhancedHandler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	_, span := handlerTracer.Start(r.Context(), "firebase.GetMetrics")
	defer span.End()

	metrics := h.service.GetMetrics()
	
	response := &MetricsResponse{
		TotalUsers:           metrics.UserCreations,
		AuthenticationsToday: metrics.AuthVerifications,
		ErrorsToday:          metrics.Errors,
	}

	span.SetAttributes(
		attribute.Int64("firebase.total_users", response.TotalUsers),
		attribute.Int64("firebase.auth_verifications", response.AuthenticationsToday),
		attribute.Int64("firebase.errors", response.ErrorsToday),
	)

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GetStatus returns comprehensive service status
func (h *EnhancedHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	_, span := handlerTracer.Start(r.Context(), "firebase.GetStatus")
	defer span.End()

	healthStatus := h.service.GetHealthStatus()

	response := &SystemInfo{
		Version:     "2.0.0",
		Environment: "development", // This should come from config
		Uptime:      healthStatus.ServiceUptime,
		Services: []ServiceStatus{
			{
				Name:      "Firebase Auth",
				Status:    getServiceStatus(healthStatus.IsHealthy),
				LastCheck: healthStatus.LastCheck,
			},
			{
				Name:      "Database",
				Status:    getServiceStatus(healthStatus.DatabaseEnabled),
				LastCheck: time.Now(),
			},
			{
				Name:      "Messaging",
				Status:    getServiceStatus(healthStatus.MessagingEnabled),
				LastCheck: time.Now(),
			},
		},
	}

	span.SetAttributes(
		attribute.String("firebase.version", response.Version),
		attribute.String("firebase.environment", response.Environment),
		attribute.String("firebase.uptime", response.Uptime.String()),
	)

	h.writeJSONResponse(w, http.StatusOK, response)
}

// CreateCustomToken creates a custom Firebase token
func (h *EnhancedHandler) CreateCustomToken(w http.ResponseWriter, r *http.Request) {
	ctx, span := handlerTracer.Start(r.Context(), "firebase.CreateCustomToken")
	defer span.End()

	var req CustomTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	token, err := h.service.CreateCustomToken(ctx, req.UID, req.Claims)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create custom token", err)
		return
	}

	response := &CustomTokenResponse{
		Token:     token,
		ExpiresIn: 3600, // 1 hour
	}

	span.SetAttributes(
		attribute.String("firebase.custom_token_uid", req.UID),
		attribute.Int("firebase.custom_token_claims_count", len(req.Claims)),
	)

	h.writeJSONResponse(w, http.StatusOK, response)
}

// SetClaims sets custom claims for a user
func (h *EnhancedHandler) SetClaims(w http.ResponseWriter, r *http.Request) {
	ctx, span := handlerTracer.Start(r.Context(), "firebase.SetClaims")
	defer span.End()

	vars := mux.Vars(r)
	uid := vars["uid"]

	var req SetClaimsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	err := h.service.SetCustomUserClaims(ctx, uid, req.Claims)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to set claims", err)
		return
	}

	span.SetAttributes(
		attribute.String("firebase.claims_uid", uid),
		attribute.Int("firebase.claims_count", len(req.Claims)),
	)

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Claims set successfully",
	})
}

// RevokeTokens revokes all refresh tokens for a user
func (h *EnhancedHandler) RevokeTokens(w http.ResponseWriter, r *http.Request) {
	ctx, span := handlerTracer.Start(r.Context(), "firebase.RevokeTokens")
	defer span.End()

	var req RevokeTokensRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	err := h.service.RevokeRefreshTokens(ctx, req.UID)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to revoke tokens", err)
		return
	}

	span.SetAttributes(attribute.String("firebase.revoked_tokens_uid", req.UID))

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Tokens revoked successfully",
	})
}

// UpdateUser updates a user's profile
func (h *EnhancedHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	_, span := handlerTracer.Start(r.Context(), "firebase.UpdateUser")
	defer span.End()

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

// DeleteUser deletes a user
func (h *EnhancedHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	_, span := handlerTracer.Start(r.Context(), "firebase.DeleteUser")
	defer span.End()

	vars := mux.Vars(r)
	uid := vars["uid"]

	if err := h.service.DeleteUser(r.Context(), uid); err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete user", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "User deleted successfully"})
}

// ListUsers lists users with pagination
func (h *EnhancedHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	_, span := handlerTracer.Start(r.Context(), "firebase.ListUsers")
	defer span.End()

	// Parse query parameters
	maxResults := 100 // default
	if maxStr := r.URL.Query().Get("max_results"); maxStr != "" {
		if max, err := strconv.Atoi(maxStr); err == nil && max > 0 && max <= 1000 {
			maxResults = max
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

// GetClaims retrieves custom claims for a user
func (h *EnhancedHandler) GetClaims(w http.ResponseWriter, r *http.Request) {
	_, span := handlerTracer.Start(r.Context(), "firebase.GetClaims")
	defer span.End()

	vars := mux.Vars(r)
	uid := vars["uid"]

	user, err := h.service.GetUser(r.Context(), uid)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "User not found", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"uid":    user.UID,
		"claims": user.CustomClaims,
	})
}

// Helper functions
func (h *EnhancedHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func (h *EnhancedHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := &ErrorResponse{
		Error:   message,
		Message: message,
	}

	if err != nil {
		h.logger.WithError(err).Error("Firebase handler error", map[string]interface{}{
			"status_code": statusCode,
			"message":     message,
		})
	}

	json.NewEncoder(w).Encode(response)
}

func getStringClaim(claims map[string]interface{}, key string) string {
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}

func getBoolClaim(claims map[string]interface{}, key string) bool {
	if val, ok := claims[key].(bool); ok {
		return val
	}
	return false
}

func getServiceStatus(isHealthy bool) string {
	if isHealthy {
		return "healthy"
	}
	return "unhealthy"
}
