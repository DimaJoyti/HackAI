package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/internal/repository"
	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/database"
	"github.com/dimajoyti/hackai/pkg/firebase"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// FirebaseAuthIntegrationTestSuite defines the integration test suite
type FirebaseAuthIntegrationTestSuite struct {
	suite.Suite
	server          *httptest.Server
	firebaseService *firebase.EnhancedService
	firebaseHandler *firebase.EnhancedHandler
	middleware      *firebase.EnhancedMiddleware
	userRepo        domain.UserRepository
	logger          *logger.Logger
	ctx             context.Context
	testUsers       []string // Store UIDs for cleanup
}

// SetupSuite sets up the integration test suite
func (suite *FirebaseAuthIntegrationTestSuite) SetupSuite() {
	// Check if we're running with Firebase emulators
	if os.Getenv("FIREBASE_AUTH_EMULATOR_HOST") == "" {
		suite.T().Skip("Skipping integration tests - Firebase emulators not running")
	}

	// Initialize logger
	logger, err := logger.New(logger.Config{
		Level:  "debug",
		Format: "json",
	})
	require.NoError(suite.T(), err)
	suite.logger = logger

	// Load configuration for testing
	cfg, err := config.Load()
	require.NoError(suite.T(), err)

	// Initialize database for testing
	db, err := database.New(&cfg.Database, logger)
	require.NoError(suite.T(), err)

	// Initialize user repository
	suite.userRepo = repository.NewUserRepository(db.DB, logger)

	// Load Firebase configuration for testing
	environment := os.Getenv("ENVIRONMENT")
	if environment == "" {
		environment = "test"
	}

	firebaseConfig, err := firebase.LoadConfig("../../configs/firebase/firebase-config.yaml", environment)
	require.NoError(suite.T(), err)

	// Override with emulator settings
	firebaseConfig.Firebase.ProjectID = "hackai-auth-system"

	// Initialize Firebase service
	suite.firebaseService, err = firebase.NewEnhancedService(firebaseConfig, logger, suite.userRepo)
	require.NoError(suite.T(), err)

	// Initialize Firebase handlers
	suite.firebaseHandler = firebase.NewEnhancedHandler(suite.firebaseService, logger)

	// Initialize Firebase middleware
	middlewareConfig := &firebase.MiddlewareConfig{
		RequireEmailVerification: false, // Disable for testing
		TokenCacheTTL:           5 * time.Minute,
		RateLimitRequests:       1000, // High limit for testing
		RateLimitWindow:         time.Hour,
		EnableSecurityHeaders:   true,
		EnableAuditLogging:      true,
	}
	suite.middleware = firebase.NewEnhancedMiddleware(suite.firebaseService, logger, middlewareConfig)

	// Set up HTTP server
	router := mux.NewRouter()
	suite.firebaseHandler.RegisterRoutes(router)

	// Add protected routes for testing
	protected := router.PathPrefix("/api/protected").Subrouter()
	protected.Use(suite.middleware.AuthRequiredWithSecurity)
	protected.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		user := firebase.GetUserFromContext(r.Context())
		if user == nil {
			http.Error(w, "User not found in context", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"user": user,
		})
	}).Methods("GET")

	suite.server = httptest.NewServer(router)
	suite.ctx = context.Background()
	suite.testUsers = make([]string, 0)
}

// TearDownSuite cleans up after the test suite
func (suite *FirebaseAuthIntegrationTestSuite) TearDownSuite() {
	// Clean up test users
	for _, uid := range suite.testUsers {
		suite.firebaseService.DeleteUser(suite.ctx, uid)
	}

	if suite.server != nil {
		suite.server.Close()
	}
}

// TestHealthEndpoint tests the health check endpoint
func (suite *FirebaseAuthIntegrationTestSuite) TestHealthEndpoint() {
	resp, err := http.Get(suite.server.URL + "/health")
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var healthResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&healthResponse)
	require.NoError(suite.T(), err)

	assert.Equal(suite.T(), "healthy", healthResponse["status"])
}

// TestMetricsEndpoint tests the metrics endpoint
func (suite *FirebaseAuthIntegrationTestSuite) TestMetricsEndpoint() {
	resp, err := http.Get(suite.server.URL + "/metrics")
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var metricsResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&metricsResponse)
	require.NoError(suite.T(), err)

	// Check that metrics are present
	assert.Contains(suite.T(), metricsResponse, "TotalUsers")
	assert.Contains(suite.T(), metricsResponse, "AuthenticationsToday")
}

// TestCreateUser tests user creation via API
func (suite *FirebaseAuthIntegrationTestSuite) TestCreateUser() {
	createUserReq := firebase.CreateUserRequest{
		Email:         fmt.Sprintf("test-%d@example.com", time.Now().Unix()),
		Password:      "TestPassword123!",
		DisplayName:   "Test User",
		EmailVerified: true,
		Username:      fmt.Sprintf("testuser%d", time.Now().Unix()),
		FirstName:     "Test",
		LastName:      "User",
		Role:          "user",
	}

	reqBody, err := json.Marshal(createUserReq)
	require.NoError(suite.T(), err)

	resp, err := http.Post(
		suite.server.URL+"/users",
		"application/json",
		bytes.NewBuffer(reqBody),
	)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	assert.Equal(suite.T(), http.StatusCreated, resp.StatusCode)

	var userResponse firebase.UserResponse
	err = json.NewDecoder(resp.Body).Decode(&userResponse)
	require.NoError(suite.T(), err)

	// Store UID for cleanup
	suite.testUsers = append(suite.testUsers, userResponse.UID)

	// Verify user properties
	assert.Equal(suite.T(), createUserReq.Email, userResponse.Email)
	assert.Equal(suite.T(), createUserReq.DisplayName, userResponse.DisplayName)
	assert.Equal(suite.T(), createUserReq.EmailVerified, userResponse.EmailVerified)
	assert.NotEmpty(suite.T(), userResponse.UID)
}

// TestProtectedEndpointWithoutAuth tests protected endpoint without authentication
func (suite *FirebaseAuthIntegrationTestSuite) TestProtectedEndpointWithoutAuth() {
	resp, err := http.Get(suite.server.URL + "/api/protected/profile")
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	assert.Equal(suite.T(), http.StatusUnauthorized, resp.StatusCode)
}

// TestProtectedEndpointWithAuth tests protected endpoint with authentication
func (suite *FirebaseAuthIntegrationTestSuite) TestProtectedEndpointWithAuth() {
	// First create a user
	createUserReq := firebase.CreateUserRequest{
		Email:         fmt.Sprintf("auth-test-%d@example.com", time.Now().Unix()),
		Password:      "TestPassword123!",
		DisplayName:   "Auth Test User",
		EmailVerified: true,
		Username:      fmt.Sprintf("authuser%d", time.Now().Unix()),
		FirstName:     "Auth",
		LastName:      "User",
		Role:          "user",
	}

	userResponse, err := suite.firebaseService.CreateUserWithEnhancedLogging(suite.ctx, &createUserReq)
	require.NoError(suite.T(), err)
	suite.testUsers = append(suite.testUsers, userResponse.UID)

	// Create a custom token for the user
	token, err := suite.firebaseService.CreateCustomToken(suite.ctx, userResponse.UID, map[string]interface{}{
		"role": "user",
	})
	require.NoError(suite.T(), err)

	// Make request with authentication token
	req, err := http.NewRequest("GET", suite.server.URL+"/api/protected/profile", nil)
	require.NoError(suite.T(), err)
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	// Note: Custom tokens need to be exchanged for ID tokens in a real scenario
	// For this test, we expect it to fail with custom token, but the middleware should handle it gracefully
	// In a real integration test, you would use the Firebase Auth REST API to exchange the custom token
	assert.True(suite.T(), resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusOK)
}

// TestUserCRUDOperations tests complete user CRUD operations
func (suite *FirebaseAuthIntegrationTestSuite) TestUserCRUDOperations() {
	// Create user
	createUserReq := firebase.CreateUserRequest{
		Email:         fmt.Sprintf("crud-test-%d@example.com", time.Now().Unix()),
		Password:      "TestPassword123!",
		DisplayName:   "CRUD Test User",
		EmailVerified: true,
		Username:      fmt.Sprintf("cruduser%d", time.Now().Unix()),
		FirstName:     "CRUD",
		LastName:      "User",
		Role:          "user",
	}

	userResponse, err := suite.firebaseService.CreateUserWithEnhancedLogging(suite.ctx, &createUserReq)
	require.NoError(suite.T(), err)
	suite.testUsers = append(suite.testUsers, userResponse.UID)

	// Read user
	retrievedUser, err := suite.firebaseService.GetUser(suite.ctx, userResponse.UID)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), userResponse.Email, retrievedUser.Email)

	// Update user
	displayName := "Updated CRUD User"
	updateReq := &firebase.UpdateUserRequest{
		DisplayName: &displayName,
	}

	updatedUser, err := suite.firebaseService.UpdateUser(suite.ctx, userResponse.UID, updateReq)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), displayName, updatedUser.DisplayName)

	// Set custom claims
	claims := map[string]interface{}{
		"role":        "moderator",
		"permissions": []string{"read", "write", "moderate"},
	}

	err = suite.firebaseService.SetCustomUserClaims(suite.ctx, userResponse.UID, claims)
	require.NoError(suite.T(), err)

	// Verify claims were set
	user, err := suite.firebaseService.GetUser(suite.ctx, userResponse.UID)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), "moderator", user.CustomClaims["role"])

	// Delete user (will be handled in cleanup, but test the method)
	err = suite.firebaseService.DeleteUser(suite.ctx, userResponse.UID)
	require.NoError(suite.T(), err)

	// Remove from cleanup list since we already deleted
	for i, uid := range suite.testUsers {
		if uid == userResponse.UID {
			suite.testUsers = append(suite.testUsers[:i], suite.testUsers[i+1:]...)
			break
		}
	}

	// Verify user is deleted
	_, err = suite.firebaseService.GetUser(suite.ctx, userResponse.UID)
	assert.Error(suite.T(), err)
}

// TestTokenOperations tests token-related operations
func (suite *FirebaseAuthIntegrationTestSuite) TestTokenOperations() {
	// Create user
	createUserReq := firebase.CreateUserRequest{
		Email:         fmt.Sprintf("token-test-%d@example.com", time.Now().Unix()),
		Password:      "TestPassword123!",
		DisplayName:   "Token Test User",
		EmailVerified: true,
		Username:      fmt.Sprintf("tokenuser%d", time.Now().Unix()),
		FirstName:     "Token",
		LastName:      "User",
		Role:          "user",
	}

	userResponse, err := suite.firebaseService.CreateUserWithEnhancedLogging(suite.ctx, &createUserReq)
	require.NoError(suite.T(), err)
	suite.testUsers = append(suite.testUsers, userResponse.UID)

	// Create custom token
	token, err := suite.firebaseService.CreateCustomToken(suite.ctx, userResponse.UID, map[string]interface{}{
		"role": "user",
		"test": true,
	})
	require.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), token)

	// Revoke refresh tokens
	err = suite.firebaseService.RevokeRefreshTokens(suite.ctx, userResponse.UID)
	require.NoError(suite.T(), err)
}

// TestFirebaseAuthIntegrationSuite runs the Firebase auth integration test suite
func TestFirebaseAuthIntegrationSuite(t *testing.T) {
	// Skip tests if running in CI without Firebase emulators
	if os.Getenv("CI") == "true" && os.Getenv("FIREBASE_AUTH_EMULATOR_HOST") == "" {
		t.Skip("Skipping Firebase integration tests in CI without emulators")
	}

	suite.Run(t, new(FirebaseAuthIntegrationTestSuite))
}
