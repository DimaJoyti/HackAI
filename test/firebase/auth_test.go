package firebase_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

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

// FirebaseAuthTestSuite defines the test suite for Firebase authentication
type FirebaseAuthTestSuite struct {
	suite.Suite
	firebaseService *firebase.EnhancedService
	userRepo        domain.UserRepository
	logger          *logger.Logger
	ctx             context.Context
	testUsers       []*firebase.CreateUserRequest
}

// SetupSuite sets up the test suite
func (suite *FirebaseAuthTestSuite) SetupSuite() {
	// Initialize logger
	logger, err := logger.New(logger.Config{
		Level:  "debug",
		Format: "json",
	})
	require.NoError(suite.T(), err)
	suite.logger = logger

	// Load configuration
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
		environment = "development"
	}

	firebaseConfig, err := firebase.LoadConfig("../../configs/firebase/firebase-config.yaml", environment)
	require.NoError(suite.T(), err)

	// Initialize Firebase service
	suite.firebaseService, err = firebase.NewEnhancedService(firebaseConfig, logger, suite.userRepo)
	require.NoError(suite.T(), err)

	suite.ctx = context.Background()

	// Prepare test users
	suite.testUsers = []*firebase.CreateUserRequest{
		{
			Email:         "test1@hackai.dev",
			Password:      "TestPassword123!",
			DisplayName:   "Test User 1",
			EmailVerified: false,
			Username:      "testuser1",
			FirstName:     "Test",
			LastName:      "User1",
			Role:          "user",
		},
		{
			Email:         "test2@hackai.dev",
			Password:      "TestPassword456!",
			DisplayName:   "Test User 2",
			EmailVerified: true,
			Username:      "testuser2",
			FirstName:     "Test",
			LastName:      "User2",
			Role:          "moderator",
		},
		{
			Email:         "admin@hackai.dev",
			Password:      "AdminPassword789!",
			DisplayName:   "Admin User",
			EmailVerified: true,
			Username:      "admin",
			FirstName:     "Admin",
			LastName:      "User",
			Role:          "admin",
		},
	}
}

// TearDownSuite cleans up after the test suite
func (suite *FirebaseAuthTestSuite) TearDownSuite() {
	// Clean up test users
	for _, testUser := range suite.testUsers {
		if testUser.UID != "" {
			// Delete from Firebase
			suite.firebaseService.DeleteUser(suite.ctx, testUser.UID)
			
			// Delete from database
			if user, err := suite.userRepo.GetByEmail(testUser.Email); err == nil {
				suite.userRepo.Delete(user.ID)
			}
		}
	}
}

// TestCreateUser tests user creation
func (suite *FirebaseAuthTestSuite) TestCreateUser() {
	testUser := suite.testUsers[0]
	
	// Create user
	userResponse, err := suite.firebaseService.CreateUserWithEnhancedLogging(suite.ctx, testUser)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), userResponse)
	
	// Store UID for cleanup
	testUser.UID = userResponse.UID
	
	// Verify user properties
	assert.Equal(suite.T(), testUser.Email, userResponse.Email)
	assert.Equal(suite.T(), testUser.DisplayName, userResponse.DisplayName)
	assert.Equal(suite.T(), testUser.EmailVerified, userResponse.EmailVerified)
	assert.NotEmpty(suite.T(), userResponse.UID)
	
	// Verify user exists in Firebase
	firebaseUser, err := suite.firebaseService.GetUser(suite.ctx, userResponse.UID)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), testUser.Email, firebaseUser.Email)
	
	// Verify user exists in database
	dbUser, err := suite.userRepo.GetByEmail(testUser.Email)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), testUser.Email, dbUser.Email)
	assert.Equal(suite.T(), testUser.Username, dbUser.Username)
}

// TestCreateUserWithCustomClaims tests user creation with custom claims
func (suite *FirebaseAuthTestSuite) TestCreateUserWithCustomClaims() {
	testUser := suite.testUsers[1]
	testUser.CustomClaims = map[string]interface{}{
		"role":         "moderator",
		"permissions":  []string{"read", "write", "moderate"},
		"organization": "hackai",
	}
	
	// Create user
	userResponse, err := suite.firebaseService.CreateUserWithEnhancedLogging(suite.ctx, testUser)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), userResponse)
	
	// Store UID for cleanup
	testUser.UID = userResponse.UID
	
	// Verify custom claims
	assert.Equal(suite.T(), testUser.CustomClaims, userResponse.CustomClaims)
}

// TestTokenVerification tests ID token verification
func (suite *FirebaseAuthTestSuite) TestTokenVerification() {
	// This test requires a valid ID token from a real authentication
	// In a real test environment, you would authenticate a user and get their token
	
	// For now, we'll test the token verification method exists and handles errors correctly
	_, err := suite.firebaseService.VerifyIDTokenWithContext(suite.ctx, "invalid-token")
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "failed to verify ID token")
}

// TestHealthCheck tests the health check functionality
func (suite *FirebaseAuthTestSuite) TestHealthCheck() {
	healthStatus := suite.firebaseService.GetHealthStatus()
	require.NotNil(suite.T(), healthStatus)
	
	assert.Equal(suite.T(), "hackai-auth-system", healthStatus.ProjectID)
	assert.True(suite.T(), healthStatus.ServiceUptime > 0)
}

// TestMetrics tests the metrics functionality
func (suite *FirebaseAuthTestSuite) TestMetrics() {
	metrics := suite.firebaseService.GetMetrics()
	require.NotNil(suite.T(), metrics)
	
	assert.True(suite.T(), metrics.ServiceUptime.Before(time.Now()))
}

// TestUserManagement tests comprehensive user management operations
func (suite *FirebaseAuthTestSuite) TestUserManagement() {
	testUser := suite.testUsers[2]
	
	// Create user
	userResponse, err := suite.firebaseService.CreateUserWithEnhancedLogging(suite.ctx, testUser)
	require.NoError(suite.T(), err)
	testUser.UID = userResponse.UID
	
	// Update user
	updateReq := &firebase.UpdateUserRequest{
		DisplayName: stringPtr("Updated Admin User"),
		Disabled:    boolPtr(false),
	}
	
	updatedUser, err := suite.firebaseService.UpdateUser(suite.ctx, testUser.UID, updateReq)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), "Updated Admin User", updatedUser.DisplayName)
	
	// Set custom claims
	claims := map[string]interface{}{
		"role":        "admin",
		"permissions": []string{"read", "write", "admin"},
	}
	
	err = suite.firebaseService.SetCustomUserClaims(suite.ctx, testUser.UID, claims)
	require.NoError(suite.T(), err)
	
	// Verify claims were set
	user, err := suite.firebaseService.GetUser(suite.ctx, testUser.UID)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), claims, user.CustomClaims)
}

// TestErrorHandling tests error handling scenarios
func (suite *FirebaseAuthTestSuite) TestErrorHandling() {
	// Test getting non-existent user
	_, err := suite.firebaseService.GetUser(suite.ctx, "non-existent-uid")
	assert.Error(suite.T(), err)
	
	// Test creating user with invalid email
	invalidUser := &firebase.CreateUserRequest{
		Email:    "invalid-email",
		Password: "password",
	}
	
	_, err = suite.firebaseService.CreateUserWithEnhancedLogging(suite.ctx, invalidUser)
	assert.Error(suite.T(), err)
	
	// Test updating non-existent user
	updateReq := &firebase.UpdateUserRequest{
		DisplayName: stringPtr("Test"),
	}
	
	_, err = suite.firebaseService.UpdateUser(suite.ctx, "non-existent-uid", updateReq)
	assert.Error(suite.T(), err)
}

// Helper functions
func stringPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}

// TestFirebaseAuthSuite runs the Firebase authentication test suite
func TestFirebaseAuthSuite(t *testing.T) {
	// Skip tests if running in CI without Firebase credentials
	if os.Getenv("CI") == "true" && os.Getenv("FIREBASE_SERVICE_ACCOUNT_PATH") == "" {
		t.Skip("Skipping Firebase tests in CI without credentials")
	}
	
	suite.Run(t, new(FirebaseAuthTestSuite))
}

// Benchmark tests
func BenchmarkCreateUser(b *testing.B) {
	// Setup
	logger, _ := logger.New(logger.Config{Level: "error", Format: "json"})
	cfg, _ := config.Load()
	db, _ := database.New(&cfg.Database, logger)
	userRepo := repository.NewUserRepository(db.DB, logger)
	
	firebaseConfig, _ := firebase.LoadConfig("../../configs/firebase/firebase-config.yaml", "development")
	firebaseService, _ := firebase.NewEnhancedService(firebaseConfig, logger, userRepo)
	
	ctx := context.Background()
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		testUser := &firebase.CreateUserRequest{
			Email:       fmt.Sprintf("benchmark%d@hackai.dev", i),
			Password:    "BenchmarkPassword123!",
			DisplayName: fmt.Sprintf("Benchmark User %d", i),
			Username:    fmt.Sprintf("benchmark%d", i),
		}
		
		userResponse, err := firebaseService.CreateUserWithEnhancedLogging(ctx, testUser)
		if err != nil {
			b.Fatal(err)
		}
		
		// Cleanup
		firebaseService.DeleteUser(ctx, userResponse.UID)
	}
}
