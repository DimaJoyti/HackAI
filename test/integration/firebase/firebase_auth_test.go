package firebase_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/internal/repository"
	"github.com/dimajoyti/hackai/pkg/database"
	"github.com/dimajoyti/hackai/pkg/firebase"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// FirebaseAuthTestSuite provides integration tests for Firebase authentication
type FirebaseAuthTestSuite struct {
	suite.Suite
	db              *database.Database
	userRepo        domain.UserRepository
	firebaseService *firebase.Service
	logger          *logger.Logger
	config          *firebase.Config
}

// SetupSuite initializes the test suite
func (suite *FirebaseAuthTestSuite) SetupSuite() {
	// Initialize logger
	suite.logger = logger.New(logger.Config{
		Level:  "debug",
		Format: "json",
	})

	// Initialize test database
	dbConfig := &database.Config{
		Host:     getEnvOrDefault("TEST_DB_HOST", "localhost"),
		Port:     getEnvOrDefault("TEST_DB_PORT", "5432"),
		Name:     getEnvOrDefault("TEST_DB_NAME", "hackai_test"),
		User:     getEnvOrDefault("TEST_DB_USER", "postgres"),
		Password: getEnvOrDefault("TEST_DB_PASSWORD", "password"),
		SSLMode:  "disable",
	}

	var err error
	suite.db, err = database.New(dbConfig)
	require.NoError(suite.T(), err)

	// Initialize repositories
	suite.userRepo = repository.NewUserRepository(suite.db.DB, suite.logger)

	// Load Firebase test configuration
	suite.config, err = firebase.LoadConfig("../../../configs/firebase/firebase-config.yaml", "development")
	require.NoError(suite.T(), err)

	// Skip if no Firebase service account is configured
	if _, err := os.Stat(suite.config.Firebase.Admin.ServiceAccountPath); os.IsNotExist(err) {
		suite.T().Skip("Firebase service account not configured for testing")
	}

	// Initialize Firebase service
	suite.firebaseService, err = firebase.NewService(suite.config, suite.logger, suite.userRepo)
	require.NoError(suite.T(), err)
}

// TearDownSuite cleans up after the test suite
func (suite *FirebaseAuthTestSuite) TearDownSuite() {
	if suite.db != nil {
		suite.db.Close()
	}
}

// SetupTest prepares each test
func (suite *FirebaseAuthTestSuite) SetupTest() {
	// Clean up test data
	suite.cleanupTestData()
}

// TearDownTest cleans up after each test
func (suite *FirebaseAuthTestSuite) TearDownTest() {
	suite.cleanupTestData()
}

// TestCreateUser tests Firebase user creation
func (suite *FirebaseAuthTestSuite) TestCreateUser() {
	ctx := context.Background()

	req := &firebase.CreateUserRequest{
		Email:         "test@example.com",
		Password:      "testPassword123",
		DisplayName:   "Test User",
		EmailVerified: false,
		Username:      "testuser",
		FirstName:     "Test",
		LastName:      "User",
		Role:          "user",
	}

	// Create user
	user, err := suite.firebaseService.CreateUser(ctx, req)
	require.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), user.UID)
	assert.Equal(suite.T(), req.Email, user.Email)
	assert.Equal(suite.T(), req.DisplayName, user.DisplayName)

	// Verify user exists in database
	dbUser, err := suite.userRepo.GetByFirebaseUID(user.UID)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), user.Email, dbUser.Email)
	assert.Equal(suite.T(), req.Username, dbUser.Username)

	// Clean up
	err = suite.firebaseService.DeleteUser(ctx, user.UID)
	assert.NoError(suite.T(), err)
}

// TestGetUser tests Firebase user retrieval
func (suite *FirebaseAuthTestSuite) TestGetUser() {
	ctx := context.Background()

	// Create test user
	req := &firebase.CreateUserRequest{
		Email:       "gettest@example.com",
		Password:    "testPassword123",
		DisplayName: "Get Test User",
		Username:    "gettestuser",
	}

	createdUser, err := suite.firebaseService.CreateUser(ctx, req)
	require.NoError(suite.T(), err)

	// Get user by UID
	user, err := suite.firebaseService.GetUser(ctx, createdUser.UID)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), createdUser.UID, user.UID)
	assert.Equal(suite.T(), createdUser.Email, user.Email)

	// Get user by email
	userByEmail, err := suite.firebaseService.GetUserByEmail(ctx, createdUser.Email)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), createdUser.UID, userByEmail.UID)

	// Clean up
	err = suite.firebaseService.DeleteUser(ctx, createdUser.UID)
	assert.NoError(suite.T(), err)
}

// TestUpdateUser tests Firebase user updates
func (suite *FirebaseAuthTestSuite) TestUpdateUser() {
	ctx := context.Background()

	// Create test user
	req := &firebase.CreateUserRequest{
		Email:       "updatetest@example.com",
		Password:    "testPassword123",
		DisplayName: "Update Test User",
		Username:    "updatetestuser",
	}

	createdUser, err := suite.firebaseService.CreateUser(ctx, req)
	require.NoError(suite.T(), err)

	// Update user
	newDisplayName := "Updated Test User"
	updateReq := &firebase.UpdateUserRequest{
		DisplayName: &newDisplayName,
	}

	updatedUser, err := suite.firebaseService.UpdateUser(ctx, createdUser.UID, updateReq)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), newDisplayName, updatedUser.DisplayName)

	// Verify update in database
	dbUser, err := suite.userRepo.GetByFirebaseUID(createdUser.UID)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), newDisplayName, dbUser.DisplayName)

	// Clean up
	err = suite.firebaseService.DeleteUser(ctx, createdUser.UID)
	assert.NoError(suite.T(), err)
}

// TestCustomClaims tests custom claims functionality
func (suite *FirebaseAuthTestSuite) TestCustomClaims() {
	ctx := context.Background()

	// Create test user
	req := &firebase.CreateUserRequest{
		Email:       "claimstest@example.com",
		Password:    "testPassword123",
		DisplayName: "Claims Test User",
		Username:    "claimstestuser",
	}

	createdUser, err := suite.firebaseService.CreateUser(ctx, req)
	require.NoError(suite.T(), err)

	// Set custom claims
	claims := map[string]interface{}{
		"role":         "admin",
		"organization": "hackai",
		"permissions":  []string{"read", "write", "admin"},
	}

	err = suite.firebaseService.SetCustomUserClaims(ctx, createdUser.UID, claims)
	require.NoError(suite.T(), err)

	// Verify claims (Note: This would require creating a custom token and verifying it)
	// For now, we just verify the operation completed without error

	// Clean up
	err = suite.firebaseService.DeleteUser(ctx, createdUser.UID)
	assert.NoError(suite.T(), err)
}

// TestTokenVerification tests Firebase token verification
func (suite *FirebaseAuthTestSuite) TestTokenVerification() {
	ctx := context.Background()

	// Create test user
	req := &firebase.CreateUserRequest{
		Email:       "tokentest@example.com",
		Password:    "testPassword123",
		DisplayName: "Token Test User",
		Username:    "tokentestuser",
	}

	createdUser, err := suite.firebaseService.CreateUser(ctx, req)
	require.NoError(suite.T(), err)

	// Create custom token
	customToken, err := suite.firebaseService.CreateCustomToken(ctx, createdUser.UID, nil)
	require.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), customToken)

	// Note: To fully test token verification, we would need to exchange the custom token
	// for an ID token using the Firebase Auth REST API, then verify that ID token

	// Clean up
	err = suite.firebaseService.DeleteUser(ctx, createdUser.UID)
	assert.NoError(suite.T(), err)
}

// TestUserSync tests user synchronization between Firebase and database
func (suite *FirebaseAuthTestSuite) TestUserSync() {
	ctx := context.Background()

	// Create test user in Firebase
	req := &firebase.CreateUserRequest{
		Email:       "synctest@example.com",
		Password:    "testPassword123",
		DisplayName: "Sync Test User",
		Username:    "synctestuser",
		FirstName:   "Sync",
		LastName:    "User",
		Role:        "user",
	}

	createdUser, err := suite.firebaseService.CreateUser(ctx, req)
	require.NoError(suite.T(), err)

	// Verify user was synced to database
	dbUser, err := suite.userRepo.GetByFirebaseUID(createdUser.UID)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), createdUser.Email, dbUser.Email)
	assert.Equal(suite.T(), req.Username, dbUser.Username)
	assert.Equal(suite.T(), req.FirstName, dbUser.FirstName)
	assert.Equal(suite.T(), req.LastName, dbUser.LastName)

	// Test manual sync
	err = suite.firebaseService.SyncFirebaseUserToDatabase(ctx, createdUser.UID)
	assert.NoError(suite.T(), err)

	// Clean up
	err = suite.firebaseService.DeleteUser(ctx, createdUser.UID)
	assert.NoError(suite.T(), err)
}

// TestListUsers tests user listing functionality
func (suite *FirebaseAuthTestSuite) TestListUsers() {
	ctx := context.Background()

	// Create multiple test users
	users := make([]*firebase.UserResponse, 3)
	for i := 0; i < 3; i++ {
		req := &firebase.CreateUserRequest{
			Email:       fmt.Sprintf("listtest%d@example.com", i),
			Password:    "testPassword123",
			DisplayName: fmt.Sprintf("List Test User %d", i),
			Username:    fmt.Sprintf("listtestuser%d", i),
		}

		user, err := suite.firebaseService.CreateUser(ctx, req)
		require.NoError(suite.T(), err)
		users[i] = user
	}

	// List users
	result, err := suite.firebaseService.ListUsers(ctx, 10, "")
	require.NoError(suite.T(), err)
	assert.GreaterOrEqual(suite.T(), len(result.Users), 3)

	// Clean up
	for _, user := range users {
		err = suite.firebaseService.DeleteUser(ctx, user.UID)
		assert.NoError(suite.T(), err)
	}
}

// cleanupTestData removes test data from the database
func (suite *FirebaseAuthTestSuite) cleanupTestData() {
	// Clean up test users from database
	testEmails := []string{
		"test@example.com",
		"gettest@example.com",
		"updatetest@example.com",
		"claimstest@example.com",
		"tokentest@example.com",
		"synctest@example.com",
	}

	for _, email := range testEmails {
		if user, err := suite.userRepo.GetByEmail(email); err == nil {
			suite.userRepo.Delete(user.ID)
		}
	}

	// Clean up list test users
	for i := 0; i < 3; i++ {
		email := fmt.Sprintf("listtest%d@example.com", i)
		if user, err := suite.userRepo.GetByEmail(email); err == nil {
			suite.userRepo.Delete(user.ID)
		}
	}
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// TestFirebaseAuthIntegration runs the Firebase auth integration test suite
func TestFirebaseAuthIntegration(t *testing.T) {
	suite.Run(t, new(FirebaseAuthTestSuite))
}
