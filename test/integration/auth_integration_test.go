package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/internal/handler"
	"github.com/dimajoyti/hackai/internal/repository"
	"github.com/dimajoyti/hackai/pkg/auth"
	"github.com/dimajoyti/hackai/pkg/database"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/middleware"
)

// AuthIntegrationTestSuite contains integration tests for authentication
type AuthIntegrationTestSuite struct {
	suite.Suite
	db             *database.DB
	authService    *auth.EnhancedAuthService
	authHandler    *handler.AuthHandler
	userRepo       domain.UserRepository
	auditRepo      domain.AuditRepository
	logger         *logger.Logger
	securityConfig *auth.SecurityConfig
}

// SetupSuite runs once before all tests
func (suite *AuthIntegrationTestSuite) SetupSuite() {
	// Initialize logger
	log, err := logger.New(logger.Config{
		Level:  "error", // Reduce noise in tests
		Format: "text",
		Output: "console",
	})
	suite.Require().NoError(err)
	suite.logger = log

	// For integration tests, we'll use mock repositories
	// In a real scenario, you would set up a test database
	suite.userRepo = repository.NewMockUserRepository()
	suite.auditRepo = repository.NewMockAuditRepository()

	// Initialize authentication service
	jwtConfig := &auth.JWTConfig{
		Secret:          "test-secret-key-for-integration-tests",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "hackai-test",
		Audience:        "hackai-test-users",
	}
	suite.securityConfig = auth.DefaultSecurityConfig()

	suite.authService = auth.NewEnhancedAuthService(
		jwtConfig,
		suite.securityConfig,
		suite.userRepo,
		suite.auditRepo,
		log,
	)

	// Initialize auth handler
	suite.authHandler = handler.NewAuthHandler(suite.authService, log)
}

// SetupTest runs before each test
func (suite *AuthIntegrationTestSuite) SetupTest() {
	// Reset mock repositories before each test
	suite.userRepo = repository.NewMockUserRepository()
	suite.auditRepo = repository.NewMockAuditRepository()

	// Reinitialize auth service with fresh repositories
	jwtConfig := &auth.JWTConfig{
		Secret:          "test-secret-key-for-integration-tests",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "hackai-test",
		Audience:        "hackai-test-users",
	}
	suite.securityConfig = auth.DefaultSecurityConfig()

	suite.authService = auth.NewEnhancedAuthService(
		jwtConfig,
		suite.securityConfig,
		suite.userRepo,
		suite.auditRepo,
		suite.logger,
	)

	// Recreate auth handler with the new auth service
	suite.authHandler = handler.NewAuthHandler(suite.authService, suite.logger)
}

// createTestUser creates a test user in the database
func (suite *AuthIntegrationTestSuite) createTestUser(username, email, password string, role domain.UserRole) *domain.User {
	// Use the same password manager configuration as the auth service
	passwordManager := auth.NewPasswordManager(suite.securityConfig)
	hashedPassword, err := passwordManager.HashPassword(password)
	suite.Require().NoError(err)

	user := &domain.User{
		Username:  username,
		Email:     email,
		Password:  hashedPassword,
		FirstName: "Test",
		LastName:  "User",
		Role:      role,
		Status:    domain.UserStatusActive,
	}

	err = suite.userRepo.Create(user)
	suite.Require().NoError(err)

	return user
}

// TestUserRegistrationFlow tests the complete user registration flow
func (suite *AuthIntegrationTestSuite) TestUserRegistrationFlow() {
	// This would typically involve a registration endpoint
	// For now, we'll test user creation directly
	user := suite.createTestUser("testuser", "test@example.com", "TestPassword123!", domain.UserRoleUser)

	// Verify user was created
	retrievedUser, err := suite.userRepo.GetByEmail("test@example.com")
	suite.Require().NoError(err)
	suite.Equal(user.ID, retrievedUser.ID)
	suite.Equal("testuser", retrievedUser.Username)
	suite.Equal("test@example.com", retrievedUser.Email)
	suite.Equal(domain.UserRoleUser, retrievedUser.Role)
}

// TestLoginFlow tests the complete login flow
func (suite *AuthIntegrationTestSuite) TestLoginFlow() {
	// Create test user
	user := suite.createTestUser("loginuser", "login@example.com", "LoginPassword123!", domain.UserRoleUser)

	// Verify user was created
	retrievedUser, err := suite.userRepo.GetByEmail("login@example.com")
	suite.Require().NoError(err)
	suite.Equal(user.ID, retrievedUser.ID)

	// Test password verification directly
	passwordManager := auth.NewPasswordManager(suite.securityConfig)
	isValid := passwordManager.VerifyPassword("LoginPassword123!", retrievedUser.Password)
	suite.True(isValid, "Password verification should succeed")

	// Test authentication service directly
	authReq := &auth.AuthenticationRequest{
		EmailOrUsername: "login@example.com",
		Password:        "LoginPassword123!",
		IPAddress:       "192.168.1.100",
		UserAgent:       "test-client",
	}

	authResp, err := suite.authService.Authenticate(context.Background(), authReq)
	suite.Require().NoError(err, "Direct authentication should succeed")
	suite.NotNil(authResp)
	suite.Equal(user.ID, authResp.User.ID)

	// Test login request
	loginReq := map[string]interface{}{
		"email_or_username": "login@example.com",
		"password":          "LoginPassword123!",
		"remember_me":       false,
	}

	reqBody, err := json.Marshal(loginReq)
	suite.Require().NoError(err)

	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-client")
	req.RemoteAddr = "192.168.1.100:12345"

	w := httptest.NewRecorder()
	suite.authHandler.Login(w, req)

	// Verify response
	suite.Equal(http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	suite.Require().NoError(err)

	// Check response structure
	suite.Contains(response, "user")
	suite.Contains(response, "access_token")
	suite.Contains(response, "expires_at")
	suite.Contains(response, "session_id")

	userResp := response["user"].(map[string]interface{})
	suite.Equal(user.ID.String(), userResp["id"])
	suite.Equal("loginuser", userResp["username"])
	suite.Equal("login@example.com", userResp["email"])
}

// TestLoginWithInvalidCredentials tests login with wrong credentials
func (suite *AuthIntegrationTestSuite) TestLoginWithInvalidCredentials() {
	// Create test user
	suite.createTestUser("validuser", "valid@example.com", "ValidPassword123!", domain.UserRoleUser)

	// Test login with wrong password
	loginReq := map[string]interface{}{
		"email_or_username": "valid@example.com",
		"password":          "WrongPassword123!",
		"remember_me":       false,
	}

	reqBody, err := json.Marshal(loginReq)
	suite.Require().NoError(err)

	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	suite.authHandler.Login(w, req)

	// Verify unauthorized response
	suite.Equal(http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	suite.Require().NoError(err)
	suite.Contains(response, "error")
}

// TestJWTTokenValidation tests JWT token validation
func (suite *AuthIntegrationTestSuite) TestJWTTokenValidation() {
	// Create test user and login
	user := suite.createTestUser("tokenuser", "token@example.com", "TokenPassword123!", domain.UserRoleUser)

	// Authenticate user to get token
	authReq := &auth.AuthenticationRequest{
		EmailOrUsername: "token@example.com",
		Password:        "TokenPassword123!",
		IPAddress:       "192.168.1.100",
		UserAgent:       "test-client",
		RememberMe:      false,
	}

	authResp, err := suite.authService.Authenticate(context.Background(), authReq)
	suite.Require().NoError(err)
	suite.NotEmpty(authResp.AccessToken)

	// Validate token
	claims, err := suite.authService.ValidateToken(authResp.AccessToken)
	suite.Require().NoError(err)
	suite.Equal(user.ID, claims.UserID)
	suite.Equal("tokenuser", claims.Username)
	suite.Equal("token@example.com", claims.Email)
	suite.Equal(domain.UserRoleUser, claims.Role)
}

// TestPasswordChange tests password change functionality
func (suite *AuthIntegrationTestSuite) TestPasswordChange() {
	// Create test user
	user := suite.createTestUser("changeuser", "change@example.com", "OldPassword123!", domain.UserRoleUser)

	// Change password
	err := suite.authService.ChangePassword(
		context.Background(),
		user.ID,
		"OldPassword123!",
		"NewPassword123!",
		"192.168.1.100",
		"test-client",
	)
	suite.Require().NoError(err)

	// Verify old password no longer works
	authReq := &auth.AuthenticationRequest{
		EmailOrUsername: "change@example.com",
		Password:        "OldPassword123!",
		IPAddress:       "192.168.1.100",
		UserAgent:       "test-client",
	}

	_, err = suite.authService.Authenticate(context.Background(), authReq)
	suite.Error(err)

	// Verify new password works
	authReq.Password = "NewPassword123!"
	authResp, err := suite.authService.Authenticate(context.Background(), authReq)
	suite.Require().NoError(err)
	suite.NotEmpty(authResp.AccessToken)
}

// TestTOTPEnablement tests TOTP enablement
func (suite *AuthIntegrationTestSuite) TestTOTPEnablement() {
	// Create test user
	user := suite.createTestUser("totpuser", "totp@example.com", "TOTPPassword123!", domain.UserRoleUser)

	// Enable TOTP
	secret, qrURL, err := suite.authService.EnableTOTP(
		context.Background(),
		user.ID,
		"192.168.1.100",
		"test-client",
	)
	suite.Require().NoError(err)
	suite.NotEmpty(secret)
	suite.NotEmpty(qrURL)
	suite.Contains(qrURL, "otpauth://totp/")
	suite.Contains(qrURL, secret)
}

// TestPermissionManagement tests permission granting and checking
func (suite *AuthIntegrationTestSuite) TestPermissionManagement() {
	// Create test users
	adminUser := suite.createTestUser("admin", "admin@example.com", "AdminPassword123!", domain.UserRoleAdmin)
	regularUser := suite.createTestUser("user", "user@example.com", "UserPassword123!", domain.UserRoleUser)

	// Grant permission
	err := suite.authService.GrantPermission(
		context.Background(),
		regularUser.ID,
		adminUser.ID,
		"scans",
		"create",
		nil,
		"192.168.1.100",
		"test-client",
	)
	suite.Require().NoError(err)

	// Check permission
	hasPermission, err := suite.authService.CheckPermission(
		context.Background(),
		regularUser.ID,
		"scans",
		"create",
	)
	suite.Require().NoError(err)
	suite.True(hasPermission)

	// Check non-existent permission
	hasPermission, err = suite.authService.CheckPermission(
		context.Background(),
		regularUser.ID,
		"admin",
		"access",
	)
	suite.Require().NoError(err)
	suite.False(hasPermission)

	// Revoke permission
	err = suite.authService.RevokePermission(
		context.Background(),
		regularUser.ID,
		adminUser.ID,
		"scans",
		"create",
		"192.168.1.100",
		"test-client",
	)
	suite.Require().NoError(err)

	// Verify permission is revoked
	hasPermission, err = suite.authService.CheckPermission(
		context.Background(),
		regularUser.ID,
		"scans",
		"create",
	)
	suite.Require().NoError(err)
	suite.False(hasPermission)
}

// TestAuthenticationMiddleware tests authentication middleware
func (suite *AuthIntegrationTestSuite) TestAuthenticationMiddleware() {
	// Create test user and get token
	user := suite.createTestUser("middlewareuser", "middleware@example.com", "MiddlewarePassword123!", domain.UserRoleUser)

	authReq := &auth.AuthenticationRequest{
		EmailOrUsername: "middleware@example.com",
		Password:        "MiddlewarePassword123!",
		IPAddress:       "192.168.1.100",
		UserAgent:       "test-client",
	}

	authResp, err := suite.authService.Authenticate(context.Background(), authReq)
	suite.Require().NoError(err)

	// Create middleware
	authMiddleware := middleware.NewAuthMiddleware(suite.authService, suite.logger)

	// Create test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if user context is set
		userID, ok := middleware.AuthContext{}.GetUserID(r.Context())
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"user_id": userID.String(),
			"message": "authenticated",
		})
	})

	// Wrap handler with authentication middleware
	protectedHandler := authMiddleware.Authentication(testHandler)

	// Test with valid token
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+authResp.AccessToken)

	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	suite.Equal(http.StatusOK, w.Code)

	var response map[string]string
	err = json.Unmarshal(w.Body.Bytes(), &response)
	suite.Require().NoError(err)
	suite.Equal(user.ID.String(), response["user_id"])
	suite.Equal("authenticated", response["message"])

	// Test without token
	req = httptest.NewRequest("GET", "/protected", nil)
	w = httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	suite.Equal(http.StatusUnauthorized, w.Code)

	// Test with invalid token
	req = httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w = httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	suite.Equal(http.StatusUnauthorized, w.Code)
}

// TestRoleBasedAccess tests role-based access control
func (suite *AuthIntegrationTestSuite) TestRoleBasedAccess() {
	// Create users with different roles
	adminUser := suite.createTestUser("admin", "admin@example.com", "AdminPassword123!", domain.UserRoleAdmin)
	moderatorUser := suite.createTestUser("moderator", "moderator@example.com", "ModeratorPassword123!", domain.UserRoleModerator)
	regularUser := suite.createTestUser("user", "user@example.com", "UserPassword123!", domain.UserRoleUser)

	// Get tokens for each user
	users := []struct {
		user *domain.User
		role domain.UserRole
	}{
		{adminUser, domain.UserRoleAdmin},
		{moderatorUser, domain.UserRoleModerator},
		{regularUser, domain.UserRoleUser},
	}

	for _, testUser := range users {
		authReq := &auth.AuthenticationRequest{
			EmailOrUsername: testUser.user.Email,
			Password:        string(testUser.role) + "Password123!",
			IPAddress:       "192.168.1.100",
			UserAgent:       "test-client",
		}

		authResp, err := suite.authService.Authenticate(context.Background(), authReq)
		suite.Require().NoError(err)

		// Validate token and check role
		claims, err := suite.authService.ValidateToken(authResp.AccessToken)
		suite.Require().NoError(err)
		suite.Equal(testUser.role, claims.Role)

		// Test role hierarchy
		switch testUser.role {
		case domain.UserRoleAdmin:
			suite.True(claims.CanAccess(domain.UserRoleAdmin))
			suite.True(claims.CanAccess(domain.UserRoleModerator))
			suite.True(claims.CanAccess(domain.UserRoleUser))
			suite.True(claims.CanAccess(domain.UserRoleGuest))
		case domain.UserRoleModerator:
			suite.False(claims.CanAccess(domain.UserRoleAdmin))
			suite.True(claims.CanAccess(domain.UserRoleModerator))
			suite.True(claims.CanAccess(domain.UserRoleUser))
			suite.True(claims.CanAccess(domain.UserRoleGuest))
		case domain.UserRoleUser:
			suite.False(claims.CanAccess(domain.UserRoleAdmin))
			suite.False(claims.CanAccess(domain.UserRoleModerator))
			suite.True(claims.CanAccess(domain.UserRoleUser))
			suite.True(claims.CanAccess(domain.UserRoleGuest))
		}
	}
}

// TestSessionManagement tests session creation and management
func (suite *AuthIntegrationTestSuite) TestSessionManagement() {
	// Create test user
	user := suite.createTestUser("sessionuser", "session@example.com", "SessionPassword123!", domain.UserRoleUser)

	// Authenticate and create session
	authReq := &auth.AuthenticationRequest{
		EmailOrUsername: "session@example.com",
		Password:        "SessionPassword123!",
		IPAddress:       "192.168.1.100",
		UserAgent:       "test-client",
		DeviceID:        "test-device-123",
		RememberMe:      false,
	}

	authResp, err := suite.authService.Authenticate(context.Background(), authReq)
	suite.Require().NoError(err)

	// Verify session was created
	session, err := suite.userRepo.GetSession(authResp.AccessToken)
	suite.Require().NoError(err)
	suite.Equal(user.ID, session.UserID)
	suite.Equal("192.168.1.100", session.IPAddress)
	suite.Equal("test-client", session.UserAgent)
	suite.Equal("test-device-123", session.DeviceID)

	// Test logout
	err = suite.authService.Logout(context.Background(), authResp.AccessToken, "192.168.1.100", "test-client")
	suite.Require().NoError(err)

	// Verify session was deleted
	_, err = suite.userRepo.GetSession(authResp.AccessToken)
	suite.Error(err)
}

// Run the test suite
func TestAuthIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(AuthIntegrationTestSuite))
}
