package security

import (
	"context"
	"testing"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// MockUserStore implements UserStore interface for testing
type MockUserStore struct {
	mock.Mock
}

func (m *MockUserStore) GetUser(ctx context.Context, userID string) (*User, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockUserStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockUserStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockUserStore) CreateUser(ctx context.Context, user *User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserStore) UpdateUser(ctx context.Context, user *User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserStore) DeleteUser(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// MockSessionStore implements SessionStore interface for testing
type MockSessionStore struct {
	mock.Mock
}

func (m *MockSessionStore) CreateSession(ctx context.Context, session *AuthSession) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *MockSessionStore) GetSession(ctx context.Context, sessionID string) (*AuthSession, error) {
	args := m.Called(ctx, sessionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AuthSession), args.Error(1)
}

func (m *MockSessionStore) UpdateSession(ctx context.Context, session *AuthSession) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *MockSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *MockSessionStore) GetUserSessions(ctx context.Context, userID string) ([]*AuthSession, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*AuthSession), args.Error(1)
}

func (m *MockSessionStore) CleanupExpiredSessions(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// MockTokenStore implements TokenStore interface for testing
type MockTokenStore struct {
	mock.Mock
}

func (m *MockTokenStore) CreateToken(ctx context.Context, token *AuthToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockTokenStore) GetToken(ctx context.Context, tokenID string) (*AuthToken, error) {
	args := m.Called(ctx, tokenID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AuthToken), args.Error(1)
}

func (m *MockTokenStore) RevokeToken(ctx context.Context, tokenID string) error {
	args := m.Called(ctx, tokenID)
	return args.Error(0)
}

func (m *MockTokenStore) CleanupExpiredTokens(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// AdvancedAuthServiceTestSuite provides comprehensive testing for AdvancedAuthService
type AdvancedAuthServiceTestSuite struct {
	suite.Suite
	authService   *AdvancedAuthService
	mockUserStore *MockUserStore
	mockSessionStore *MockSessionStore
	mockTokenStore *MockTokenStore
	logger        *logger.Logger
	ctx           context.Context
	testUser      *User
	config        *AdvancedAuthConfig
}

// SetupSuite sets up the test suite
func (suite *AdvancedAuthServiceTestSuite) SetupSuite() {
	var err error
	suite.logger, err = logger.New(logger.Config{
		Level:  logger.LevelDebug,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(suite.T(), err)
	
	suite.ctx = context.Background()
	
	// Create test configuration
	suite.config = &AdvancedAuthConfig{
		ServiceName:           "test-auth-service",
		Environment:           "test",
		EnableMFA:             true,
		EnableDeviceTracking:  true,
		EnableIPRestrictions:  false,
		EnableThreatDetection: true,
		EnableAuditLogging:    true,
		EnableRBAC:            true,
		EnablePolicyEngine:    false,
		JWT: &JWTConfig{
			Secret:                "test-secret-key-for-testing-only",
			Issuer:                "test-issuer",
			Audience:              "test-audience",
			AccessTokenTTL:        15 * time.Minute,
			RefreshTokenTTL:       24 * time.Hour,
			Algorithm:             "HS256",
			EnableRefreshRotation: true,
			MaxRefreshTokens:      5,
		},
		PasswordPolicy: &PasswordPolicyConfig{
			MinLength:             8,
			MaxLength:             128,
			RequireUppercase:      true,
			RequireLowercase:      true,
			RequireNumbers:        true,
			RequireSpecialChars:   true,
			ForbidCommonPasswords: true,
			PasswordHistoryCount:  5,
			PasswordExpiry:        90 * 24 * time.Hour,
			HashAlgorithm:         "bcrypt",
			HashCost:              10, // Lower cost for faster tests
		},
		MFA: &MFAConfig{
			EnableTOTP:            true,
			EnableSMS:             false,
			EnableEmail:           true,
			EnableWebAuthn:        false,
			EnableBackupCodes:     true,
			TOTPIssuer:            "HackAI-Test",
			TOTPDigits:            6,
			TOTPPeriod:            30,
			BackupCodeCount:       10,
			BackupCodeLength:      8,
			RequireMFAForAdmin:    true,
			MFAGracePeriod:        24 * time.Hour,
		},
		SessionConfig: &SessionConfig{
			DefaultTTL:            24 * time.Hour,
			MaxTTL:                7 * 24 * time.Hour,
			ExtendOnActivity:      true,
			MaxConcurrentSessions: 5,
			SessionCookieName:     "test_session",
			SessionCookieSecure:   false, // For testing
			SessionCookieHTTPOnly: true,
			SessionCookieSameSite: "strict",
		},
		RateLimit: &RateLimitConfig{
			LoginAttempts:         5,
			LoginWindow:           15 * time.Minute,
			PasswordResetAttempts: 3,
			PasswordResetWindow:   time.Hour,
			TokenRefreshAttempts:  10,
			TokenRefreshWindow:    time.Hour,
			GlobalRateLimit:       100,
			GlobalRateWindow:      time.Minute,
		},
		AccountLockout: &AccountLockoutConfig{
			MaxFailedAttempts:     3, // Lower for testing
			LockoutDuration:       5 * time.Minute,
			ProgressiveLockout:    true,
			LockoutMultiplier:     2.0,
			MaxLockoutDuration:    time.Hour,
			AutoUnlockEnabled:     true,
		},
		IPSecurity: &IPSecurityConfig{
			EnableWhitelist:       false,
			EnableBlacklist:       false,
			WhitelistedIPs:        []string{},
			BlacklistedIPs:        []string{},
			EnableGeoBlocking:     false,
			AllowedCountries:      []string{},
			BlockedCountries:      []string{},
			EnableVPNDetection:    false,
			BlockVPNs:             false,
		},
		DeviceManagement: &DeviceConfig{
			EnableDeviceTracking:  true,
			RequireDeviceApproval: false,
			DeviceApprovalTTL:     30 * 24 * time.Hour,
			MaxDevicesPerUser:     10,
			DeviceFingerprintAlgo: "sha256",
			TrustNewDevices:       true,
		},
		Authorization: &AuthorizationConfig{
			EnableRBAC:            true,
			EnableABAC:            false,
			DefaultRole:           "user",
			AdminRole:             "admin",
			SuperAdminRole:        "super_admin",
			PermissionCacheTime:   5 * time.Minute,
			PolicyEvaluationMode:  "strict",
		},
		SecurityMonitoring: &SecurityMonitorConfig{
			EnableThreatDetection:  true,
			EnableAnomalyDetection: true,
			ThreatScoreThreshold:   0.7,
			AnomalyThreshold:       0.8,
			MonitoringInterval:     time.Minute,
			AlertingEnabled:        true,
			AlertWebhookURL:        "",
		},
		AuditLogging: &AuditConfig{
			EnableAuditLogging:    true,
			AuditLogLevel:         "info",
			AuditLogFormat:        "json",
			AuditLogRetention:     90 * 24 * time.Hour,
			AuditLogCompression:   true,
			AuditLogEncryption:    false, // For testing
			IncludeSensitiveData:  false,
		},
	}
	
	// Create test user
	suite.testUser = &User{
		ID:                    "test-user-123",
		Username:              "testuser",
		Email:                 "test@example.com",
		PasswordHash:          "$2a$10$N9qo8uLOickgx2ZMRZoMye.IjPeqvAg/vqjxnHXtO.eMHZg7vTXOi", // "secret"
		PasswordHistory:       []string{},
		PasswordChangedAt:     time.Now().Add(-30 * 24 * time.Hour),
		Role:                  "user",
		Permissions:           []string{"read:profile", "update:profile"},
		IsActive:              true,
		IsLocked:              false,
		LockedUntil:           nil,
		FailedLoginAttempts:   0,
		LastLoginAt:           nil,
		LastLoginIP:           "",
		MFAEnabled:            false,
		MFASecret:             "",
		BackupCodes:           []string{},
		TrustedDevices:        []string{},
		CreatedAt:             time.Now().Add(-30 * 24 * time.Hour),
		UpdatedAt:             time.Now(),
		Metadata:              make(map[string]interface{}),
	}
}

// SetupTest sets up each test
func (suite *AdvancedAuthServiceTestSuite) SetupTest() {
	// Create mock stores
	suite.mockUserStore = new(MockUserStore)
	suite.mockSessionStore = new(MockSessionStore)
	suite.mockTokenStore = new(MockTokenStore)
	
	// Create auth service
	var err error
	suite.authService, err = NewAdvancedAuthService(
		suite.config,
		suite.logger,
		suite.mockUserStore,
		suite.mockSessionStore,
		suite.mockTokenStore,
	)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), suite.authService)
}

// TearDownTest cleans up after each test
func (suite *AdvancedAuthServiceTestSuite) TearDownTest() {
	if suite.mockUserStore != nil {
		suite.mockUserStore.AssertExpectations(suite.T())
	}
	if suite.mockSessionStore != nil {
		suite.mockSessionStore.AssertExpectations(suite.T())
	}
	if suite.mockTokenStore != nil {
		suite.mockTokenStore.AssertExpectations(suite.T())
	}
}

// Test successful login
func (suite *AdvancedAuthServiceTestSuite) TestLogin_Success() {
	// Setup mocks
	suite.mockUserStore.On("GetUserByEmail", suite.ctx, "test@example.com").Return(suite.testUser, nil)
	suite.mockUserStore.On("UpdateUser", suite.ctx, mock.AnythingOfType("*security.User")).Return(nil)
	suite.mockSessionStore.On("CreateSession", suite.ctx, mock.AnythingOfType("*security.AuthSession")).Return(nil)
	
	// Create login request
	loginReq := &LoginRequest{
		EmailOrUsername: "test@example.com",
		Password:        "secret",
		IPAddress:       "192.168.1.1",
		UserAgent:       "Mozilla/5.0 (Test Browser)",
		RememberMe:      false,
		TrustDevice:     false,
	}
	
	// Execute login
	response, err := suite.authService.Login(suite.ctx, loginReq)
	
	// Assertions
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), response)
	assert.True(suite.T(), response.Success)
	assert.NotEmpty(suite.T(), response.AccessToken)
	assert.NotEmpty(suite.T(), response.RefreshToken)
	assert.NotEmpty(suite.T(), response.SessionID)
	assert.False(suite.T(), response.RequiresMFA)
	assert.NotNil(suite.T(), response.User)
	assert.Equal(suite.T(), suite.testUser.ID, response.User.ID)
	assert.Equal(suite.T(), suite.testUser.Email, response.User.Email)
}

// Test login with invalid credentials
func (suite *AdvancedAuthServiceTestSuite) TestLogin_InvalidCredentials() {
	// Setup mocks
	suite.mockUserStore.On("GetUserByEmail", suite.ctx, "test@example.com").Return(suite.testUser, nil)
	
	// Create login request with wrong password
	loginReq := &LoginRequest{
		EmailOrUsername: "test@example.com",
		Password:        "wrongpassword",
		IPAddress:       "192.168.1.1",
		UserAgent:       "Mozilla/5.0 (Test Browser)",
	}
	
	// Execute login
	response, err := suite.authService.Login(suite.ctx, loginReq)
	
	// Assertions
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), response)
	assert.False(suite.T(), response.Success)
	assert.Empty(suite.T(), response.AccessToken)
	assert.Equal(suite.T(), "Invalid credentials.", response.Error)
}

// Test login with non-existent user
func (suite *AdvancedAuthServiceTestSuite) TestLogin_UserNotFound() {
	// Setup mocks
	suite.mockUserStore.On("GetUserByEmail", suite.ctx, "nonexistent@example.com").Return(nil, nil)
	
	// Create login request
	loginReq := &LoginRequest{
		EmailOrUsername: "nonexistent@example.com",
		Password:        "secret",
		IPAddress:       "192.168.1.1",
		UserAgent:       "Mozilla/5.0 (Test Browser)",
	}
	
	// Execute login
	response, err := suite.authService.Login(suite.ctx, loginReq)
	
	// Assertions
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), response)
	assert.False(suite.T(), response.Success)
	assert.Equal(suite.T(), "Invalid credentials.", response.Error)
}

// Test login with MFA enabled
func (suite *AdvancedAuthServiceTestSuite) TestLogin_MFARequired() {
	// Enable MFA for test user
	testUserWithMFA := *suite.testUser
	testUserWithMFA.MFAEnabled = true
	testUserWithMFA.MFASecret = "JBSWY3DPEHPK3PXP"
	
	// Setup mocks
	suite.mockUserStore.On("GetUserByEmail", suite.ctx, "test@example.com").Return(&testUserWithMFA, nil)
	
	// Create login request without MFA code
	loginReq := &LoginRequest{
		EmailOrUsername: "test@example.com",
		Password:        "secret",
		IPAddress:       "192.168.1.1",
		UserAgent:       "Mozilla/5.0 (Test Browser)",
	}
	
	// Execute login
	response, err := suite.authService.Login(suite.ctx, loginReq)
	
	// Assertions
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), response)
	assert.False(suite.T(), response.Success)
	assert.True(suite.T(), response.RequiresMFA)
	assert.Contains(suite.T(), response.MFAMethods, "totp")
	assert.Equal(suite.T(), "Multi-factor authentication required.", response.Error)
}

// Test token validation
func (suite *AdvancedAuthServiceTestSuite) TestValidateToken_Success() {
	// Generate a valid token first
	suite.mockUserStore.On("GetUserByEmail", suite.ctx, "test@example.com").Return(suite.testUser, nil)
	suite.mockUserStore.On("UpdateUser", suite.ctx, mock.AnythingOfType("*security.User")).Return(nil)
	suite.mockSessionStore.On("CreateSession", suite.ctx, mock.AnythingOfType("*security.AuthSession")).Return(nil)
	
	loginReq := &LoginRequest{
		EmailOrUsername: "test@example.com",
		Password:        "secret",
		IPAddress:       "192.168.1.1",
		UserAgent:       "Mozilla/5.0 (Test Browser)",
	}
	
	loginResponse, err := suite.authService.Login(suite.ctx, loginReq)
	require.NoError(suite.T(), err)
	require.True(suite.T(), loginResponse.Success)
	
	// Setup mocks for token validation
	suite.mockUserStore.On("GetUser", suite.ctx, suite.testUser.ID).Return(suite.testUser, nil)
	
	// Validate the token
	tokenResult, err := suite.authService.ValidateToken(suite.ctx, loginResponse.AccessToken)
	
	// Assertions
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), tokenResult)
	assert.True(suite.T(), tokenResult.Valid)
	assert.Equal(suite.T(), suite.testUser.ID, tokenResult.UserID)
	assert.Equal(suite.T(), suite.testUser.Email, tokenResult.Email)
	assert.Equal(suite.T(), suite.testUser.Role, tokenResult.Role)
}

// Test token validation with invalid token
func (suite *AdvancedAuthServiceTestSuite) TestValidateToken_Invalid() {
	// Validate an invalid token
	tokenResult, err := suite.authService.ValidateToken(suite.ctx, "invalid.token.here")
	
	// Assertions
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), tokenResult)
	assert.False(suite.T(), tokenResult.Valid)
	assert.Equal(suite.T(), "Invalid token", tokenResult.Error)
}

// Test logout
func (suite *AdvancedAuthServiceTestSuite) TestLogout_Success() {
	// Create a test session
	testSession := &AuthSession{
		ID:           "test-session-123",
		UserID:       suite.testUser.ID,
		IPAddress:    "192.168.1.1",
		UserAgent:    "Mozilla/5.0 (Test Browser)",
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		IsActive:     true,
		MFAVerified:  false,
		Permissions:  suite.testUser.Permissions,
		Metadata:     make(map[string]interface{}),
	}
	
	// Setup mocks
	suite.mockSessionStore.On("GetSession", suite.ctx, "test-session-123").Return(testSession, nil)
	suite.mockSessionStore.On("UpdateSession", suite.ctx, mock.AnythingOfType("*security.AuthSession")).Return(nil)
	
	// Execute logout
	err := suite.authService.Logout(suite.ctx, "test-session-123")
	
	// Assertions
	require.NoError(suite.T(), err)
}

// Run the test suite
func TestAdvancedAuthServiceTestSuite(t *testing.T) {
	suite.Run(t, new(AdvancedAuthServiceTestSuite))
}

// Benchmark tests
func BenchmarkLogin(b *testing.B) {
	// Setup
	logger, _ := logger.New(logger.Config{
		Level:  logger.LevelError,
		Format: "text",
		Output: "stdout",
	})
	
	config := DefaultAdvancedAuthConfig()
	config.PasswordPolicy.HashCost = 4 // Lower cost for benchmarking
	
	mockUserStore := new(MockUserStore)
	mockSessionStore := new(MockSessionStore)
	mockTokenStore := new(MockTokenStore)
	
	authService, _ := NewAdvancedAuthService(config, logger, mockUserStore, mockSessionStore, mockTokenStore)
	
	testUser := &User{
		ID:           "bench-user",
		Email:        "bench@example.com",
		PasswordHash: "$2a$04$N9qo8uLOickgx2ZMRZoMye.IjPeqvAg/vqjxnHXtO.eMHZg7vTXOi", // "secret" with cost 4
		IsActive:     true,
		Role:         "user",
		Permissions:  []string{"read:profile"},
	}
	
	mockUserStore.On("GetUserByEmail", mock.Anything, "bench@example.com").Return(testUser, nil)
	mockUserStore.On("UpdateUser", mock.Anything, mock.Anything).Return(nil)
	mockSessionStore.On("CreateSession", mock.Anything, mock.Anything).Return(nil)
	
	loginReq := &LoginRequest{
		EmailOrUsername: "bench@example.com",
		Password:        "secret",
		IPAddress:       "192.168.1.1",
		UserAgent:       "Benchmark",
	}
	
	ctx := context.Background()
	
	// Reset timer and run benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = authService.Login(ctx, loginReq)
	}
}
