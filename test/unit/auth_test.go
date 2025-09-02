package unit

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/auth"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// MockUserRepository is a mock implementation of domain.UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(user *domain.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) GetByID(id uuid.UUID) (*domain.User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(email string) (*domain.User, error) {
	args := m.Called(email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) GetByUsername(username string) (*domain.User, error) {
	args := m.Called(username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) Update(user *domain.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(id uuid.UUID) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserRepository) List(limit, offset int) ([]*domain.User, error) {
	args := m.Called(limit, offset)
	return args.Get(0).([]*domain.User), args.Error(1)
}

func (m *MockUserRepository) Search(query string, limit, offset int) ([]*domain.User, error) {
	args := m.Called(query, limit, offset)
	return args.Get(0).([]*domain.User), args.Error(1)
}

func (m *MockUserRepository) CreateSession(session *domain.UserSession) error {
	args := m.Called(session)
	return args.Error(0)
}

func (m *MockUserRepository) GetSession(token string) (*domain.UserSession, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.UserSession), args.Error(1)
}

func (m *MockUserRepository) DeleteSession(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

func (m *MockUserRepository) DeleteUserSessions(userID uuid.UUID) error {
	args := m.Called(userID)
	return args.Error(0)
}

func (m *MockUserRepository) GrantPermission(permission *domain.UserPermission) error {
	args := m.Called(permission)
	return args.Error(0)
}

func (m *MockUserRepository) RevokePermission(userID uuid.UUID, resource, action string) error {
	args := m.Called(userID, resource, action)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserPermissions(userID uuid.UUID) ([]*domain.UserPermission, error) {
	args := m.Called(userID)
	return args.Get(0).([]*domain.UserPermission), args.Error(1)
}

func (m *MockUserRepository) HasPermission(userID uuid.UUID, resource, action string) (bool, error) {
	args := m.Called(userID, resource, action)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) LogActivity(activity *domain.UserActivity) error {
	args := m.Called(activity)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserActivity(userID uuid.UUID, limit, offset int) ([]*domain.UserActivity, error) {
	args := m.Called(userID, limit, offset)
	return args.Get(0).([]*domain.UserActivity), args.Error(1)
}

func (m *MockUserRepository) GetByFirebaseUID(firebaseUID string) (*domain.User, error) {
	args := m.Called(firebaseUID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) UpdateFirebaseUID(userID uuid.UUID, firebaseUID string) error {
	args := m.Called(userID, firebaseUID)
	return args.Error(0)
}

func (m *MockUserRepository) ListUsersWithoutFirebaseUID(limit, offset int) ([]*domain.User, error) {
	args := m.Called(limit, offset)
	return args.Get(0).([]*domain.User), args.Error(1)
}

// MockAuditRepository is a mock implementation of domain.AuditRepository
type MockAuditRepository struct {
	mock.Mock
}

func (m *MockAuditRepository) CreateAuditLog(log *domain.AuditLog) error {
	args := m.Called(log)
	return args.Error(0)
}

func (m *MockAuditRepository) GetAuditLog(id uuid.UUID) (*domain.AuditLog, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.AuditLog), args.Error(1)
}

func (m *MockAuditRepository) ListAuditLogs(filters map[string]interface{}, limit, offset int) ([]*domain.AuditLog, error) {
	args := m.Called(filters, limit, offset)
	return args.Get(0).([]*domain.AuditLog), args.Error(1)
}

func (m *MockAuditRepository) SearchAuditLogs(query string, filters map[string]interface{}, limit, offset int) ([]*domain.AuditLog, error) {
	args := m.Called(query, filters, limit, offset)
	return args.Get(0).([]*domain.AuditLog), args.Error(1)
}

func (m *MockAuditRepository) LogUserAction(userID uuid.UUID, sessionID *uuid.UUID, action, resource string, details map[string]interface{}) error {
	args := m.Called(userID, sessionID, action, resource, details)
	return args.Error(0)
}

func (m *MockAuditRepository) LogSecurityAction(userID *uuid.UUID, action, resource string, riskLevel domain.RiskLevel, details map[string]interface{}) error {
	args := m.Called(userID, action, resource, riskLevel, details)
	return args.Error(0)
}

func (m *MockAuditRepository) DeleteExpiredAuditLogs(before time.Time) (int64, error) {
	args := m.Called(before)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAuditRepository) CreateSecurityEvent(event *domain.SecurityEvent) error {
	args := m.Called(event)
	return args.Error(0)
}

func (m *MockAuditRepository) GetSecurityEvent(id uuid.UUID) (*domain.SecurityEvent, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.SecurityEvent), args.Error(1)
}

func (m *MockAuditRepository) UpdateSecurityEvent(event *domain.SecurityEvent) error {
	args := m.Called(event)
	return args.Error(0)
}

func (m *MockAuditRepository) ListSecurityEvents(filters map[string]interface{}, limit, offset int) ([]*domain.SecurityEvent, error) {
	args := m.Called(filters, limit, offset)
	return args.Get(0).([]*domain.SecurityEvent), args.Error(1)
}

func (m *MockAuditRepository) CreateThreatIntelligence(intel *domain.ThreatIntelligence) error {
	args := m.Called(intel)
	return args.Error(0)
}

func (m *MockAuditRepository) GetThreatIntelligence(id uuid.UUID) (*domain.ThreatIntelligence, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.ThreatIntelligence), args.Error(1)
}

func (m *MockAuditRepository) UpdateThreatIntelligence(intel *domain.ThreatIntelligence) error {
	args := m.Called(intel)
	return args.Error(0)
}

func (m *MockAuditRepository) FindThreatIntelligence(value string) (*domain.ThreatIntelligence, error) {
	args := m.Called(value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.ThreatIntelligence), args.Error(1)
}

func (m *MockAuditRepository) ListThreatIntelligence(filters map[string]interface{}, limit, offset int) ([]*domain.ThreatIntelligence, error) {
	args := m.Called(filters, limit, offset)
	return args.Get(0).([]*domain.ThreatIntelligence), args.Error(1)
}

func (m *MockAuditRepository) CreateSystemMetrics(metrics []*domain.SystemMetrics) error {
	args := m.Called(metrics)
	return args.Error(0)
}

func (m *MockAuditRepository) GetSystemMetrics(filters map[string]interface{}, from, to time.Time) ([]*domain.SystemMetrics, error) {
	args := m.Called(filters, from, to)
	return args.Get(0).([]*domain.SystemMetrics), args.Error(1)
}

func (m *MockAuditRepository) DeleteOldMetrics(before time.Time) (int64, error) {
	args := m.Called(before)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAuditRepository) CreateBackupRecord(record *domain.BackupRecord) error {
	args := m.Called(record)
	return args.Error(0)
}

func (m *MockAuditRepository) GetBackupRecord(id uuid.UUID) (*domain.BackupRecord, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.BackupRecord), args.Error(1)
}

func (m *MockAuditRepository) UpdateBackupRecord(record *domain.BackupRecord) error {
	args := m.Called(record)
	return args.Error(0)
}

func (m *MockAuditRepository) ListBackupRecords(limit, offset int) ([]*domain.BackupRecord, error) {
	args := m.Called(limit, offset)
	return args.Get(0).([]*domain.BackupRecord), args.Error(1)
}

func (m *MockAuditRepository) LogAPICall(userID *uuid.UUID, method, path, ipAddress, userAgent string, statusCode int, duration int64) error {
	args := m.Called(userID, method, path, ipAddress, userAgent, statusCode, duration)
	return args.Error(0)
}

// Test Password Manager
func TestPasswordManager_HashPassword(t *testing.T) {
	config := auth.DefaultSecurityConfig()
	pm := auth.NewPasswordManager(config)

	password := "TestPassword123!"
	hash, err := pm.HashPassword(password)

	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEqual(t, password, hash)
	assert.True(t, len(hash) > 50) // bcrypt hashes are typically 60 characters
}

func TestPasswordManager_VerifyPassword(t *testing.T) {
	config := auth.DefaultSecurityConfig()
	pm := auth.NewPasswordManager(config)

	password := "TestPassword123!"
	hash, err := pm.HashPassword(password)
	require.NoError(t, err)

	// Test correct password
	assert.True(t, pm.VerifyPassword(password, hash))

	// Test incorrect password
	assert.False(t, pm.VerifyPassword("WrongPassword", hash))
}

func TestPasswordManager_ValidatePassword(t *testing.T) {
	config := auth.DefaultSecurityConfig()
	pm := auth.NewPasswordManager(config)

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid strong password",
			password: "VeryStr0ng&UniqueP@ssw0rd!",
			wantErr:  false,
		},
		{
			name:     "too short",
			password: "Short1!",
			wantErr:  true,
		},
		{
			name:     "no uppercase",
			password: "lowercase123!",
			wantErr:  true,
		},
		{
			name:     "no lowercase",
			password: "UPPERCASE123!",
			wantErr:  true,
		},
		{
			name:     "no numbers",
			password: "NoNumbers!",
			wantErr:  true,
		},
		{
			name:     "no special chars",
			password: "NoSpecialChars123",
			wantErr:  true,
		},
		{
			name:     "weak common password",
			password: "Password123!",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pm.ValidatePassword(tt.password)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Test JWT Service
func TestJWTService_GenerateAndValidateToken(t *testing.T) {
	config := &auth.JWTConfig{
		Secret:          "test-secret-key",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "test-issuer",
		Audience:        "test-audience",
	}

	jwtService := auth.NewJWTService(config)

	userID := uuid.New()
	sessionID := uuid.New()
	claims := &auth.Claims{
		UserID:    userID,
		Username:  "testuser",
		Email:     "test@example.com",
		Role:      domain.UserRoleUser,
		SessionID: sessionID,
	}

	// Generate token
	token, err := jwtService.GenerateToken(claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Validate token
	validatedClaims, err := jwtService.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, userID, validatedClaims.UserID)
	assert.Equal(t, "testuser", validatedClaims.Username)
	assert.Equal(t, "test@example.com", validatedClaims.Email)
	assert.Equal(t, domain.UserRoleUser, validatedClaims.Role)
	assert.Equal(t, sessionID, validatedClaims.SessionID)
}

func TestJWTService_InvalidToken(t *testing.T) {
	config := &auth.JWTConfig{
		Secret:          "test-secret-key",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "test-issuer",
		Audience:        "test-audience",
	}

	jwtService := auth.NewJWTService(config)

	// Test invalid token
	_, err := jwtService.ValidateToken("invalid-token")
	assert.Error(t, err)

	// Test empty token
	_, err = jwtService.ValidateToken("")
	assert.Error(t, err)
}

// Test TOTP Manager
func TestTOTPManager_GenerateSecret(t *testing.T) {
	config := auth.DefaultSecurityConfig()
	totpManager := auth.NewTOTPManager(config)

	secret, err := totpManager.GenerateSecret()
	require.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.True(t, len(secret) > 20) // Base32 encoded 160-bit secret should be longer
}

func TestTOTPManager_GenerateQRCodeURL(t *testing.T) {
	config := auth.DefaultSecurityConfig()
	totpManager := auth.NewTOTPManager(config)

	secret := "JBSWY3DPEHPK3PXP"
	accountName := "test@example.com"

	qrURL := totpManager.GenerateQRCodeURL(secret, accountName)
	assert.Contains(t, qrURL, "otpauth://totp/")
	assert.Contains(t, qrURL, secret)
	assert.Contains(t, qrURL, accountName)
	assert.Contains(t, qrURL, config.TOTPIssuer)
}

// Test Security Features
func TestIPSecurityManager_IsIPAllowed(t *testing.T) {
	config := &auth.SecurityConfig{
		AllowedIPRanges: []string{"192.168.1.0/24", "10.0.0.0/8"},
		BlockedIPRanges: []string{"192.168.1.100"},
	}

	ipManager := auth.NewIPSecurityManager(config)

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "allowed IP in range",
			ip:       "192.168.1.50",
			expected: true,
		},
		{
			name:     "blocked IP",
			ip:       "192.168.1.100",
			expected: false,
		},
		{
			name:     "IP outside allowed range",
			ip:       "203.0.113.1",
			expected: false,
		},
		{
			name:     "allowed IP in second range",
			ip:       "10.0.0.5",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ipManager.IsIPAllowed(tt.ip)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRateLimiter_IsAllowed(t *testing.T) {
	config := &auth.SecurityConfig{
		LoginRateLimit:  3,
		LoginRateWindow: time.Minute,
	}

	rateLimiter := auth.NewRateLimiter(config)
	identifier := "test-user"

	// First 3 attempts should be allowed
	for i := 0; i < 3; i++ {
		assert.True(t, rateLimiter.IsAllowed(identifier))
	}

	// 4th attempt should be blocked
	assert.False(t, rateLimiter.IsAllowed(identifier))
}

func TestAccountLockoutManager(t *testing.T) {
	config := &auth.SecurityConfig{
		MaxFailedAttempts: 3,
		LockoutDuration:   5 * time.Minute,
	}

	lockoutManager := auth.NewAccountLockoutManager(config)
	identifier := "test-user"

	// First 2 attempts should not lock account
	assert.False(t, lockoutManager.RecordFailedAttempt(identifier))
	assert.False(t, lockoutManager.RecordFailedAttempt(identifier))
	assert.False(t, lockoutManager.IsAccountLocked(identifier))

	// 3rd attempt should lock account
	assert.True(t, lockoutManager.RecordFailedAttempt(identifier))
	assert.True(t, lockoutManager.IsAccountLocked(identifier))

	// Clear attempts should unlock account
	lockoutManager.ClearFailedAttempts(identifier)
	assert.False(t, lockoutManager.IsAccountLocked(identifier))
}

// Test Enhanced Auth Service
func TestEnhancedAuthService_Authenticate(t *testing.T) {
	// Setup mocks
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)

	// Create logger
	log, err := logger.New(logger.Config{
		Level:  "error", // Reduce log noise in tests
		Format: "text",
		Output: "console",
	})
	require.NoError(t, err)

	// Create auth service
	jwtConfig := &auth.JWTConfig{
		Secret:          "test-secret",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "test",
		Audience:        "test",
	}
	securityConfig := auth.DefaultSecurityConfig()

	authService := auth.NewEnhancedAuthService(jwtConfig, securityConfig, userRepo, auditRepo, log)

	// Create test user
	userID := uuid.New()
	hashedPassword, _ := auth.NewPasswordManager(securityConfig).HashPassword("VeryStr0ng&UniqueP@ssw0rd!")
	user := &domain.User{
		ID:       userID,
		Username: "testuser",
		Email:    "test@example.com",
		Password: hashedPassword,
		Role:     domain.UserRoleUser,
		Status:   domain.UserStatusActive,
	}

	// Setup mock expectations
	userRepo.On("GetByEmail", "test@example.com").Return(user, nil)
	userRepo.On("CreateSession", mock.AnythingOfType("*domain.UserSession")).Return(nil)
	userRepo.On("Update", mock.AnythingOfType("*domain.User")).Return(nil)
	auditRepo.On("LogUserAction", mock.AnythingOfType("uuid.UUID"), mock.AnythingOfType("*uuid.UUID"), "login", "authentication", mock.Anything).Return(nil)
	auditRepo.On("LogSecurityAction", mock.AnythingOfType("*uuid.UUID"), "login", "authentication", mock.AnythingOfType("domain.RiskLevel"), mock.Anything).Return(nil)

	// Test authentication
	authReq := &auth.AuthenticationRequest{
		EmailOrUsername: "test@example.com",
		Password:        "VeryStr0ng&UniqueP@ssw0rd!",
		IPAddress:       "192.168.1.100",
		UserAgent:       "test-agent",
		RememberMe:      false,
	}

	authResp, err := authService.Authenticate(context.Background(), authReq)
	require.NoError(t, err)
	assert.NotNil(t, authResp)
	assert.Equal(t, user.ID, authResp.User.ID)
	assert.NotEmpty(t, authResp.AccessToken)
	assert.False(t, authResp.RequiresTOTP)

	// Verify mock expectations
	userRepo.AssertExpectations(t)
	auditRepo.AssertExpectations(t)
}
