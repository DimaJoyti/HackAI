package benchmark

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/auth"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// BenchmarkPasswordHashing benchmarks password hashing performance
func BenchmarkPasswordHashing(b *testing.B) {
	config := auth.DefaultSecurityConfig()
	pm := auth.NewPasswordManager(config)
	password := "BenchmarkPassword123!"

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := pm.HashPassword(password)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkPasswordVerification benchmarks password verification performance
func BenchmarkPasswordVerification(b *testing.B) {
	config := auth.DefaultSecurityConfig()
	pm := auth.NewPasswordManager(config)
	password := "BenchmarkPassword123!"

	// Pre-hash the password
	hash, err := pm.HashPassword(password)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !pm.VerifyPassword(password, hash) {
				b.Fatal("password verification failed")
			}
		}
	})
}

// BenchmarkPasswordValidation benchmarks password validation performance
func BenchmarkPasswordValidation(b *testing.B) {
	config := auth.DefaultSecurityConfig()
	pm := auth.NewPasswordManager(config)
	password := "VeryStr0ng&UniqueP@ssw0rd!"

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			err := pm.ValidatePassword(password)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkJWTTokenGeneration benchmarks JWT token generation performance
func BenchmarkJWTTokenGeneration(b *testing.B) {
	config := &auth.JWTConfig{
		Secret:          "benchmark-secret-key",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "benchmark-issuer",
		Audience:        "benchmark-audience",
	}

	jwtService := auth.NewJWTService(config)
	claims := &auth.Claims{
		UserID:    uuid.New(),
		Username:  "benchmarkuser",
		Email:     "benchmark@example.com",
		Role:      domain.UserRoleUser,
		SessionID: uuid.New(),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := jwtService.GenerateToken(claims)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkJWTTokenValidation benchmarks JWT token validation performance
func BenchmarkJWTTokenValidation(b *testing.B) {
	config := &auth.JWTConfig{
		Secret:          "benchmark-secret-key",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "benchmark-issuer",
		Audience:        "benchmark-audience",
	}

	jwtService := auth.NewJWTService(config)
	claims := &auth.Claims{
		UserID:    uuid.New(),
		Username:  "benchmarkuser",
		Email:     "benchmark@example.com",
		Role:      domain.UserRoleUser,
		SessionID: uuid.New(),
	}

	// Pre-generate token
	token, err := jwtService.GenerateToken(claims)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := jwtService.ValidateToken(token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkTOTPSecretGeneration benchmarks TOTP secret generation performance
func BenchmarkTOTPSecretGeneration(b *testing.B) {
	config := auth.DefaultSecurityConfig()
	totpManager := auth.NewTOTPManager(config)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := totpManager.GenerateSecret()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkTOTPVerification benchmarks TOTP verification performance
func BenchmarkTOTPVerification(b *testing.B) {
	config := auth.DefaultSecurityConfig()
	totpManager := auth.NewTOTPManager(config)
	secret := "JBSWY3DPEHPK3PXP"
	code := "123456" // Mock code for benchmarking

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Note: This will always return false for the mock code,
			// but we're benchmarking the verification process
			totpManager.VerifyTOTP(secret, code)
		}
	})
}

// BenchmarkIPSecurityCheck benchmarks IP security checking performance
func BenchmarkIPSecurityCheck(b *testing.B) {
	config := &auth.SecurityConfig{
		AllowedIPRanges: []string{"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"},
		BlockedIPRanges: []string{"192.168.1.100", "10.0.0.50"},
	}

	ipManager := auth.NewIPSecurityManager(config)
	testIP := "192.168.1.50"

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ipManager.IsIPAllowed(testIP)
		}
	})
}

// BenchmarkRateLimiting benchmarks rate limiting performance
func BenchmarkRateLimiting(b *testing.B) {
	config := &auth.SecurityConfig{
		LoginRateLimit:  1000, // High limit to avoid blocking during benchmark
		LoginRateWindow: time.Minute,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rateLimiter := auth.NewRateLimiter(config)
		identifier := uuid.New().String()
		rateLimiter.IsAllowed(identifier)
	}
}

// BenchmarkAccountLockoutCheck benchmarks account lockout checking performance
func BenchmarkAccountLockoutCheck(b *testing.B) {
	config := &auth.SecurityConfig{
		MaxFailedAttempts: 5,
		LockoutDuration:   15 * time.Minute,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lockoutManager := auth.NewAccountLockoutManager(config)
		identifier := uuid.New().String()
		lockoutManager.IsAccountLocked(identifier)
	}
}

// BenchmarkSessionGeneration benchmarks session ID generation performance
func BenchmarkSessionGeneration(b *testing.B) {
	config := auth.DefaultSecurityConfig()
	sessionManager := auth.NewSessionManager(config)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := sessionManager.GenerateSessionID()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkCSRFTokenGeneration benchmarks CSRF token generation performance
func BenchmarkCSRFTokenGeneration(b *testing.B) {
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := auth.GenerateCSRFToken()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkCSRFTokenValidation benchmarks CSRF token validation performance
func BenchmarkCSRFTokenValidation(b *testing.B) {
	// Pre-generate token
	token, err := auth.GenerateCSRFToken()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			auth.ValidateCSRFToken(token, token)
		}
	})
}

// BenchmarkSecureTokenGeneration benchmarks secure token generation performance
func BenchmarkSecureTokenGeneration(b *testing.B) {
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := auth.GenerateSecureToken(32)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkCompleteAuthenticationFlow benchmarks the complete authentication flow
func BenchmarkCompleteAuthenticationFlow(b *testing.B) {
	// Setup
	log, err := logger.New(logger.Config{
		Level:  "error",
		Format: "text",
		Output: "console",
	})
	if err != nil {
		b.Fatal(err)
	}

	jwtConfig := &auth.JWTConfig{
		Secret:          "benchmark-secret-key",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "benchmark-issuer",
		Audience:        "benchmark-audience",
	}
	securityConfig := auth.DefaultSecurityConfig()

	// Create mock repositories
	userRepo := &MockUserRepository{}
	auditRepo := &MockAuditRepository{}

	authService := auth.NewEnhancedAuthService(jwtConfig, securityConfig, userRepo, auditRepo, log)

	// Pre-create test user
	passwordManager := auth.NewPasswordManager(securityConfig)
	hashedPassword, err := passwordManager.HashPassword("VeryStr0ng&UniqueP@ssw0rd!")
	if err != nil {
		b.Fatal(err)
	}

	user := &domain.User{
		ID:       uuid.New(),
		Username: "benchmarkuser",
		Email:    "benchmark@example.com",
		Password: hashedPassword,
		Role:     domain.UserRoleUser,
		Status:   domain.UserStatusActive,
	}

	// Setup mock expectations
	userRepo.SetUser(user)

	authReq := &auth.AuthenticationRequest{
		EmailOrUsername: "benchmark@example.com",
		Password:        "VeryStr0ng&UniqueP@ssw0rd!",
		IPAddress:       "192.168.1.100",
		UserAgent:       "benchmark-client",
		RememberMe:      false,
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := authService.Authenticate(context.Background(), authReq)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// MockUserRepository for benchmarking
type MockUserRepository struct {
	user *domain.User
}

func (m *MockUserRepository) SetUser(user *domain.User) {
	m.user = user
}

func (m *MockUserRepository) GetByEmail(email string) (*domain.User, error) {
	if m.user != nil && m.user.Email == email {
		return m.user, nil
	}
	return nil, errors.New("user not found")
}

func (m *MockUserRepository) GetByUsername(username string) (*domain.User, error) {
	if m.user != nil && m.user.Username == username {
		return m.user, nil
	}
	return nil, errors.New("user not found")
}

func (m *MockUserRepository) CreateSession(session *domain.UserSession) error {
	return nil
}

func (m *MockUserRepository) Update(user *domain.User) error {
	return nil
}

// Implement other required methods with no-op implementations
func (m *MockUserRepository) Create(user *domain.User) error                 { return nil }
func (m *MockUserRepository) GetByID(id uuid.UUID) (*domain.User, error)     { return nil, nil }
func (m *MockUserRepository) Delete(id uuid.UUID) error                      { return nil }
func (m *MockUserRepository) List(limit, offset int) ([]*domain.User, error) { return nil, nil }
func (m *MockUserRepository) Search(query string, limit, offset int) ([]*domain.User, error) {
	return nil, nil
}
func (m *MockUserRepository) GetSession(token string) (*domain.UserSession, error)    { return nil, nil }
func (m *MockUserRepository) DeleteSession(token string) error                        { return nil }
func (m *MockUserRepository) DeleteUserSessions(userID uuid.UUID) error               { return nil }
func (m *MockUserRepository) GrantPermission(permission *domain.UserPermission) error { return nil }
func (m *MockUserRepository) RevokePermission(userID uuid.UUID, resource, action string) error {
	return nil
}
func (m *MockUserRepository) GetUserPermissions(userID uuid.UUID) ([]*domain.UserPermission, error) {
	return nil, nil
}
func (m *MockUserRepository) HasPermission(userID uuid.UUID, resource, action string) (bool, error) {
	return false, nil
}
func (m *MockUserRepository) LogActivity(activity *domain.UserActivity) error { return nil }
func (m *MockUserRepository) GetUserActivity(userID uuid.UUID, limit, offset int) ([]*domain.UserActivity, error) {
	return nil, nil
}

// MockAuditRepository for benchmarking
type MockAuditRepository struct{}

func (m *MockAuditRepository) CreateAuditLog(log *domain.AuditLog) error {
	return nil
}

func (m *MockAuditRepository) GetAuditLog(id uuid.UUID) (*domain.AuditLog, error) {
	return nil, nil
}

func (m *MockAuditRepository) ListAuditLogs(filters map[string]interface{}, limit, offset int) ([]*domain.AuditLog, error) {
	return nil, nil
}

func (m *MockAuditRepository) SearchAuditLogs(query string, filters map[string]interface{}, limit, offset int) ([]*domain.AuditLog, error) {
	return nil, nil
}

func (m *MockAuditRepository) LogUserAction(userID uuid.UUID, sessionID *uuid.UUID, action, resource string, details map[string]interface{}) error {
	return nil
}

func (m *MockAuditRepository) LogSecurityAction(userID *uuid.UUID, action, resource string, riskLevel domain.RiskLevel, details map[string]interface{}) error {
	return nil
}

func (m *MockAuditRepository) DeleteExpiredAuditLogs(before time.Time) (int64, error) {
	return 0, nil
}

func (m *MockAuditRepository) CreateSecurityEvent(event *domain.SecurityEvent) error {
	return nil
}

func (m *MockAuditRepository) GetSecurityEvent(id uuid.UUID) (*domain.SecurityEvent, error) {
	return nil, nil
}

func (m *MockAuditRepository) UpdateSecurityEvent(event *domain.SecurityEvent) error {
	return nil
}

func (m *MockAuditRepository) ListSecurityEvents(filters map[string]interface{}, limit, offset int) ([]*domain.SecurityEvent, error) {
	return nil, nil
}

func (m *MockAuditRepository) CreateThreatIntelligence(intel *domain.ThreatIntelligence) error {
	return nil
}

func (m *MockAuditRepository) GetThreatIntelligence(id uuid.UUID) (*domain.ThreatIntelligence, error) {
	return nil, nil
}

func (m *MockAuditRepository) UpdateThreatIntelligence(intel *domain.ThreatIntelligence) error {
	return nil
}

func (m *MockAuditRepository) FindThreatIntelligence(value string) (*domain.ThreatIntelligence, error) {
	return nil, nil
}

func (m *MockAuditRepository) ListThreatIntelligence(filters map[string]interface{}, limit, offset int) ([]*domain.ThreatIntelligence, error) {
	return nil, nil
}

func (m *MockAuditRepository) CreateSystemMetrics(metrics []*domain.SystemMetrics) error {
	return nil
}

func (m *MockAuditRepository) GetSystemMetrics(filters map[string]interface{}, from, to time.Time) ([]*domain.SystemMetrics, error) {
	return nil, nil
}

func (m *MockAuditRepository) DeleteOldMetrics(before time.Time) (int64, error) {
	return 0, nil
}

func (m *MockAuditRepository) CreateBackupRecord(record *domain.BackupRecord) error {
	return nil
}

func (m *MockAuditRepository) GetBackupRecord(id uuid.UUID) (*domain.BackupRecord, error) {
	return nil, nil
}

func (m *MockAuditRepository) UpdateBackupRecord(record *domain.BackupRecord) error {
	return nil
}

func (m *MockAuditRepository) ListBackupRecords(limit, offset int) ([]*domain.BackupRecord, error) {
	return nil, nil
}

func (m *MockAuditRepository) LogAPICall(userID *uuid.UUID, method, path, ipAddress, userAgent string, statusCode int, duration int64) error {
	return nil
}
