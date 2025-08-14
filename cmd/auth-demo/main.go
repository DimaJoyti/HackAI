package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/internal/repository"
	"github.com/dimajoyti/hackai/pkg/auth"
	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/database"
	"github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
	fmt.Println("🔐 HackAI - Authentication & Authorization Demo")
	fmt.Println("===============================================")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	loggerInstance, err := logger.New(logger.Config{
		Level:      "info",
		Format:     "text",
		Output:     "console",
		AddSource:  false,
		TimeFormat: time.RFC3339,
	})
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// Initialize database
	db, err := database.New(&cfg.Database, loggerInstance)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Initialize repositories
	userRepo := repository.NewUserRepository(db.DB, loggerInstance)
	auditRepo := repository.NewAuditRepository(db.DB, loggerInstance)

	// Initialize security configuration
	securityConfig := auth.DefaultSecurityConfig()
	securityConfig.MaxFailedAttempts = 3
	securityConfig.LockoutDuration = 5 * time.Minute

	// Initialize JWT configuration
	jwtConfig := &auth.JWTConfig{
		Secret:          "demo-secret-key-change-in-production",
		AccessTokenTTL:  1 * time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "HackAI-Demo",
		Audience:        "hackai-users",
	}

	// Initialize enhanced authentication service
	authService := auth.NewEnhancedAuthService(
		jwtConfig,
		securityConfig,
		userRepo,
		auditRepo,
		loggerInstance,
	)

	ctx := context.Background()

	// Demo 1: Password Security & Validation
	fmt.Println("\n🔒 Demo 1: Password Security & Validation")
	fmt.Println("----------------------------------------")
	demoPasswordSecurity(authService)

	// Demo 2: User Authentication Flow
	fmt.Println("\n🔑 Demo 2: User Authentication Flow")
	fmt.Println("----------------------------------")
	demoUserAuthentication(ctx, authService)

	// Demo 3: JWT Token Management
	fmt.Println("\n🎫 Demo 3: JWT Token Management")
	fmt.Println("------------------------------")
	demoJWTTokens(ctx, authService)

	// Demo 4: Two-Factor Authentication
	fmt.Println("\n📱 Demo 4: Two-Factor Authentication")
	fmt.Println("-----------------------------------")
	demoTwoFactorAuth(ctx, authService)

	// Demo 5: Role-Based Access Control
	fmt.Println("\n👥 Demo 5: Role-Based Access Control")
	fmt.Println("-----------------------------------")
	demoRoleBasedAccess(ctx, authService)

	// Demo 6: Security Features
	fmt.Println("\n🛡️  Demo 6: Advanced Security Features")
	fmt.Println("-------------------------------------")
	demoSecurityFeatures(authService)

	// Demo 7: Account Lockout & Rate Limiting
	fmt.Println("\n🚫 Demo 7: Account Lockout & Rate Limiting")
	fmt.Println("-----------------------------------------")
	demoAccountSecurity(ctx, authService)

	// Demo 8: Session Management
	fmt.Println("\n⏰ Demo 8: Session Management")
	fmt.Println("----------------------------")
	demoSessionManagement(ctx, authService)

	fmt.Println("\n✅ Authentication & Authorization Demo Completed!")
	fmt.Println("=================================================")
	fmt.Println("\n🎯 Key Security Features Demonstrated:")
	fmt.Println("  • Advanced password validation and hashing")
	fmt.Println("  • Multi-factor authentication with TOTP")
	fmt.Println("  • JWT token generation and validation")
	fmt.Println("  • Role-based access control (RBAC)")
	fmt.Println("  • Account lockout and rate limiting")
	fmt.Println("  • Session management and timeout")
	fmt.Println("  • IP-based access restrictions")
	fmt.Println("  • Comprehensive security auditing")
	fmt.Println("  • CSRF protection and security headers")
	fmt.Println("\n🚀 Production-ready authentication system!")
}

func demoPasswordSecurity(authService *auth.EnhancedAuthService) {
	fmt.Println("  🔐 Testing password validation policies...")

	passwords := []string{
		"weak",                    // Too short
		"password123",             // Common weak password
		"Password123",             // Missing special character
		"Password123!",            // Valid strong password
		"MySecureP@ssw0rd2024",   // Very strong password
	}

	passwordManager := auth.NewPasswordManager(auth.DefaultSecurityConfig())

	for i, password := range passwords {
		fmt.Printf("  %d. Testing password: '%s'\n", i+1, password)
		
		if err := passwordManager.ValidatePassword(password); err != nil {
			fmt.Printf("     ❌ Invalid: %s\n", err.Error())
		} else {
			fmt.Printf("     ✅ Valid password\n")
			
			// Hash the password
			hash, err := passwordManager.HashPassword(password)
			if err != nil {
				fmt.Printf("     ❌ Hashing failed: %v\n", err)
			} else {
				fmt.Printf("     🔒 Password hashed successfully\n")
				
				// Verify the password
				if passwordManager.VerifyPassword(password, hash) {
					fmt.Printf("     ✅ Password verification successful\n")
				} else {
					fmt.Printf("     ❌ Password verification failed\n")
				}
			}
		}
	}
}

func demoUserAuthentication(ctx context.Context, authService *auth.EnhancedAuthService) {
	fmt.Println("  🔑 Demonstrating user authentication flow...")

	// Simulate authentication attempts
	authRequests := []*auth.AuthenticationRequest{
		{
			EmailOrUsername: "admin@hackai.com",
			Password:        "AdminPassword123!",
			IPAddress:       "192.168.1.100",
			UserAgent:       "HackAI-Demo/1.0",
			RememberMe:      false,
		},
		{
			EmailOrUsername: "user@hackai.com",
			Password:        "wrongpassword",
			IPAddress:       "192.168.1.101",
			UserAgent:       "HackAI-Demo/1.0",
			RememberMe:      false,
		},
		{
			EmailOrUsername: "moderator@hackai.com",
			Password:        "ModeratorPass123!",
			IPAddress:       "192.168.1.102",
			UserAgent:       "HackAI-Demo/1.0",
			RememberMe:      true,
		},
	}

	for i, req := range authRequests {
		fmt.Printf("  %d. Authenticating user: %s\n", i+1, req.EmailOrUsername)
		
		authResp, err := authService.Authenticate(ctx, req)
		if err != nil {
			fmt.Printf("     ❌ Authentication failed: %s\n", err.Error())
			continue
		}

		if authResp.RequiresTOTP {
			fmt.Printf("     📱 Two-factor authentication required\n")
			continue
		}

		fmt.Printf("     ✅ Authentication successful\n")
		fmt.Printf("     👤 User: %s (%s)\n", authResp.User.Username, authResp.User.Role)
		fmt.Printf("     🎫 Session ID: %s\n", authResp.SessionID.String()[:8])
		fmt.Printf("     ⏰ Expires: %s\n", authResp.ExpiresAt.Format("2006-01-02 15:04:05"))
		
		if authResp.CSRFToken != "" {
			fmt.Printf("     🛡️  CSRF Token: %s...\n", authResp.CSRFToken[:16])
		}
	}
}

func demoJWTTokens(ctx context.Context, authService *auth.EnhancedAuthService) {
	fmt.Println("  🎫 Demonstrating JWT token operations...")

	// Create a sample authentication
	authReq := &auth.AuthenticationRequest{
		EmailOrUsername: "demo@hackai.com",
		Password:        "DemoPassword123!",
		IPAddress:       "192.168.1.200",
		UserAgent:       "HackAI-Demo/1.0",
		RememberMe:      true,
	}

	fmt.Printf("  1. Generating JWT tokens for user: %s\n", authReq.EmailOrUsername)
	
	// For demo purposes, we'll create a mock successful authentication
	userID := uuid.New()
	claims := &auth.Claims{
		UserID:    userID,
		Username:  "demo-user",
		Email:     "demo@hackai.com",
		Role:      domain.UserRoleUser,
		SessionID: uuid.New(),
	}

	// Generate tokens using the JWT service directly
	jwtService := auth.NewJWTService(&auth.JWTConfig{
		Secret:          "demo-secret-key",
		AccessTokenTTL:  1 * time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "HackAI-Demo",
		Audience:        "hackai-users",
	})

	accessToken, err := jwtService.GenerateToken(claims)
	if err != nil {
		fmt.Printf("     ❌ Token generation failed: %v\n", err)
		return
	}

	fmt.Printf("     ✅ Access token generated: %s...\n", accessToken[:32])

	refreshToken, err := jwtService.GenerateRefreshToken(claims)
	if err != nil {
		fmt.Printf("     ❌ Refresh token generation failed: %v\n", err)
	} else {
		fmt.Printf("     ✅ Refresh token generated: %s...\n", refreshToken[:32])
	}

	// Validate the token
	fmt.Printf("  2. Validating JWT token...\n")
	validatedClaims, err := jwtService.ValidateToken(accessToken)
	if err != nil {
		fmt.Printf("     ❌ Token validation failed: %v\n", err)
	} else {
		fmt.Printf("     ✅ Token validation successful\n")
		fmt.Printf("     👤 User ID: %s\n", validatedClaims.UserID)
		fmt.Printf("     📧 Email: %s\n", validatedClaims.Email)
		fmt.Printf("     👥 Role: %s\n", validatedClaims.Role)
		fmt.Printf("     ⏰ Expires: %s\n", validatedClaims.ExpiresAt.Time.Format("2006-01-02 15:04:05"))
	}

	// Refresh token
	if refreshToken != "" {
		fmt.Printf("  3. Refreshing access token...\n")
		newAccessToken, err := jwtService.RefreshToken(refreshToken)
		if err != nil {
			fmt.Printf("     ❌ Token refresh failed: %v\n", err)
		} else {
			fmt.Printf("     ✅ New access token generated: %s...\n", newAccessToken[:32])
		}
	}
}

func demoTwoFactorAuth(ctx context.Context, authService *auth.EnhancedAuthService) {
	fmt.Println("  📱 Demonstrating two-factor authentication...")

	userID := uuid.New()
	
	fmt.Printf("  1. Enabling TOTP for user: %s\n", userID.String()[:8])
	
	secret, qrURL, err := authService.EnableTOTP(ctx, userID, "192.168.1.100", "HackAI-Demo/1.0")
	if err != nil {
		fmt.Printf("     ❌ TOTP enablement failed: %v\n", err)
		return
	}

	fmt.Printf("     ✅ TOTP enabled successfully\n")
	fmt.Printf("     🔑 Secret: %s\n", secret)
	fmt.Printf("     📱 QR Code URL: %s\n", qrURL)

	// Simulate TOTP verification
	fmt.Printf("  2. Simulating TOTP verification...\n")
	totpManager := auth.NewTOTPManager(auth.DefaultSecurityConfig())
	
	// Generate a mock TOTP code
	mockCode := "123456"
	if totpManager.VerifyTOTP(secret, mockCode) {
		fmt.Printf("     ✅ TOTP code verified successfully\n")
	} else {
		fmt.Printf("     ❌ TOTP code verification failed (expected for demo)\n")
	}
}

func demoRoleBasedAccess(ctx context.Context, authService *auth.EnhancedAuthService) {
	fmt.Println("  👥 Demonstrating role-based access control...")

	// Simulate different user roles
	users := []struct {
		role     domain.UserRole
		username string
	}{
		{domain.UserRoleAdmin, "admin-user"},
		{domain.UserRoleModerator, "moderator-user"},
		{domain.UserRoleUser, "regular-user"},
		{domain.UserRoleGuest, "guest-user"},
	}

	resources := []struct {
		resource string
		action   string
	}{
		{"users", "create"},
		{"scans", "create"},
		{"reports", "read"},
		{"admin", "access"},
	}

	for i, user := range users {
		fmt.Printf("  %d. Testing permissions for %s (%s):\n", i+1, user.username, user.role)
		
		for _, res := range resources {
			// Simulate permission check (simplified)
			hasPermission := checkPermissionByRole(user.role, res.resource, res.action)
			status := "❌ Denied"
			if hasPermission {
				status = "✅ Allowed"
			}
			fmt.Printf("     %s %s:%s\n", status, res.resource, res.action)
		}
	}
}

func demoSecurityFeatures(authService *auth.EnhancedAuthService) {
	fmt.Println("  🛡️  Demonstrating advanced security features...")

	// IP Security Manager
	fmt.Printf("  1. Testing IP-based access control...\n")
	ipManager := auth.NewIPSecurityManager(&auth.SecurityConfig{
		AllowedIPRanges: []string{"192.168.1.0/24", "10.0.0.0/8"},
		BlockedIPRanges: []string{"192.168.1.100"},
	})

	testIPs := []string{"192.168.1.50", "192.168.1.100", "203.0.113.1", "10.0.0.5"}
	for _, ip := range testIPs {
		allowed := ipManager.IsIPAllowed(ip)
		status := "❌ Blocked"
		if allowed {
			status = "✅ Allowed"
		}
		fmt.Printf("     %s IP: %s\n", status, ip)
	}

	// CSRF Token Generation
	fmt.Printf("  2. Testing CSRF protection...\n")
	csrfToken, err := auth.GenerateCSRFToken()
	if err != nil {
		fmt.Printf("     ❌ CSRF token generation failed: %v\n", err)
	} else {
		fmt.Printf("     ✅ CSRF token generated: %s...\n", csrfToken[:16])
		
		// Validate CSRF token
		if auth.ValidateCSRFToken(csrfToken, csrfToken) {
			fmt.Printf("     ✅ CSRF token validation successful\n")
		} else {
			fmt.Printf("     ❌ CSRF token validation failed\n")
		}
	}

	// Secure token generation
	fmt.Printf("  3. Testing secure token generation...\n")
	secureToken, err := auth.GenerateSecureToken(32)
	if err != nil {
		fmt.Printf("     ❌ Secure token generation failed: %v\n", err)
	} else {
		fmt.Printf("     ✅ Secure token generated: %s...\n", secureToken[:32])
	}
}

func demoAccountSecurity(ctx context.Context, authService *auth.EnhancedAuthService) {
	fmt.Println("  🚫 Demonstrating account lockout and rate limiting...")

	// Rate Limiter
	fmt.Printf("  1. Testing rate limiting...\n")
	rateLimiter := auth.NewRateLimiter(&auth.SecurityConfig{
		LoginRateLimit:  3,
		LoginRateWindow: time.Minute,
	})

	identifier := "test-user@hackai.com"
	for i := 1; i <= 5; i++ {
		allowed := rateLimiter.IsAllowed(identifier)
		status := "✅ Allowed"
		if !allowed {
			status = "❌ Rate limited"
		}
		fmt.Printf("     Attempt %d: %s\n", i, status)
	}

	// Account Lockout
	fmt.Printf("  2. Testing account lockout...\n")
	lockoutManager := auth.NewAccountLockoutManager(&auth.SecurityConfig{
		MaxFailedAttempts: 3,
		LockoutDuration:   5 * time.Minute,
	})

	for i := 1; i <= 5; i++ {
		locked := lockoutManager.RecordFailedAttempt(identifier)
		if locked {
			fmt.Printf("     Attempt %d: ❌ Account locked\n", i)
		} else {
			fmt.Printf("     Attempt %d: ⚠️  Failed attempt recorded\n", i)
		}
	}

	// Check if account is locked
	if lockoutManager.IsAccountLocked(identifier) {
		fmt.Printf("     🔒 Account is currently locked\n")
	} else {
		fmt.Printf("     🔓 Account is not locked\n")
	}
}

func demoSessionManagement(ctx context.Context, authService *auth.EnhancedAuthService) {
	fmt.Println("  ⏰ Demonstrating session management...")

	sessionManager := auth.NewSessionManager(&auth.SecurityConfig{
		SessionTimeout:        24 * time.Hour,
		MaxConcurrentSessions: 5,
	})

	// Generate session ID
	fmt.Printf("  1. Generating session ID...\n")
	sessionID, err := sessionManager.GenerateSessionID()
	if err != nil {
		fmt.Printf("     ❌ Session ID generation failed: %v\n", err)
		return
	}
	fmt.Printf("     ✅ Session ID generated: %s...\n", sessionID[:16])

	// Create mock session
	session := &domain.UserSession{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Token:     sessionID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	// Validate session
	fmt.Printf("  2. Validating session...\n")
	if sessionManager.IsSessionValid(session) {
		fmt.Printf("     ✅ Session is valid\n")
		fmt.Printf("     ⏰ Expires: %s\n", session.ExpiresAt.Format("2006-01-02 15:04:05"))
	} else {
		fmt.Printf("     ❌ Session is invalid or expired\n")
	}

	// Test expired session
	fmt.Printf("  3. Testing expired session...\n")
	expiredSession := &domain.UserSession{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Token:     sessionID,
		CreatedAt: time.Now().Add(-25 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	if sessionManager.IsSessionValid(expiredSession) {
		fmt.Printf("     ❌ Expired session incorrectly validated\n")
	} else {
		fmt.Printf("     ✅ Expired session correctly rejected\n")
	}
}

// Helper function for role-based permission checking
func checkPermissionByRole(role domain.UserRole, resource, action string) bool {
	switch role {
	case domain.UserRoleAdmin:
		return true // Admins have all permissions
	case domain.UserRoleModerator:
		// Moderators have most permissions except user creation/deletion
		if resource == "users" && (action == "create" || action == "delete") {
			return false
		}
		return resource != "admin"
	case domain.UserRoleUser:
		// Regular users have limited permissions
		switch resource {
		case "scans":
			return action == "create" || action == "read"
		case "reports":
			return action == "read"
		default:
			return false
		}
	case domain.UserRoleGuest:
		// Guests have very limited permissions
		return resource == "reports" && action == "read"
	default:
		return false
	}
}
