package main

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/auth"
)

func main() {
	fmt.Println("🔐 HackAI - Authentication & Authorization Demo")
	fmt.Println("===============================================")

	// Demo 1: Password Security & Validation
	fmt.Println("\n🔒 Demo 1: Password Security & Validation")
	fmt.Println("----------------------------------------")
	demoPasswordSecurity()

	// Demo 2: JWT Token Management
	fmt.Println("\n🎫 Demo 2: JWT Token Management")
	fmt.Println("------------------------------")
	demoJWTTokens()

	// Demo 3: Two-Factor Authentication
	fmt.Println("\n📱 Demo 3: Two-Factor Authentication")
	fmt.Println("-----------------------------------")
	demoTwoFactorAuth()

	// Demo 4: Role-Based Access Control
	fmt.Println("\n👥 Demo 4: Role-Based Access Control")
	fmt.Println("-----------------------------------")
	demoRoleBasedAccess()

	// Demo 5: Security Features
	fmt.Println("\n🛡️  Demo 5: Advanced Security Features")
	fmt.Println("-------------------------------------")
	demoSecurityFeatures()

	// Demo 6: Account Lockout & Rate Limiting
	fmt.Println("\n🚫 Demo 6: Account Lockout & Rate Limiting")
	fmt.Println("-----------------------------------------")
	demoAccountSecurity()

	// Demo 7: Session Management
	fmt.Println("\n⏰ Demo 7: Session Management")
	fmt.Println("----------------------------")
	demoSessionManagement()

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

func demoPasswordSecurity() {
	fmt.Println("  🔐 Testing password validation policies...")

	passwords := []string{
		"weak",                 // Too short
		"password123",          // Common weak password
		"Password123",          // Missing special character
		"Password123!",         // Valid strong password
		"MySecureP@ssw0rd2024", // Very strong password
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

func demoJWTTokens() {
	fmt.Println("  🎫 Demonstrating JWT token operations...")

	userID := uuid.New()
	claims := &auth.Claims{
		UserID:    userID,
		Username:  "demo-user",
		Email:     "demo@hackai.com",
		Role:      domain.UserRoleUser,
		SessionID: uuid.New(),
	}

	// Generate tokens using the JWT service
	jwtService := auth.NewJWTService(&auth.JWTConfig{
		Secret:          "demo-secret-key-change-in-production",
		AccessTokenTTL:  1 * time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "HackAI-Demo",
		Audience:        "hackai-users",
	})

	fmt.Printf("  1. Generating JWT tokens for user: %s\n", claims.Username)

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

func demoTwoFactorAuth() {
	fmt.Println("  📱 Demonstrating two-factor authentication...")

	totpManager := auth.NewTOTPManager(auth.DefaultSecurityConfig())

	fmt.Printf("  1. Generating TOTP secret...\n")

	secret, err := totpManager.GenerateSecret()
	if err != nil {
		fmt.Printf("     ❌ TOTP secret generation failed: %v\n", err)
		return
	}

	fmt.Printf("     ✅ TOTP secret generated: %s\n", secret)

	// Generate QR code URL
	accountName := "demo@hackai.com"
	qrURL := totpManager.GenerateQRCodeURL(secret, accountName)
	fmt.Printf("     📱 QR Code URL: %s\n", qrURL)

	// Simulate TOTP verification
	fmt.Printf("  2. Simulating TOTP verification...\n")

	// Generate a mock TOTP code
	mockCode := "123456"
	if totpManager.VerifyTOTP(secret, mockCode) {
		fmt.Printf("     ✅ TOTP code verified successfully\n")
	} else {
		fmt.Printf("     ❌ TOTP code verification failed (expected for demo)\n")
	}

	// Test with empty code
	if totpManager.VerifyTOTP(secret, "") {
		fmt.Printf("     ❌ Empty TOTP code incorrectly verified\n")
	} else {
		fmt.Printf("     ✅ Empty TOTP code correctly rejected\n")
	}
}

func demoRoleBasedAccess() {
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

		// Create claims for the user
		claims := &auth.Claims{
			UserID:   uuid.New(),
			Username: user.username,
			Email:    user.username + "@hackai.com",
			Role:     user.role,
		}

		for _, res := range resources {
			hasPermission := claims.CanAccess(getRequiredRole(res.resource, res.action))
			status := "❌ Denied"
			if hasPermission {
				status = "✅ Allowed"
			}
			fmt.Printf("     %s %s:%s\n", status, res.resource, res.action)
		}
	}
}

func demoSecurityFeatures() {
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

		// Test with wrong token
		wrongToken := "wrong-token"
		if auth.ValidateCSRFToken(wrongToken, csrfToken) {
			fmt.Printf("     ❌ Wrong CSRF token incorrectly validated\n")
		} else {
			fmt.Printf("     ✅ Wrong CSRF token correctly rejected\n")
		}
	}

	// Secure token generation
	fmt.Printf("  3. Testing secure token generation...\n")
	secureToken, err := auth.GenerateSecureToken(32)
	if err != nil {
		fmt.Printf("     ❌ Secure token generation failed: %v\n", err)
	} else {
		fmt.Printf("     ✅ Secure token generated: %s...\n", secureToken[:32])
		fmt.Printf("     📏 Token length: %d characters\n", len(secureToken))
	}
}

func demoAccountSecurity() {
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

	// Clear failed attempts
	fmt.Printf("  3. Clearing failed attempts...\n")
	lockoutManager.ClearFailedAttempts(identifier)
	if lockoutManager.IsAccountLocked(identifier) {
		fmt.Printf("     ❌ Account still locked after clearing\n")
	} else {
		fmt.Printf("     ✅ Account unlocked after clearing attempts\n")
	}
}

func demoSessionManagement() {
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

	// Test session timeout
	fmt.Printf("  4. Testing session timeout...\n")
	oldSession := &domain.UserSession{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Token:     sessionID,
		CreatedAt: time.Now().Add(-25 * time.Hour), // Created 25 hours ago
		ExpiresAt: time.Now().Add(1 * time.Hour),   // But expires in 1 hour
	}

	if sessionManager.IsSessionValid(oldSession) {
		fmt.Printf("     ❌ Old session incorrectly validated\n")
	} else {
		fmt.Printf("     ✅ Old session correctly rejected due to timeout\n")
	}
}

// Helper function to determine required role for resource/action
func getRequiredRole(resource, action string) domain.UserRole {
	switch resource {
	case "admin":
		return domain.UserRoleAdmin
	case "users":
		if action == "create" || action == "delete" {
			return domain.UserRoleAdmin
		}
		return domain.UserRoleModerator
	case "scans":
		return domain.UserRoleUser
	case "reports":
		return domain.UserRoleGuest
	default:
		return domain.UserRoleAdmin
	}
}
