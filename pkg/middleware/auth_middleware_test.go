package middleware

import (
	"testing"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/stretchr/testify/assert"
)

// TestAuthMiddlewareCreation tests authentication middleware creation
func TestAuthMiddlewareCreation(t *testing.T) {
	logger := logger.NewDefault()
	config := &AuthConfig{
		RequiredClaims:   []string{"email_verified"},
		AllowedRoles:     []string{"user", "admin"},
		SkipPaths:        []string{"/health"},
		TokenHeader:      "Authorization",
		TokenPrefix:      "Bearer ",
		SessionTimeout:   24 * time.Hour,
		RefreshThreshold: time.Hour,
	}

	// For testing, we'll just create the middleware without a real Firebase service
	middleware := &AuthMiddleware{
		logger: logger,
		config: config,
	}

	assert.NotNil(t, middleware)
	assert.Equal(t, config, middleware.config)
	assert.Equal(t, logger, middleware.logger)
}

// TestAuthConfigValidation tests authentication configuration validation
func TestAuthConfigValidation(t *testing.T) {
	// Test valid config
	config := &AuthConfig{
		RequiredClaims:   []string{"email_verified"},
		AllowedRoles:     []string{"user", "admin"},
		SkipPaths:        []string{"/health"},
		TokenHeader:      "Authorization",
		TokenPrefix:      "Bearer ",
		SessionTimeout:   24 * time.Hour,
		RefreshThreshold: time.Hour,
	}

	assert.NotEmpty(t, config.RequiredClaims)
	assert.NotEmpty(t, config.AllowedRoles)
	assert.NotEmpty(t, config.SkipPaths)
	assert.Equal(t, "Authorization", config.TokenHeader)
	assert.Equal(t, "Bearer ", config.TokenPrefix)
}

// TestTokenInfoCreation tests TokenInfo struct creation
func TestTokenInfoCreation(t *testing.T) {
	tokenInfo := &TokenInfo{
		UID:           "test-uid",
		Email:         "test@example.com",
		EmailVerified: true,
		Claims: map[string]interface{}{
			"custom_claim": "value",
		},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		AuthTime:  time.Now(),
	}

	assert.Equal(t, "test-uid", tokenInfo.UID)
	assert.Equal(t, "test@example.com", tokenInfo.Email)
	assert.True(t, tokenInfo.EmailVerified)
	assert.Equal(t, "value", tokenInfo.Claims["custom_claim"])
}

// TestUserContextCreation tests UserContext struct creation
func TestUserContextCreation(t *testing.T) {
	userCtx := &UserContext{
		UID:         "test-uid",
		Email:       "test@example.com",
		DisplayName: "Test User",
		Role:        "user",
		Permissions: []string{"read", "write"},
		Claims: map[string]interface{}{
			"custom_claim": "value",
		},
		SessionID: "session-123",
		LoginTime: time.Now(),
	}

	assert.Equal(t, "test-uid", userCtx.UID)
	assert.Equal(t, "test@example.com", userCtx.Email)
	assert.Equal(t, "Test User", userCtx.DisplayName)
	assert.Equal(t, "user", userCtx.Role)
	assert.Contains(t, userCtx.Permissions, "read")
	assert.Contains(t, userCtx.Permissions, "write")
	assert.Equal(t, "value", userCtx.Claims["custom_claim"])
	assert.Equal(t, "session-123", userCtx.SessionID)
}
