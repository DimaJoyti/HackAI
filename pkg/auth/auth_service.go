package auth

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var authServiceTracer = otel.Tracer("hackai/auth/auth_service")

// AuthenticationService provides comprehensive authentication services
type AuthenticationService struct {
	jwtManager          *JWTManager
	oauth2Manager       *OAuth2Manager
	refreshTokenManager *RefreshTokenManager
	logger              *logger.Logger
	config              *AuthConfig
}

// AuthConfig represents authentication service configuration
type AuthConfig struct {
	JWT          *config.JWTConfig      `json:"jwt"`
	OAuth2       *OAuth2Config          `json:"oauth2"`
	RefreshToken *RefreshTokenConfig    `json:"refresh_token"`
	Security     *SecurityConfig        `json:"security"`
}



// NewAuthenticationService creates a new authentication service
func NewAuthenticationService(config *AuthConfig, logger *logger.Logger) (*AuthenticationService, error) {
	// Initialize JWT manager
	jwtManager := NewJWTManager(config.JWT)

	// Initialize OAuth2 manager
	oauth2Manager := NewOAuth2Manager(config.OAuth2, logger)

	// Initialize refresh token manager
	refreshTokenManager := NewRefreshTokenManager(jwtManager, config.RefreshToken, logger)

	return &AuthenticationService{
		jwtManager:          jwtManager,
		oauth2Manager:       oauth2Manager,
		refreshTokenManager: refreshTokenManager,
		logger:              logger,
		config:              config,
	}, nil
}

// Login authenticates a user with username/password
func (as *AuthenticationService) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	username := req.Username
	if username == "" && req.EmailOrUsername != "" {
		username = req.EmailOrUsername
	}
	
	ctx, span := authServiceTracer.Start(ctx, "auth_service.login",
		trace.WithAttributes(attribute.String("username", username)))
	defer span.End()

	// TODO: Implement user validation against database
	// For now, create a mock user
	user := &domain.User{
		ID:       uuid.New(),
		Username: username,
		Email:    username + "@hackai.com",
		Role:     domain.UserRoleUser,
	}

	// Generate session ID
	sessionID := uuid.New().String()

	// Generate token pair
	tokenPair, err := as.jwtManager.GenerateTokenPair(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Generate refresh token
	refreshToken, err := as.refreshTokenManager.GenerateRefreshToken(ctx, user, sessionID, req.DeviceInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	as.logger.Info("User logged in successfully",
		"user_id", user.ID,
		"username", user.Username,
		"session_id", sessionID)

	return &LoginResponse{
		User:         user,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    tokenPair.ExpiresAt,
		TokenType:    tokenPair.TokenType,
		SessionID:    sessionID,
		RequiresMFA:  false, // TODO: Implement MFA logic
	}, nil
}

// OAuth2Login authenticates a user with OAuth2
func (as *AuthenticationService) OAuth2Login(ctx context.Context, req *OAuth2LoginRequest) (*LoginResponse, error) {
	ctx, span := authServiceTracer.Start(ctx, "auth_service.oauth2_login",
		trace.WithAttributes(attribute.String("provider", req.Provider)))
	defer span.End()

	// Exchange code for token
	tokenResp, err := as.oauth2Manager.ExchangeCodeForToken(ctx, &OAuth2TokenRequest{
		Provider: req.Provider,
		Code:     req.Code,
		State:    req.State,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to exchange OAuth2 code: %w", err)
	}

	// Get user info from OAuth2 provider
	userInfo, err := as.oauth2Manager.GetUserInfo(ctx, req.Provider, tokenResp.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// TODO: Find or create user in database
	// For now, create a mock user
	user := &domain.User{
		ID:       uuid.New(),
		Username: userInfo.Username,
		Email:    userInfo.Email,
		Role:     domain.UserRoleUser,
	}

	// Generate session ID
	sessionID := uuid.New().String()

	// Generate token pair
	tokenPair, err := as.jwtManager.GenerateTokenPair(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Generate refresh token
	refreshToken, err := as.refreshTokenManager.GenerateRefreshToken(ctx, user, sessionID, req.DeviceInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	as.logger.Info("User logged in via OAuth2",
		"user_id", user.ID,
		"provider", req.Provider,
		"session_id", sessionID)

	return &LoginResponse{
		User:         user,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    tokenPair.ExpiresAt,
		TokenType:    tokenPair.TokenType,
		SessionID:    sessionID,
		RequiresMFA:  false,
	}, nil
}

// RefreshToken refreshes an access token
func (as *AuthenticationService) RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*RefreshTokenResponse, error) {
	ctx, span := authServiceTracer.Start(ctx, "auth_service.refresh_token")
	defer span.End()

	response, err := as.refreshTokenManager.RefreshAccessToken(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	as.logger.Info("Token refreshed successfully")

	return response, nil
}

// Logout logs out a user
func (as *AuthenticationService) Logout(ctx context.Context, req *LogoutRequest) error {
	ctx, span := authServiceTracer.Start(ctx, "auth_service.logout")
	defer span.End()

	if req.RefreshToken != "" {
		// Revoke refresh token
		revokeReq := &TokenRevocationRequest{
			Token:     req.RefreshToken,
			TokenType: "refresh_token",
			Reason:    "user_logout",
		}
		if err := as.refreshTokenManager.RevokeToken(ctx, revokeReq); err != nil {
			as.logger.Error("Failed to revoke refresh token during logout", "error", err)
		}
	}

	if req.LogoutAll {
		// TODO: Get user ID from session and revoke all tokens
		// For now, we'll skip this as we need user context
		as.logger.Info("Logout all requested but not implemented")
	}

	as.logger.Info("User logged out successfully",
		"session_id", req.SessionID,
		"logout_all", req.LogoutAll)

	return nil
}

// ValidateToken validates a JWT token
func (as *AuthenticationService) ValidateToken(ctx context.Context, token string) (*Claims, error) {
	ctx, span := authServiceTracer.Start(ctx, "auth_service.validate_token")
	defer span.End()

	claims, err := as.jwtManager.ValidateToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	return claims, nil
}

// GetOAuth2AuthorizationURL generates an OAuth2 authorization URL
func (as *AuthenticationService) GetOAuth2AuthorizationURL(ctx context.Context, req *OAuth2AuthorizationRequest) (*OAuth2AuthorizationResponse, error) {
	ctx, span := authServiceTracer.Start(ctx, "auth_service.get_oauth2_authorization_url",
		trace.WithAttributes(attribute.String("provider", req.Provider)))
	defer span.End()

	response, err := as.oauth2Manager.GetAuthorizationURL(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate authorization URL: %w", err)
	}

	return response, nil
}

// RevokeToken revokes a token
func (as *AuthenticationService) RevokeToken(ctx context.Context, req *TokenRevocationRequest) error {
	ctx, span := authServiceTracer.Start(ctx, "auth_service.revoke_token",
		trace.WithAttributes(attribute.String("token_type", req.TokenType)))
	defer span.End()

	if req.TokenType == "refresh_token" {
		return as.refreshTokenManager.RevokeToken(ctx, req)
	}

	// TODO: Implement access token revocation (blacklist)
	return fmt.Errorf("access token revocation not implemented")
}

// RevokeAllUserTokens revokes all tokens for a user
func (as *AuthenticationService) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID, reason string) error {
	ctx, span := authServiceTracer.Start(ctx, "auth_service.revoke_all_user_tokens",
		trace.WithAttributes(attribute.String("user_id", userID.String())))
	defer span.End()

	return as.refreshTokenManager.RevokeAllUserTokens(ctx, userID, reason)
}

// GetUserSessions returns all active sessions for a user
func (as *AuthenticationService) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*RefreshTokenInfo, error) {
	ctx, span := authServiceTracer.Start(ctx, "auth_service.get_user_sessions",
		trace.WithAttributes(attribute.String("user_id", userID.String())))
	defer span.End()

	tokens := as.refreshTokenManager.GetUserTokens(userID)
	return tokens, nil
}

// ValidatePasswordPolicy validates a password against the configured policy
func (as *AuthenticationService) ValidatePasswordPolicy(password string) error {
	if as.config.Security == nil || as.config.Security.PasswordPolicy == nil {
		return nil // No policy configured
	}

	policy := as.config.Security.PasswordPolicy

	if len(password) < policy.MinLength {
		return fmt.Errorf("password must be at least %d characters long", policy.MinLength)
	}

	if policy.RequireUppercase && !containsUppercase(password) {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}

	if policy.RequireLowercase && !containsLowercase(password) {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}

	if policy.RequireNumbers && !containsNumber(password) {
		return fmt.Errorf("password must contain at least one number")
	}

	if policy.RequireSpecial && !containsSpecialChar(password) {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// Helper functions for password validation
func containsUppercase(s string) bool {
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			return true
		}
	}
	return false
}

func containsLowercase(s string) bool {
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			return true
		}
	}
	return false
}

func containsNumber(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

func containsSpecialChar(s string) bool {
	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	for _, r := range s {
		for _, special := range specialChars {
			if r == special {
				return true
			}
		}
	}
	return false
}
