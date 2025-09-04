package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var tokenRefreshTracer = otel.Tracer("hackai/auth/token_refresh")

// RefreshTokenManager handles refresh token operations
type RefreshTokenManager struct {
	jwtManager    *JWTManager
	logger        *logger.Logger
	tokenStore    map[string]*RefreshTokenInfo // In production, use Redis or database
	tokenStoreMux sync.RWMutex
	config        *RefreshTokenConfig
}

// RefreshTokenConfig represents refresh token configuration
type RefreshTokenConfig struct {
	TTL                time.Duration `json:"ttl"`
	MaxTokensPerUser   int           `json:"max_tokens_per_user"`
	RotateOnRefresh    bool          `json:"rotate_on_refresh"`
	RevokeOnLogout     bool          `json:"revoke_on_logout"`
	CleanupInterval    time.Duration `json:"cleanup_interval"`
	GracePeriod        time.Duration `json:"grace_period"`
}

// RefreshTokenInfo represents refresh token metadata
type RefreshTokenInfo struct {
	TokenID     string    `json:"token_id"`
	UserID      uuid.UUID `json:"user_id"`
	SessionID   string    `json:"session_id"`
	TokenHash   string    `json:"token_hash"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	LastUsedAt  time.Time `json:"last_used_at"`
	IsRevoked   bool      `json:"is_revoked"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	RevokeReason string   `json:"revoke_reason,omitempty"`
	DeviceInfo  *DeviceInfo `json:"device_info,omitempty"`
}


// RefreshTokenRequest represents a token refresh request
type RefreshTokenRequest struct {
	RefreshToken string      `json:"refresh_token"`
	DeviceInfo   *DeviceInfo `json:"device_info,omitempty"`
}

// RefreshTokenResponse represents a token refresh response
type RefreshTokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

// TokenRevocationRequest represents a token revocation request
type TokenRevocationRequest struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type"` // "refresh_token" or "access_token"
	Reason    string `json:"reason,omitempty"`
}

// NewRefreshTokenManager creates a new refresh token manager
func NewRefreshTokenManager(jwtManager *JWTManager, config *RefreshTokenConfig, logger *logger.Logger) *RefreshTokenManager {
	if config.TTL == 0 {
		config.TTL = 7 * 24 * time.Hour // 7 days default
	}
	if config.MaxTokensPerUser == 0 {
		config.MaxTokensPerUser = 5 // 5 tokens per user default
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 1 * time.Hour // 1 hour default
	}
	if config.GracePeriod == 0 {
		config.GracePeriod = 5 * time.Minute // 5 minutes default
	}

	rtm := &RefreshTokenManager{
		jwtManager: jwtManager,
		logger:     logger,
		tokenStore: make(map[string]*RefreshTokenInfo),
		config:     config,
	}

	// Start cleanup goroutine
	go rtm.startCleanupRoutine()

	return rtm
}

// GenerateRefreshToken generates a new refresh token
func (rtm *RefreshTokenManager) GenerateRefreshToken(ctx context.Context, user *domain.User, sessionID string, deviceInfo *DeviceInfo) (string, error) {
	ctx, span := tokenRefreshTracer.Start(ctx, "refresh_token.generate",
		trace.WithAttributes(
			attribute.String("user_id", user.ID.String()),
			attribute.String("session_id", sessionID)))
	defer span.End()

	// Generate secure random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	// Create token info
	tokenID := uuid.New().String()
	now := time.Now()
	tokenInfo := &RefreshTokenInfo{
		TokenID:    tokenID,
		UserID:     user.ID,
		SessionID:  sessionID,
		TokenHash:  rtm.hashToken(token),
		CreatedAt:  now,
		ExpiresAt:  now.Add(rtm.config.TTL),
		LastUsedAt: now,
		IsRevoked:  false,
		DeviceInfo: deviceInfo,
	}

	// Check token limit per user
	if err := rtm.enforceTokenLimit(user.ID); err != nil {
		return "", fmt.Errorf("token limit exceeded: %w", err)
	}

	// Store token info
	rtm.tokenStoreMux.Lock()
	rtm.tokenStore[tokenID] = tokenInfo
	rtm.tokenStoreMux.Unlock()

	rtm.logger.Info("Generated refresh token",
		"user_id", user.ID,
		"token_id", tokenID,
		"session_id", sessionID,
		"expires_at", tokenInfo.ExpiresAt)

	return fmt.Sprintf("%s.%s", tokenID, token), nil
}

// RefreshAccessToken refreshes an access token using a refresh token
func (rtm *RefreshTokenManager) RefreshAccessToken(ctx context.Context, req *RefreshTokenRequest) (*RefreshTokenResponse, error) {
	ctx, span := tokenRefreshTracer.Start(ctx, "refresh_token.refresh_access_token")
	defer span.End()

	// Parse refresh token
	tokenID, token, err := rtm.parseRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token format: %w", err)
	}

	// Validate refresh token
	tokenInfo, err := rtm.validateRefreshToken(tokenID, token)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Update last used time
	rtm.tokenStoreMux.Lock()
	tokenInfo.LastUsedAt = time.Now()
	rtm.tokenStoreMux.Unlock()

	// Parse session ID from string to UUID
	sessionUUID, err := uuid.Parse(tokenInfo.SessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid session ID format: %w", err)
	}

	// Create new access token claims
	claims := &Claims{
		UserID:    tokenInfo.UserID,
		SessionID: sessionUUID,
		// Note: Username, Email, Role would be fetched from user service in production
	}

	// Generate new access token
	accessToken, err := rtm.jwtManager.GenerateToken(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	response := &RefreshTokenResponse{
		AccessToken: accessToken,
		ExpiresAt:   time.Now().Add(rtm.jwtManager.config.AccessTokenTTL),
		TokenType:   "Bearer",
	}

	// Rotate refresh token if configured
	if rtm.config.RotateOnRefresh {
		// Revoke old refresh token
		rtm.revokeTokenInternal(tokenID, "rotated")

		// Generate new refresh token
		newRefreshToken, err := rtm.GenerateRefreshToken(ctx, &domain.User{ID: tokenInfo.UserID}, tokenInfo.SessionID, req.DeviceInfo)
		if err != nil {
			rtm.logger.Error("Failed to generate new refresh token during rotation", "error", err)
			// Continue with old token
		} else {
			response.RefreshToken = newRefreshToken
		}
	}

	span.SetAttributes(
		attribute.String("user_id", tokenInfo.UserID.String()),
		attribute.String("session_id", tokenInfo.SessionID),
		attribute.Bool("token_rotated", rtm.config.RotateOnRefresh))

	rtm.logger.Info("Refreshed access token",
		"user_id", tokenInfo.UserID,
		"session_id", tokenInfo.SessionID,
		"token_rotated", rtm.config.RotateOnRefresh)

	return response, nil
}

// RevokeToken revokes a refresh token
func (rtm *RefreshTokenManager) RevokeToken(ctx context.Context, req *TokenRevocationRequest) error {
	ctx, span := tokenRefreshTracer.Start(ctx, "refresh_token.revoke_token",
		trace.WithAttributes(attribute.String("token_type", req.TokenType)))
	defer span.End()

	if req.TokenType != "refresh_token" {
		return fmt.Errorf("unsupported token type: %s", req.TokenType)
	}

	// Parse refresh token
	tokenID, token, err := rtm.parseRefreshToken(req.Token)
	if err != nil {
		return fmt.Errorf("invalid refresh token format: %w", err)
	}

	// Validate refresh token exists
	_, err = rtm.validateRefreshToken(tokenID, token)
	if err != nil {
		return fmt.Errorf("invalid refresh token: %w", err)
	}

	// Revoke token
	rtm.revokeTokenInternal(tokenID, req.Reason)

	rtm.logger.Info("Revoked refresh token",
		"token_id", tokenID,
		"reason", req.Reason)

	return nil
}

// RevokeAllUserTokens revokes all refresh tokens for a user
func (rtm *RefreshTokenManager) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID, reason string) error {
	ctx, span := tokenRefreshTracer.Start(ctx, "refresh_token.revoke_all_user_tokens",
		trace.WithAttributes(attribute.String("user_id", userID.String())))
	defer span.End()

	rtm.tokenStoreMux.Lock()
	defer rtm.tokenStoreMux.Unlock()

	count := 0
	for _, tokenInfo := range rtm.tokenStore {
		if tokenInfo.UserID == userID && !tokenInfo.IsRevoked {
			tokenInfo.IsRevoked = true
			now := time.Now()
			tokenInfo.RevokedAt = &now
			tokenInfo.RevokeReason = reason
			count++
		}
	}

	rtm.logger.Info("Revoked all user tokens",
		"user_id", userID,
		"count", count,
		"reason", reason)

	return nil
}

// IsTokenRevoked checks if a refresh token is revoked
func (rtm *RefreshTokenManager) IsTokenRevoked(refreshToken string) (bool, error) {
	tokenID, token, err := rtm.parseRefreshToken(refreshToken)
	if err != nil {
		return true, fmt.Errorf("invalid refresh token format: %w", err)
	}

	rtm.tokenStoreMux.RLock()
	tokenInfo, exists := rtm.tokenStore[tokenID]
	rtm.tokenStoreMux.RUnlock()

	if !exists {
		return true, fmt.Errorf("token not found")
	}

	if tokenInfo.IsRevoked {
		return true, nil
	}

	if time.Now().After(tokenInfo.ExpiresAt) {
		return true, nil
	}

	if rtm.hashToken(token) != tokenInfo.TokenHash {
		return true, fmt.Errorf("token hash mismatch")
	}

	return false, nil
}

// GetUserTokens returns all active refresh tokens for a user
func (rtm *RefreshTokenManager) GetUserTokens(userID uuid.UUID) []*RefreshTokenInfo {
	rtm.tokenStoreMux.RLock()
	defer rtm.tokenStoreMux.RUnlock()

	var tokens []*RefreshTokenInfo
	for _, tokenInfo := range rtm.tokenStore {
		if tokenInfo.UserID == userID && !tokenInfo.IsRevoked && time.Now().Before(tokenInfo.ExpiresAt) {
			tokens = append(tokens, tokenInfo)
		}
	}

	return tokens
}

// parseRefreshToken parses a refresh token into token ID and token
func (rtm *RefreshTokenManager) parseRefreshToken(refreshToken string) (string, string, error) {
	parts := strings.SplitN(refreshToken, ".", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid token format")
	}
	return parts[0], parts[1], nil
}

// validateRefreshToken validates a refresh token
func (rtm *RefreshTokenManager) validateRefreshToken(tokenID, token string) (*RefreshTokenInfo, error) {
	rtm.tokenStoreMux.RLock()
	tokenInfo, exists := rtm.tokenStore[tokenID]
	rtm.tokenStoreMux.RUnlock()

	if !exists {
		return nil, fmt.Errorf("token not found")
	}

	if tokenInfo.IsRevoked {
		return nil, fmt.Errorf("token revoked")
	}

	if time.Now().After(tokenInfo.ExpiresAt) {
		return nil, fmt.Errorf("token expired")
	}

	if rtm.hashToken(token) != tokenInfo.TokenHash {
		return nil, fmt.Errorf("invalid token")
	}

	return tokenInfo, nil
}

// hashToken creates a hash of the token for storage
func (rtm *RefreshTokenManager) hashToken(token string) string {
	// In production, use a proper cryptographic hash function
	return fmt.Sprintf("hash_%s", token[:16])
}

// enforceTokenLimit enforces the maximum number of tokens per user
func (rtm *RefreshTokenManager) enforceTokenLimit(userID uuid.UUID) error {
	rtm.tokenStoreMux.Lock()
	defer rtm.tokenStoreMux.Unlock()

	count := 0
	var oldestToken *RefreshTokenInfo

	for _, tokenInfo := range rtm.tokenStore {
		if tokenInfo.UserID == userID && !tokenInfo.IsRevoked && time.Now().Before(tokenInfo.ExpiresAt) {
			count++
			if oldestToken == nil || tokenInfo.CreatedAt.Before(oldestToken.CreatedAt) {
				oldestToken = tokenInfo
			}
		}
	}

	if count >= rtm.config.MaxTokensPerUser {
		// Revoke oldest token
		if oldestToken != nil {
			oldestToken.IsRevoked = true
			now := time.Now()
			oldestToken.RevokedAt = &now
			oldestToken.RevokeReason = "token_limit_exceeded"
		}
	}

	return nil
}

// revokeTokenInternal revokes a token internally
func (rtm *RefreshTokenManager) revokeTokenInternal(tokenID, reason string) {
	rtm.tokenStoreMux.Lock()
	defer rtm.tokenStoreMux.Unlock()

	if tokenInfo, exists := rtm.tokenStore[tokenID]; exists {
		tokenInfo.IsRevoked = true
		now := time.Now()
		tokenInfo.RevokedAt = &now
		tokenInfo.RevokeReason = reason
	}
}

// startCleanupRoutine starts the cleanup routine for expired tokens
func (rtm *RefreshTokenManager) startCleanupRoutine() {
	ticker := time.NewTicker(rtm.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rtm.cleanupExpiredTokens()
	}
}

// cleanupExpiredTokens removes expired tokens from storage
func (rtm *RefreshTokenManager) cleanupExpiredTokens() {
	rtm.tokenStoreMux.Lock()
	defer rtm.tokenStoreMux.Unlock()

	now := time.Now()
	count := 0

	for tokenID, tokenInfo := range rtm.tokenStore {
		if now.After(tokenInfo.ExpiresAt.Add(rtm.config.GracePeriod)) {
			delete(rtm.tokenStore, tokenID)
			count++
		}
	}

	if count > 0 {
		rtm.logger.Info("Cleaned up expired refresh tokens", "count", count)
	}
}
