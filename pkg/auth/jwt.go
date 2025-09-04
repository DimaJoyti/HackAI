package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/config"
)

// JWTConfig represents JWT configuration
type JWTConfig struct {
	Secret          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	Issuer          string
	Audience        string
}

// JWTManager handles JWT token operations
type JWTManager struct {
	config *config.JWTConfig
}

// JWTService provides JWT operations (alias for compatibility)
type JWTService = JWTManager

// Claims represents JWT claims
type Claims struct {
	UserID    uuid.UUID       `json:"user_id"`
	Username  string          `json:"username"`
	Email     string          `json:"email"`
	Role      domain.UserRole `json:"role"`
	SessionID uuid.UUID       `json:"session_id"`
	jwt.RegisteredClaims
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(config *config.JWTConfig) *JWTManager {
	return &JWTManager{
		config: config,
	}
}

// NewJWTService creates a new JWT service (alias for NewJWTManager)
func NewJWTService(jwtConfig *JWTConfig) *JWTService {
	// Convert JWTConfig to config.JWTConfig
	configJWT := &config.JWTConfig{
		Secret:          jwtConfig.Secret,
		AccessTokenTTL:  jwtConfig.AccessTokenTTL,
		RefreshTokenTTL: jwtConfig.RefreshTokenTTL,
		Issuer:          jwtConfig.Issuer,
		Audience:        jwtConfig.Audience,
	}
	return NewJWTManager(configJWT)
}

// GenerateTokenPair generates access and refresh tokens for a user
func (j *JWTManager) GenerateTokenPair(user *domain.User) (*TokenPair, error) {
	// Generate access token
	accessToken, expiresAt, err := j.generateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := j.generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		TokenType:    "Bearer",
	}, nil
}

// generateAccessToken generates a JWT access token
func (j *JWTManager) generateAccessToken(user *domain.User) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(j.config.AccessTokenTTL)

	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Subject:   user.ID.String(),
			Issuer:    j.config.Issuer,
			Audience:  []string{j.config.Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(j.config.Secret))
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expiresAt, nil
}

// generateRefreshToken generates a random refresh token
func (j *JWTManager) generateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// ValidateToken validates and parses a JWT token
func (j *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.config.Secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validate issuer and audience
	if claims.Issuer != j.config.Issuer {
		return nil, fmt.Errorf("invalid token issuer")
	}

	if len(claims.Audience) == 0 || claims.Audience[0] != j.config.Audience {
		return nil, fmt.Errorf("invalid token audience")
	}

	return claims, nil
}

// GenerateToken generates an access token for the given claims
func (j *JWTManager) GenerateToken(claims *Claims) (string, error) {
	// Set standard claims
	claims.RegisteredClaims = jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.config.AccessTokenTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    j.config.Issuer,
		Audience:  []string{j.config.Audience},
		ID:        uuid.New().String(),
		Subject:   claims.UserID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.config.Secret))
}

// GenerateRefreshToken generates a refresh token for the given claims
func (j *JWTManager) GenerateRefreshToken(claims *Claims) (string, error) {
	// Set standard claims for refresh token
	refreshClaims := &Claims{
		UserID:    claims.UserID,
		SessionID: claims.SessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.config.RefreshTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    j.config.Issuer,
			Audience:  []string{j.config.Audience},
			ID:        uuid.New().String(),
			Subject:   claims.UserID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	return token.SignedString([]byte(j.config.Secret))
}

// RefreshToken generates a new access token using a refresh token
func (j *JWTManager) RefreshToken(refreshTokenString string) (string, error) {
	// Validate refresh token
	claims, err := j.ValidateToken(refreshTokenString)
	if err != nil {
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Generate new access token
	newClaims := &Claims{
		UserID:    claims.UserID,
		Username:  claims.Username,
		Email:     claims.Email,
		Role:      claims.Role,
		SessionID: claims.SessionID,
	}

	return j.GenerateToken(newClaims)
}

// ExtractTokenFromHeader extracts token from Authorization header
func ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", fmt.Errorf("authorization header is empty")
	}

	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return authHeader[len(bearerPrefix):], nil
}

// HashToken creates a hash of the token for storage
func HashToken(token string) string {
	// In production, use a proper hashing algorithm like SHA-256
	// For simplicity, we'll use a basic approach here
	return fmt.Sprintf("%x", []byte(token))
}

// TokenInfo represents token information
type TokenInfo struct {
	UserID    uuid.UUID       `json:"user_id"`
	Username  string          `json:"username"`
	Email     string          `json:"email"`
	Role      domain.UserRole `json:"role"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	JTI       string          `json:"jti"`
}

// GetTokenInfo extracts token information from claims
func (c *Claims) GetTokenInfo() *TokenInfo {
	return &TokenInfo{
		UserID:    c.UserID,
		Username:  c.Username,
		Email:     c.Email,
		Role:      c.Role,
		IssuedAt:  c.IssuedAt.Time,
		ExpiresAt: c.ExpiresAt.Time,
		JTI:       c.ID,
	}
}

// IsExpired checks if the token is expired
func (c *Claims) IsExpired() bool {
	return time.Now().After(c.ExpiresAt.Time)
}

// IsValid checks if the token is valid (not expired and properly formatted)
func (c *Claims) IsValid() bool {
	return !c.IsExpired() && c.UserID != uuid.Nil && c.Username != "" && c.Email != ""
}

// HasRole checks if the user has the specified role
func (c *Claims) HasRole(role domain.UserRole) bool {
	return c.Role == role
}

// IsAdmin checks if the user is an admin
func (c *Claims) IsAdmin() bool {
	return c.Role == domain.UserRoleAdmin
}

// IsModerator checks if the user is a moderator or admin
func (c *Claims) IsModerator() bool {
	return c.Role == domain.UserRoleModerator || c.Role == domain.UserRoleAdmin
}

// CanAccess checks if the user can access a resource based on role
func (c *Claims) CanAccess(requiredRole domain.UserRole) bool {
	switch requiredRole {
	case domain.UserRoleAdmin:
		return c.Role == domain.UserRoleAdmin
	case domain.UserRoleModerator:
		return c.Role == domain.UserRoleModerator || c.Role == domain.UserRoleAdmin
	case domain.UserRoleUser:
		return c.Role == domain.UserRoleUser || c.Role == domain.UserRoleModerator || c.Role == domain.UserRoleAdmin
	case domain.UserRoleGuest:
		return true // Everyone can access guest-level resources
	default:
		return false
	}
}

// AuthService defines the interface for authentication operations
type AuthService interface {
	// Token operations
	GenerateTokenPair(user *domain.User) (*TokenPair, error)
	ValidateToken(token string) (*Claims, error)
	RefreshToken(user *domain.User) (*TokenPair, error)
	RevokeToken(token string) error
	IsTokenRevoked(token string) (bool, error)

	// Authentication operations (for middleware compatibility)
	Authenticate(ctx context.Context, req *AuthenticationRequest) (*AuthenticationResponse, error)
	Logout(ctx context.Context, token string, ipAddress, userAgent string) error
}

// Service implements AuthService
type Service struct {
	jwtManager *JWTManager
	// Add token blacklist storage here (Redis, database, etc.)
}

// NewService creates a new auth service
func NewService(config *config.JWTConfig) *Service {
	return &Service{
		jwtManager: NewJWTManager(config),
	}
}

// GenerateTokenPair generates access and refresh tokens
func (s *Service) GenerateTokenPair(user *domain.User) (*TokenPair, error) {
	return s.jwtManager.GenerateTokenPair(user)
}

// ValidateToken validates a JWT token
func (s *Service) ValidateToken(token string) (*Claims, error) {
	return s.jwtManager.ValidateToken(token)
}

// RefreshToken generates new tokens
func (s *Service) RefreshToken(user *domain.User) (*TokenPair, error) {
	return s.jwtManager.GenerateTokenPair(user)
}

// RevokeToken revokes a token (add to blacklist)
func (s *Service) RevokeToken(token string) error {
	// TODO: Implement token blacklisting
	// This could be done using Redis with token expiration
	return nil
}

// IsTokenRevoked checks if a token is revoked
func (s *Service) IsTokenRevoked(token string) (bool, error) {
	// TODO: Check token blacklist
	return false, nil
}

// Authenticate authenticates a user (placeholder implementation)
func (s *Service) Authenticate(ctx context.Context, req *AuthenticationRequest) (*AuthenticationResponse, error) {
	// This is a placeholder implementation
	// In a real implementation, this would validate credentials and return authentication response
	return nil, fmt.Errorf("authenticate method not implemented in basic service")
}

// Logout logs out a user (placeholder implementation)
func (s *Service) Logout(ctx context.Context, token string, ipAddress, userAgent string) error {
	// This is a placeholder implementation
	// In a real implementation, this would revoke the token and log the logout event
	return s.RevokeToken(token)
}
