package firebase

import (
	"context"
	"fmt"
	"time"

	"firebase.google.com/go/v4/auth"

	"github.com/dimajoyti/hackai/internal/domain"
	pkgAuth "github.com/dimajoyti/hackai/pkg/auth"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// HybridAuthService provides authentication using both Firebase and JWT
type HybridAuthService struct {
	firebaseService *Service
	jwtService      *pkgAuth.JWTService
	enhancedAuth    *pkgAuth.EnhancedAuthService
	logger          *logger.Logger
	config          *Config
}

// NewHybridAuthService creates a new hybrid authentication service
func NewHybridAuthService(
	firebaseService *Service,
	jwtService *pkgAuth.JWTService,
	enhancedAuth *pkgAuth.EnhancedAuthService,
	logger *logger.Logger,
	config *Config,
) *HybridAuthService {
	return &HybridAuthService{
		firebaseService: firebaseService,
		jwtService:      jwtService,
		enhancedAuth:    enhancedAuth,
		logger:          logger,
		config:          config,
	}
}

// HybridAuthRequest represents a hybrid authentication request
type HybridAuthRequest struct {
	// Firebase token
	FirebaseIDToken string `json:"firebase_id_token,omitempty"`
	
	// Traditional credentials
	EmailOrUsername string `json:"email_or_username,omitempty"`
	Password        string `json:"password,omitempty"`
	
	// Common fields
	IPAddress   string `json:"ip_address"`
	UserAgent   string `json:"user_agent"`
	DeviceID    string `json:"device_id"`
	RememberMe  bool   `json:"remember_me"`
	TOTPCode    string `json:"totp_code,omitempty"`
}

// HybridAuthResponse represents a hybrid authentication response
type HybridAuthResponse struct {
	User         *UserResponse `json:"user"`
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token,omitempty"`
	ExpiresIn    int64         `json:"expires_in"`
	TokenType    string        `json:"token_type"`
	
	// Firebase specific
	FirebaseToken *auth.Token `json:"firebase_token,omitempty"`
	
	// Security info
	RequiresTOTP bool `json:"requires_totp,omitempty"`
}

// Authenticate performs hybrid authentication
func (h *HybridAuthService) Authenticate(ctx context.Context, req *HybridAuthRequest) (*HybridAuthResponse, error) {
	if req.FirebaseIDToken != "" {
		return h.authenticateWithFirebase(ctx, req)
	}
	
	if req.EmailOrUsername != "" && req.Password != "" {
		return h.authenticateWithCredentials(ctx, req)
	}
	
	return nil, fmt.Errorf("invalid authentication request")
}

// authenticateWithFirebase authenticates using Firebase ID token
func (h *HybridAuthService) authenticateWithFirebase(ctx context.Context, req *HybridAuthRequest) (*HybridAuthResponse, error) {
	// Verify Firebase token
	firebaseToken, err := h.firebaseService.VerifyIDToken(ctx, req.FirebaseIDToken)
	if err != nil {
		return nil, fmt.Errorf("invalid Firebase token: %w", err)
	}

	// Get or create user in local database
	user, err := h.getOrCreateUserFromFirebase(ctx, firebaseToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get or create user: %w", err)
	}

	// Check if user is active
	if !user.IsActive() {
		return nil, fmt.Errorf("account is not active")
	}

	// Generate JWT tokens
	claims := &pkgAuth.Claims{
		UserID:    user.ID,
		Email:     user.Email,
		Username:  user.Username,
		Role:      user.Role,
		SessionID: user.ID, // Use user ID as session ID for Firebase auth
	}

	accessToken, err := h.jwtService.GenerateToken(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	var refreshToken string
	if req.RememberMe {
		refreshToken, err = h.jwtService.GenerateRefreshToken(claims)
		if err != nil {
			h.logger.WithError(err).Warn("Failed to generate refresh token")
		}
	}

	// Update last login time
	user.LastLoginAt = &time.Time{}
	*user.LastLoginAt = time.Now()
	if err := h.firebaseService.userRepo.Update(user); err != nil {
		h.logger.WithError(err).Warn("Failed to update last login time")
	}

	// Map to response format
	userResponse := h.mapDomainUserToResponse(user)

	response := &HybridAuthResponse{
		User:          userResponse,
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		ExpiresIn:     3600, // 1 hour
		TokenType:     "Bearer",
		FirebaseToken: firebaseToken,
	}

	h.logger.Info("Firebase authentication successful", map[string]interface{}{
		"user_id":      user.ID.String(),
		"firebase_uid": user.FirebaseUID,
		"email":        user.Email,
		"ip_address":   req.IPAddress,
	})

	return response, nil
}

// authenticateWithCredentials authenticates using traditional credentials
func (h *HybridAuthService) authenticateWithCredentials(ctx context.Context, req *HybridAuthRequest) (*HybridAuthResponse, error) {
	// Use existing enhanced auth service
	authReq := &pkgAuth.AuthenticationRequest{
		EmailOrUsername: req.EmailOrUsername,
		Password:        req.Password,
		TOTPCode:        req.TOTPCode,
		IPAddress:       req.IPAddress,
		UserAgent:       req.UserAgent,
		DeviceID:        req.DeviceID,
		RememberMe:      req.RememberMe,
	}

	authResp, err := h.enhancedAuth.Authenticate(ctx, authReq)
	if err != nil {
		return nil, err
	}

	// If TOTP is required, return early
	if authResp.RequiresTOTP {
		return &HybridAuthResponse{
			RequiresTOTP: true,
		}, nil
	}

	// Get user from database
	user, err := h.firebaseService.userRepo.GetByID(authResp.User.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Sync user to Firebase if not already synced
	if user.FirebaseUID == "" {
		if err := h.firebaseService.SyncDatabaseUserToFirebase(ctx, user.ID); err != nil {
			h.logger.WithError(err).Warn("Failed to sync user to Firebase")
		}
	}

	// Map to response format
	userResponse := h.mapDomainUserToResponse(user)

	response := &HybridAuthResponse{
		User:         userResponse,
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
		ExpiresIn:    authResp.ExpiresIn,
		TokenType:    "Bearer",
	}

	h.logger.Info("Credential authentication successful", map[string]interface{}{
		"user_id":    user.ID.String(),
		"email":      user.Email,
		"ip_address": req.IPAddress,
	})

	return response, nil
}

// getOrCreateUserFromFirebase gets or creates a user from Firebase token
func (h *HybridAuthService) getOrCreateUserFromFirebase(ctx context.Context, token *auth.Token) (*domain.User, error) {
	// Try to get existing user by Firebase UID
	user, err := h.firebaseService.userRepo.GetByFirebaseUID(token.UID)
	if err == nil {
		return user, nil
	}

	// Try to get existing user by email
	if email, ok := token.Claims["email"].(string); ok {
		user, err = h.firebaseService.userRepo.GetByEmail(email)
		if err == nil {
			// Update Firebase UID
			user.FirebaseUID = token.UID
			if err := h.firebaseService.userRepo.Update(user); err != nil {
				h.logger.WithError(err).Warn("Failed to update Firebase UID")
			}
			return user, nil
		}
	}

	// Create new user from Firebase token
	return h.createUserFromFirebaseToken(ctx, token)
}

// createUserFromFirebaseToken creates a new user from Firebase token
func (h *HybridAuthService) createUserFromFirebaseToken(ctx context.Context, token *auth.Token) (*domain.User, error) {
	// Get Firebase user details
	firebaseUser, err := h.firebaseService.authClient.GetUser(ctx, token.UID)
	if err != nil {
		return nil, fmt.Errorf("failed to get Firebase user: %w", err)
	}

	// Extract user information
	email := firebaseUser.Email
	displayName := firebaseUser.DisplayName
	emailVerified := firebaseUser.EmailVerified

	// Generate username from email
	username := generateUsernameFromEmail(email)

	// Create domain user
	user := &domain.User{
		FirebaseUID:   firebaseUser.UID,
		Email:         email,
		Username:      username,
		DisplayName:   displayName,
		EmailVerified: emailVerified,
		PhoneNumber:   firebaseUser.PhoneNumber,
		Role:          domain.UserRoleUser,
		Status:        domain.UserStatusActive,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Set password to a random value (not used for Firebase auth)
	user.Password = "firebase-auth-user"

	// Create user in database
	if err := h.firebaseService.userRepo.Create(user); err != nil {
		return nil, fmt.Errorf("failed to create user in database: %w", err)
	}

	h.logger.Info("User created from Firebase token", map[string]interface{}{
		"user_id":      user.ID.String(),
		"firebase_uid": user.FirebaseUID,
		"email":        user.Email,
	})

	return user, nil
}

// mapDomainUserToResponse maps domain user to response format
func (h *HybridAuthService) mapDomainUserToResponse(user *domain.User) *UserResponse {
	return &UserResponse{
		UID:           user.FirebaseUID,
		Email:         user.Email,
		DisplayName:   user.DisplayName,
		PhoneNumber:   user.PhoneNumber,
		EmailVerified: user.EmailVerified,
		Disabled:      user.Status != domain.UserStatusActive,
		Username:      user.Username,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		Role:          string(user.Role),
		Organization:  user.Organization,
		CreatedAt:     user.CreatedAt.Unix(),
	}
}

// ValidateToken validates either Firebase or JWT token
func (h *HybridAuthService) ValidateToken(ctx context.Context, token string) (*TokenValidationResponse, error) {
	// Try Firebase token first
	firebaseToken, err := h.firebaseService.VerifyIDToken(ctx, token)
	if err == nil {
		return &TokenValidationResponse{
			Valid:     true,
			UID:       firebaseToken.UID,
			Email:     firebaseToken.Claims["email"].(string),
			Claims:    firebaseToken.Claims,
			ExpiresAt: firebaseToken.Expires,
			IssuedAt:  firebaseToken.IssuedAt,
			AuthTime:  firebaseToken.AuthTime,
			Issuer:    firebaseToken.Issuer,
			Audience:  firebaseToken.Audience,
			Subject:   firebaseToken.Subject,
		}, nil
	}

	// Try JWT token
	claims, err := h.jwtService.ValidateToken(token)
	if err != nil {
		return &TokenValidationResponse{
			Valid: false,
		}, fmt.Errorf("invalid token")
	}

	return &TokenValidationResponse{
		Valid:     true,
		UID:       claims.UserID.String(),
		Email:     claims.Email,
		Claims:    map[string]interface{}{
			"user_id":  claims.UserID.String(),
			"email":    claims.Email,
			"username": claims.Username,
			"role":     claims.Role,
		},
		ExpiresAt: claims.ExpiresAt.Unix(),
		IssuedAt:  claims.IssuedAt.Unix(),
		Subject:   claims.UserID.String(),
	}, nil
}

// Logout handles logout for both Firebase and JWT sessions
func (h *HybridAuthService) Logout(ctx context.Context, token, ipAddress, userAgent string) error {
	// Try to validate as Firebase token
	firebaseToken, err := h.firebaseService.VerifyIDToken(ctx, token)
	if err == nil {
		// Revoke Firebase refresh tokens
		if err := h.firebaseService.RevokeRefreshTokens(ctx, firebaseToken.UID); err != nil {
			h.logger.WithError(err).Warn("Failed to revoke Firebase refresh tokens")
		}
		return nil
	}

	// Try to handle as JWT token
	return h.enhancedAuth.Logout(ctx, token, ipAddress, userAgent)
}
