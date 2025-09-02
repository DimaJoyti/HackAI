package firebase

import (
	"context"
	"fmt"
	"time"

	"firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// Service provides Firebase authentication and user management
type Service struct {
	app        *firebase.App
	authClient *auth.Client
	config     *Config
	logger     *logger.Logger
	userRepo   domain.UserRepository
}

// NewService creates a new Firebase service
func NewService(config *Config, log *logger.Logger, userRepo domain.UserRepository) (*Service, error) {
	ctx := context.Background()

	// Initialize Firebase app with service account
	opt := option.WithCredentialsFile(config.Firebase.Admin.ServiceAccountPath)
	firebaseConfig := &firebase.Config{
		ProjectID:   config.Firebase.ProjectID,
		DatabaseURL: config.Firebase.Admin.DatabaseURL,
	}

	app, err := firebase.NewApp(ctx, firebaseConfig, opt)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Firebase app: %w", err)
	}

	// Get Auth client
	authClient, err := app.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Firebase Auth client: %w", err)
	}

	service := &Service{
		app:        app,
		authClient: authClient,
		config:     config,
		logger:     log,
		userRepo:   userRepo,
	}

	log.Info("Firebase service initialized successfully")
	return service, nil
}

// CreateUser creates a new user in Firebase and syncs with local database
func (s *Service) CreateUser(ctx context.Context, req *CreateUserRequest) (*UserResponse, error) {
	s.logger.Info("Creating Firebase user", map[string]interface{}{
		"email": req.Email,
		"uid":   req.UID,
	})

	// Create user in Firebase
	params := (&auth.UserToCreate{}).
		UID(req.UID).
		Email(req.Email).
		EmailVerified(req.EmailVerified).
		DisplayName(req.DisplayName).
		Disabled(req.Disabled)

	if req.Password != "" {
		params = params.Password(req.Password)
	}

	if req.PhoneNumber != "" {
		params = params.PhoneNumber(req.PhoneNumber)
	}

	firebaseUser, err := s.authClient.CreateUser(ctx, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to create Firebase user")
		return nil, fmt.Errorf("failed to create Firebase user: %w", err)
	}

	// Set custom claims if provided
	if len(req.CustomClaims) > 0 {
		if err := s.authClient.SetCustomUserClaims(ctx, firebaseUser.UID, req.CustomClaims); err != nil {
			s.logger.WithError(err).Warn("Failed to set custom claims")
		}
	}

	// Sync with local database if enabled
	if s.config.Common.Integration.DatabaseSync.Enabled && s.config.Common.Integration.DatabaseSync.SyncOnCreate {
		if err := s.syncUserToDatabase(ctx, firebaseUser, req); err != nil {
			s.logger.WithError(err).Error("Failed to sync user to database")
			// Don't fail the entire operation, just log the error
		}
	}

	response := &UserResponse{
		UID:           firebaseUser.UID,
		Email:         firebaseUser.Email,
		DisplayName:   firebaseUser.DisplayName,
		EmailVerified: firebaseUser.EmailVerified,
		PhoneNumber:   firebaseUser.PhoneNumber,
		Disabled:      firebaseUser.Disabled,
		CreatedAt:     firebaseUser.UserMetadata.CreationTimestamp,
		LastLoginAt:   firebaseUser.UserMetadata.LastLogInTimestamp,
		CustomClaims:  req.CustomClaims,
	}

	s.logger.Info("Firebase user created successfully", map[string]interface{}{
		"uid":   firebaseUser.UID,
		"email": firebaseUser.Email,
	})

	return response, nil
}

// GetUser retrieves a user by UID
func (s *Service) GetUser(ctx context.Context, uid string) (*UserResponse, error) {
	firebaseUser, err := s.authClient.GetUser(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("failed to get Firebase user: %w", err)
	}

	return s.mapFirebaseUserToResponse(firebaseUser), nil
}

// GetUserByEmail retrieves a user by email
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*UserResponse, error) {
	firebaseUser, err := s.authClient.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("failed to get Firebase user by email: %w", err)
	}

	return s.mapFirebaseUserToResponse(firebaseUser), nil
}

// UpdateUser updates a user in Firebase
func (s *Service) UpdateUser(ctx context.Context, uid string, req *UpdateUserRequest) (*UserResponse, error) {
	params := (&auth.UserToUpdate{})

	if req.Email != nil {
		params = params.Email(*req.Email)
	}
	if req.DisplayName != nil {
		params = params.DisplayName(*req.DisplayName)
	}
	if req.PhoneNumber != nil {
		params = params.PhoneNumber(*req.PhoneNumber)
	}
	if req.Password != nil {
		params = params.Password(*req.Password)
	}
	if req.EmailVerified != nil {
		params = params.EmailVerified(*req.EmailVerified)
	}
	if req.Disabled != nil {
		params = params.Disabled(*req.Disabled)
	}

	firebaseUser, err := s.authClient.UpdateUser(ctx, uid, params)
	if err != nil {
		return nil, fmt.Errorf("failed to update Firebase user: %w", err)
	}

	// Update custom claims if provided
	if req.CustomClaims != nil {
		if err := s.authClient.SetCustomUserClaims(ctx, uid, req.CustomClaims); err != nil {
			s.logger.WithError(err).Warn("Failed to update custom claims")
		}
	}

	// Sync with local database if enabled
	if s.config.Common.Integration.DatabaseSync.Enabled && s.config.Common.Integration.DatabaseSync.SyncOnUpdate {
		if err := s.syncUpdatedUserToDatabase(ctx, firebaseUser, req); err != nil {
			s.logger.WithError(err).Error("Failed to sync updated user to database")
		}
	}

	return s.mapFirebaseUserToResponse(firebaseUser), nil
}

// DeleteUser deletes a user from Firebase
func (s *Service) DeleteUser(ctx context.Context, uid string) error {
	if err := s.authClient.DeleteUser(ctx, uid); err != nil {
		return fmt.Errorf("failed to delete Firebase user: %w", err)
	}

	// Handle database sync for deletion
	if s.config.Common.Integration.DatabaseSync.Enabled && s.config.Common.Integration.DatabaseSync.SyncOnDelete {
		if err := s.handleUserDeletion(ctx, uid); err != nil {
			s.logger.WithError(err).Error("Failed to handle user deletion in database")
		}
	}

	s.logger.Info("Firebase user deleted successfully", map[string]interface{}{
		"uid": uid,
	})

	return nil
}

// VerifyIDToken verifies a Firebase ID token
func (s *Service) VerifyIDToken(ctx context.Context, idToken string) (*auth.Token, error) {
	token, err := s.authClient.VerifyIDToken(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	return token, nil
}

// CreateCustomToken creates a custom token for a user
func (s *Service) CreateCustomToken(ctx context.Context, uid string, claims map[string]interface{}) (string, error) {
	token, err := s.authClient.CustomToken(ctx, uid)
	if err != nil {
		return "", fmt.Errorf("failed to create custom token: %w", err)
	}

	return token, nil
}

// SetCustomUserClaims sets custom claims for a user
func (s *Service) SetCustomUserClaims(ctx context.Context, uid string, claims map[string]interface{}) error {
	if err := s.authClient.SetCustomUserClaims(ctx, uid, claims); err != nil {
		return fmt.Errorf("failed to set custom user claims: %w", err)
	}

	s.logger.Info("Custom claims set successfully", map[string]interface{}{
		"uid":    uid,
		"claims": claims,
	})

	return nil
}

// RevokeRefreshTokens revokes all refresh tokens for a user
func (s *Service) RevokeRefreshTokens(ctx context.Context, uid string) error {
	if err := s.authClient.RevokeRefreshTokens(ctx, uid); err != nil {
		return fmt.Errorf("failed to revoke refresh tokens: %w", err)
	}

	s.logger.Info("Refresh tokens revoked successfully", map[string]interface{}{
		"uid": uid,
	})

	return nil
}

// ListUsers lists users with pagination
func (s *Service) ListUsers(ctx context.Context, maxResults int, pageToken string) (*ListUsersResponse, error) {
	iter := s.authClient.Users(ctx, pageToken)
	iter = iter.PageSize(maxResults)

	var users []*UserResponse
	var nextPageToken string

	for {
		user, err := iter.Next()
		if err != nil {
			break
		}
		users = append(users, s.mapFirebaseUserToResponse(user))
	}

	// Get next page token if available
	if iter.PageInfo().Token != "" {
		nextPageToken = iter.PageInfo().Token
	}

	return &ListUsersResponse{
		Users:         users,
		NextPageToken: nextPageToken,
	}, nil
}

// mapFirebaseUserToResponse converts Firebase user to response format
func (s *Service) mapFirebaseUserToResponse(user *auth.UserRecord) *UserResponse {
	return &UserResponse{
		UID:           user.UID,
		Email:         user.Email,
		DisplayName:   user.DisplayName,
		EmailVerified: user.EmailVerified,
		PhoneNumber:   user.PhoneNumber,
		Disabled:      user.Disabled,
		CreatedAt:     user.UserMetadata.CreationTimestamp,
		LastLoginAt:   user.UserMetadata.LastLogInTimestamp,
		CustomClaims:  user.CustomClaims,
	}
}
