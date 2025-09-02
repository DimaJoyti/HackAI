package firebase

import (
	"context"
	"fmt"
	"time"

	"firebase.google.com/go/v4/auth"
	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
)

// syncUserToDatabase syncs a Firebase user to the local PostgreSQL database
func (s *Service) syncUserToDatabase(ctx context.Context, firebaseUser *auth.UserRecord, req *CreateUserRequest) error {
	// Create domain user from Firebase user and request
	user := &domain.User{
		ID:                uuid.New(),
		FirebaseUID:       firebaseUser.UID,
		Username:          req.Username,
		Email:             firebaseUser.Email,
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		DisplayName:       firebaseUser.DisplayName,
		PhoneNumber:       firebaseUser.PhoneNumber,
		EmailVerified:     firebaseUser.EmailVerified,
		Role:              req.Role,
		Organization:      req.Organization,
		Status:            domain.UserStatusActive,
		TwoFactorEnabled:  false, // Will be updated based on Firebase MFA status
		CreatedAt:         time.Unix(firebaseUser.UserMetadata.CreationTimestamp, 0),
		UpdatedAt:         time.Now(),
	}

	// Set default role if not provided
	if user.Role == "" {
		user.Role = "user"
	}

	// Set default username if not provided
	if user.Username == "" {
		user.Username = generateUsernameFromEmail(user.Email)
	}

	// Create user in database
	if err := s.userRepo.Create(user); err != nil {
		return fmt.Errorf("failed to create user in database: %w", err)
	}

	s.logger.Info("User synced to database successfully", map[string]interface{}{
		"firebase_uid": firebaseUser.UID,
		"user_id":      user.ID.String(),
		"email":        user.Email,
	})

	return nil
}

// syncUpdatedUserToDatabase syncs an updated Firebase user to the local database
func (s *Service) syncUpdatedUserToDatabase(ctx context.Context, firebaseUser *auth.UserRecord, req *UpdateUserRequest) error {
	// Find existing user by Firebase UID
	user, err := s.userRepo.GetByFirebaseUID(firebaseUser.UID)
	if err != nil {
		return fmt.Errorf("failed to find user by Firebase UID: %w", err)
	}

	// Update user fields
	if req.Email != nil {
		user.Email = *req.Email
	}
	if req.DisplayName != nil {
		user.DisplayName = *req.DisplayName
	}
	if req.Username != nil {
		user.Username = *req.Username
	}
	if req.FirstName != nil {
		user.FirstName = *req.FirstName
	}
	if req.LastName != nil {
		user.LastName = *req.LastName
	}
	if req.Role != nil {
		user.Role = *req.Role
	}
	if req.Organization != nil {
		user.Organization = *req.Organization
	}
	if req.PhoneNumber != nil {
		user.PhoneNumber = *req.PhoneNumber
	}
	if req.EmailVerified != nil {
		user.EmailVerified = *req.EmailVerified
	}
	if req.Disabled != nil {
		if *req.Disabled {
			user.Status = domain.UserStatusInactive
		} else {
			user.Status = domain.UserStatusActive
		}
	}

	user.UpdatedAt = time.Now()

	// Update user in database
	if err := s.userRepo.Update(user); err != nil {
		return fmt.Errorf("failed to update user in database: %w", err)
	}

	s.logger.Info("User updated in database successfully", map[string]interface{}{
		"firebase_uid": firebaseUser.UID,
		"user_id":      user.ID.String(),
		"email":        user.Email,
	})

	return nil
}

// handleUserDeletion handles user deletion in the database
func (s *Service) handleUserDeletion(ctx context.Context, firebaseUID string) error {
	// Find existing user by Firebase UID
	user, err := s.userRepo.GetByFirebaseUID(firebaseUID)
	if err != nil {
		return fmt.Errorf("failed to find user by Firebase UID: %w", err)
	}

	// Soft delete or hard delete based on configuration
	if s.config.Common.Integration.DatabaseSync.SyncOnDelete {
		// Hard delete
		if err := s.userRepo.Delete(user.ID); err != nil {
			return fmt.Errorf("failed to delete user from database: %w", err)
		}
	} else {
		// Soft delete - mark as inactive
		user.Status = domain.UserStatusDeleted
		user.UpdatedAt = time.Now()
		if err := s.userRepo.Update(user); err != nil {
			return fmt.Errorf("failed to soft delete user in database: %w", err)
		}
	}

	s.logger.Info("User deletion handled in database", map[string]interface{}{
		"firebase_uid": firebaseUID,
		"user_id":      user.ID.String(),
		"hard_delete":  s.config.Common.Integration.DatabaseSync.SyncOnDelete,
	})

	return nil
}

// SyncFirebaseUserToDatabase manually syncs a Firebase user to the database
func (s *Service) SyncFirebaseUserToDatabase(ctx context.Context, firebaseUID string) error {
	// Get Firebase user
	firebaseUser, err := s.authClient.GetUser(ctx, firebaseUID)
	if err != nil {
		return fmt.Errorf("failed to get Firebase user: %w", err)
	}

	// Check if user already exists in database
	existingUser, err := s.userRepo.GetByFirebaseUID(firebaseUID)
	if err == nil {
		// User exists, update it
		req := &UpdateUserRequest{
			Email:         &firebaseUser.Email,
			DisplayName:   &firebaseUser.DisplayName,
			PhoneNumber:   &firebaseUser.PhoneNumber,
			EmailVerified: &firebaseUser.EmailVerified,
			Disabled:      &firebaseUser.Disabled,
		}
		return s.syncUpdatedUserToDatabase(ctx, firebaseUser, req)
	}

	// User doesn't exist, create it
	req := &CreateUserRequest{
		UID:           firebaseUser.UID,
		Email:         firebaseUser.Email,
		DisplayName:   firebaseUser.DisplayName,
		PhoneNumber:   firebaseUser.PhoneNumber,
		EmailVerified: firebaseUser.EmailVerified,
		Disabled:      firebaseUser.Disabled,
		Username:      generateUsernameFromEmail(firebaseUser.Email),
		Role:          "user", // Default role
	}

	return s.syncUserToDatabase(ctx, firebaseUser, req)
}

// SyncDatabaseUserToFirebase syncs a database user to Firebase
func (s *Service) SyncDatabaseUserToFirebase(ctx context.Context, userID uuid.UUID) error {
	// Get user from database
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("failed to get user from database: %w", err)
	}

	// Check if user already exists in Firebase
	var firebaseUser *auth.UserRecord
	if user.FirebaseUID != "" {
		firebaseUser, err = s.authClient.GetUser(ctx, user.FirebaseUID)
		if err != nil {
			// User doesn't exist in Firebase, create it
			firebaseUser = nil
		}
	}

	if firebaseUser == nil {
		// Create user in Firebase
		params := (&auth.UserToCreate{}).
			Email(user.Email).
			DisplayName(user.DisplayName).
			EmailVerified(user.EmailVerified).
			Disabled(user.Status != domain.UserStatusActive)

		if user.PhoneNumber != "" {
			params = params.PhoneNumber(user.PhoneNumber)
		}

		firebaseUser, err = s.authClient.CreateUser(ctx, params)
		if err != nil {
			return fmt.Errorf("failed to create user in Firebase: %w", err)
		}

		// Update database with Firebase UID
		user.FirebaseUID = firebaseUser.UID
		user.UpdatedAt = time.Now()
		if err := s.userRepo.Update(user); err != nil {
			s.logger.WithError(err).Error("Failed to update user with Firebase UID")
		}
	} else {
		// Update existing Firebase user
		params := (&auth.UserToUpdate{}).
			Email(user.Email).
			DisplayName(user.DisplayName).
			EmailVerified(user.EmailVerified).
			Disabled(user.Status != domain.UserStatusActive)

		if user.PhoneNumber != "" {
			params = params.PhoneNumber(user.PhoneNumber)
		}

		firebaseUser, err = s.authClient.UpdateUser(ctx, user.FirebaseUID, params)
		if err != nil {
			return fmt.Errorf("failed to update user in Firebase: %w", err)
		}
	}

	// Set custom claims
	claims := map[string]interface{}{
		s.config.Common.Integration.CustomClaims.RoleClaim:         user.Role,
		s.config.Common.Integration.CustomClaims.OrganizationClaim: user.Organization,
	}

	if err := s.authClient.SetCustomUserClaims(ctx, firebaseUser.UID, claims); err != nil {
		s.logger.WithError(err).Warn("Failed to set custom claims")
	}

	s.logger.Info("Database user synced to Firebase successfully", map[string]interface{}{
		"user_id":      user.ID.String(),
		"firebase_uid": firebaseUser.UID,
		"email":        user.Email,
	})

	return nil
}

// BatchSyncUsersToFirebase syncs multiple database users to Firebase
func (s *Service) BatchSyncUsersToFirebase(ctx context.Context, userIDs []uuid.UUID) (*BatchOperationResponse, error) {
	response := &BatchOperationResponse{
		Total: len(userIDs),
	}

	for _, userID := range userIDs {
		if err := s.SyncDatabaseUserToFirebase(ctx, userID); err != nil {
			response.Failed = append(response.Failed, struct {
				UID   string `json:"uid"`
				Error string `json:"error"`
			}{
				UID:   userID.String(),
				Error: err.Error(),
			})
		} else {
			response.Success = append(response.Success, userID.String())
		}
	}

	return response, nil
}

// generateUsernameFromEmail generates a username from an email address
func generateUsernameFromEmail(email string) string {
	if email == "" {
		return ""
	}

	// Extract the part before @ symbol
	atIndex := 0
	for i, char := range email {
		if char == '@' {
			atIndex = i
			break
		}
	}

	if atIndex == 0 {
		return email
	}

	username := email[:atIndex]
	
	// Replace dots and other special characters with underscores
	result := make([]rune, 0, len(username))
	for _, char := range username {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			result = append(result, char)
		} else {
			result = append(result, '_')
		}
	}

	return string(result)
}

// GetUserWithFirebaseData retrieves a user with both database and Firebase data
func (s *Service) GetUserWithFirebaseData(ctx context.Context, userID uuid.UUID) (*UserResponse, error) {
	// Get user from database
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user from database: %w", err)
	}

	response := &UserResponse{
		UID:          user.FirebaseUID,
		Email:        user.Email,
		DisplayName:  user.DisplayName,
		PhoneNumber:  user.PhoneNumber,
		EmailVerified: user.EmailVerified,
		Disabled:     user.Status != domain.UserStatusActive,
		Username:     user.Username,
		FirstName:    user.FirstName,
		LastName:     user.LastName,
		Role:         user.Role,
		Organization: user.Organization,
		CreatedAt:    user.CreatedAt.Unix(),
	}

	// Get additional data from Firebase if UID exists
	if user.FirebaseUID != "" {
		firebaseUser, err := s.authClient.GetUser(ctx, user.FirebaseUID)
		if err == nil {
			response.LastLoginAt = firebaseUser.UserMetadata.LastLogInTimestamp
			response.CustomClaims = firebaseUser.CustomClaims
		}
	}

	return response, nil
}
