package usecase

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/auth"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// UserUseCase implements user business logic
type UserUseCase struct {
	userRepo    domain.UserRepository
	authService *auth.EnhancedAuthService
	logger      *logger.Logger
}

// NewUserUseCase creates a new user use case
func NewUserUseCase(userRepo domain.UserRepository, authService *auth.EnhancedAuthService, log *logger.Logger) domain.UserUseCase {
	return &UserUseCase{
		userRepo:    userRepo,
		authService: authService,
		logger:      log,
	}
}

// Register creates a new user account
func (u *UserUseCase) Register(email, username, password, firstName, lastName string) (*domain.User, error) {
	// Create password manager for validation and hashing
	passwordManager := auth.NewPasswordManager(auth.DefaultSecurityConfig())

	// Validate password
	if err := passwordManager.ValidatePassword(password); err != nil {
		return nil, fmt.Errorf("password validation failed: %w", err)
	}

	// Hash password
	hashedPassword, err := passwordManager.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &domain.User{
		Email:     email,
		Username:  username,
		Password:  hashedPassword,
		FirstName: firstName,
		LastName:  lastName,
		Role:      domain.UserRoleUser,
		Status:    domain.UserStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := u.userRepo.Create(user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	u.logger.WithField("user_id", user.ID).Info("User registered successfully")
	return user, nil
}

// Login authenticates a user and returns user and token
func (u *UserUseCase) Login(emailOrUsername, password string) (*domain.User, string, error) {
	// This is handled by the auth service, but we can add additional business logic here
	return nil, "", fmt.Errorf("login should be handled by auth service directly")
}

// Logout invalidates a user session
func (u *UserUseCase) Logout(token string) error {
	// This is handled by the auth service
	return fmt.Errorf("logout should be handled by auth service directly")
}

// GetProfile retrieves a user's profile
func (u *UserUseCase) GetProfile(userID uuid.UUID) (*domain.User, error) {
	user, err := u.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user profile: %w", err)
	}

	return user, nil
}

// UpdateProfile updates a user's profile information
func (u *UserUseCase) UpdateProfile(userID uuid.UUID, updates map[string]interface{}) (*domain.User, error) {
	user, err := u.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Apply updates
	if firstName, ok := updates["first_name"].(string); ok {
		user.FirstName = firstName
	}
	if lastName, ok := updates["last_name"].(string); ok {
		user.LastName = lastName
	}
	if bio, ok := updates["bio"].(string); ok {
		user.Bio = bio
	}
	if company, ok := updates["company"].(string); ok {
		user.Company = company
	}
	if location, ok := updates["location"].(string); ok {
		user.Location = location
	}
	if website, ok := updates["website"].(string); ok {
		user.Website = website
	}
	if avatar, ok := updates["avatar"].(string); ok {
		user.Avatar = avatar
	}

	user.UpdatedAt = time.Now()

	if err := u.userRepo.Update(user); err != nil {
		return nil, fmt.Errorf("failed to update user profile: %w", err)
	}

	u.logger.WithField("user_id", userID).Info("User profile updated successfully")
	return user, nil
}

// ChangePassword changes a user's password
func (u *UserUseCase) ChangePassword(userID uuid.UUID, oldPassword, newPassword string) error {
	user, err := u.userRepo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Create password manager for verification, validation and hashing
	passwordManager := auth.NewPasswordManager(auth.DefaultSecurityConfig())

	// Verify old password
	if !passwordManager.VerifyPassword(oldPassword, user.Password) {
		return fmt.Errorf("invalid current password")
	}

	// Validate new password
	if err := passwordManager.ValidatePassword(newPassword); err != nil {
		return fmt.Errorf("new password validation failed: %w", err)
	}

	// Hash new password
	hashedPassword, err := passwordManager.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	user.Password = hashedPassword
	user.UpdatedAt = time.Now()

	if err := u.userRepo.Update(user); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	u.logger.WithField("user_id", userID).Info("User password changed successfully")
	return nil
}

// ResetPassword initiates password reset process
func (u *UserUseCase) ResetPassword(email string) error {
	user, err := u.userRepo.GetByEmail(email)
	if err != nil {
		// Don't reveal if email exists or not
		u.logger.WithField("email", email).Warn("Password reset requested for non-existent email")
		return nil
	}

	// TODO: Implement password reset token generation and email sending
	u.logger.WithField("user_id", user.ID).Info("Password reset requested")
	return nil
}

// VerifyToken verifies a JWT token and returns the user
func (u *UserUseCase) VerifyToken(token string) (*domain.User, error) {
	// This is handled by the auth service
	return nil, fmt.Errorf("token verification should be handled by auth service directly")
}

// ListUsers returns a paginated list of users (admin only)
func (u *UserUseCase) ListUsers(limit, offset int) ([]*domain.User, error) {
	users, err := u.userRepo.List(limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	return users, nil
}

// SearchUsers searches for users by query (admin only)
func (u *UserUseCase) SearchUsers(query string, limit, offset int) ([]*domain.User, error) {
	users, err := u.userRepo.Search(query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to search users: %w", err)
	}

	return users, nil
}

// UpdateUserRole updates a user's role (admin only)
func (u *UserUseCase) UpdateUserRole(userID uuid.UUID, role domain.UserRole) error {
	user, err := u.userRepo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	user.Role = role
	user.UpdatedAt = time.Now()

	if err := u.userRepo.Update(user); err != nil {
		return fmt.Errorf("failed to update user role: %w", err)
	}

	u.logger.WithFields(map[string]interface{}{
		"user_id": userID,
		"role":    role,
	}).Info("User role updated successfully")
	return nil
}

// UpdateUserStatus updates a user's status (admin only)
func (u *UserUseCase) UpdateUserStatus(userID uuid.UUID, status domain.UserStatus) error {
	user, err := u.userRepo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	user.Status = status
	user.UpdatedAt = time.Now()

	if err := u.userRepo.Update(user); err != nil {
		return fmt.Errorf("failed to update user status: %w", err)
	}

	u.logger.WithFields(map[string]interface{}{
		"user_id": userID,
		"status":  status,
	}).Info("User status updated successfully")
	return nil
}

// GrantPermission grants a permission to a user
func (u *UserUseCase) GrantPermission(userID uuid.UUID, resource, action string, grantedBy uuid.UUID) error {
	return u.userRepo.GrantPermission(&domain.UserPermission{
		UserID:    userID,
		Resource:  resource,
		Action:    action,
		Granted:   true,
		GrantedBy: grantedBy,
		GrantedAt: time.Now(),
	})
}

// RevokePermission revokes a permission from a user
func (u *UserUseCase) RevokePermission(userID uuid.UUID, resource, action string) error {
	return u.userRepo.RevokePermission(userID, resource, action)
}

// CheckPermission checks if a user has a specific permission
func (u *UserUseCase) CheckPermission(userID uuid.UUID, resource, action string) (bool, error) {
	return u.userRepo.HasPermission(userID, resource, action)
}

// GetUserActivity retrieves a user's activity history
func (u *UserUseCase) GetUserActivity(userID uuid.UUID, limit, offset int) ([]*domain.UserActivity, error) {
	activities, err := u.userRepo.GetUserActivity(userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get user activity: %w", err)
	}

	return activities, nil
}
