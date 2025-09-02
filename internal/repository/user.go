package repository

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// UserRepository implements domain.UserRepository
type UserRepository struct {
	db     *gorm.DB
	logger *logger.Logger
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *gorm.DB, log *logger.Logger) domain.UserRepository {
	return &UserRepository{
		db:     db,
		logger: log,
	}
}

// Create creates a new user
func (r *UserRepository) Create(user *domain.User) error {
	if err := r.db.Create(user).Error; err != nil {
		r.logger.WithError(err).Error("Failed to create user")
		return fmt.Errorf("failed to create user: %w", err)
	}

	r.logger.WithField("user_id", user.ID).Info("User created successfully")
	return nil
}

// GetByID retrieves a user by ID
func (r *UserRepository) GetByID(id uuid.UUID) (*domain.User, error) {
	var user domain.User
	if err := r.db.Where("id = ?", id).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		r.logger.WithError(err).WithField("user_id", id).Error("Failed to get user by ID")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetByEmail retrieves a user by email
func (r *UserRepository) GetByEmail(email string) (*domain.User, error) {
	var user domain.User
	if err := r.db.Where("email = ?", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		r.logger.WithError(err).WithField("email", email).Error("Failed to get user by email")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetByUsername retrieves a user by username
func (r *UserRepository) GetByUsername(username string) (*domain.User, error) {
	var user domain.User
	if err := r.db.Where("username = ?", username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		r.logger.WithError(err).WithField("username", username).Error("Failed to get user by username")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// Update updates a user
func (r *UserRepository) Update(user *domain.User) error {
	if err := r.db.Save(user).Error; err != nil {
		r.logger.WithError(err).WithField("user_id", user.ID).Error("Failed to update user")
		return fmt.Errorf("failed to update user: %w", err)
	}

	r.logger.WithField("user_id", user.ID).Info("User updated successfully")
	return nil
}

// Delete deletes a user by ID
func (r *UserRepository) Delete(id uuid.UUID) error {
	if err := r.db.Delete(&domain.User{}, id).Error; err != nil {
		r.logger.WithError(err).WithField("user_id", id).Error("Failed to delete user")
		return fmt.Errorf("failed to delete user: %w", err)
	}

	r.logger.WithField("user_id", id).Info("User deleted successfully")
	return nil
}

// List retrieves a list of users with pagination
func (r *UserRepository) List(limit, offset int) ([]*domain.User, error) {
	var users []*domain.User
	if err := r.db.Limit(limit).Offset(offset).Find(&users).Error; err != nil {
		r.logger.WithError(err).Error("Failed to list users")
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	return users, nil
}

// Search searches for users by query
func (r *UserRepository) Search(query string, limit, offset int) ([]*domain.User, error) {
	var users []*domain.User
	searchPattern := "%" + query + "%"

	if err := r.db.Where("username ILIKE ? OR email ILIKE ? OR first_name ILIKE ? OR last_name ILIKE ?",
		searchPattern, searchPattern, searchPattern, searchPattern).
		Limit(limit).Offset(offset).Find(&users).Error; err != nil {
		r.logger.WithError(err).WithField("query", query).Error("Failed to search users")
		return nil, fmt.Errorf("failed to search users: %w", err)
	}

	return users, nil
}

// CreateSession creates a new user session
func (r *UserRepository) CreateSession(session *domain.UserSession) error {
	if err := r.db.Create(session).Error; err != nil {
		r.logger.WithError(err).WithField("user_id", session.UserID).Error("Failed to create session")
		return fmt.Errorf("failed to create session: %w", err)
	}

	r.logger.WithFields(map[string]interface{}{
		"user_id":    session.UserID,
		"session_id": session.ID,
	}).Info("Session created successfully")
	return nil
}

// GetSession retrieves a session by token
func (r *UserRepository) GetSession(token string) (*domain.UserSession, error) {
	var session domain.UserSession
	if err := r.db.Where("token = ?", token).First(&session).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("session not found")
		}
		r.logger.WithError(err).WithField("token", token[:8]+"...").Error("Failed to get session")
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &session, nil
}

// DeleteSession deletes a session by token
func (r *UserRepository) DeleteSession(token string) error {
	if err := r.db.Where("token = ?", token).Delete(&domain.UserSession{}).Error; err != nil {
		r.logger.WithError(err).WithField("token", token[:8]+"...").Error("Failed to delete session")
		return fmt.Errorf("failed to delete session: %w", err)
	}

	r.logger.WithField("token", token[:8]+"...").Info("Session deleted successfully")
	return nil
}

// DeleteUserSessions deletes all sessions for a user
func (r *UserRepository) DeleteUserSessions(userID uuid.UUID) error {
	if err := r.db.Where("user_id = ?", userID).Delete(&domain.UserSession{}).Error; err != nil {
		r.logger.WithError(err).WithField("user_id", userID).Error("Failed to delete user sessions")
		return fmt.Errorf("failed to delete user sessions: %w", err)
	}

	r.logger.WithField("user_id", userID).Info("User sessions deleted successfully")
	return nil
}

// GrantPermission grants a permission to a user
func (r *UserRepository) GrantPermission(permission *domain.UserPermission) error {
	if err := r.db.Create(permission).Error; err != nil {
		r.logger.WithError(err).WithFields(map[string]interface{}{
			"user_id":  permission.UserID,
			"resource": permission.Resource,
			"action":   permission.Action,
		}).Error("Failed to grant permission")
		return fmt.Errorf("failed to grant permission: %w", err)
	}

	r.logger.WithFields(map[string]interface{}{
		"user_id":  permission.UserID,
		"resource": permission.Resource,
		"action":   permission.Action,
	}).Info("Permission granted successfully")
	return nil
}

// RevokePermission revokes a permission from a user
func (r *UserRepository) RevokePermission(userID uuid.UUID, resource, action string) error {
	if err := r.db.Where("user_id = ? AND resource = ? AND action = ?", userID, resource, action).
		Delete(&domain.UserPermission{}).Error; err != nil {
		r.logger.WithError(err).WithFields(map[string]interface{}{
			"user_id":  userID,
			"resource": resource,
			"action":   action,
		}).Error("Failed to revoke permission")
		return fmt.Errorf("failed to revoke permission: %w", err)
	}

	r.logger.WithFields(map[string]interface{}{
		"user_id":  userID,
		"resource": resource,
		"action":   action,
	}).Info("Permission revoked successfully")
	return nil
}

// GetUserPermissions retrieves all permissions for a user
func (r *UserRepository) GetUserPermissions(userID uuid.UUID) ([]*domain.UserPermission, error) {
	var permissions []*domain.UserPermission
	if err := r.db.Where("user_id = ? AND granted = true", userID).Find(&permissions).Error; err != nil {
		r.logger.WithError(err).WithField("user_id", userID).Error("Failed to get user permissions")
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	return permissions, nil
}

// HasPermission checks if a user has a specific permission
func (r *UserRepository) HasPermission(userID uuid.UUID, resource, action string) (bool, error) {
	var count int64
	if err := r.db.Model(&domain.UserPermission{}).
		Where("user_id = ? AND resource = ? AND action = ? AND granted = true", userID, resource, action).
		Where("expires_at IS NULL OR expires_at > ?", time.Now()).
		Count(&count).Error; err != nil {
		r.logger.WithError(err).WithFields(map[string]interface{}{
			"user_id":  userID,
			"resource": resource,
			"action":   action,
		}).Error("Failed to check permission")
		return false, fmt.Errorf("failed to check permission: %w", err)
	}

	return count > 0, nil
}

// LogActivity logs a user activity
func (r *UserRepository) LogActivity(activity *domain.UserActivity) error {
	if err := r.db.Create(activity).Error; err != nil {
		r.logger.WithError(err).WithFields(map[string]interface{}{
			"user_id": activity.UserID,
			"action":  activity.Action,
		}).Error("Failed to log activity")
		return fmt.Errorf("failed to log activity: %w", err)
	}

	return nil
}

// GetUserActivity retrieves user activity logs
func (r *UserRepository) GetUserActivity(userID uuid.UUID, limit, offset int) ([]*domain.UserActivity, error) {
	var activities []*domain.UserActivity
	if err := r.db.Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).Offset(offset).
		Find(&activities).Error; err != nil {
		r.logger.WithError(err).WithField("user_id", userID).Error("Failed to get user activity")
		return nil, fmt.Errorf("failed to get user activity: %w", err)
	}

	return activities, nil
}

// GetByFirebaseUID retrieves a user by Firebase UID
func (r *UserRepository) GetByFirebaseUID(firebaseUID string) (*domain.User, error) {
	var user domain.User
	if err := r.db.Where("firebase_uid = ?", firebaseUID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		r.logger.WithError(err).WithField("firebase_uid", firebaseUID).Error("Failed to get user by Firebase UID")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// UpdateFirebaseUID updates a user's Firebase UID
func (r *UserRepository) UpdateFirebaseUID(userID uuid.UUID, firebaseUID string) error {
	if err := r.db.Model(&domain.User{}).Where("id = ?", userID).Update("firebase_uid", firebaseUID).Error; err != nil {
		r.logger.WithError(err).WithFields(map[string]interface{}{
			"user_id":      userID,
			"firebase_uid": firebaseUID,
		}).Error("Failed to update Firebase UID")
		return fmt.Errorf("failed to update Firebase UID: %w", err)
	}

	r.logger.WithFields(map[string]interface{}{
		"user_id":      userID,
		"firebase_uid": firebaseUID,
	}).Info("Firebase UID updated successfully")
	return nil
}

// ListUsersWithoutFirebaseUID retrieves users without Firebase UID
func (r *UserRepository) ListUsersWithoutFirebaseUID(limit, offset int) ([]*domain.User, error) {
	var users []*domain.User
	if err := r.db.Where("firebase_uid IS NULL OR firebase_uid = ''").
		Limit(limit).Offset(offset).Find(&users).Error; err != nil {
		r.logger.WithError(err).Error("Failed to list users without Firebase UID")
		return nil, fmt.Errorf("failed to list users without Firebase UID: %w", err)
	}

	return users, nil
}
