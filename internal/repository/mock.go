package repository

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
)

// MockUserRepository is a mock implementation of UserRepository for testing
type MockUserRepository struct {
	users       map[uuid.UUID]*domain.User
	sessions    map[string]*domain.UserSession
	permissions map[uuid.UUID][]*domain.UserPermission
	activities  map[uuid.UUID][]*domain.UserActivity
	mu          sync.RWMutex
}

// NewMockUserRepository creates a new mock user repository
func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		users:       make(map[uuid.UUID]*domain.User),
		sessions:    make(map[string]*domain.UserSession),
		permissions: make(map[uuid.UUID][]*domain.UserPermission),
		activities:  make(map[uuid.UUID][]*domain.UserActivity),
	}
}

// Create creates a new user
func (r *MockUserRepository) Create(user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	r.users[user.ID] = user
	return nil
}

// GetByID retrieves a user by ID
func (r *MockUserRepository) GetByID(id uuid.UUID) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	user, exists := r.users[id]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

// GetByEmail retrieves a user by email
func (r *MockUserRepository) GetByEmail(email string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, user := range r.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

// GetByUsername retrieves a user by username
func (r *MockUserRepository) GetByUsername(username string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, user := range r.users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

// Update updates a user
func (r *MockUserRepository) Update(user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.users[user.ID]; !exists {
		return fmt.Errorf("user not found")
	}

	user.UpdatedAt = time.Now()
	r.users[user.ID] = user
	return nil
}

// Delete deletes a user
func (r *MockUserRepository) Delete(id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.users[id]; !exists {
		return fmt.Errorf("user not found")
	}

	delete(r.users, id)
	return nil
}

// List lists users with pagination
func (r *MockUserRepository) List(limit, offset int) ([]*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	users := make([]*domain.User, 0, len(r.users))
	for _, user := range r.users {
		users = append(users, user)
	}

	start := offset
	if start > len(users) {
		start = len(users)
	}

	end := start + limit
	if end > len(users) {
		end = len(users)
	}

	return users[start:end], nil
}

// Search searches users
func (r *MockUserRepository) Search(query string, limit, offset int) ([]*domain.User, error) {
	// Simple search implementation
	return r.List(limit, offset)
}

// CreateSession creates a user session
func (r *MockUserRepository) CreateSession(session *domain.UserSession) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if session.ID == uuid.Nil {
		session.ID = uuid.New()
	}
	session.CreatedAt = time.Now()

	r.sessions[session.Token] = session
	return nil
}

// GetSession retrieves a session by token
func (r *MockUserRepository) GetSession(token string) (*domain.UserSession, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	session, exists := r.sessions[token]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}
	return session, nil
}

// DeleteSession deletes a session
func (r *MockUserRepository) DeleteSession(token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sessions[token]; !exists {
		return fmt.Errorf("session not found")
	}

	delete(r.sessions, token)
	return nil
}

// DeleteUserSessions deletes all sessions for a user
func (r *MockUserRepository) DeleteUserSessions(userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for token, session := range r.sessions {
		if session.UserID == userID {
			delete(r.sessions, token)
		}
	}
	return nil
}

// GrantPermission grants a permission to a user
func (r *MockUserRepository) GrantPermission(permission *domain.UserPermission) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if permission.ID == uuid.Nil {
		permission.ID = uuid.New()
	}
	permission.GrantedAt = time.Now()

	r.permissions[permission.UserID] = append(r.permissions[permission.UserID], permission)
	return nil
}

// RevokePermission revokes a permission from a user
func (r *MockUserRepository) RevokePermission(userID uuid.UUID, resource, action string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	permissions := r.permissions[userID]
	for i, perm := range permissions {
		if perm.Resource == resource && perm.Action == action {
			r.permissions[userID] = append(permissions[:i], permissions[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("permission not found")
}

// GetUserPermissions retrieves all permissions for a user
func (r *MockUserRepository) GetUserPermissions(userID uuid.UUID) ([]*domain.UserPermission, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.permissions[userID], nil
}

// HasPermission checks if a user has a specific permission
func (r *MockUserRepository) HasPermission(userID uuid.UUID, resource, action string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	permissions := r.permissions[userID]
	for _, perm := range permissions {
		if perm.Resource == resource && perm.Action == action && perm.Granted {
			if perm.ExpiresAt == nil || perm.ExpiresAt.After(time.Now()) {
				return true, nil
			}
		}
	}
	return false, nil
}

// LogActivity logs a user activity
func (r *MockUserRepository) LogActivity(activity *domain.UserActivity) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if activity.ID == uuid.Nil {
		activity.ID = uuid.New()
	}
	activity.CreatedAt = time.Now()

	r.activities[activity.UserID] = append(r.activities[activity.UserID], activity)
	return nil
}

// GetUserActivities retrieves user activities
func (r *MockUserRepository) GetUserActivities(userID uuid.UUID, limit, offset int) ([]*domain.UserActivity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	activities := r.activities[userID]
	start := offset
	if start > len(activities) {
		start = len(activities)
	}

	end := start + limit
	if end > len(activities) {
		end = len(activities)
	}

	return activities[start:end], nil
}

// GetUserActivity retrieves user activities (alias for GetUserActivities)
func (r *MockUserRepository) GetUserActivity(userID uuid.UUID, limit, offset int) ([]*domain.UserActivity, error) {
	return r.GetUserActivities(userID, limit, offset)
}

// GetByFirebaseUID retrieves a user by Firebase UID
func (r *MockUserRepository) GetByFirebaseUID(firebaseUID string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, user := range r.users {
		if user.FirebaseUID == firebaseUID {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

// UpdateFirebaseUID updates a user's Firebase UID
func (r *MockUserRepository) UpdateFirebaseUID(userID uuid.UUID, firebaseUID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	user, exists := r.users[userID]
	if !exists {
		return fmt.Errorf("user not found")
	}

	user.FirebaseUID = firebaseUID
	user.UpdatedAt = time.Now()
	r.users[userID] = user
	return nil
}

// ListUsersWithoutFirebaseUID retrieves users without Firebase UID
func (r *MockUserRepository) ListUsersWithoutFirebaseUID(limit, offset int) ([]*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var users []*domain.User
	count := 0
	skipped := 0

	for _, user := range r.users {
		if user.FirebaseUID == "" {
			if skipped < offset {
				skipped++
				continue
			}
			if count >= limit {
				break
			}
			users = append(users, user)
			count++
		}
	}

	return users, nil
}

// MockAuditRepository is a mock implementation of AuditRepository for testing
type MockAuditRepository struct {
	logs map[uuid.UUID][]*domain.AuditLog
	mu   sync.RWMutex
}

// NewMockAuditRepository creates a new mock audit repository
func NewMockAuditRepository() *MockAuditRepository {
	return &MockAuditRepository{
		logs: make(map[uuid.UUID][]*domain.AuditLog),
	}
}

// LogSecurityAction logs a security action
func (r *MockAuditRepository) LogSecurityAction(userID *uuid.UUID, action, resource string, riskLevel domain.RiskLevel, details map[string]interface{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Convert details to JSON
	detailsJSON, _ := json.Marshal(details)

	log := &domain.AuditLog{
		ID:        uuid.New(),
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		RiskLevel: riskLevel,
		Details:   detailsJSON,
		CreatedAt: time.Now(),
	}

	var uid uuid.UUID
	if userID != nil {
		uid = *userID
	}

	r.logs[uid] = append(r.logs[uid], log)
	return nil
}

// GetUserAuditLogs retrieves audit logs for a user
func (r *MockAuditRepository) GetUserAuditLogs(userID uuid.UUID, limit, offset int) ([]*domain.AuditLog, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	logs := r.logs[userID]
	start := offset
	if start > len(logs) {
		start = len(logs)
	}

	end := start + limit
	if end > len(logs) {
		end = len(logs)
	}

	return logs[start:end], nil
}

// GetAuditLogs retrieves all audit logs
func (r *MockAuditRepository) GetAuditLogs(limit, offset int) ([]*domain.AuditLog, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	allLogs := make([]*domain.AuditLog, 0)
	for _, logs := range r.logs {
		allLogs = append(allLogs, logs...)
	}

	start := offset
	if start > len(allLogs) {
		start = len(allLogs)
	}

	end := start + limit
	if end > len(allLogs) {
		end = len(allLogs)
	}

	return allLogs[start:end], nil
}

// Additional methods to implement the full AuditRepository interface

// CreateAuditLog creates a new audit log
func (r *MockAuditRepository) CreateAuditLog(log *domain.AuditLog) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if log.ID == uuid.Nil {
		log.ID = uuid.New()
	}
	log.CreatedAt = time.Now()

	userID := uuid.Nil
	if log.UserID != nil {
		userID = *log.UserID
	}

	r.logs[userID] = append(r.logs[userID], log)
	return nil
}

// GetAuditLog retrieves an audit log by ID
func (r *MockAuditRepository) GetAuditLog(id uuid.UUID) (*domain.AuditLog, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, logs := range r.logs {
		for _, log := range logs {
			if log.ID == id {
				return log, nil
			}
		}
	}
	return nil, fmt.Errorf("audit log not found")
}

// ListAuditLogs lists audit logs with filters
func (r *MockAuditRepository) ListAuditLogs(filters map[string]interface{}, limit, offset int) ([]*domain.AuditLog, error) {
	// For simplicity, ignore filters in mock implementation
	return r.GetAuditLogs(limit, offset)
}

// SearchAuditLogs searches audit logs
func (r *MockAuditRepository) SearchAuditLogs(query string, filters map[string]interface{}, limit, offset int) ([]*domain.AuditLog, error) {
	// For simplicity, ignore search query and filters in mock implementation
	return r.GetAuditLogs(limit, offset)
}

// DeleteExpiredAuditLogs deletes expired audit logs
func (r *MockAuditRepository) DeleteExpiredAuditLogs(before time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var deleted int64
	for userID, logs := range r.logs {
		var remaining []*domain.AuditLog
		for _, log := range logs {
			if log.CreatedAt.After(before) {
				remaining = append(remaining, log)
			} else {
				deleted++
			}
		}
		r.logs[userID] = remaining
	}
	return deleted, nil
}

// Stub implementations for other interface methods
func (r *MockAuditRepository) CreateSecurityEvent(event *domain.SecurityEvent) error {
	return nil // Stub implementation
}

func (r *MockAuditRepository) GetSecurityEvent(id uuid.UUID) (*domain.SecurityEvent, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (r *MockAuditRepository) UpdateSecurityEvent(event *domain.SecurityEvent) error {
	return nil // Stub implementation
}

func (r *MockAuditRepository) ListSecurityEvents(filters map[string]interface{}, limit, offset int) ([]*domain.SecurityEvent, error) {
	return []*domain.SecurityEvent{}, nil // Return empty slice
}

func (r *MockAuditRepository) CreateThreatIntelligence(intel *domain.ThreatIntelligence) error {
	return nil // Stub implementation
}

func (r *MockAuditRepository) GetThreatIntelligence(id uuid.UUID) (*domain.ThreatIntelligence, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (r *MockAuditRepository) UpdateThreatIntelligence(intel *domain.ThreatIntelligence) error {
	return nil // Stub implementation
}

func (r *MockAuditRepository) FindThreatIntelligence(value string) (*domain.ThreatIntelligence, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (r *MockAuditRepository) ListThreatIntelligence(filters map[string]interface{}, limit, offset int) ([]*domain.ThreatIntelligence, error) {
	return []*domain.ThreatIntelligence{}, nil // Return empty slice
}

func (r *MockAuditRepository) CreateSystemMetrics(metrics []*domain.SystemMetrics) error {
	return nil // Stub implementation
}

func (r *MockAuditRepository) GetSystemMetrics(filters map[string]interface{}, from, to time.Time) ([]*domain.SystemMetrics, error) {
	return []*domain.SystemMetrics{}, nil // Return empty slice
}

func (r *MockAuditRepository) DeleteOldMetrics(before time.Time) (int64, error) {
	return 0, nil // Stub implementation
}

func (r *MockAuditRepository) CreateBackupRecord(record *domain.BackupRecord) error {
	return nil // Stub implementation
}

func (r *MockAuditRepository) GetBackupRecord(id uuid.UUID) (*domain.BackupRecord, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (r *MockAuditRepository) UpdateBackupRecord(record *domain.BackupRecord) error {
	return nil // Stub implementation
}

func (r *MockAuditRepository) ListBackupRecords(limit, offset int) ([]*domain.BackupRecord, error) {
	return []*domain.BackupRecord{}, nil // Return empty slice
}

func (r *MockAuditRepository) LogUserAction(userID uuid.UUID, sessionID *uuid.UUID, action, resource string, details map[string]interface{}) error {
	return r.LogSecurityAction(&userID, action, resource, domain.RiskLevel("medium"), details)
}

func (r *MockAuditRepository) LogAPICall(userID *uuid.UUID, method, path, ipAddress, userAgent string, statusCode int, duration int64) error {
	details := map[string]interface{}{
		"method":      method,
		"path":        path,
		"ip_address":  ipAddress,
		"user_agent":  userAgent,
		"status_code": statusCode,
		"duration":    duration,
	}

	return r.LogSecurityAction(userID, "api_call", path, domain.RiskLevel("low"), details)
}
