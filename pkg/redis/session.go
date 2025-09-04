package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// SessionManager handles Redis-based session management
type SessionManager struct {
	client *Client
	logger *logger.Logger
	prefix string
	ttl    time.Duration
}

// SessionData represents session data structure
type SessionData struct {
	UserID      string                 `json:"user_id"`
	Username    string                 `json:"username"`
	Email       string                 `json:"email"`
	Role        string                 `json:"role"`
	Permissions []string               `json:"permissions"`
	DeviceID    string                 `json:"device_id"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	CreatedAt   time.Time              `json:"created_at"`
	LastAccess  time.Time              `json:"last_access"`
	ExpiresAt   time.Time              `json:"expires_at"`
	Data        map[string]interface{} `json:"data"`
}

// NewSessionManager creates a new session manager
func NewSessionManager(client *Client, logger *logger.Logger) *SessionManager {
	return &SessionManager{
		client: client,
		logger: logger,
		prefix: "session:",
		ttl:    24 * time.Hour, // Default 24 hour TTL
	}
}

// SetTTL sets the default session TTL
func (sm *SessionManager) SetTTL(ttl time.Duration) {
	sm.ttl = ttl
}

// SetPrefix sets the Redis key prefix for sessions
func (sm *SessionManager) SetPrefix(prefix string) {
	sm.prefix = prefix
}

// CreateSession creates a new session
func (sm *SessionManager) CreateSession(ctx context.Context, userID, username, email, role string, permissions []string, deviceID, ipAddress, userAgent string) (string, error) {
	sessionID := uuid.New().String()
	now := time.Now()
	
	sessionData := &SessionData{
		UserID:      userID,
		Username:    username,
		Email:       email,
		Role:        role,
		Permissions: permissions,
		DeviceID:    deviceID,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   now,
		LastAccess:  now,
		ExpiresAt:   now.Add(sm.ttl),
		Data:        make(map[string]interface{}),
	}

	// Serialize session data
	data, err := json.Marshal(sessionData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Store in Redis
	key := sm.getSessionKey(sessionID)
	if err := sm.client.Set(ctx, key, data, sm.ttl).Err(); err != nil {
		return "", fmt.Errorf("failed to store session: %w", err)
	}

	// Add to user sessions set for tracking
	userSessionsKey := sm.getUserSessionsKey(userID)
	if err := sm.client.SAdd(ctx, userSessionsKey, sessionID).Err(); err != nil {
		sm.logger.Warnf("Failed to add session to user sessions set: %v", err)
	}

	// Set expiration for user sessions set
	sm.client.Expire(ctx, userSessionsKey, sm.ttl)

	sm.logger.Infof("Created session %s for user %s", sessionID, userID)
	return sessionID, nil
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
	key := sm.getSessionKey(sessionID)
	
	data, err := sm.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var sessionData SessionData
	if err := json.Unmarshal([]byte(data), &sessionData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	// Check if session is expired
	if time.Now().After(sessionData.ExpiresAt) {
		sm.DeleteSession(ctx, sessionID)
		return nil, fmt.Errorf("session expired")
	}

	return &sessionData, nil
}

// UpdateSession updates session data
func (sm *SessionManager) UpdateSession(ctx context.Context, sessionID string, sessionData *SessionData) error {
	// Update last access time
	sessionData.LastAccess = time.Now()

	// Serialize session data
	data, err := json.Marshal(sessionData)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Store in Redis
	key := sm.getSessionKey(sessionID)
	if err := sm.client.Set(ctx, key, data, sm.ttl).Err(); err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	return nil
}

// RefreshSession extends the session TTL
func (sm *SessionManager) RefreshSession(ctx context.Context, sessionID string) error {
	sessionData, err := sm.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	// Update expiration time
	sessionData.ExpiresAt = time.Now().Add(sm.ttl)
	sessionData.LastAccess = time.Now()

	return sm.UpdateSession(ctx, sessionID, sessionData)
}

// DeleteSession deletes a session
func (sm *SessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	// Get session data to find user ID
	sessionData, err := sm.GetSession(ctx, sessionID)
	if err != nil {
		// Session might already be deleted, continue with cleanup
		sm.logger.Warnf("Session %s not found during deletion: %v", sessionID, err)
	}

	// Delete session
	key := sm.getSessionKey(sessionID)
	if err := sm.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	// Remove from user sessions set
	if sessionData != nil {
		userSessionsKey := sm.getUserSessionsKey(sessionData.UserID)
		if err := sm.client.SRem(ctx, userSessionsKey, sessionID).Err(); err != nil {
			sm.logger.Warnf("Failed to remove session from user sessions set: %v", err)
		}
	}

	sm.logger.Infof("Deleted session %s", sessionID)
	return nil
}

// DeleteUserSessions deletes all sessions for a user
func (sm *SessionManager) DeleteUserSessions(ctx context.Context, userID string) error {
	userSessionsKey := sm.getUserSessionsKey(userID)
	
	// Get all session IDs for the user
	sessionIDs, err := sm.client.SMembers(ctx, userSessionsKey).Result()
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	// Delete each session
	for _, sessionID := range sessionIDs {
		if err := sm.DeleteSession(ctx, sessionID); err != nil {
			sm.logger.Warnf("Failed to delete session %s: %v", sessionID, err)
		}
	}

	// Delete the user sessions set
	if err := sm.client.Del(ctx, userSessionsKey).Err(); err != nil {
		sm.logger.Warnf("Failed to delete user sessions set: %v", err)
	}

	sm.logger.Infof("Deleted all sessions for user %s", userID)
	return nil
}

// GetUserSessions returns all active sessions for a user
func (sm *SessionManager) GetUserSessions(ctx context.Context, userID string) ([]*SessionData, error) {
	userSessionsKey := sm.getUserSessionsKey(userID)
	
	// Get all session IDs for the user
	sessionIDs, err := sm.client.SMembers(ctx, userSessionsKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}

	var sessions []*SessionData
	for _, sessionID := range sessionIDs {
		sessionData, err := sm.GetSession(ctx, sessionID)
		if err != nil {
			// Session might be expired, remove from set
			sm.client.SRem(ctx, userSessionsKey, sessionID)
			continue
		}
		sessions = append(sessions, sessionData)
	}

	return sessions, nil
}

// CleanupExpiredSessions removes expired sessions (should be run periodically)
func (sm *SessionManager) CleanupExpiredSessions(ctx context.Context) error {
	pattern := sm.prefix + "*"
	
	// Scan for all session keys
	iter := sm.client.Scan(ctx, 0, pattern, 100).Iterator()
	var expiredKeys []string
	
	for iter.Next(ctx) {
		key := iter.Val()
		
		// Check if key exists and get TTL
		ttl, err := sm.client.TTL(ctx, key).Result()
		if err != nil {
			continue
		}
		
		// If TTL is -1 (no expiration) or -2 (key doesn't exist), mark for cleanup
		if ttl == -1 || ttl == -2 {
			expiredKeys = append(expiredKeys, key)
		}
	}
	
	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to scan session keys: %w", err)
	}

	// Delete expired keys
	if len(expiredKeys) > 0 {
		if err := sm.client.Del(ctx, expiredKeys...).Err(); err != nil {
			return fmt.Errorf("failed to delete expired sessions: %w", err)
		}
		sm.logger.Infof("Cleaned up %d expired sessions", len(expiredKeys))
	}

	return nil
}

// GetSessionStats returns session statistics
func (sm *SessionManager) GetSessionStats(ctx context.Context) (map[string]interface{}, error) {
	pattern := sm.prefix + "*"
	
	// Count total sessions
	keys, err := sm.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get session keys: %w", err)
	}

	stats := map[string]interface{}{
		"total_sessions": len(keys),
		"prefix":         sm.prefix,
		"default_ttl":    sm.ttl.String(),
	}

	return stats, nil
}

// Helper methods
func (sm *SessionManager) getSessionKey(sessionID string) string {
	return sm.prefix + sessionID
}

func (sm *SessionManager) getUserSessionsKey(userID string) string {
	return fmt.Sprintf("user_sessions:%s", userID)
}
