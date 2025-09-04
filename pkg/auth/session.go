package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// SessionManager manages user sessions
type SessionManager struct {
	sessions     map[string]*SessionInfo
	userSessions map[uuid.UUID][]string // User ID -> Session IDs
	config       *SecurityConfig
	logger       *logger.Logger
	mutex        sync.RWMutex
}

// SessionInfo represents session information
type SessionInfo struct {
	ID           string                 `json:"id"`
	UserID       uuid.UUID              `json:"user_id"`
	DeviceID     string                 `json:"device_id"`
	UserAgent    string                 `json:"user_agent"`
	IPAddress    string                 `json:"ip_address"`
	CreatedAt    time.Time              `json:"created_at"`
	LastActivity time.Time              `json:"last_activity"`
	ExpiresAt    time.Time              `json:"expires_at"`
	IsActive     bool                   `json:"is_active"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// NewSessionManager creates a new session manager
func NewSessionManager(config *SecurityConfig) *SessionManager {
	loggerInstance, _ := logger.New(logger.Config{}) // Use default logger config
	return &SessionManager{
		sessions:     make(map[string]*SessionInfo),
		userSessions: make(map[uuid.UUID][]string),
		config:       config,
		logger:       loggerInstance,
	}
}

// GenerateSessionID generates a cryptographically secure session ID
func (sm *SessionManager) GenerateSessionID() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// CreateSession creates a new session for a user
func (sm *SessionManager) CreateSession(userID uuid.UUID, deviceID, userAgent, ipAddress string, rememberMe bool) (*SessionInfo, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Check if user has too many active sessions
	if sm.getUserSessionCount(userID) >= sm.config.MaxConcurrentSessions {
		// Remove oldest session
		if err := sm.removeOldestUserSession(userID); err != nil {
			return nil, fmt.Errorf("failed to remove oldest session: %w", err)
		}
	}

	// Generate session ID
	sessionID, err := sm.GenerateSessionID()
	if err != nil {
		return nil, err
	}

	// Calculate expiration
	expiresAt := time.Now().Add(sm.config.SessionTimeout)
	if rememberMe {
		expiresAt = time.Now().Add(30 * 24 * time.Hour) // 30 days
	}

	// Create session info
	session := &SessionInfo{
		ID:           sessionID,
		UserID:       userID,
		DeviceID:     deviceID,
		UserAgent:    userAgent,
		IPAddress:    ipAddress,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		ExpiresAt:    expiresAt,
		IsActive:     true,
		Metadata:     make(map[string]interface{}),
	}

	// Store session
	sm.sessions[sessionID] = session

	// Add to user sessions
	if sm.userSessions[userID] == nil {
		sm.userSessions[userID] = []string{}
	}
	sm.userSessions[userID] = append(sm.userSessions[userID], sessionID)

	sm.logger.WithFields(logger.Fields{
		"session_id": sessionID,
		"user_id":    userID,
		"device_id":  deviceID,
		"ip_address": ipAddress,
		"expires_at": expiresAt,
	}).Info("Session created")

	return session, nil
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(sessionID string) (*SessionInfo, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired")
	}

	if !session.IsActive {
		return nil, fmt.Errorf("session is inactive")
	}

	return session, nil
}

// ValidateSession validates a session and updates last activity
func (sm *SessionManager) ValidateSession(sessionID string, ipAddress string) (*SessionInfo, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		session.IsActive = false
		return nil, fmt.Errorf("session expired")
	}

	if !session.IsActive {
		return nil, fmt.Errorf("session is inactive")
	}

	// Check IP address consistency (optional security measure)
	if sm.config != nil && len(sm.config.AllowedIPRanges) > 0 {
		if session.IPAddress != ipAddress {
			sm.logger.WithFields(logger.Fields{
				"session_id":  sessionID,
				"original_ip": session.IPAddress,
				"current_ip":  ipAddress,
			}).Warn("Session IP address mismatch")
			// You might want to invalidate the session here for security
		}
	}

	// Update last activity
	session.LastActivity = time.Now()

	return session, nil
}

// InvalidateSession invalidates a session
func (sm *SessionManager) InvalidateSession(sessionID string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found")
	}

	session.IsActive = false

	// Remove from user sessions
	userSessions := sm.userSessions[session.UserID]
	for i, id := range userSessions {
		if id == sessionID {
			sm.userSessions[session.UserID] = append(userSessions[:i], userSessions[i+1:]...)
			break
		}
	}

	sm.logger.WithFields(logger.Fields{
		"session_id": sessionID,
		"user_id":    session.UserID,
	}).Info("Session invalidated")

	return nil
}

// InvalidateAllUserSessions invalidates all sessions for a user
func (sm *SessionManager) InvalidateAllUserSessions(userID uuid.UUID) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	userSessions, exists := sm.userSessions[userID]
	if !exists {
		return nil // No sessions to invalidate
	}

	count := 0
	for _, sessionID := range userSessions {
		if session, exists := sm.sessions[sessionID]; exists {
			session.IsActive = false
			count++
		}
	}

	// Clear user sessions
	delete(sm.userSessions, userID)

	sm.logger.WithFields(logger.Fields{
		"user_id":        userID,
		"sessions_count": count,
	}).Info("All user sessions invalidated")

	return nil
}

// GetUserSessions returns all active sessions for a user
func (sm *SessionManager) GetUserSessions(userID uuid.UUID) []*SessionInfo {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	userSessions, exists := sm.userSessions[userID]
	if !exists {
		return []*SessionInfo{}
	}

	var sessions []*SessionInfo
	now := time.Now()

	for _, sessionID := range userSessions {
		if session, exists := sm.sessions[sessionID]; exists {
			if session.IsActive && now.Before(session.ExpiresAt) {
				sessions = append(sessions, session)
			}
		}
	}

	return sessions
}

// CleanupExpiredSessions removes expired sessions
func (sm *SessionManager) CleanupExpiredSessions() int {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	now := time.Now()
	expiredCount := 0

	// Find expired sessions
	var expiredSessions []string
	for sessionID, session := range sm.sessions {
		if now.After(session.ExpiresAt) {
			expiredSessions = append(expiredSessions, sessionID)
			expiredCount++
		}
	}

	// Remove expired sessions
	for _, sessionID := range expiredSessions {
		session := sm.sessions[sessionID]
		delete(sm.sessions, sessionID)

		// Remove from user sessions
		userSessions := sm.userSessions[session.UserID]
		for i, id := range userSessions {
			if id == sessionID {
				sm.userSessions[session.UserID] = append(userSessions[:i], userSessions[i+1:]...)
				break
			}
		}
	}

	if expiredCount > 0 {
		sm.logger.WithFields(logger.Fields{
			"expired_count": expiredCount,
		}).Info("Cleaned up expired sessions")
	}

	return expiredCount
}

// GetSessionStats returns session statistics
func (sm *SessionManager) GetSessionStats() map[string]interface{} {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	now := time.Now()
	activeCount := 0
	expiredCount := 0
	totalUsers := len(sm.userSessions)

	for _, session := range sm.sessions {
		if session.IsActive && now.Before(session.ExpiresAt) {
			activeCount++
		} else {
			expiredCount++
		}
	}

	return map[string]interface{}{
		"total_sessions":   len(sm.sessions),
		"active_sessions":  activeCount,
		"expired_sessions": expiredCount,
		"total_users":      totalUsers,
		"max_concurrent":   sm.config.MaxConcurrentSessions,
	}
}

// ExtendSession extends a session's expiration time
func (sm *SessionManager) ExtendSession(sessionID string, duration time.Duration) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found")
	}

	if !session.IsActive {
		return fmt.Errorf("cannot extend inactive session")
	}

	session.ExpiresAt = session.ExpiresAt.Add(duration)
	session.LastActivity = time.Now()

	sm.logger.WithFields(logger.Fields{
		"session_id": sessionID,
		"new_expiry": session.ExpiresAt,
		"extension":  duration,
	}).Info("Session extended")

	return nil
}

// UpdateSessionMetadata updates session metadata
func (sm *SessionManager) UpdateSessionMetadata(sessionID string, metadata map[string]interface{}) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found")
	}

	if session.Metadata == nil {
		session.Metadata = make(map[string]interface{})
	}

	for key, value := range metadata {
		session.Metadata[key] = value
	}

	session.LastActivity = time.Now()

	return nil
}

// getUserSessionCount returns the number of active sessions for a user
func (sm *SessionManager) getUserSessionCount(userID uuid.UUID) int {
	userSessions, exists := sm.userSessions[userID]
	if !exists {
		return 0
	}

	count := 0
	now := time.Now()

	for _, sessionID := range userSessions {
		if session, exists := sm.sessions[sessionID]; exists {
			if session.IsActive && now.Before(session.ExpiresAt) {
				count++
			}
		}
	}

	return count
}

// removeOldestUserSession removes the oldest session for a user
func (sm *SessionManager) removeOldestUserSession(userID uuid.UUID) error {
	userSessions, exists := sm.userSessions[userID]
	if !exists {
		return fmt.Errorf("user has no sessions")
	}

	var oldestSessionID string
	var oldestTime time.Time

	// Find oldest session
	for _, sessionID := range userSessions {
		if session, exists := sm.sessions[sessionID]; exists {
			if session.IsActive && (oldestSessionID == "" || session.CreatedAt.Before(oldestTime)) {
				oldestSessionID = sessionID
				oldestTime = session.CreatedAt
			}
		}
	}

	if oldestSessionID == "" {
		return fmt.Errorf("no active sessions found")
	}

	// Invalidate oldest session
	return sm.InvalidateSession(oldestSessionID)
}

// StartCleanupRoutine starts a background routine to clean up expired sessions
func (sm *SessionManager) StartCleanupRoutine(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	sm.logger.WithFields(logger.Fields{
		"cleanup_interval": interval,
	}).Info("Started session cleanup routine")

	for {
		select {
		case <-ctx.Done():
			sm.logger.Info("Session cleanup routine stopped")
			return
		case <-ticker.C:
			sm.CleanupExpiredSessions()
		}
	}
}

// IsSessionValid validates a domain UserSession object
func (sm *SessionManager) IsSessionValid(session *domain.UserSession) bool {
	if session == nil {
		return false
	}
	
	now := time.Now()
	
	// Check if session is expired
	if now.After(session.ExpiresAt) {
		return false
	}
	
	// Check if session has exceeded the timeout duration from creation
	if sm.config != nil && sm.config.SessionTimeout > 0 {
		sessionAge := now.Sub(session.CreatedAt)
		if sessionAge > sm.config.SessionTimeout {
			return false
		}
	}
	
	return true
}

// SessionActivity represents session activity information
type SessionActivity struct {
	SessionID string                 `json:"session_id"`
	UserID    uuid.UUID              `json:"user_id"`
	Activity  string                 `json:"activity"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// LogActivity logs session activity
func (sm *SessionManager) LogActivity(sessionID, activity, ipAddress, userAgent string, metadata map[string]interface{}) error {
	session, err := sm.GetSession(sessionID)
	if err != nil {
		return err
	}

	sm.logger.WithFields(logger.Fields{
		"session_id": sessionID,
		"user_id":    session.UserID,
		"activity":   activity,
		"ip_address": ipAddress,
		"user_agent": userAgent,
		"metadata":   metadata,
	}).Info("Session activity logged")

	// In a production system, you might want to store this in a database
	// or send it to an analytics service

	return nil
}
