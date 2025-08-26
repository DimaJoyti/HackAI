package integration

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// ToolSecurityManager manages security for tool execution
type ToolSecurityManager struct {
	level           SecurityLevel
	permissions     map[string]*PermissionSet
	sessions        map[string]*SecuritySession
	auditLog        []*AuditEntry
	encryptionKeys  map[string]string
	logger          *logger.Logger
	mutex           sync.RWMutex
}

// PermissionSet represents a set of permissions for a user/role
type PermissionSet struct {
	UserID      string                 `json:"user_id"`
	Roles       []string               `json:"roles"`
	Permissions []Permission           `json:"permissions"`
	Scopes      []string               `json:"scopes"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// SecuritySession represents an active security session
type SecuritySession struct {
	ID          string                 `json:"id"`
	UserID      string                 `json:"user_id"`
	CreatedAt   time.Time              `json:"created_at"`
	ExpiresAt   time.Time              `json:"expires_at"`
	LastAccess  time.Time              `json:"last_access"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	Permissions *PermissionSet         `json:"permissions"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AuditEntry represents an audit log entry
type AuditEntry struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	UserID    string                 `json:"user_id"`
	Action    string                 `json:"action"`
	ToolID    string                 `json:"tool_id"`
	Success   bool                   `json:"success"`
	Error     string                 `json:"error,omitempty"`
	Input     map[string]interface{} `json:"input,omitempty"`
	Output    interface{}            `json:"output,omitempty"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// SecurityContext holds security information for a request
type SecurityContext struct {
	UserID      string                 `json:"user_id"`
	SessionID   string                 `json:"session_id"`
	Permissions *PermissionSet         `json:"permissions"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewToolSecurityManager creates a new tool security manager
func NewToolSecurityManager(level SecurityLevel, logger *logger.Logger) *ToolSecurityManager {
	return &ToolSecurityManager{
		level:          level,
		permissions:    make(map[string]*PermissionSet),
		sessions:       make(map[string]*SecuritySession),
		auditLog:       make([]*AuditEntry, 0),
		encryptionKeys: make(map[string]string),
		logger:         logger,
	}
}

// InitializeSecurity initializes security for a tool integration
func (tsm *ToolSecurityManager) InitializeSecurity(ctx context.Context, integration *ToolIntegration) error {
	tsm.mutex.Lock()
	defer tsm.mutex.Unlock()

	toolID := integration.Tool.ID()

	// Generate encryption key if encryption is enabled
	if integration.Security.Encryption != nil && integration.Security.Encryption.Enabled {
		key, err := tsm.generateEncryptionKey()
		if err != nil {
			return fmt.Errorf("failed to generate encryption key: %w", err)
		}
		tsm.encryptionKeys[toolID] = key
		integration.Security.Encryption.KeyID = toolID
	}

	// Initialize audit configuration
	if integration.Security.Audit == nil {
		integration.Security.Audit = &AuditConfig{
			Enabled:    tsm.level >= SecurityLevelStandard,
			LogLevel:   "info",
			LogInputs:  tsm.level >= SecurityLevelHigh,
			LogOutputs: tsm.level >= SecurityLevelHigh,
			Retention:  30 * 24 * time.Hour, // 30 days
		}
	}

	tsm.logger.Info("Security initialized for tool",
		"tool_id", toolID,
		"security_level", tsm.level,
		"encryption_enabled", integration.Security.Encryption != nil && integration.Security.Encryption.Enabled)

	return nil
}

// CheckPermissions checks if a user has permission to execute a tool
func (tsm *ToolSecurityManager) CheckPermissions(ctx context.Context, integration *ToolIntegration, options *ExecutionOptions) error {
	if tsm.level == SecurityLevelNone {
		return nil
	}

	tsm.mutex.RLock()
	defer tsm.mutex.RUnlock()

	// Extract security context
	securityCtx := tsm.extractSecurityContext(ctx, options)

	// Check if user is allowed
	if len(integration.Security.AllowedUsers) > 0 {
		if !tsm.containsString(integration.Security.AllowedUsers, securityCtx.UserID) {
			return fmt.Errorf("user %s not allowed to execute tool %s", securityCtx.UserID, integration.Tool.ID())
		}
	}

	// Check role-based permissions
	if len(integration.Security.AllowedRoles) > 0 {
		userPermissions := tsm.getUserPermissions(securityCtx.UserID)
		if userPermissions == nil {
			return fmt.Errorf("no permissions found for user %s", securityCtx.UserID)
		}

		hasAllowedRole := false
		for _, userRole := range userPermissions.Roles {
			if tsm.containsString(integration.Security.AllowedRoles, userRole) {
				hasAllowedRole = true
				break
			}
		}

		if !hasAllowedRole {
			return fmt.Errorf("user %s does not have required role for tool %s", securityCtx.UserID, integration.Tool.ID())
		}
	}

	// Check permission-based access
	if len(integration.Security.Permissions) > 0 {
		userPermissions := tsm.getUserPermissions(securityCtx.UserID)
		if userPermissions == nil {
			return fmt.Errorf("no permissions found for user %s", securityCtx.UserID)
		}

		for _, requiredPerm := range integration.Security.Permissions {
			if !tsm.containsPermission(userPermissions.Permissions, requiredPerm) {
				return fmt.Errorf("user %s lacks permission %s for tool %s", securityCtx.UserID, requiredPerm, integration.Tool.ID())
			}
		}
	}

	// Check scopes
	if len(integration.Security.RequiredScopes) > 0 {
		userPermissions := tsm.getUserPermissions(securityCtx.UserID)
		if userPermissions == nil {
			return fmt.Errorf("no permissions found for user %s", securityCtx.UserID)
		}

		for _, requiredScope := range integration.Security.RequiredScopes {
			if !tsm.containsString(userPermissions.Scopes, requiredScope) {
				return fmt.Errorf("user %s lacks scope %s for tool %s", securityCtx.UserID, requiredScope, integration.Tool.ID())
			}
		}
	}

	return nil
}

// CreateSession creates a new security session
func (tsm *ToolSecurityManager) CreateSession(userID, ipAddress, userAgent string, permissions *PermissionSet) (*SecuritySession, error) {
	tsm.mutex.Lock()
	defer tsm.mutex.Unlock()

	sessionID, err := tsm.generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	session := &SecuritySession{
		ID:          sessionID,
		UserID:      userID,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour), // 24 hour session
		LastAccess:  time.Now(),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		Permissions: permissions,
		Metadata:    make(map[string]interface{}),
	}

	tsm.sessions[sessionID] = session

	tsm.logger.Info("Security session created",
		"session_id", sessionID,
		"user_id", userID,
		"expires_at", session.ExpiresAt)

	return session, nil
}

// ValidateSession validates a security session
func (tsm *ToolSecurityManager) ValidateSession(sessionID string) (*SecuritySession, error) {
	tsm.mutex.RLock()
	defer tsm.mutex.RUnlock()

	session, exists := tsm.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired")
	}

	// Update last access time
	session.LastAccess = time.Now()

	return session, nil
}

// RevokeSession revokes a security session
func (tsm *ToolSecurityManager) RevokeSession(sessionID string) error {
	tsm.mutex.Lock()
	defer tsm.mutex.Unlock()

	if _, exists := tsm.sessions[sessionID]; !exists {
		return fmt.Errorf("session not found")
	}

	delete(tsm.sessions, sessionID)

	tsm.logger.Info("Security session revoked", "session_id", sessionID)
	return nil
}

// SetUserPermissions sets permissions for a user
func (tsm *ToolSecurityManager) SetUserPermissions(userID string, permissions *PermissionSet) {
	tsm.mutex.Lock()
	defer tsm.mutex.Unlock()

	permissions.UserID = userID
	tsm.permissions[userID] = permissions

	tsm.logger.Info("User permissions updated",
		"user_id", userID,
		"roles", len(permissions.Roles),
		"permissions", len(permissions.Permissions),
		"scopes", len(permissions.Scopes))
}

// GetUserPermissions retrieves permissions for a user
func (tsm *ToolSecurityManager) GetUserPermissions(userID string) *PermissionSet {
	tsm.mutex.RLock()
	defer tsm.mutex.RUnlock()

	return tsm.getUserPermissions(userID)
}

// LogAuditEntry logs an audit entry
func (tsm *ToolSecurityManager) LogAuditEntry(entry *AuditEntry) {
	tsm.mutex.Lock()
	defer tsm.mutex.Unlock()

	entry.ID = tsm.generateAuditID()
	entry.Timestamp = time.Now()

	tsm.auditLog = append(tsm.auditLog, entry)

	// Limit audit log size (keep last 10000 entries)
	if len(tsm.auditLog) > 10000 {
		tsm.auditLog = tsm.auditLog[len(tsm.auditLog)-10000:]
	}

	tsm.logger.Info("Audit entry logged",
		"audit_id", entry.ID,
		"user_id", entry.UserID,
		"action", entry.Action,
		"tool_id", entry.ToolID,
		"success", entry.Success)
}

// GetAuditLog retrieves audit log entries
func (tsm *ToolSecurityManager) GetAuditLog(userID string, limit int) []*AuditEntry {
	tsm.mutex.RLock()
	defer tsm.mutex.RUnlock()

	var entries []*AuditEntry

	// Filter by user if specified
	for _, entry := range tsm.auditLog {
		if userID == "" || entry.UserID == userID {
			entries = append(entries, entry)
		}
	}

	// Apply limit
	if limit > 0 && len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}

	return entries
}

// EncryptData encrypts data using the tool's encryption key
func (tsm *ToolSecurityManager) EncryptData(toolID string, data []byte) ([]byte, error) {
	tsm.mutex.RLock()
	defer tsm.mutex.RUnlock()

	key, exists := tsm.encryptionKeys[toolID]
	if !exists {
		return nil, fmt.Errorf("encryption key not found for tool %s", toolID)
	}

	// Simple encryption (in production, use proper encryption)
	hash := sha256.Sum256(append([]byte(key), data...))
	return hash[:], nil
}

// DecryptData decrypts data using the tool's encryption key
func (tsm *ToolSecurityManager) DecryptData(toolID string, encryptedData []byte) ([]byte, error) {
	tsm.mutex.RLock()
	defer tsm.mutex.RUnlock()

	_, exists := tsm.encryptionKeys[toolID]
	if !exists {
		return nil, fmt.Errorf("encryption key not found for tool %s", toolID)
	}

	// Simple decryption (in production, use proper decryption)
	// For this demo, we'll just return the encrypted data
	return encryptedData, nil
}

// Helper methods

func (tsm *ToolSecurityManager) extractSecurityContext(ctx context.Context, options *ExecutionOptions) *SecurityContext {
	securityCtx := &SecurityContext{
		UserID:    options.UserID,
		Metadata:  make(map[string]interface{}),
	}

	// Extract additional context from options
	if options.Context != nil {
		if sessionID, exists := options.Context["session_id"]; exists {
			if sid, ok := sessionID.(string); ok {
				securityCtx.SessionID = sid
			}
		}

		if ipAddress, exists := options.Context["ip_address"]; exists {
			if ip, ok := ipAddress.(string); ok {
				securityCtx.IPAddress = ip
			}
		}

		if userAgent, exists := options.Context["user_agent"]; exists {
			if ua, ok := userAgent.(string); ok {
				securityCtx.UserAgent = ua
			}
		}
	}

	// Get user permissions
	securityCtx.Permissions = tsm.getUserPermissions(securityCtx.UserID)

	return securityCtx
}

func (tsm *ToolSecurityManager) getUserPermissions(userID string) *PermissionSet {
	permissions, exists := tsm.permissions[userID]
	if !exists {
		return nil
	}

	// Check if permissions have expired
	if permissions.ExpiresAt != nil && time.Now().After(*permissions.ExpiresAt) {
		return nil
	}

	return permissions
}

func (tsm *ToolSecurityManager) generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (tsm *ToolSecurityManager) generateEncryptionKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (tsm *ToolSecurityManager) generateAuditID() string {
	return fmt.Sprintf("audit_%d", time.Now().UnixNano())
}

func (tsm *ToolSecurityManager) containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (tsm *ToolSecurityManager) containsPermission(slice []Permission, item Permission) bool {
	for _, p := range slice {
		if p == item {
			return true
		}
	}
	return false
}

// CleanupExpiredSessions removes expired sessions
func (tsm *ToolSecurityManager) CleanupExpiredSessions() {
	tsm.mutex.Lock()
	defer tsm.mutex.Unlock()

	now := time.Now()
	expiredSessions := make([]string, 0)

	for sessionID, session := range tsm.sessions {
		if now.After(session.ExpiresAt) {
			expiredSessions = append(expiredSessions, sessionID)
		}
	}

	for _, sessionID := range expiredSessions {
		delete(tsm.sessions, sessionID)
	}

	if len(expiredSessions) > 0 {
		tsm.logger.Info("Expired sessions cleaned up", "count", len(expiredSessions))
	}
}

// GetSecurityStats returns security statistics
func (tsm *ToolSecurityManager) GetSecurityStats() *SecurityStats {
	tsm.mutex.RLock()
	defer tsm.mutex.RUnlock()

	stats := &SecurityStats{
		ActiveSessions:   len(tsm.sessions),
		TotalUsers:       len(tsm.permissions),
		AuditEntries:     len(tsm.auditLog),
		EncryptionKeys:   len(tsm.encryptionKeys),
		SecurityLevel:    tsm.level,
		Timestamp:        time.Now(),
	}

	// Count successful vs failed audit entries
	for _, entry := range tsm.auditLog {
		if entry.Success {
			stats.SuccessfulActions++
		} else {
			stats.FailedActions++
		}
	}

	return stats
}

// SecurityStats holds security statistics
type SecurityStats struct {
	ActiveSessions    int           `json:"active_sessions"`
	TotalUsers        int           `json:"total_users"`
	AuditEntries      int           `json:"audit_entries"`
	EncryptionKeys    int           `json:"encryption_keys"`
	SuccessfulActions int64         `json:"successful_actions"`
	FailedActions     int64         `json:"failed_actions"`
	SecurityLevel     SecurityLevel `json:"security_level"`
	Timestamp         time.Time     `json:"timestamp"`
}
