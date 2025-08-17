package chains

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var securityTracer = otel.Tracer("hackai/llm/chains/security")

// ChainSecurity provides access control and security for chains
type ChainSecurity interface {
	// Permission management
	SetPermissions(ctx context.Context, chainID string, permissions ChainPermissions) error
	GetPermissions(ctx context.Context, chainID string) (ChainPermissions, error)
	RemovePermissions(ctx context.Context, chainID string) error

	// Access control
	CheckAccess(ctx context.Context, chainID string, userID string, action string) error
	GrantAccess(ctx context.Context, chainID string, userID string, permissions []string) error
	RevokeAccess(ctx context.Context, chainID string, userID string, permissions []string) error

	// Role-based access control
	CreateRole(ctx context.Context, role Role) error
	AssignRole(ctx context.Context, userID string, roleID string) error
	RevokeRole(ctx context.Context, userID string, roleID string) error
	GetUserRoles(ctx context.Context, userID string) ([]Role, error)

	// Audit logging
	LogAccess(ctx context.Context, chainID string, userID string, action string, result string) error
	GetAuditLog(ctx context.Context, chainID string, filter AuditFilter) ([]AuditEntry, error)

	// Security policies
	SetSecurityPolicy(ctx context.Context, chainID string, policy SecurityPolicy) error
	GetSecurityPolicy(ctx context.Context, chainID string) (SecurityPolicy, error)
	ValidateSecurityPolicy(ctx context.Context, policy SecurityPolicy) error

	// Token management
	GenerateAccessToken(ctx context.Context, userID string, chainID string, permissions []string, expiry time.Duration) (string, error)
	ValidateAccessToken(ctx context.Context, token string) (TokenClaims, error)
	RevokeAccessToken(ctx context.Context, token string) error
}

// DefaultChainSecurity implements the ChainSecurity interface
type DefaultChainSecurity struct {
	permissions      map[string]ChainPermissions
	roles            map[string]Role
	userRoles        map[string][]string // userID -> roleIDs
	auditLog         []AuditEntry
	securityPolicies map[string]SecurityPolicy
	accessTokens     map[string]TokenClaims
	logger           *logger.Logger
	mutex            sync.RWMutex
}

// Role represents a security role
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AuditEntry represents an audit log entry
type AuditEntry struct {
	ID        string                 `json:"id"`
	ChainID   string                 `json:"chain_id"`
	UserID    string                 `json:"user_id"`
	Action    string                 `json:"action"`
	Result    string                 `json:"result"`
	Timestamp time.Time              `json:"timestamp"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// AuditFilter provides filtering options for audit logs
type AuditFilter struct {
	UserID    string     `json:"user_id"`
	Action    string     `json:"action"`
	Result    string     `json:"result"`
	StartTime *time.Time `json:"start_time"`
	EndTime   *time.Time `json:"end_time"`
	Limit     int        `json:"limit"`
	Offset    int        `json:"offset"`
}

// SecurityPolicy defines security policies for a chain
type SecurityPolicy struct {
	ChainID               string        `json:"chain_id"`
	RequireAuthentication bool          `json:"require_authentication"`
	RequireAuthorization  bool          `json:"require_authorization"`
	AllowAnonymousRead    bool          `json:"allow_anonymous_read"`
	AllowAnonymousExecute bool          `json:"allow_anonymous_execute"`
	MaxExecutionsPerUser  int           `json:"max_executions_per_user"`
	MaxExecutionsPerHour  int           `json:"max_executions_per_hour"`
	AllowedIPRanges       []string      `json:"allowed_ip_ranges"`
	BlockedIPRanges       []string      `json:"blocked_ip_ranges"`
	SessionTimeout        time.Duration `json:"session_timeout"`
	RequireMFA            bool          `json:"require_mfa"`
	AuditAllAccess        bool          `json:"audit_all_access"`
	EncryptionRequired    bool          `json:"encryption_required"`
}

// TokenClaims represents claims in an access token
type TokenClaims struct {
	UserID      string    `json:"user_id"`
	ChainID     string    `json:"chain_id"`
	Permissions []string  `json:"permissions"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	TokenID     string    `json:"token_id"`
}

// NewDefaultChainSecurity creates a new default chain security manager
func NewDefaultChainSecurity(logger *logger.Logger) *DefaultChainSecurity {
	return &DefaultChainSecurity{
		permissions:      make(map[string]ChainPermissions),
		roles:            make(map[string]Role),
		userRoles:        make(map[string][]string),
		auditLog:         make([]AuditEntry, 0),
		securityPolicies: make(map[string]SecurityPolicy),
		accessTokens:     make(map[string]TokenClaims),
		logger:           logger,
	}
}

// SetPermissions sets permissions for a chain
func (s *DefaultChainSecurity) SetPermissions(ctx context.Context, chainID string, permissions ChainPermissions) error {
	ctx, span := securityTracer.Start(ctx, "security.set_permissions",
		trace.WithAttributes(
			attribute.String("chain.id", chainID),
			attribute.Int("owners.count", len(permissions.Owners)),
			attribute.Int("readers.count", len(permissions.Readers)),
			attribute.Int("executors.count", len(permissions.Executors)),
		),
	)
	defer span.End()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	permissions.ChainID = chainID
	s.permissions[chainID] = permissions

	span.SetAttributes(attribute.Bool("success", true))
	s.logger.Info("Permissions set for chain",
		"chain_id", chainID,
		"owners", len(permissions.Owners),
		"readers", len(permissions.Readers),
		"executors", len(permissions.Executors),
	)

	return nil
}

// GetPermissions retrieves permissions for a chain
func (s *DefaultChainSecurity) GetPermissions(ctx context.Context, chainID string) (ChainPermissions, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	permissions, exists := s.permissions[chainID]
	if !exists {
		return ChainPermissions{}, fmt.Errorf("permissions not found for chain %s", chainID)
	}

	return permissions, nil
}

// RemovePermissions removes permissions for a chain
func (s *DefaultChainSecurity) RemovePermissions(ctx context.Context, chainID string) error {
	ctx, span := securityTracer.Start(ctx, "security.remove_permissions",
		trace.WithAttributes(attribute.String("chain.id", chainID)),
	)
	defer span.End()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.permissions, chainID)

	span.SetAttributes(attribute.Bool("success", true))
	s.logger.Info("Permissions removed for chain", "chain_id", chainID)

	return nil
}

// CheckAccess checks if a user has access to perform an action on a chain
func (s *DefaultChainSecurity) CheckAccess(ctx context.Context, chainID string, userID string, action string) error {
	ctx, span := securityTracer.Start(ctx, "security.check_access",
		trace.WithAttributes(
			attribute.String("chain.id", chainID),
			attribute.String("user.id", userID),
			attribute.String("action", action),
		),
	)
	defer span.End()

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Get permissions for the chain
	permissions, exists := s.permissions[chainID]
	if !exists {
		err := fmt.Errorf("no permissions configured for chain %s", chainID)
		span.RecordError(err)
		return err
	}

	// Check public access first
	if action == "read" && permissions.PublicRead {
		span.SetAttributes(attribute.Bool("access.granted", true), attribute.String("access.reason", "public_read"))
		return nil
	}
	if action == "execute" && permissions.PublicExecute {
		span.SetAttributes(attribute.Bool("access.granted", true), attribute.String("access.reason", "public_execute"))
		return nil
	}

	// Check specific permissions
	hasAccess := false
	accessReason := ""

	switch action {
	case "read":
		if s.userInList(userID, permissions.Owners) ||
			s.userInList(userID, permissions.Readers) ||
			s.userInList(userID, permissions.Executors) ||
			s.userInList(userID, permissions.Admins) {
			hasAccess = true
			accessReason = "explicit_permission"
		}
	case "execute":
		if s.userInList(userID, permissions.Owners) ||
			s.userInList(userID, permissions.Executors) ||
			s.userInList(userID, permissions.Admins) {
			hasAccess = true
			accessReason = "explicit_permission"
		}
	case "admin":
		if s.userInList(userID, permissions.Owners) ||
			s.userInList(userID, permissions.Admins) {
			hasAccess = true
			accessReason = "admin_permission"
		}
	case "owner":
		if s.userInList(userID, permissions.Owners) {
			hasAccess = true
			accessReason = "owner_permission"
		}
	}

	// Check role-based permissions
	if !hasAccess {
		userRoles := s.userRoles[userID]
		for _, roleID := range userRoles {
			if role, exists := s.roles[roleID]; exists {
				if s.roleHasPermission(role, action) {
					hasAccess = true
					accessReason = fmt.Sprintf("role_permission:%s", roleID)
					break
				}
			}
		}
	}

	// Check group permissions
	if !hasAccess {
		for groupName, groupMembers := range permissions.Groups {
			if s.userInList(userID, groupMembers) {
				// For simplicity, assume group members have read and execute permissions
				if action == "read" || action == "execute" {
					hasAccess = true
					accessReason = fmt.Sprintf("group_permission:%s", groupName)
					break
				}
			}
		}
	}

	if !hasAccess {
		err := fmt.Errorf("access denied for user %s to perform action %s on chain %s", userID, action, chainID)
		span.RecordError(err)
		span.SetAttributes(attribute.Bool("access.granted", false))

		// Log access denial
		s.LogAccess(ctx, chainID, userID, action, "denied")

		return err
	}

	span.SetAttributes(
		attribute.Bool("access.granted", true),
		attribute.String("access.reason", accessReason),
	)

	// Log successful access
	s.LogAccess(ctx, chainID, userID, action, "granted")

	return nil
}

// CreateRole creates a new role
func (s *DefaultChainSecurity) CreateRole(ctx context.Context, role Role) error {
	ctx, span := securityTracer.Start(ctx, "security.create_role",
		trace.WithAttributes(
			attribute.String("role.id", role.ID),
			attribute.String("role.name", role.Name),
		),
	)
	defer span.End()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.roles[role.ID]; exists {
		err := fmt.Errorf("role %s already exists", role.ID)
		span.RecordError(err)
		return err
	}

	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()
	s.roles[role.ID] = role

	span.SetAttributes(attribute.Bool("success", true))
	s.logger.Info("Role created", "role_id", role.ID, "role_name", role.Name)

	return nil
}

// AssignRole assigns a role to a user
func (s *DefaultChainSecurity) AssignRole(ctx context.Context, userID string, roleID string) error {
	ctx, span := securityTracer.Start(ctx, "security.assign_role",
		trace.WithAttributes(
			attribute.String("user.id", userID),
			attribute.String("role.id", roleID),
		),
	)
	defer span.End()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if role exists
	if _, exists := s.roles[roleID]; !exists {
		err := fmt.Errorf("role %s not found", roleID)
		span.RecordError(err)
		return err
	}

	// Initialize user roles if not exists
	if s.userRoles[userID] == nil {
		s.userRoles[userID] = make([]string, 0)
	}

	// Check if user already has the role
	for _, existingRoleID := range s.userRoles[userID] {
		if existingRoleID == roleID {
			return nil // Already assigned
		}
	}

	// Assign role
	s.userRoles[userID] = append(s.userRoles[userID], roleID)

	span.SetAttributes(attribute.Bool("success", true))
	s.logger.Info("Role assigned to user", "user_id", userID, "role_id", roleID)

	return nil
}

// LogAccess logs an access attempt
func (s *DefaultChainSecurity) LogAccess(ctx context.Context, chainID string, userID string, action string, result string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	entry := AuditEntry{
		ID:        fmt.Sprintf("audit_%d", time.Now().UnixNano()),
		ChainID:   chainID,
		UserID:    userID,
		Action:    action,
		Result:    result,
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	// Extract additional context from the request context if available
	if traceID := trace.SpanContextFromContext(ctx).TraceID(); traceID.IsValid() {
		entry.Metadata["trace_id"] = traceID.String()
	}

	s.auditLog = append(s.auditLog, entry)

	// Keep only last 10000 entries to prevent memory growth
	if len(s.auditLog) > 10000 {
		s.auditLog = s.auditLog[len(s.auditLog)-10000:]
	}

	return nil
}

// GetAuditLog retrieves audit log entries
func (s *DefaultChainSecurity) GetAuditLog(ctx context.Context, chainID string, filter AuditFilter) ([]AuditEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var results []AuditEntry

	for _, entry := range s.auditLog {
		// Filter by chain ID
		if entry.ChainID != chainID {
			continue
		}

		// Apply filters
		if filter.UserID != "" && entry.UserID != filter.UserID {
			continue
		}
		if filter.Action != "" && entry.Action != filter.Action {
			continue
		}
		if filter.Result != "" && entry.Result != filter.Result {
			continue
		}
		if filter.StartTime != nil && entry.Timestamp.Before(*filter.StartTime) {
			continue
		}
		if filter.EndTime != nil && entry.Timestamp.After(*filter.EndTime) {
			continue
		}

		results = append(results, entry)
	}

	// Apply pagination
	if filter.Offset > 0 && filter.Offset < len(results) {
		results = results[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(results) {
		results = results[:filter.Limit]
	}

	return results, nil
}

// SetSecurityPolicy sets a security policy for a chain
func (s *DefaultChainSecurity) SetSecurityPolicy(ctx context.Context, chainID string, policy SecurityPolicy) error {
	ctx, span := securityTracer.Start(ctx, "security.set_security_policy",
		trace.WithAttributes(attribute.String("chain.id", chainID)),
	)
	defer span.End()

	// Validate policy
	if err := s.ValidateSecurityPolicy(ctx, policy); err != nil {
		span.RecordError(err)
		return fmt.Errorf("invalid security policy: %w", err)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	policy.ChainID = chainID
	s.securityPolicies[chainID] = policy

	span.SetAttributes(attribute.Bool("success", true))
	s.logger.Info("Security policy set for chain", "chain_id", chainID)

	return nil
}

// GetSecurityPolicy retrieves a security policy for a chain
func (s *DefaultChainSecurity) GetSecurityPolicy(ctx context.Context, chainID string) (SecurityPolicy, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	policy, exists := s.securityPolicies[chainID]
	if !exists {
		// Return default policy
		return SecurityPolicy{
			ChainID:               chainID,
			RequireAuthentication: true,
			RequireAuthorization:  true,
			AllowAnonymousRead:    false,
			AllowAnonymousExecute: false,
			AuditAllAccess:        true,
		}, nil
	}

	return policy, nil
}

// ValidateSecurityPolicy validates a security policy
func (s *DefaultChainSecurity) ValidateSecurityPolicy(ctx context.Context, policy SecurityPolicy) error {
	if policy.MaxExecutionsPerUser < 0 {
		return fmt.Errorf("max executions per user cannot be negative")
	}
	if policy.MaxExecutionsPerHour < 0 {
		return fmt.Errorf("max executions per hour cannot be negative")
	}
	if policy.SessionTimeout < 0 {
		return fmt.Errorf("session timeout cannot be negative")
	}

	// Validate IP ranges (simplified validation)
	for _, ipRange := range policy.AllowedIPRanges {
		if !s.isValidIPRange(ipRange) {
			return fmt.Errorf("invalid IP range: %s", ipRange)
		}
	}
	for _, ipRange := range policy.BlockedIPRanges {
		if !s.isValidIPRange(ipRange) {
			return fmt.Errorf("invalid IP range: %s", ipRange)
		}
	}

	return nil
}

// Helper methods

// userInList checks if a user is in a list of users
func (s *DefaultChainSecurity) userInList(userID string, users []string) bool {
	for _, user := range users {
		if user == userID {
			return true
		}
	}
	return false
}

// roleHasPermission checks if a role has a specific permission
func (s *DefaultChainSecurity) roleHasPermission(role Role, permission string) bool {
	for _, perm := range role.Permissions {
		if perm == permission || perm == "*" {
			return true
		}
	}
	return false
}

// isValidIPRange validates an IP range (simplified)
func (s *DefaultChainSecurity) isValidIPRange(ipRange string) bool {
	// This is a simplified validation - in production, you'd use proper IP parsing
	return strings.Contains(ipRange, ".") || strings.Contains(ipRange, ":")
}

// Placeholder implementations for token management
func (s *DefaultChainSecurity) GenerateAccessToken(ctx context.Context, userID string, chainID string, permissions []string, expiry time.Duration) (string, error) {
	// This would implement JWT token generation in production
	return fmt.Sprintf("token_%s_%s_%d", userID, chainID, time.Now().Unix()), nil
}

func (s *DefaultChainSecurity) ValidateAccessToken(ctx context.Context, token string) (TokenClaims, error) {
	// This would implement JWT token validation in production
	return TokenClaims{}, fmt.Errorf("token validation not implemented")
}

func (s *DefaultChainSecurity) RevokeAccessToken(ctx context.Context, token string) error {
	// This would implement token revocation in production
	return nil
}

// GrantAccess grants specific permissions to a user for a chain
func (s *DefaultChainSecurity) GrantAccess(ctx context.Context, chainID string, userID string, permissions []string) error {
	ctx, span := securityTracer.Start(ctx, "security.grant_access",
		trace.WithAttributes(
			attribute.String("chain.id", chainID),
			attribute.String("user.id", userID),
			attribute.StringSlice("permissions", permissions),
		),
	)
	defer span.End()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	chainPermissions, exists := s.permissions[chainID]
	if !exists {
		// Create default permissions if they don't exist
		chainPermissions = ChainPermissions{
			ChainID:   chainID,
			Owners:    []string{},
			Readers:   []string{},
			Executors: []string{},
			Admins:    []string{},
			Groups:    make(map[string][]string),
		}
	}

	// Grant permissions
	for _, permission := range permissions {
		switch permission {
		case "read":
			if !s.userInList(userID, chainPermissions.Readers) {
				chainPermissions.Readers = append(chainPermissions.Readers, userID)
			}
		case "execute":
			if !s.userInList(userID, chainPermissions.Executors) {
				chainPermissions.Executors = append(chainPermissions.Executors, userID)
			}
		case "admin":
			if !s.userInList(userID, chainPermissions.Admins) {
				chainPermissions.Admins = append(chainPermissions.Admins, userID)
			}
		case "owner":
			if !s.userInList(userID, chainPermissions.Owners) {
				chainPermissions.Owners = append(chainPermissions.Owners, userID)
			}
		}
	}

	s.permissions[chainID] = chainPermissions

	span.SetAttributes(attribute.Bool("success", true))
	s.logger.Info("Access granted", "chain_id", chainID, "user_id", userID, "permissions", permissions)

	return nil
}

// RevokeAccess revokes specific permissions from a user for a chain
func (s *DefaultChainSecurity) RevokeAccess(ctx context.Context, chainID string, userID string, permissions []string) error {
	ctx, span := securityTracer.Start(ctx, "security.revoke_access",
		trace.WithAttributes(
			attribute.String("chain.id", chainID),
			attribute.String("user.id", userID),
			attribute.StringSlice("permissions", permissions),
		),
	)
	defer span.End()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	chainPermissions, exists := s.permissions[chainID]
	if !exists {
		return fmt.Errorf("no permissions found for chain %s", chainID)
	}

	// Revoke permissions
	for _, permission := range permissions {
		switch permission {
		case "read":
			chainPermissions.Readers = s.removeUserFromList(chainPermissions.Readers, userID)
		case "execute":
			chainPermissions.Executors = s.removeUserFromList(chainPermissions.Executors, userID)
		case "admin":
			chainPermissions.Admins = s.removeUserFromList(chainPermissions.Admins, userID)
		case "owner":
			chainPermissions.Owners = s.removeUserFromList(chainPermissions.Owners, userID)
		}
	}

	s.permissions[chainID] = chainPermissions

	span.SetAttributes(attribute.Bool("success", true))
	s.logger.Info("Access revoked", "chain_id", chainID, "user_id", userID, "permissions", permissions)

	return nil
}

// RevokeRole revokes a role from a user
func (s *DefaultChainSecurity) RevokeRole(ctx context.Context, userID string, roleID string) error {
	ctx, span := securityTracer.Start(ctx, "security.revoke_role",
		trace.WithAttributes(
			attribute.String("user.id", userID),
			attribute.String("role.id", roleID),
		),
	)
	defer span.End()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	userRoles := s.userRoles[userID]
	if userRoles == nil {
		return nil // User has no roles
	}

	// Remove role from user's roles
	newRoles := make([]string, 0)
	for _, existingRoleID := range userRoles {
		if existingRoleID != roleID {
			newRoles = append(newRoles, existingRoleID)
		}
	}

	s.userRoles[userID] = newRoles

	span.SetAttributes(attribute.Bool("success", true))
	s.logger.Info("Role revoked from user", "user_id", userID, "role_id", roleID)

	return nil
}

// GetUserRoles retrieves all roles for a user
func (s *DefaultChainSecurity) GetUserRoles(ctx context.Context, userID string) ([]Role, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	roleIDs := s.userRoles[userID]
	if roleIDs == nil {
		return []Role{}, nil
	}

	var roles []Role
	for _, roleID := range roleIDs {
		if role, exists := s.roles[roleID]; exists {
			roles = append(roles, role)
		}
	}

	return roles, nil
}

// removeUserFromList removes a user from a list of users
func (s *DefaultChainSecurity) removeUserFromList(users []string, userID string) []string {
	result := make([]string, 0)
	for _, user := range users {
		if user != userID {
			result = append(result, user)
		}
	}
	return result
}
