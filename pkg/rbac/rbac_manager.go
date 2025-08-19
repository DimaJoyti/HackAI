package rbac

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// RBACManager manages role-based access control
type RBACManager struct {
	logger      *logger.Logger
	config      *RBACConfig
	roles       map[string]*Role
	permissions map[string]*Permission
	policies    map[string]*Policy
	users       map[string]*User
	sessions    map[string]*Session
	auditor     *AccessAuditor
	mu          sync.RWMutex
	isRunning   bool
}

// RBACConfig configuration for RBAC manager
type RBACConfig struct {
	EnableAuditLogging    bool          `json:"enable_audit_logging"`
	SessionTimeout        time.Duration `json:"session_timeout"`
	MaxSessions           int           `json:"max_sessions"`
	EnableMFA             bool          `json:"enable_mfa"`
	PasswordPolicy        *PasswordPolicy `json:"password_policy"`
	EnableRoleHierarchy   bool          `json:"enable_role_hierarchy"`
	EnableDynamicRoles    bool          `json:"enable_dynamic_roles"`
	EnableTimeBasedAccess bool          `json:"enable_time_based_access"`
	EnableIPRestrictions  bool          `json:"enable_ip_restrictions"`
}

// Role represents a role in the system
type Role struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Permissions []string               `json:"permissions"`
	ParentRoles []string               `json:"parent_roles"`
	ChildRoles  []string               `json:"child_roles"`
	IsSystem    bool                   `json:"is_system"`
	IsActive    bool                   `json:"is_active"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	CreatedBy   string                 `json:"created_by"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Permission represents a permission in the system
type Permission struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Resource    string                 `json:"resource"`
	Action      string                 `json:"action"`
	Scope       string                 `json:"scope"`
	IsSystem    bool                   `json:"is_system"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Policy represents an access policy
type Policy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Rules       []*PolicyRule          `json:"rules"`
	IsActive    bool                   `json:"is_active"`
	Priority    int                    `json:"priority"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	CreatedBy   string                 `json:"created_by"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PolicyRule represents a rule within a policy
type PolicyRule struct {
	ID          string                 `json:"id"`
	Effect      string                 `json:"effect"` // allow, deny
	Resource    string                 `json:"resource"`
	Action      string                 `json:"action"`
	Conditions  []*Condition           `json:"conditions"`
	TimeWindow  *TimeWindow            `json:"time_window,omitempty"`
	IPRestrictions []string            `json:"ip_restrictions,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Condition represents a condition in a policy rule
type Condition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// TimeWindow represents a time-based access window
type TimeWindow struct {
	StartTime string   `json:"start_time"` // HH:MM format
	EndTime   string   `json:"end_time"`   // HH:MM format
	Days      []string `json:"days"`       // monday, tuesday, etc.
	Timezone  string   `json:"timezone"`
}

// User represents a user in the system
type User struct {
	ID          string                 `json:"id"`
	Username    string                 `json:"username"`
	Email       string                 `json:"email"`
	FirstName   string                 `json:"first_name"`
	LastName    string                 `json:"last_name"`
	Roles       []string               `json:"roles"`
	Permissions []string               `json:"permissions"`
	IsActive    bool                   `json:"is_active"`
	IsLocked    bool                   `json:"is_locked"`
	MFAEnabled  bool                   `json:"mfa_enabled"`
	LastLogin   *time.Time             `json:"last_login,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Session represents a user session
type Session struct {
	ID          string                 `json:"id"`
	UserID      string                 `json:"user_id"`
	Token       string                 `json:"token"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	CreatedAt   time.Time              `json:"created_at"`
	ExpiresAt   time.Time              `json:"expires_at"`
	LastAccess  time.Time              `json:"last_access"`
	IsActive    bool                   `json:"is_active"`
	Permissions []string               `json:"permissions"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PasswordPolicy represents password policy
type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireNumbers   bool `json:"require_numbers"`
	RequireSymbols   bool `json:"require_symbols"`
	MaxAge           int  `json:"max_age"` // days
	HistoryCount     int  `json:"history_count"`
}

// AccessAuditor handles access audit logging
type AccessAuditor struct {
	logger *logger.Logger
	config *AuditConfig
	events chan *AuditEvent
	mu     sync.RWMutex
}

// AuditConfig configuration for audit logging
type AuditConfig struct {
	EnableLogging   bool          `json:"enable_logging"`
	LogLevel        string        `json:"log_level"`
	RetentionPeriod time.Duration `json:"retention_period"`
	BufferSize      int           `json:"buffer_size"`
}

// AuditEvent represents an audit event
type AuditEvent struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	UserID      string                 `json:"user_id"`
	Resource    string                 `json:"resource"`
	Action      string                 `json:"action"`
	Result      string                 `json:"result"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	Timestamp   time.Time              `json:"timestamp"`
	Details     map[string]interface{} `json:"details"`
}

// AccessRequest represents an access request
type AccessRequest struct {
	UserID      string                 `json:"user_id"`
	Resource    string                 `json:"resource"`
	Action      string                 `json:"action"`
	Context     map[string]interface{} `json:"context"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	Timestamp   time.Time              `json:"timestamp"`
}

// AccessResult represents the result of an access check
type AccessResult struct {
	Allowed     bool                   `json:"allowed"`
	Reason      string                 `json:"reason"`
	PolicyID    string                 `json:"policy_id,omitempty"`
	RuleID      string                 `json:"rule_id,omitempty"`
	Permissions []string               `json:"permissions"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewRBACManager creates a new RBAC manager
func NewRBACManager(config *RBACConfig, logger *logger.Logger) *RBACManager {
	if config == nil {
		config = DefaultRBACConfig()
	}

	auditor := NewAccessAuditor(DefaultAuditConfig(), logger)

	return &RBACManager{
		logger:      logger,
		config:      config,
		roles:       make(map[string]*Role),
		permissions: make(map[string]*Permission),
		policies:    make(map[string]*Policy),
		users:       make(map[string]*User),
		sessions:    make(map[string]*Session),
		auditor:     auditor,
	}
}

// DefaultRBACConfig returns default RBAC configuration
func DefaultRBACConfig() *RBACConfig {
	return &RBACConfig{
		EnableAuditLogging:    true,
		SessionTimeout:        24 * time.Hour,
		MaxSessions:           10000,
		EnableMFA:             true,
		EnableRoleHierarchy:   true,
		EnableDynamicRoles:    true,
		EnableTimeBasedAccess: true,
		EnableIPRestrictions:  true,
		PasswordPolicy: &PasswordPolicy{
			MinLength:        8,
			RequireUppercase: true,
			RequireLowercase: true,
			RequireNumbers:   true,
			RequireSymbols:   true,
			MaxAge:           90,
			HistoryCount:     5,
		},
	}
}

// Start starts the RBAC manager
func (rbac *RBACManager) Start(ctx context.Context) error {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	if rbac.isRunning {
		return fmt.Errorf("RBAC manager is already running")
	}

	rbac.logger.Info("Starting RBAC manager")

	// Start auditor
	if rbac.config.EnableAuditLogging {
		if err := rbac.auditor.Start(ctx); err != nil {
			return fmt.Errorf("failed to start auditor: %w", err)
		}
	}

	// Initialize default roles and permissions
	rbac.initializeDefaults()

	// Start session cleanup worker
	go rbac.sessionCleanupWorker(ctx)

	rbac.isRunning = true
	rbac.logger.Info("RBAC manager started successfully")
	return nil
}

// Stop stops the RBAC manager
func (rbac *RBACManager) Stop(ctx context.Context) error {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	if !rbac.isRunning {
		return nil
	}

	rbac.logger.Info("Stopping RBAC manager")
	rbac.isRunning = false
	rbac.logger.Info("RBAC manager stopped")
	return nil
}

// CheckAccess checks if a user has access to a resource
func (rbac *RBACManager) CheckAccess(ctx context.Context, request *AccessRequest) (*AccessResult, error) {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()

	user, exists := rbac.users[request.UserID]
	if !exists {
		result := &AccessResult{
			Allowed: false,
			Reason:  "user not found",
		}
		rbac.auditAccess(request, result)
		return result, nil
	}

	if !user.IsActive || user.IsLocked {
		result := &AccessResult{
			Allowed: false,
			Reason:  "user is inactive or locked",
		}
		rbac.auditAccess(request, result)
		return result, nil
	}

	// Check policies
	for _, policy := range rbac.policies {
		if !policy.IsActive {
			continue
		}

		for _, rule := range policy.Rules {
			if rbac.matchesRule(rule, request) {
				result := &AccessResult{
					Allowed:  rule.Effect == "allow",
					Reason:   fmt.Sprintf("matched policy %s rule %s", policy.ID, rule.ID),
					PolicyID: policy.ID,
					RuleID:   rule.ID,
				}
				rbac.auditAccess(request, result)
				return result, nil
			}
		}
	}

	// Check role-based permissions
	userPermissions := rbac.getUserPermissions(user)
	permissionKey := fmt.Sprintf("%s:%s", request.Resource, request.Action)
	
	for _, perm := range userPermissions {
		if perm == permissionKey || perm == "*" {
			result := &AccessResult{
				Allowed:     true,
				Reason:      "permission granted via role",
				Permissions: userPermissions,
			}
			rbac.auditAccess(request, result)
			return result, nil
		}
	}

	result := &AccessResult{
		Allowed: false,
		Reason:  "no matching permissions found",
	}
	rbac.auditAccess(request, result)
	return result, nil
}

// CreateRole creates a new role
func (rbac *RBACManager) CreateRole(role *Role) error {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	role.ID = uuid.New().String()
	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()
	role.IsActive = true

	rbac.roles[role.ID] = role
	rbac.logger.Info("Role created", "role_id", role.ID, "name", role.Name)
	return nil
}

// CreatePermission creates a new permission
func (rbac *RBACManager) CreatePermission(permission *Permission) error {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	permission.ID = uuid.New().String()
	permission.CreatedAt = time.Now()
	permission.UpdatedAt = time.Now()

	rbac.permissions[permission.ID] = permission
	rbac.logger.Info("Permission created", "permission_id", permission.ID, "name", permission.Name)
	return nil
}

// CreateUser creates a new user
func (rbac *RBACManager) CreateUser(user *User) error {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	user.ID = uuid.New().String()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	user.IsActive = true

	rbac.users[user.ID] = user
	rbac.logger.Info("User created", "user_id", user.ID, "username", user.Username)
	return nil
}

// AssignRoleToUser assigns a role to a user
func (rbac *RBACManager) AssignRoleToUser(userID, roleID string) error {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	user, exists := rbac.users[userID]
	if !exists {
		return fmt.Errorf("user not found: %s", userID)
	}

	role, exists := rbac.roles[roleID]
	if !exists {
		return fmt.Errorf("role not found: %s", roleID)
	}

	// Check if role is already assigned
	for _, existingRoleID := range user.Roles {
		if existingRoleID == roleID {
			return fmt.Errorf("role already assigned to user")
		}
	}

	user.Roles = append(user.Roles, roleID)
	user.UpdatedAt = time.Now()

	rbac.logger.Info("Role assigned to user", 
		"user_id", userID, 
		"role_id", roleID, 
		"role_name", role.Name)
	return nil
}
