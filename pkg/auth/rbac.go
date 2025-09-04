package auth

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// Permission represents a specific permission
type Permission struct {
	ID          uuid.UUID `json:"id"`
	Resource    string    `json:"resource"` // e.g., "users", "posts", "admin"
	Action      string    `json:"action"`   // e.g., "read", "write", "delete", "manage"
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// Role represents a role with associated permissions
type Role struct {
	ID          uuid.UUID     `json:"id"`
	Name        string        `json:"name"`         // e.g., "admin", "moderator", "user"
	DisplayName string        `json:"display_name"` // e.g., "Administrator", "Content Moderator"
	Description string        `json:"description"`
	Permissions []*Permission `json:"permissions"`
	IsSystem    bool          `json:"is_system"` // System roles cannot be deleted
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// RoleAssignment represents a user's role assignment
type RoleAssignment struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	RoleID     uuid.UUID  `json:"role_id"`
	AssignedBy uuid.UUID  `json:"assigned_by"`
	AssignedAt time.Time  `json:"assigned_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	IsActive   bool       `json:"is_active"`
}

// RBACManager manages role-based access control
type RBACManager struct {
	roles           map[string]*Role
	permissions     map[string]*Permission
	userRoles       map[uuid.UUID][]*RoleAssignment
	rolePermissions map[string][]*Permission
	mutex           sync.RWMutex
	logger          *logger.Logger
}

// NewRBACManager creates a new RBAC manager
func NewRBACManager(logger *logger.Logger) *RBACManager {
	rbac := &RBACManager{
		roles:           make(map[string]*Role),
		permissions:     make(map[string]*Permission),
		userRoles:       make(map[uuid.UUID][]*RoleAssignment),
		rolePermissions: make(map[string][]*Permission),
		logger:          logger,
	}

	// Initialize default roles and permissions
	rbac.initializeDefaultRoles()
	return rbac
}

// initializeDefaultRoles sets up default system roles and permissions
func (rbac *RBACManager) initializeDefaultRoles() {
	now := time.Now()

	// Define default permissions
	defaultPermissions := []*Permission{
		// User management
		{ID: uuid.New(), Resource: "users", Action: "read", Description: "Read user information", CreatedAt: now},
		{ID: uuid.New(), Resource: "users", Action: "write", Description: "Create and update users", CreatedAt: now},
		{ID: uuid.New(), Resource: "users", Action: "delete", Description: "Delete users", CreatedAt: now},
		{ID: uuid.New(), Resource: "users", Action: "manage", Description: "Full user management", CreatedAt: now},

		// Content management
		{ID: uuid.New(), Resource: "content", Action: "read", Description: "Read content", CreatedAt: now},
		{ID: uuid.New(), Resource: "content", Action: "write", Description: "Create and edit content", CreatedAt: now},
		{ID: uuid.New(), Resource: "content", Action: "delete", Description: "Delete content", CreatedAt: now},
		{ID: uuid.New(), Resource: "content", Action: "moderate", Description: "Moderate content", CreatedAt: now},

		// AI services
		{ID: uuid.New(), Resource: "ai", Action: "use", Description: "Use AI services", CreatedAt: now},
		{ID: uuid.New(), Resource: "ai", Action: "configure", Description: "Configure AI services", CreatedAt: now},
		{ID: uuid.New(), Resource: "ai", Action: "manage", Description: "Manage AI services", CreatedAt: now},

		// System administration
		{ID: uuid.New(), Resource: "system", Action: "read", Description: "Read system information", CreatedAt: now},
		{ID: uuid.New(), Resource: "system", Action: "configure", Description: "Configure system settings", CreatedAt: now},
		{ID: uuid.New(), Resource: "system", Action: "manage", Description: "Full system administration", CreatedAt: now},

		// Analytics and reporting
		{ID: uuid.New(), Resource: "analytics", Action: "read", Description: "View analytics and reports", CreatedAt: now},
		{ID: uuid.New(), Resource: "analytics", Action: "export", Description: "Export analytics data", CreatedAt: now},

		// Security management
		{ID: uuid.New(), Resource: "security", Action: "read", Description: "View security logs", CreatedAt: now},
		{ID: uuid.New(), Resource: "security", Action: "manage", Description: "Manage security settings", CreatedAt: now},
	}

	// Store permissions
	for _, perm := range defaultPermissions {
		key := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
		rbac.permissions[key] = perm
	}

	// Define default roles
	guestRole := &Role{
		ID:          uuid.New(),
		Name:        "guest",
		DisplayName: "Guest",
		Description: "Guest user with minimal permissions",
		Permissions: []*Permission{
			rbac.permissions["content:read"],
		},
		IsSystem:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	userRole := &Role{
		ID:          uuid.New(),
		Name:        "user",
		DisplayName: "User",
		Description: "Regular user with basic permissions",
		Permissions: []*Permission{
			rbac.permissions["content:read"],
			rbac.permissions["content:write"],
			rbac.permissions["ai:use"],
			rbac.permissions["users:read"], // Can read own profile
		},
		IsSystem:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	moderatorRole := &Role{
		ID:          uuid.New(),
		Name:        "moderator",
		DisplayName: "Moderator",
		Description: "Content moderator with extended permissions",
		Permissions: []*Permission{
			rbac.permissions["content:read"],
			rbac.permissions["content:write"],
			rbac.permissions["content:moderate"],
			rbac.permissions["content:delete"],
			rbac.permissions["ai:use"],
			rbac.permissions["users:read"],
			rbac.permissions["analytics:read"],
		},
		IsSystem:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	adminRole := &Role{
		ID:          uuid.New(),
		Name:        "admin",
		DisplayName: "Administrator",
		Description: "System administrator with full permissions",
		Permissions: defaultPermissions, // All permissions
		IsSystem:    true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Store roles
	rbac.roles["guest"] = guestRole
	rbac.roles["user"] = userRole
	rbac.roles["moderator"] = moderatorRole
	rbac.roles["admin"] = adminRole

	// Store role-permission mappings
	rbac.rolePermissions["guest"] = guestRole.Permissions
	rbac.rolePermissions["user"] = userRole.Permissions
	rbac.rolePermissions["moderator"] = moderatorRole.Permissions
	rbac.rolePermissions["admin"] = adminRole.Permissions

	rbac.logger.Info("Initialized default RBAC roles and permissions")
}

// HasPermission checks if a user has a specific permission
func (rbac *RBACManager) HasPermission(userID uuid.UUID, resource, action string) bool {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	userRoles, exists := rbac.userRoles[userID]
	if !exists {
		return false
	}

	now := time.Now()
	permissionKey := fmt.Sprintf("%s:%s", resource, action)

	for _, assignment := range userRoles {
		// Check if assignment is active and not expired
		if !assignment.IsActive {
			continue
		}
		if assignment.ExpiresAt != nil && assignment.ExpiresAt.Before(now) {
			continue
		}

		// Find the role
		var role *Role
		for _, r := range rbac.roles {
			if r.ID == assignment.RoleID {
				role = r
				break
			}
		}

		if role == nil {
			continue
		}

		// Check if role has the permission
		for _, perm := range role.Permissions {
			if fmt.Sprintf("%s:%s", perm.Resource, perm.Action) == permissionKey {
				return true
			}
			// Check for wildcard permissions
			if perm.Action == "manage" && perm.Resource == resource {
				return true
			}
			if perm.Resource == "*" && perm.Action == action {
				return true
			}
			if perm.Resource == "*" && perm.Action == "*" {
				return true
			}
		}
	}

	return false
}

// GetUserRoles returns all active roles for a user
func (rbac *RBACManager) GetUserRoles(userID uuid.UUID) []*Role {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	userRoles, exists := rbac.userRoles[userID]
	if !exists {
		return []*Role{}
	}

	now := time.Now()
	var roles []*Role

	for _, assignment := range userRoles {
		// Check if assignment is active and not expired
		if !assignment.IsActive {
			continue
		}
		if assignment.ExpiresAt != nil && assignment.ExpiresAt.Before(now) {
			continue
		}

		// Find the role
		for _, role := range rbac.roles {
			if role.ID == assignment.RoleID {
				roles = append(roles, role)
				break
			}
		}
	}

	return roles
}

// GetUserPermissions returns all permissions for a user
func (rbac *RBACManager) GetUserPermissions(userID uuid.UUID) []*Permission {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	var permissions []*Permission
	permissionMap := make(map[string]*Permission)

	userRoles := rbac.GetUserRoles(userID)
	for _, role := range userRoles {
		for _, perm := range role.Permissions {
			key := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
			if _, exists := permissionMap[key]; !exists {
				permissionMap[key] = perm
				permissions = append(permissions, perm)
			}
		}
	}

	return permissions
}

// AssignRole assigns a role to a user
func (rbac *RBACManager) AssignRole(userID, roleID, assignedBy uuid.UUID, expiresAt *time.Time) error {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	// Check if role exists
	var roleExists bool
	for _, role := range rbac.roles {
		if role.ID == roleID {
			roleExists = true
			break
		}
	}

	if !roleExists {
		return fmt.Errorf("role not found")
	}

	// Create role assignment
	assignment := &RoleAssignment{
		ID:         uuid.New(),
		UserID:     userID,
		RoleID:     roleID,
		AssignedBy: assignedBy,
		AssignedAt: time.Now(),
		ExpiresAt:  expiresAt,
		IsActive:   true,
	}

	// Add to user roles
	if rbac.userRoles[userID] == nil {
		rbac.userRoles[userID] = []*RoleAssignment{}
	}
	rbac.userRoles[userID] = append(rbac.userRoles[userID], assignment)

	rbac.logger.WithFields(logger.Fields{
		"user_id":     userID,
		"role_id":     roleID,
		"assigned_by": assignedBy,
		"expires_at":  expiresAt,
	}).Info("Role assigned to user")

	return nil
}

// RevokeRole revokes a role from a user
func (rbac *RBACManager) RevokeRole(userID, roleID uuid.UUID) error {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	userRoles, exists := rbac.userRoles[userID]
	if !exists {
		return fmt.Errorf("user has no role assignments")
	}

	for _, assignment := range userRoles {
		if assignment.RoleID == roleID && assignment.IsActive {
			assignment.IsActive = false
			rbac.logger.WithFields(logger.Fields{
				"user_id": userID,
				"role_id": roleID,
			}).Info("Role revoked from user")
			return nil
		}
	}

	return fmt.Errorf("role assignment not found")
}

// CreateRole creates a new role
func (rbac *RBACManager) CreateRole(name, displayName, description string, permissionKeys []string) (*Role, error) {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	// Check if role already exists
	if _, exists := rbac.roles[name]; exists {
		return nil, fmt.Errorf("role already exists")
	}

	// Validate permissions
	var permissions []*Permission
	for _, key := range permissionKeys {
		if perm, exists := rbac.permissions[key]; exists {
			permissions = append(permissions, perm)
		} else {
			return nil, fmt.Errorf("permission not found: %s", key)
		}
	}

	// Create role
	role := &Role{
		ID:          uuid.New(),
		Name:        name,
		DisplayName: displayName,
		Description: description,
		Permissions: permissions,
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	rbac.roles[name] = role
	rbac.rolePermissions[name] = permissions

	rbac.logger.WithFields(logger.Fields{
		"role_name":        name,
		"permission_count": len(permissions),
	}).Info("New role created")

	return role, nil
}

// GetRole returns a role by name
func (rbac *RBACManager) GetRole(name string) (*Role, bool) {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	role, exists := rbac.roles[name]
	return role, exists
}

// GetAllRoles returns all roles
func (rbac *RBACManager) GetAllRoles() []*Role {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	var roles []*Role
	for _, role := range rbac.roles {
		roles = append(roles, role)
	}
	return roles
}

// GetAllPermissions returns all permissions
func (rbac *RBACManager) GetAllPermissions() []*Permission {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	var permissions []*Permission
	for _, perm := range rbac.permissions {
		permissions = append(permissions, perm)
	}
	return permissions
}

// ValidatePermissionString validates a permission string format
func ValidatePermissionString(permission string) (resource, action string, err error) {
	parts := strings.Split(permission, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid permission format, expected 'resource:action'")
	}

	resource = strings.TrimSpace(parts[0])
	action = strings.TrimSpace(parts[1])

	if resource == "" || action == "" {
		return "", "", fmt.Errorf("resource and action cannot be empty")
	}

	return resource, action, nil
}

// PermissionCheck represents a permission check result
type PermissionCheck struct {
	Resource  string `json:"resource"`
	Action    string `json:"action"`
	Granted   bool   `json:"granted"`
	GrantedBy string `json:"granted_by,omitempty"` // Role name that granted the permission
}

// CheckMultiplePermissions checks multiple permissions at once
func (rbac *RBACManager) CheckMultiplePermissions(userID uuid.UUID, permissions []string) []PermissionCheck {
	var results []PermissionCheck

	for _, perm := range permissions {
		resource, action, err := ValidatePermissionString(perm)
		if err != nil {
			results = append(results, PermissionCheck{
				Resource: perm,
				Action:   "",
				Granted:  false,
			})
			continue
		}

		granted := rbac.HasPermission(userID, resource, action)
		var grantedBy string
		if granted {
			// Find which role granted this permission
			userRoles := rbac.GetUserRoles(userID)
			for _, role := range userRoles {
				for _, rolePerm := range role.Permissions {
					if rolePerm.Resource == resource && rolePerm.Action == action {
						grantedBy = role.Name
						break
					}
				}
				if grantedBy != "" {
					break
				}
			}
		}

		results = append(results, PermissionCheck{
			Resource:  resource,
			Action:    action,
			Granted:   granted,
			GrantedBy: grantedBy,
		})
	}

	return results
}
