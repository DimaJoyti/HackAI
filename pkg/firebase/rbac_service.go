package firebase

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// RBACService provides role-based access control functionality
type RBACService struct {
	mcpIntegration *MCPIntegration
	logger         *logger.Logger
	config         *Config
}

// NewRBACService creates a new RBAC service
func NewRBACService(mcpIntegration *MCPIntegration, logger *logger.Logger, config *Config) *RBACService {
	return &RBACService{
		mcpIntegration: mcpIntegration,
		logger:         logger,
		config:         config,
	}
}

// Role represents a user role with permissions
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	Level       int       `json:"level"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Permission represents a specific permission
type Permission struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// UserRole represents a user's role assignment
type UserRole struct {
	UserID      string                 `json:"user_id"`
	RoleID      string                 `json:"role_id"`
	Permissions []string               `json:"permissions"`
	CustomClaims map[string]interface{} `json:"custom_claims"`
	AssignedBy  string                 `json:"assigned_by"`
	AssignedAt  time.Time              `json:"assigned_at"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	Active      bool                   `json:"active"`
}

// AccessRequest represents an access control request
type AccessRequest struct {
	UserID     string `json:"user_id"`
	Resource   string `json:"resource"`
	Action     string `json:"action"`
	Context    map[string]interface{} `json:"context,omitempty"`
}

// AccessResult represents the result of an access control check
type AccessResult struct {
	Allowed     bool     `json:"allowed"`
	Reason      string   `json:"reason"`
	Permissions []string `json:"permissions"`
	Role        string   `json:"role"`
}

// Predefined roles and permissions
var (
	// Default roles
	DefaultRoles = map[string]*Role{
		"super_admin": {
			ID:          "super_admin",
			Name:        "Super Administrator",
			Description: "Full system access with all permissions",
			Permissions: []string{"*"},
			Level:       100,
			Active:      true,
		},
		"admin": {
			ID:          "admin",
			Name:        "Administrator",
			Description: "Administrative access with user management",
			Permissions: []string{
				"user:*", "role:*", "system:read", "system:write",
				"profile:*", "auth:*", "audit:read",
			},
			Level:  90,
			Active: true,
		},
		"moderator": {
			ID:          "moderator",
			Name:        "Moderator",
			Description: "Content moderation and user management",
			Permissions: []string{
				"user:read", "user:suspend", "user:activate",
				"content:*", "profile:read", "audit:read",
			},
			Level:  70,
			Active: true,
		},
		"user": {
			ID:          "user",
			Name:        "User",
			Description: "Standard user with basic permissions",
			Permissions: []string{
				"profile:read", "profile:write", "auth:refresh",
				"content:read", "content:create",
			},
			Level:  10,
			Active: true,
		},
		"guest": {
			ID:          "guest",
			Name:        "Guest",
			Description: "Limited access for unauthenticated users",
			Permissions: []string{
				"content:read", "auth:login", "auth:register",
			},
			Level:  0,
			Active: true,
		},
	}

	// Default permissions
	DefaultPermissions = map[string]*Permission{
		// User management
		"user:create": {ID: "user:create", Name: "Create User", Resource: "user", Action: "create"},
		"user:read":   {ID: "user:read", Name: "Read User", Resource: "user", Action: "read"},
		"user:write":  {ID: "user:write", Name: "Update User", Resource: "user", Action: "write"},
		"user:delete": {ID: "user:delete", Name: "Delete User", Resource: "user", Action: "delete"},
		"user:suspend": {ID: "user:suspend", Name: "Suspend User", Resource: "user", Action: "suspend"},
		"user:activate": {ID: "user:activate", Name: "Activate User", Resource: "user", Action: "activate"},
		
		// Profile management
		"profile:read":  {ID: "profile:read", Name: "Read Profile", Resource: "profile", Action: "read"},
		"profile:write": {ID: "profile:write", Name: "Update Profile", Resource: "profile", Action: "write"},
		
		// Role management
		"role:create": {ID: "role:create", Name: "Create Role", Resource: "role", Action: "create"},
		"role:read":   {ID: "role:read", Name: "Read Role", Resource: "role", Action: "read"},
		"role:write":  {ID: "role:write", Name: "Update Role", Resource: "role", Action: "write"},
		"role:delete": {ID: "role:delete", Name: "Delete Role", Resource: "role", Action: "delete"},
		"role:assign": {ID: "role:assign", Name: "Assign Role", Resource: "role", Action: "assign"},
		
		// Authentication
		"auth:login":   {ID: "auth:login", Name: "Login", Resource: "auth", Action: "login"},
		"auth:register": {ID: "auth:register", Name: "Register", Resource: "auth", Action: "register"},
		"auth:refresh": {ID: "auth:refresh", Name: "Refresh Token", Resource: "auth", Action: "refresh"},
		"auth:revoke":  {ID: "auth:revoke", Name: "Revoke Token", Resource: "auth", Action: "revoke"},
		
		// Content management
		"content:create": {ID: "content:create", Name: "Create Content", Resource: "content", Action: "create"},
		"content:read":   {ID: "content:read", Name: "Read Content", Resource: "content", Action: "read"},
		"content:write":  {ID: "content:write", Name: "Update Content", Resource: "content", Action: "write"},
		"content:delete": {ID: "content:delete", Name: "Delete Content", Resource: "content", Action: "delete"},
		
		// System management
		"system:read":  {ID: "system:read", Name: "Read System", Resource: "system", Action: "read"},
		"system:write": {ID: "system:write", Name: "Update System", Resource: "system", Action: "write"},
		
		// Audit
		"audit:read": {ID: "audit:read", Name: "Read Audit Logs", Resource: "audit", Action: "read"},
	}
)

// InitializeRBAC initializes the RBAC system with default roles and permissions
func (s *RBACService) InitializeRBAC(ctx context.Context) error {
	s.logger.Info("Initializing RBAC system")

	// Create default permissions
	for _, permission := range DefaultPermissions {
		if err := s.CreatePermission(ctx, permission); err != nil {
			s.logger.WithError(err).Warn("Failed to create permission", map[string]interface{}{
				"permission_id": permission.ID,
			})
		}
	}

	// Create default roles
	for _, role := range DefaultRoles {
		if err := s.CreateRole(ctx, role); err != nil {
			s.logger.WithError(err).Warn("Failed to create role", map[string]interface{}{
				"role_id": role.ID,
			})
		}
	}

	s.logger.Info("RBAC system initialized successfully")
	return nil
}

// CreateRole creates a new role
func (s *RBACService) CreateRole(ctx context.Context, role *Role) error {
	s.logger.Info("Creating role", map[string]interface{}{
		"role_id": role.ID,
		"name":    role.Name,
	})

	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()

	roleData := map[string]interface{}{
		"id":          role.ID,
		"name":        role.Name,
		"description": role.Description,
		"permissions": role.Permissions,
		"level":       role.Level,
		"active":      role.Active,
		"created_at":  role.CreatedAt.Unix(),
		"updated_at":  role.UpdatedAt.Unix(),
	}

	_, err := s.mcpIntegration.callFirestoreAddDocument(ctx, &FirestoreAddDocumentRequest{
		Collection: "roles",
		Data:       roleData,
	})

	return err
}

// CreatePermission creates a new permission
func (s *RBACService) CreatePermission(ctx context.Context, permission *Permission) error {
	permission.CreatedAt = time.Now()
	permission.UpdatedAt = time.Now()
	permission.Active = true

	permissionData := map[string]interface{}{
		"id":          permission.ID,
		"name":        permission.Name,
		"description": permission.Description,
		"resource":    permission.Resource,
		"action":      permission.Action,
		"active":      permission.Active,
		"created_at":  permission.CreatedAt.Unix(),
		"updated_at":  permission.UpdatedAt.Unix(),
	}

	_, err := s.mcpIntegration.callFirestoreAddDocument(ctx, &FirestoreAddDocumentRequest{
		Collection: "permissions",
		Data:       permissionData,
	})

	return err
}

// AssignRole assigns a role to a user
func (s *RBACService) AssignRole(ctx context.Context, userID, roleID, assignedBy string, expiresAt *time.Time) error {
	s.logger.Info("Assigning role to user", map[string]interface{}{
		"user_id":     userID,
		"role_id":     roleID,
		"assigned_by": assignedBy,
	})

	// Get role details
	role, err := s.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to get role: %w", err)
	}

	userRole := &UserRole{
		UserID:      userID,
		RoleID:      roleID,
		Permissions: role.Permissions,
		CustomClaims: map[string]interface{}{
			"role":  roleID,
			"level": role.Level,
		},
		AssignedBy: assignedBy,
		AssignedAt: time.Now(),
		ExpiresAt:  expiresAt,
		Active:     true,
	}

	userRoleData := map[string]interface{}{
		"user_id":      userRole.UserID,
		"role_id":      userRole.RoleID,
		"permissions":  userRole.Permissions,
		"custom_claims": userRole.CustomClaims,
		"assigned_by":  userRole.AssignedBy,
		"assigned_at":  userRole.AssignedAt.Unix(),
		"active":       userRole.Active,
	}

	if userRole.ExpiresAt != nil {
		userRoleData["expires_at"] = userRole.ExpiresAt.Unix()
	}

	_, err = s.mcpIntegration.callFirestoreAddDocument(ctx, &FirestoreAddDocumentRequest{
		Collection: "user_roles",
		Data:       userRoleData,
	})

	return err
}

// CheckAccess checks if a user has access to perform an action on a resource
func (s *RBACService) CheckAccess(ctx context.Context, request *AccessRequest) (*AccessResult, error) {
	s.logger.Debug("Checking access", map[string]interface{}{
		"user_id":  request.UserID,
		"resource": request.Resource,
		"action":   request.Action,
	})

	// Get user role
	userRole, err := s.GetUserRole(ctx, request.UserID)
	if err != nil {
		return &AccessResult{
			Allowed: false,
			Reason:  "User role not found",
		}, nil
	}

	// Check if role is active and not expired
	if !userRole.Active {
		return &AccessResult{
			Allowed: false,
			Reason:  "User role is inactive",
		}, nil
	}

	if userRole.ExpiresAt != nil && time.Now().After(*userRole.ExpiresAt) {
		return &AccessResult{
			Allowed: false,
			Reason:  "User role has expired",
		}, nil
	}

	// Check permissions
	requiredPermission := fmt.Sprintf("%s:%s", request.Resource, request.Action)
	allowed := s.hasPermission(userRole.Permissions, requiredPermission)

	result := &AccessResult{
		Allowed:     allowed,
		Permissions: userRole.Permissions,
		Role:        userRole.RoleID,
	}

	if allowed {
		result.Reason = "Access granted"
	} else {
		result.Reason = fmt.Sprintf("Missing permission: %s", requiredPermission)
	}

	return result, nil
}

// hasPermission checks if a permission list contains the required permission
func (s *RBACService) hasPermission(permissions []string, required string) bool {
	for _, permission := range permissions {
		// Check for exact match
		if permission == required {
			return true
		}

		// Check for wildcard permissions
		if permission == "*" {
			return true
		}

		// Check for resource-level wildcard (e.g., "user:*")
		if strings.HasSuffix(permission, ":*") {
			resource := strings.TrimSuffix(permission, ":*")
			if strings.HasPrefix(required, resource+":") {
				return true
			}
		}
	}

	return false
}

// GetRole retrieves a role by ID
func (s *RBACService) GetRole(ctx context.Context, roleID string) (*Role, error) {
	roleDoc, err := s.mcpIntegration.callFirestoreListDocuments(ctx, &FirestoreListDocumentsRequest{
		Collection: "roles",
		Filters: []FirestoreFilter{
			{Field: "id", Operator: "==", Value: roleID},
		},
		Limit: 1,
	})
	if err != nil {
		return nil, err
	}

	if len(roleDoc.Documents) == 0 {
		return nil, fmt.Errorf("role not found")
	}

	return s.mapToRole(roleDoc.Documents[0]), nil
}

// GetUserRole retrieves a user's role assignment
func (s *RBACService) GetUserRole(ctx context.Context, userID string) (*UserRole, error) {
	userRoleDoc, err := s.mcpIntegration.callFirestoreListDocuments(ctx, &FirestoreListDocumentsRequest{
		Collection: "user_roles",
		Filters: []FirestoreFilter{
			{Field: "user_id", Operator: "==", Value: userID},
			{Field: "active", Operator: "==", Value: true},
		},
		Limit: 1,
	})
	if err != nil {
		return nil, err
	}

	if len(userRoleDoc.Documents) == 0 {
		return nil, fmt.Errorf("user role not found")
	}

	return s.mapToUserRole(userRoleDoc.Documents[0]), nil
}

// ListRoles lists all available roles
func (s *RBACService) ListRoles(ctx context.Context) ([]*Role, error) {
	rolesDoc, err := s.mcpIntegration.callFirestoreListDocuments(ctx, &FirestoreListDocumentsRequest{
		Collection: "roles",
		Filters: []FirestoreFilter{
			{Field: "active", Operator: "==", Value: true},
		},
		OrderBy: []FirestoreOrderBy{
			{Field: "level", Direction: "desc"},
		},
	})
	if err != nil {
		return nil, err
	}

	var roles []*Role
	for _, doc := range rolesDoc.Documents {
		roles = append(roles, s.mapToRole(doc))
	}

	return roles, nil
}

// ListPermissions lists all available permissions
func (s *RBACService) ListPermissions(ctx context.Context) ([]*Permission, error) {
	permissionsDoc, err := s.mcpIntegration.callFirestoreListDocuments(ctx, &FirestoreListDocumentsRequest{
		Collection: "permissions",
		Filters: []FirestoreFilter{
			{Field: "active", Operator: "==", Value: true},
		},
		OrderBy: []FirestoreOrderBy{
			{Field: "resource", Direction: "asc"},
			{Field: "action", Direction: "asc"},
		},
	})
	if err != nil {
		return nil, err
	}

	var permissions []*Permission
	for _, doc := range permissionsDoc.Documents {
		permissions = append(permissions, s.mapToPermission(doc))
	}

	return permissions, nil
}

// RevokeRole revokes a user's role
func (s *RBACService) RevokeRole(ctx context.Context, userID string) error {
	s.logger.Info("Revoking user role", map[string]interface{}{
		"user_id": userID,
	})

	updates := map[string]interface{}{
		"active":     false,
		"revoked_at": time.Now().Unix(),
		"updated_at": time.Now().Unix(),
	}

	_, err := s.mcpIntegration.callFirestoreUpdateDocument(ctx, "user_roles", userID, updates)
	return err
}

// Helper methods for data conversion

func (s *RBACService) mapToRole(data map[string]interface{}) *Role {
	role := &Role{
		ID:          getStringFromMap(data, "id"),
		Name:        getStringFromMap(data, "name"),
		Description: getStringFromMap(data, "description"),
		Level:       int(getInt64FromMap(data, "level")),
		Active:      getBoolFromMap(data, "active"),
		CreatedAt:   time.Unix(getInt64FromMap(data, "created_at"), 0),
		UpdatedAt:   time.Unix(getInt64FromMap(data, "updated_at"), 0),
	}

	if perms, ok := data["permissions"].([]interface{}); ok {
		role.Permissions = make([]string, len(perms))
		for i, perm := range perms {
			if str, ok := perm.(string); ok {
				role.Permissions[i] = str
			}
		}
	}

	return role
}

func (s *RBACService) mapToPermission(data map[string]interface{}) *Permission {
	return &Permission{
		ID:          getStringFromMap(data, "id"),
		Name:        getStringFromMap(data, "name"),
		Description: getStringFromMap(data, "description"),
		Resource:    getStringFromMap(data, "resource"),
		Action:      getStringFromMap(data, "action"),
		Active:      getBoolFromMap(data, "active"),
		CreatedAt:   time.Unix(getInt64FromMap(data, "created_at"), 0),
		UpdatedAt:   time.Unix(getInt64FromMap(data, "updated_at"), 0),
	}
}

func (s *RBACService) mapToUserRole(data map[string]interface{}) *UserRole {
	userRole := &UserRole{
		UserID:     getStringFromMap(data, "user_id"),
		RoleID:     getStringFromMap(data, "role_id"),
		AssignedBy: getStringFromMap(data, "assigned_by"),
		AssignedAt: time.Unix(getInt64FromMap(data, "assigned_at"), 0),
		Active:     getBoolFromMap(data, "active"),
	}

	if perms, ok := data["permissions"].([]interface{}); ok {
		userRole.Permissions = make([]string, len(perms))
		for i, perm := range perms {
			if str, ok := perm.(string); ok {
				userRole.Permissions[i] = str
			}
		}
	}

	if claims, ok := data["custom_claims"].(map[string]interface{}); ok {
		userRole.CustomClaims = claims
	}

	if expiresAt := getInt64FromMap(data, "expires_at"); expiresAt > 0 {
		expiry := time.Unix(expiresAt, 0)
		userRole.ExpiresAt = &expiry
	}

	return userRole
}
