package rbac

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Helper methods for RBAC manager

// matchesRule checks if a policy rule matches the access request
func (rbac *RBACManager) matchesRule(rule *PolicyRule, request *AccessRequest) bool {
	// Check resource and action
	if rule.Resource != "*" && rule.Resource != request.Resource {
		return false
	}
	if rule.Action != "*" && rule.Action != request.Action {
		return false
	}

	// Check conditions
	for _, condition := range rule.Conditions {
		if !rbac.evaluateCondition(condition, request) {
			return false
		}
	}

	// Check time window
	if rule.TimeWindow != nil && !rbac.isWithinTimeWindow(rule.TimeWindow) {
		return false
	}

	// Check IP restrictions
	if len(rule.IPRestrictions) > 0 && !rbac.isIPAllowed(rule.IPRestrictions, request.IPAddress) {
		return false
	}

	return true
}

// evaluateCondition evaluates a condition against the request
func (rbac *RBACManager) evaluateCondition(condition *Condition, request *AccessRequest) bool {
	// Simplified condition evaluation
	switch condition.Field {
	case "user_id":
		return rbac.compareValues(request.UserID, condition.Operator, condition.Value)
	case "ip_address":
		return rbac.compareValues(request.IPAddress, condition.Operator, condition.Value)
	default:
		if contextValue, exists := request.Context[condition.Field]; exists {
			return rbac.compareValues(contextValue, condition.Operator, condition.Value)
		}
	}
	return false
}

// compareValues compares two values using the specified operator
func (rbac *RBACManager) compareValues(actual interface{}, operator string, expected interface{}) bool {
	switch operator {
	case "eq":
		return actual == expected
	case "ne":
		return actual != expected
	case "in":
		if slice, ok := expected.([]interface{}); ok {
			for _, item := range slice {
				if actual == item {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
}

// isWithinTimeWindow checks if current time is within the specified time window
func (rbac *RBACManager) isWithinTimeWindow(window *TimeWindow) bool {
	now := time.Now()

	// Check day of week
	currentDay := now.Weekday().String()
	dayAllowed := false
	for _, day := range window.Days {
		if day == currentDay {
			dayAllowed = true
			break
		}
	}
	if !dayAllowed {
		return false
	}

	// Check time range (simplified)
	currentTime := now.Format("15:04")
	return currentTime >= window.StartTime && currentTime <= window.EndTime
}

// isIPAllowed checks if the client IP is in the allowed list
func (rbac *RBACManager) isIPAllowed(allowedIPs []string, clientIP string) bool {
	for _, ip := range allowedIPs {
		if ip == clientIP || ip == "*" {
			return true
		}
	}
	return false
}

// getUserPermissions gets all permissions for a user (direct + role-based)
func (rbac *RBACManager) getUserPermissions(user *User) []string {
	permissions := make([]string, 0)

	// Add direct permissions
	permissions = append(permissions, user.Permissions...)

	// Add role-based permissions
	for _, roleID := range user.Roles {
		if role, exists := rbac.roles[roleID]; exists && role.IsActive {
			permissions = append(permissions, role.Permissions...)

			// Add parent role permissions if hierarchy is enabled
			if rbac.config.EnableRoleHierarchy {
				permissions = append(permissions, rbac.getParentRolePermissions(role)...)
			}
		}
	}

	return rbac.deduplicatePermissions(permissions)
}

// getParentRolePermissions recursively gets permissions from parent roles
func (rbac *RBACManager) getParentRolePermissions(role *Role) []string {
	permissions := make([]string, 0)

	for _, parentRoleID := range role.ParentRoles {
		if parentRole, exists := rbac.roles[parentRoleID]; exists && parentRole.IsActive {
			permissions = append(permissions, parentRole.Permissions...)
			// Recursive call for nested hierarchy
			permissions = append(permissions, rbac.getParentRolePermissions(parentRole)...)
		}
	}

	return permissions
}

// deduplicatePermissions removes duplicate permissions from the list
func (rbac *RBACManager) deduplicatePermissions(permissions []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)

	for _, perm := range permissions {
		if !seen[perm] {
			seen[perm] = true
			result = append(result, perm)
		}
	}

	return result
}

// auditAccess logs an access attempt for auditing
func (rbac *RBACManager) auditAccess(request *AccessRequest, result *AccessResult) {
	if !rbac.config.EnableAuditLogging {
		return
	}

	event := &AuditEvent{
		ID:        uuid.New().String(),
		Type:      "access_check",
		UserID:    request.UserID,
		Resource:  request.Resource,
		Action:    request.Action,
		Result:    fmt.Sprintf("allowed=%t", result.Allowed),
		IPAddress: request.IPAddress,
		UserAgent: request.UserAgent,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"reason":    result.Reason,
			"policy_id": result.PolicyID,
			"rule_id":   result.RuleID,
			"context":   request.Context,
		},
	}

	rbac.auditor.LogEvent(event)
}

// sessionCleanupWorker periodically cleans up expired sessions
func (rbac *RBACManager) sessionCleanupWorker(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rbac.cleanupExpiredSessions()
		}
	}
}

// cleanupExpiredSessions removes expired sessions
func (rbac *RBACManager) cleanupExpiredSessions() {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	now := time.Now()
	expiredSessions := make([]string, 0)

	for sessionID, session := range rbac.sessions {
		if now.After(session.ExpiresAt) {
			expiredSessions = append(expiredSessions, sessionID)
		}
	}

	for _, sessionID := range expiredSessions {
		delete(rbac.sessions, sessionID)
	}

	if len(expiredSessions) > 0 {
		rbac.logger.Info("Cleaned up expired sessions", "count", len(expiredSessions))
	}
}

// initializeDefaults creates default roles, permissions, and policies
func (rbac *RBACManager) initializeDefaults() {
	// Create default permissions
	defaultPermissions := []*Permission{
		{
			Name:        "read_all",
			Description: "Read access to all resources",
			Resource:    "*",
			Action:      "read",
			Scope:       "global",
			IsSystem:    true,
		},
		{
			Name:        "write_all",
			Description: "Write access to all resources",
			Resource:    "*",
			Action:      "write",
			Scope:       "global",
			IsSystem:    true,
		},
		{
			Name:        "admin_all",
			Description: "Administrative access to all resources",
			Resource:    "*",
			Action:      "*",
			Scope:       "global",
			IsSystem:    true,
		},
		{
			Name:        "dashboard_read",
			Description: "Read access to dashboards",
			Resource:    "dashboard",
			Action:      "read",
			Scope:       "application",
			IsSystem:    true,
		},
		{
			Name:        "reports_read",
			Description: "Read access to reports",
			Resource:    "reports",
			Action:      "read",
			Scope:       "application",
			IsSystem:    true,
		},
		{
			Name:        "security_manage",
			Description: "Manage security settings",
			Resource:    "security",
			Action:      "*",
			Scope:       "application",
			IsSystem:    true,
		},
	}

	for _, perm := range defaultPermissions {
		rbac.CreatePermission(perm)
	}

	// Create default roles
	defaultRoles := []*Role{
		{
			Name:        "admin",
			Description: "System administrator with full access",
			Permissions: []string{"*:*"},
			IsSystem:    true,
		},
		{
			Name:        "security_admin",
			Description: "Security administrator with security management access",
			Permissions: []string{"security:*", "dashboard:read", "reports:read"},
			IsSystem:    true,
		},
		{
			Name:        "analyst",
			Description: "Security analyst with read access to security data",
			Permissions: []string{"dashboard:read", "reports:read", "security:read"},
			IsSystem:    true,
		},
		{
			Name:        "user",
			Description: "Regular user with basic read access",
			Permissions: []string{"dashboard:read"},
			IsSystem:    true,
		},
		{
			Name:        "viewer",
			Description: "Read-only access to dashboards and reports",
			Permissions: []string{"dashboard:read", "reports:read"},
			IsSystem:    true,
		},
	}

	for _, role := range defaultRoles {
		rbac.CreateRole(role)
	}

	// Create default policies
	defaultPolicies := []*Policy{
		{
			Name:        "admin_policy",
			Description: "Full access policy for administrators",
			Type:        "allow",
			IsActive:    true,
			Priority:    100,
			Rules: []*PolicyRule{
				{
					ID:       uuid.New().String(),
					Effect:   "allow",
					Resource: "*",
					Action:   "*",
					Conditions: []*Condition{
						{
							Field:    "user_role",
							Operator: "in",
							Value:    []interface{}{"admin", "security_admin"},
						},
					},
				},
			},
		},
		{
			Name:        "time_restricted_policy",
			Description: "Time-restricted access policy",
			Type:        "conditional",
			IsActive:    true,
			Priority:    50,
			Rules: []*PolicyRule{
				{
					ID:       uuid.New().String(),
					Effect:   "allow",
					Resource: "dashboard",
					Action:   "read",
					TimeWindow: &TimeWindow{
						StartTime: "09:00",
						EndTime:   "17:00",
						Days:      []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"},
						Timezone:  "UTC",
					},
				},
			},
		},
	}

	for _, policy := range defaultPolicies {
		rbac.CreatePolicy(policy)
	}

	rbac.logger.Info("Default RBAC entities initialized",
		"permissions", len(defaultPermissions),
		"roles", len(defaultRoles),
		"policies", len(defaultPolicies))
}

// CreatePolicy creates a new access policy
func (rbac *RBACManager) CreatePolicy(policy *Policy) error {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	policy.ID = uuid.New().String()
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	rbac.policies[policy.ID] = policy
	rbac.logger.Info("Policy created", "policy_id", policy.ID, "name", policy.Name)
	return nil
}

// GetUser gets a user by ID
func (rbac *RBACManager) GetUser(userID string) (*User, error) {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()

	user, exists := rbac.users[userID]
	if !exists {
		return nil, fmt.Errorf("user not found: %s", userID)
	}

	return user, nil
}

// GetRole gets a role by ID
func (rbac *RBACManager) GetRole(roleID string) (*Role, error) {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()

	role, exists := rbac.roles[roleID]
	if !exists {
		return nil, fmt.Errorf("role not found: %s", roleID)
	}

	return role, nil
}

// ListUsers lists all users
func (rbac *RBACManager) ListUsers() []*User {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()

	users := make([]*User, 0, len(rbac.users))
	for _, user := range rbac.users {
		users = append(users, user)
	}

	return users
}

// ListRoles lists all roles
func (rbac *RBACManager) ListRoles() []*Role {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()

	roles := make([]*Role, 0, len(rbac.roles))
	for _, role := range rbac.roles {
		roles = append(roles, role)
	}

	return roles
}
