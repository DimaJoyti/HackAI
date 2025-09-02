package rbac

import (
	"context"
	"testing"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestRBACLogger() *logger.Logger {
	config := logger.Config{
		Level:     logger.LevelDebug,
		Format:    "text",
		Output:    "stdout",
		AddSource: false,
	}
	testLogger, _ := logger.New(config)
	return testLogger
}

func TestRBACManager_CreateUser(t *testing.T) {
	logger := createTestRBACLogger()
	config := DefaultRBACConfig()
	config.EnableAuditLogging = false // Disable for testing
	rbac := NewRBACManager(config, logger)

	user := &User{
		Username:    "testuser",
		Email:       "test@example.com",
		FirstName:   "Test",
		LastName:    "User",
		Roles:       []string{},
		Permissions: []string{},
		MFAEnabled:  false,
		Metadata:    make(map[string]interface{}),
	}

	err := rbac.CreateUser(user)
	require.NoError(t, err)
	assert.NotEmpty(t, user.ID)
	assert.True(t, user.IsActive)
	assert.False(t, user.IsLocked)

	// Verify user was created
	retrieved, err := rbac.GetUser(user.ID)
	require.NoError(t, err)
	assert.Equal(t, "testuser", retrieved.Username)
	assert.Equal(t, "test@example.com", retrieved.Email)
}

func TestRBACManager_CreateRole(t *testing.T) {
	logger := createTestRBACLogger()
	config := DefaultRBACConfig()
	config.EnableAuditLogging = false
	rbac := NewRBACManager(config, logger)

	role := &Role{
		Name:        "test-role",
		Description: "A test role",
		Permissions: []string{"read:dashboard", "write:reports"},
		ParentRoles: []string{},
		ChildRoles:  []string{},
		IsSystem:    false,
		CreatedBy:   "admin",
		Metadata:    make(map[string]interface{}),
	}

	err := rbac.CreateRole(role)
	require.NoError(t, err)
	assert.NotEmpty(t, role.ID)
	assert.True(t, role.IsActive)

	// Verify role was created
	retrieved, err := rbac.GetRole(role.ID)
	require.NoError(t, err)
	assert.Equal(t, "test-role", retrieved.Name)
	assert.Contains(t, retrieved.Permissions, "read:dashboard")
}

func TestRBACManager_AssignRoleToUser(t *testing.T) {
	logger := createTestRBACLogger()
	config := DefaultRBACConfig()
	config.EnableAuditLogging = false
	rbac := NewRBACManager(config, logger)

	// Create user
	user := &User{
		Username:    "roleuser",
		Email:       "roleuser@example.com",
		FirstName:   "Role",
		LastName:    "User",
		Roles:       []string{},
		Permissions: []string{},
		Metadata:    make(map[string]interface{}),
	}
	err := rbac.CreateUser(user)
	require.NoError(t, err)

	// Create role
	role := &Role{
		Name:        "user-role",
		Description: "A user role",
		Permissions: []string{"read:dashboard"},
		Metadata:    make(map[string]interface{}),
	}
	err = rbac.CreateRole(role)
	require.NoError(t, err)

	// Assign role to user
	err = rbac.AssignRoleToUser(user.ID, role.ID)
	require.NoError(t, err)

	// Verify role assignment
	retrieved, err := rbac.GetUser(user.ID)
	require.NoError(t, err)
	assert.Contains(t, retrieved.Roles, role.ID)

	// Test duplicate assignment (should fail)
	err = rbac.AssignRoleToUser(user.ID, role.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already assigned")
}

func TestRBACManager_CheckAccess_Allow(t *testing.T) {
	logger := createTestRBACLogger()
	config := DefaultRBACConfig()
	config.EnableAuditLogging = false
	rbac := NewRBACManager(config, logger)

	// Create user with permissions
	user := &User{
		Username:    "accessuser",
		Email:       "access@example.com",
		FirstName:   "Access",
		LastName:    "User",
		Roles:       []string{},
		Permissions: []string{"dashboard:read"},
		Metadata:    make(map[string]interface{}),
	}
	err := rbac.CreateUser(user)
	require.NoError(t, err)

	// Check access
	request := &AccessRequest{
		UserID:    user.ID,
		Resource:  "dashboard",
		Action:    "read",
		Context:   make(map[string]interface{}),
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent",
		Timestamp: time.Now(),
	}

	result, err := rbac.CheckAccess(context.Background(), request)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Contains(t, result.Reason, "permission granted")
}

func TestRBACManager_CheckAccess_Deny(t *testing.T) {
	logger := createTestRBACLogger()
	config := DefaultRBACConfig()
	config.EnableAuditLogging = false
	rbac := NewRBACManager(config, logger)

	// Create user without permissions
	user := &User{
		Username:    "noaccessuser",
		Email:       "noaccess@example.com",
		FirstName:   "NoAccess",
		LastName:    "User",
		Roles:       []string{},
		Permissions: []string{},
		Metadata:    make(map[string]interface{}),
	}
	err := rbac.CreateUser(user)
	require.NoError(t, err)

	// Check access
	request := &AccessRequest{
		UserID:    user.ID,
		Resource:  "admin",
		Action:    "delete",
		Context:   make(map[string]interface{}),
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent",
		Timestamp: time.Now(),
	}

	result, err := rbac.CheckAccess(context.Background(), request)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "no matching permissions")
}

func TestRBACManager_CheckAccess_InactiveUser(t *testing.T) {
	logger := createTestRBACLogger()
	config := DefaultRBACConfig()
	config.EnableAuditLogging = false
	rbac := NewRBACManager(config, logger)

	// Create inactive user
	user := &User{
		Username:    "inactiveuser",
		Email:       "inactive@example.com",
		FirstName:   "Inactive",
		LastName:    "User",
		Roles:       []string{},
		Permissions: []string{"dashboard:read"},
		IsActive:    false,
		Metadata:    make(map[string]interface{}),
	}
	err := rbac.CreateUser(user)
	require.NoError(t, err)

	// Manually set user as inactive
	rbac.users[user.ID].IsActive = false

	// Check access
	request := &AccessRequest{
		UserID:    user.ID,
		Resource:  "dashboard",
		Action:    "read",
		Context:   make(map[string]interface{}),
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent",
		Timestamp: time.Now(),
	}

	result, err := rbac.CheckAccess(context.Background(), request)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "inactive or locked")
}

func TestRBACManager_CheckAccess_UserNotFound(t *testing.T) {
	logger := createTestRBACLogger()
	config := DefaultRBACConfig()
	config.EnableAuditLogging = false
	rbac := NewRBACManager(config, logger)

	// Check access for non-existent user
	request := &AccessRequest{
		UserID:    "non-existent-user",
		Resource:  "dashboard",
		Action:    "read",
		Context:   make(map[string]interface{}),
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent",
		Timestamp: time.Now(),
	}

	result, err := rbac.CheckAccess(context.Background(), request)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "user not found")
}

func TestRBACManager_Start_Stop(t *testing.T) {
	logger := createTestRBACLogger()
	config := DefaultRBACConfig()
	config.EnableAuditLogging = false
	rbac := NewRBACManager(config, logger)

	ctx := context.Background()

	// Test start
	err := rbac.Start(ctx)
	require.NoError(t, err)

	// Verify default entities were created
	roles := rbac.ListRoles()
	assert.NotEmpty(t, roles)

	// Find admin role
	var adminRole *Role
	for _, role := range roles {
		if role.Name == "admin" {
			adminRole = role
			break
		}
	}
	require.NotNil(t, adminRole)
	assert.True(t, adminRole.IsSystem)

	// Test double start (should fail)
	err = rbac.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")

	// Test stop
	err = rbac.Stop(ctx)
	require.NoError(t, err)

	// Test double stop (should not fail)
	err = rbac.Stop(ctx)
	require.NoError(t, err)
}

func TestRBACManager_ListUsers(t *testing.T) {
	logger := createTestRBACLogger()
	config := DefaultRBACConfig()
	config.EnableAuditLogging = false
	rbac := NewRBACManager(config, logger)

	// Create multiple users
	users := []*User{
		{
			Username:    "user1",
			Email:       "user1@example.com",
			FirstName:   "User",
			LastName:    "One",
			Roles:       []string{},
			Permissions: []string{},
			Metadata:    make(map[string]interface{}),
		},
		{
			Username:    "user2",
			Email:       "user2@example.com",
			FirstName:   "User",
			LastName:    "Two",
			Roles:       []string{},
			Permissions: []string{},
			Metadata:    make(map[string]interface{}),
		},
	}

	for _, user := range users {
		err := rbac.CreateUser(user)
		require.NoError(t, err)
	}

	// List all users
	allUsers := rbac.ListUsers()
	assert.Len(t, allUsers, 2)

	// Verify usernames
	usernames := make([]string, len(allUsers))
	for i, u := range allUsers {
		usernames[i] = u.Username
	}
	assert.Contains(t, usernames, "user1")
	assert.Contains(t, usernames, "user2")
}

func TestRBACManager_ListRoles(t *testing.T) {
	logger := createTestRBACLogger()
	config := DefaultRBACConfig()
	config.EnableAuditLogging = false
	rbac := NewRBACManager(config, logger)

	// Start to initialize default roles
	ctx := context.Background()
	err := rbac.Start(ctx)
	require.NoError(t, err)

	// Create additional role
	role := &Role{
		Name:        "custom-role",
		Description: "A custom role",
		Permissions: []string{"custom:action"},
		Metadata:    make(map[string]interface{}),
	}
	err = rbac.CreateRole(role)
	require.NoError(t, err)

	// List all roles
	allRoles := rbac.ListRoles()
	assert.GreaterOrEqual(t, len(allRoles), 6) // 5 default + 1 custom

	// Verify custom role exists
	roleNames := make([]string, len(allRoles))
	for i, r := range allRoles {
		roleNames[i] = r.Name
	}
	assert.Contains(t, roleNames, "custom-role")
	assert.Contains(t, roleNames, "admin")
	assert.Contains(t, roleNames, "user")
}
