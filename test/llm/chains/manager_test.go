package chains

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/llm/chains"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// TestChainManager tests the comprehensive chain management system
func TestChainManager(t *testing.T) {
	logger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "json",
		Output: "stdout",
	})
	require.NoError(t, err)

	// Create components
	registry := chains.NewDefaultChainRegistry(logger)
	validator := chains.NewDefaultChainValidator(chains.ValidatorConfig{
		MaxNameLength:        100,
		MaxDescriptionLength: 500,
		MaxDependencies:      10,
		SecurityChecks: chains.SecurityChecks{
			CheckPromptInjection: true,
			CheckDataLeakage:     true,
			CheckMaliciousCode:   true,
		},
	}, logger)
	
	monitor, err := chains.NewDefaultChainMonitor(logger)
	require.NoError(t, err)
	
	security := chains.NewDefaultChainSecurity(logger)
	templates := chains.NewDefaultTemplateManager(logger)

	// Create chain manager
	manager := chains.NewDefaultChainManager(registry, validator, monitor, security, templates, logger)
	require.NotNil(t, manager)

	ctx := context.Background()

	t.Run("RegisterChain", func(t *testing.T) {
		chain := &MockChain{
			id:          "test-chain-1",
			name:        "Test Chain 1",
			description: "A test chain for unit testing",
		}

		metadata := chains.ChainMetadata{
			Version:     "1.0.0",
			Author:      "test-author",
			Tags:        []string{"test", "demo"},
			Category:    "testing",
			Description: "Test chain metadata",
		}

		err := manager.RegisterChain(ctx, chain, metadata)
		assert.NoError(t, err)

		// Verify chain was registered
		retrievedChain, err := manager.GetChain(ctx, "test-chain-1")
		assert.NoError(t, err)
		assert.Equal(t, chain.ID(), retrievedChain.ID())
		assert.Equal(t, chain.Name(), retrievedChain.Name())
	})

	t.Run("ListChains", func(t *testing.T) {
		filter := chains.ChainFilter{
			Tags:   []string{"test"},
			Limit:  10,
			Offset: 0,
		}

		chainList, err := manager.ListChains(ctx, filter)
		assert.NoError(t, err)
		assert.Len(t, chainList, 1)
		assert.Equal(t, "test-chain-1", chainList[0].ID)
	})

	t.Run("SearchChains", func(t *testing.T) {
		results, err := manager.SearchChains(ctx, "test")
		assert.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "test-chain-1", results[0].ID)
	})

	t.Run("ExecuteChain", func(t *testing.T) {
		// Set up permissions first
		permissions := chains.ChainPermissions{
			ChainID:       "test-chain-1",
			Owners:        []string{"test-user"},
			PublicExecute: true,
		}
		err := manager.SetChainPermissions(ctx, "test-chain-1", permissions)
		assert.NoError(t, err)

		input := llm.ChainInput{
			"test_input": "Hello, world!",
		}

		options := chains.ExecutionOptions{
			UserID:  "test-user",
			Timeout: 30 * time.Second,
		}

		output, err := manager.ExecuteChain(ctx, "test-chain-1", input, options)
		assert.NoError(t, err)
		assert.NotNil(t, output)
		assert.Equal(t, "Mock response", output["result"])
	})

	t.Run("GetChainMetrics", func(t *testing.T) {
		metrics, err := manager.GetChainMetrics(ctx, "test-chain-1")
		assert.NoError(t, err)
		assert.Equal(t, "test-chain-1", metrics.ChainID)
		assert.Greater(t, metrics.TotalExecutions, int64(0))
	})

	t.Run("GetChainHealth", func(t *testing.T) {
		health, err := manager.GetChainHealth(ctx, "test-chain-1")
		assert.NoError(t, err)
		assert.Equal(t, "test-chain-1", health.ChainID)
		assert.NotEmpty(t, health.Status)
	})

	t.Run("UpdateChain", func(t *testing.T) {
		updatedChain := &MockChain{
			id:          "test-chain-1",
			name:        "Updated Test Chain 1",
			description: "An updated test chain",
		}

		err := manager.UpdateChain(ctx, "test-chain-1", updatedChain)
		assert.NoError(t, err)

		// Verify chain was updated
		retrievedChain, err := manager.GetChain(ctx, "test-chain-1")
		assert.NoError(t, err)
		assert.Equal(t, "Updated Test Chain 1", retrievedChain.Name())
	})

	t.Run("UnregisterChain", func(t *testing.T) {
		err := manager.UnregisterChain(ctx, "test-chain-1")
		assert.NoError(t, err)

		// Verify chain was unregistered
		_, err = manager.GetChain(ctx, "test-chain-1")
		assert.Error(t, err)
	})
}

// TestChainRegistry tests the chain registry functionality
func TestChainRegistry(t *testing.T) {
	logger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "json",
		Output: "stdout",
	})
	require.NoError(t, err)

	registry := chains.NewDefaultChainRegistry(logger)
	ctx := context.Background()

	t.Run("RegisterAndGet", func(t *testing.T) {
		chain := &MockChain{
			id:          "registry-test-1",
			name:        "Registry Test Chain",
			description: "A chain for testing registry",
		}

		metadata := chains.ChainMetadata{
			Version:     "1.0.0",
			Author:      "test-author",
			Tags:        []string{"registry", "test"},
			Category:    "testing",
			Description: "Registry test metadata",
		}

		err := registry.Register(ctx, chain, metadata)
		assert.NoError(t, err)

		// Test existence
		assert.True(t, registry.Exists(ctx, "registry-test-1"))

		// Test retrieval
		retrievedChain, err := registry.Get(ctx, "registry-test-1")
		assert.NoError(t, err)
		assert.Equal(t, chain.ID(), retrievedChain.ID())

		// Test metadata retrieval
		retrievedMetadata, err := registry.GetMetadata(ctx, "registry-test-1")
		assert.NoError(t, err)
		assert.Equal(t, metadata.Version, retrievedMetadata.Version)
		assert.Equal(t, metadata.Author, retrievedMetadata.Author)
	})

	t.Run("ListWithFilter", func(t *testing.T) {
		filter := chains.ChainFilter{
			Tags:     []string{"registry"},
			Category: "testing",
			Limit:    10,
		}

		chains, err := registry.List(ctx, filter)
		assert.NoError(t, err)
		assert.Len(t, chains, 1)
		assert.Equal(t, "registry-test-1", chains[0].ID)
	})

	t.Run("Search", func(t *testing.T) {
		results, err := registry.Search(ctx, "registry")
		assert.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "registry-test-1", results[0].ID)
	})

	t.Run("Dependencies", func(t *testing.T) {
		// Test dependency management
		dependencies := []string{"dep1", "dep2"}
		err := registry.UpdateDependencies(ctx, "registry-test-1", dependencies)
		assert.NoError(t, err)

		retrievedDeps, err := registry.GetDependencies(ctx, "registry-test-1")
		assert.NoError(t, err)
		assert.Equal(t, dependencies, retrievedDeps)
	})
}

// TestChainValidator tests the chain validation functionality
func TestChainValidator(t *testing.T) {
	logger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "json",
		Output: "stdout",
	})
	require.NoError(t, err)

	config := chains.ValidatorConfig{
		MaxNameLength:        100,
		MaxDescriptionLength: 500,
		RequiredTags:         []string{"category"},
		MaxDependencies:      5,
		SecurityChecks: chains.SecurityChecks{
			CheckPromptInjection: true,
			CheckDataLeakage:     true,
			CheckMaliciousCode:   true,
		},
	}

	validator := chains.NewDefaultChainValidator(config, logger)
	ctx := context.Background()

	t.Run("ValidChain", func(t *testing.T) {
		chain := &MockChain{
			id:          "valid-chain",
			name:        "Valid Chain",
			description: "A valid chain for testing",
		}

		result, err := validator.ValidateChain(ctx, chain)
		assert.NoError(t, err)
		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)
	})

	t.Run("InvalidChain", func(t *testing.T) {
		chain := &MockChain{
			id:          "", // Invalid: empty ID
			name:        "",  // Invalid: empty name
			description: "A chain with validation issues",
		}

		result, err := validator.ValidateChain(ctx, chain)
		assert.NoError(t, err)
		assert.False(t, result.Valid)
		assert.NotEmpty(t, result.Errors)
	})

	t.Run("ValidateMetadata", func(t *testing.T) {
		metadata := chains.ChainMetadata{
			Version:      "1.0.0",
			Author:       "test-author",
			Tags:         []string{"category", "test"},
			Dependencies: []string{"dep1"},
		}

		result, err := validator.ValidateMetadata(ctx, metadata)
		assert.NoError(t, err)
		assert.True(t, result.Valid)
	})

	t.Run("CustomValidator", func(t *testing.T) {
		// Add custom validator
		customValidator := func(ctx context.Context, chain llm.Chain) (chains.ValidationResult, error) {
			result := chains.ValidationResult{
				Valid:       true,
				Errors:      []chains.ValidationError{},
				Warnings:    []chains.ValidationWarning{},
				Score:       100.0,
				Suggestions: []string{},
			}

			if chain.Name() == "forbidden" {
				result.Valid = false
				result.Errors = append(result.Errors, chains.ValidationError{
					Type:      "custom_validation",
					Message:   "Chain name 'forbidden' is not allowed",
					Severity:  "error",
					Timestamp: time.Now(),
				})
			}

			return result, nil
		}

		err := validator.AddCustomValidator("forbidden_name", customValidator)
		assert.NoError(t, err)

		// Test with forbidden name
		chain := &MockChain{
			id:          "test-chain",
			name:        "forbidden",
			description: "A chain with forbidden name",
		}

		result, err := validator.ValidateChain(ctx, chain)
		assert.NoError(t, err)
		assert.False(t, result.Valid)
	})
}

// TestChainSecurity tests the security functionality
func TestChainSecurity(t *testing.T) {
	logger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "json",
		Output: "stdout",
	})
	require.NoError(t, err)

	security := chains.NewDefaultChainSecurity(logger)
	ctx := context.Background()

	t.Run("SetAndGetPermissions", func(t *testing.T) {
		permissions := chains.ChainPermissions{
			ChainID:   "security-test-chain",
			Owners:    []string{"owner1", "owner2"},
			Readers:   []string{"reader1", "reader2"},
			Executors: []string{"executor1"},
			Admins:    []string{"admin1"},
		}

		err := security.SetPermissions(ctx, "security-test-chain", permissions)
		assert.NoError(t, err)

		retrievedPermissions, err := security.GetPermissions(ctx, "security-test-chain")
		assert.NoError(t, err)
		assert.Equal(t, permissions.ChainID, retrievedPermissions.ChainID)
		assert.Equal(t, permissions.Owners, retrievedPermissions.Owners)
	})

	t.Run("CheckAccess", func(t *testing.T) {
		// Test owner access
		err := security.CheckAccess(ctx, "security-test-chain", "owner1", "admin")
		assert.NoError(t, err)

		// Test reader access
		err = security.CheckAccess(ctx, "security-test-chain", "reader1", "read")
		assert.NoError(t, err)

		// Test unauthorized access
		err = security.CheckAccess(ctx, "security-test-chain", "unauthorized", "admin")
		assert.Error(t, err)
	})

	t.Run("RoleManagement", func(t *testing.T) {
		role := chains.Role{
			ID:          "test-role",
			Name:        "Test Role",
			Description: "A role for testing",
			Permissions: []string{"read", "execute"},
		}

		err := security.CreateRole(ctx, role)
		assert.NoError(t, err)

		err = security.AssignRole(ctx, "test-user", "test-role")
		assert.NoError(t, err)

		roles, err := security.GetUserRoles(ctx, "test-user")
		assert.NoError(t, err)
		assert.Len(t, roles, 1)
		assert.Equal(t, "test-role", roles[0].ID)
	})

	t.Run("AuditLogging", func(t *testing.T) {
		err := security.LogAccess(ctx, "security-test-chain", "test-user", "read", "success")
		assert.NoError(t, err)

		filter := chains.AuditFilter{
			UserID: "test-user",
			Action: "read",
			Limit:  10,
		}

		entries, err := security.GetAuditLog(ctx, "security-test-chain", filter)
		assert.NoError(t, err)
		assert.Len(t, entries, 1)
		assert.Equal(t, "test-user", entries[0].UserID)
		assert.Equal(t, "read", entries[0].Action)
	})
}

// MockChain implements the Chain interface for testing
type MockChain struct {
	id          string
	name        string
	description string
	memory      llm.Memory
}

func (mc *MockChain) ID() string          { return mc.id }
func (mc *MockChain) Name() string        { return mc.name }
func (mc *MockChain) Description() string { return mc.description }

func (mc *MockChain) Execute(ctx context.Context, input llm.ChainInput) (llm.ChainOutput, error) {
	return llm.ChainOutput{
		"result":  "Mock response",
		"success": true,
		"input":   input,
	}, nil
}

func (mc *MockChain) GetMemory() llm.Memory     { return mc.memory }
func (mc *MockChain) SetMemory(memory llm.Memory) { mc.memory = memory }
func (mc *MockChain) Validate() error          { return nil }
