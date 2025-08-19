package ai

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dimajoyti/hackai/pkg/logger"
)

func TestAdvancedAgent_ExecuteWithContext(t *testing.T) {
	var testLogger *logger.Logger // nil logger for testing

	// Create advanced agent
	agent := NewAdvancedAgent("test-agent", "Test Agent", "Advanced agent for testing", testLogger)
	require.NotNil(t, agent)

	// Add a test tool
	testTool := NewSecurityScannerTool(testLogger)
	err := agent.AddTool(testTool)
	require.NoError(t, err)

	// Test execution context
	execCtx := AgentExecutionContext{
		RequestID:        "test-request-123",
		UserID:           "test-user",
		SessionID:        "test-session",
		SecurityLevel:    SecurityLevelMedium,
		MaxExecutionTime: 30 * time.Second,
		Priority:         PriorityNormal,
		StartTime:        time.Now(),
		Metadata:         map[string]interface{}{"test": true},
	}

	// Test input
	input := AgentInput{
		Query:       "Scan target for vulnerabilities",
		Context:     map[string]interface{}{"target": "example.com"},
		MaxSteps:    5,
		Tools:       []string{"security_scanner"},
		Constraints: []string{"no_aggressive_scans"},
		Goals:       []string{"find_vulnerabilities"},
	}

	t.Run("successful execution", func(t *testing.T) {
		result, err := agent.ExecuteWithContext(context.Background(), execCtx, input)

		if err != nil {
			t.Logf("Execution error: %v", err)
		}
		if result != nil {
			t.Logf("Result success: %v, error: %v", result.Success, result.Error)
		}

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.NotNil(t, result.Output)
		assert.Greater(t, result.ExecutionTime, time.Duration(0))
		assert.NotNil(t, result.DecisionPoints)
		assert.NotNil(t, result.PerformanceMetrics)
	})

	t.Run("async execution", func(t *testing.T) {
		resultChan, err := agent.ExecuteAsync(context.Background(), execCtx, input)
		require.NoError(t, err)
		require.NotNil(t, resultChan)

		// Wait for result
		select {
		case result := <-resultChan:
			require.NotNil(t, result)
			assert.True(t, result.Success)
		case <-time.After(5 * time.Second):
			t.Fatal("Async execution timed out")
		}
	})

	t.Run("execution history", func(t *testing.T) {
		// Execute multiple times
		for i := 0; i < 3; i++ {
			_, err := agent.ExecuteWithContext(context.Background(), execCtx, input)
			require.NoError(t, err)
		}

		history := agent.GetExecutionHistory()
		assert.GreaterOrEqual(t, len(history), 3)
	})
}

func TestAdvancedAgent_ToolValidation(t *testing.T) {
	var testLogger *logger.Logger // nil logger for testing

	agent := NewAdvancedAgent("test-agent", "Test Agent", "Test agent", testLogger)

	// Add a security tool
	securityTool := NewSecurityScannerTool(testLogger)
	err := agent.AddTool(securityTool)
	require.NoError(t, err)

	// Add a security validator
	validator := NewSecurityToolValidator("test-validator", testLogger)
	validator.SetAllowLocalhost(true)
	validator.SetAllowPrivateIPs(false)

	err = agent.AddToolValidator(validator)
	require.NoError(t, err)

	t.Run("valid tool execution", func(t *testing.T) {
		execCtx := AgentExecutionContext{
			RequestID:     "test-request",
			SecurityLevel: SecurityLevelMedium,
			StartTime:     time.Now(),
		}

		input := AgentInput{
			Query:    "Scan localhost for vulnerabilities",
			Context:  map[string]interface{}{"target": "localhost"},
			MaxSteps: 3,
		}

		result, err := agent.ExecuteWithContext(context.Background(), execCtx, input)
		require.NoError(t, err)
		assert.True(t, result.Success)
	})

	t.Run("validator management", func(t *testing.T) {
		// Test adding duplicate validator
		duplicateValidator := NewSecurityToolValidator("test-validator", testLogger)
		err := agent.AddToolValidator(duplicateValidator)
		assert.Error(t, err) // Should fail because validator with same ID already exists

		// Test removing validator
		err = agent.RemoveToolValidator("test-validator")
		assert.NoError(t, err)

		// Test removing non-existent validator
		err = agent.RemoveToolValidator("non-existent")
		assert.Error(t, err)
	})
}

func TestAdvancedAgent_StrategyManagement(t *testing.T) {
	var testLogger *logger.Logger // nil logger for testing

	agent := NewAdvancedAgent("test-agent", "Test Agent", "Test agent", testLogger)

	t.Run("update strategy", func(t *testing.T) {
		newStrategy := AgentStrategy{
			ID:                "custom-strategy",
			Name:              "Custom Strategy",
			Description:       "Custom agent strategy for testing",
			DecisionThreshold: 0.8,
			RiskTolerance:     RiskHigh,
			MaxRetries:        5,
			TimeoutStrategy:   "linear_backoff",
			Metadata:          map[string]interface{}{"custom": true},
		}

		err := agent.UpdateStrategy(newStrategy)
		assert.NoError(t, err)
	})

	t.Run("invalid strategy", func(t *testing.T) {
		invalidStrategy := AgentStrategy{
			ID:                "invalid-strategy",
			DecisionThreshold: 1.5, // Invalid threshold > 1
			MaxRetries:        -1,  // Invalid negative retries
		}

		err := agent.UpdateStrategy(invalidStrategy)
		assert.Error(t, err)
	})
}

func TestAdvancedAgent_Recommendations(t *testing.T) {
	var testLogger *logger.Logger // nil logger for testing

	agent := NewAdvancedAgent("test-agent", "Test Agent", "Test agent", testLogger)

	// Add tools
	securityTool := NewSecurityScannerTool(testLogger)
	err := agent.AddTool(securityTool)
	require.NoError(t, err)

	pentestTool := NewPenetrationTesterTool(testLogger)
	err = agent.AddTool(pentestTool)
	require.NoError(t, err)

	t.Run("get recommendations", func(t *testing.T) {
		input := AgentInput{
			Query:    "Analyze security of web application",
			Context:  map[string]interface{}{"target": "example.com"},
			MaxSteps: 5,
		}

		recommendations, err := agent.GetRecommendations(context.Background(), input)
		require.NoError(t, err)
		assert.NotEmpty(t, recommendations)

		// Check recommendation structure
		for _, rec := range recommendations {
			assert.NotEmpty(t, rec.Action.Type)
			assert.GreaterOrEqual(t, rec.Confidence, 0.0)
			assert.LessOrEqual(t, rec.Confidence, 1.0)
			assert.NotEmpty(t, rec.Reasoning)
			assert.GreaterOrEqual(t, rec.EstimatedCost, 0.0)
		}
	})
}

func TestToolRegistry_Enhanced(t *testing.T) {
	var testLogger *logger.Logger // nil logger for testing

	registry := NewToolRegistry(testLogger)

	// Create test tools
	securityTool := NewSecurityScannerTool(testLogger)
	pentestTool := NewPenetrationTesterTool(testLogger)

	// Create security policies
	securityPolicy := ToolSecurityPolicy{
		ID:               "security-policy",
		Name:             "Security Tool Policy",
		RequiredSecLevel: SecurityLevelHigh,
		Enabled:          true,
	}

	pentestPolicy := ToolSecurityPolicy{
		ID:               "pentest-policy",
		Name:             "Penetration Testing Policy",
		RequiredSecLevel: SecurityLevelCritical,
		AllowedUsers:     []string{"admin", "security-team"},
		Enabled:          true,
	}

	t.Run("register tools with categories", func(t *testing.T) {
		err := registry.RegisterToolWithCategory(securityTool, CategorySecurity, securityPolicy)
		assert.NoError(t, err)

		err = registry.RegisterToolWithCategory(pentestTool, CategoryPenetration, pentestPolicy)
		assert.NoError(t, err)
	})

	t.Run("get tools by category", func(t *testing.T) {
		securityTools := registry.GetToolsByCategory(CategorySecurity)
		assert.Len(t, securityTools, 1)
		assert.Equal(t, "security_scanner", securityTools[0].Name())

		pentestTools := registry.GetToolsByCategory(CategoryPenetration)
		assert.Len(t, pentestTools, 1)
		assert.Equal(t, "penetration_tester", pentestTools[0].Name())

		// Test non-existent category
		emptyTools := registry.GetToolsByCategory(CategoryGeneral)
		assert.Empty(t, emptyTools)
	})

	t.Run("tool validators", func(t *testing.T) {
		validator := NewSecurityToolValidator("test-validator", testLogger)

		err := registry.AddToolValidator("security_scanner", validator)
		assert.NoError(t, err)

		// Test duplicate validator
		err = registry.AddToolValidator("security_scanner", validator)
		assert.Error(t, err)

		// Test remove validator
		err = registry.RemoveToolValidator("security_scanner", "test-validator")
		assert.NoError(t, err)

		// Test remove non-existent validator
		err = registry.RemoveToolValidator("security_scanner", "non-existent")
		assert.Error(t, err)
	})

	t.Run("security policy management", func(t *testing.T) {
		newPolicy := ToolSecurityPolicy{
			ID:               "updated-policy",
			Name:             "Updated Security Policy",
			RequiredSecLevel: SecurityLevelMedium,
			Enabled:          true,
		}

		err := registry.UpdateSecurityPolicy("security_scanner", newPolicy)
		assert.NoError(t, err)

		// Test update policy for non-existent tool
		err = registry.UpdateSecurityPolicy("non-existent", newPolicy)
		assert.Error(t, err)
	})

	t.Run("execute with validation", func(t *testing.T) {
		input := map[string]interface{}{
			"target":    "localhost",
			"scan_type": "quick",
		}

		output, err := registry.ExecuteToolWithValidation(
			context.Background(),
			"security_scanner",
			input,
			"test-user",
			SecurityLevelHigh,
		)

		require.NoError(t, err)
		assert.NotNil(t, output)
		assert.Contains(t, output, "vulnerabilities")
		assert.Contains(t, output, "scan_summary")
	})

	t.Run("get categories", func(t *testing.T) {
		categories := registry.GetCategories()
		assert.Contains(t, categories, "security")
		assert.Contains(t, categories, "penetration")
	})
}

func TestSecurityToolValidator(t *testing.T) {
	var testLogger *logger.Logger // nil logger for testing

	validator := NewSecurityToolValidator("test-validator", testLogger)
	validator.SetAllowLocalhost(true)
	validator.SetAllowPrivateIPs(false)

	securityTool := NewSecurityScannerTool(testLogger)

	t.Run("valid target validation", func(t *testing.T) {
		input := map[string]interface{}{
			"target": "localhost",
		}

		err := validator.ValidateTool(context.Background(), securityTool, input)
		assert.NoError(t, err)
	})

	t.Run("invalid private IP", func(t *testing.T) {
		input := map[string]interface{}{
			"target": "192.168.1.1",
		}

		err := validator.ValidateTool(context.Background(), securityTool, input)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private IP")
	})

	t.Run("invalid scan intensity", func(t *testing.T) {
		pentestTool := NewPenetrationTesterTool(testLogger)
		input := map[string]interface{}{
			"target":    "localhost",
			"intensity": "aggressive",
		}

		err := validator.ValidateTool(context.Background(), pentestTool, input)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "intensity")
	})

	t.Run("output validation", func(t *testing.T) {
		validOutput := map[string]interface{}{
			"vulnerabilities": []interface{}{},
			"open_ports":      []interface{}{},
			"scan_summary":    map[string]interface{}{},
		}

		err := validator.ValidateOutput(context.Background(), securityTool, validOutput)
		assert.NoError(t, err)

		// Test missing required field
		invalidOutput := map[string]interface{}{
			"vulnerabilities": []interface{}{},
			// Missing open_ports and scan_summary
		}

		err = validator.ValidateOutput(context.Background(), securityTool, invalidOutput)
		assert.Error(t, err)
	})
}
