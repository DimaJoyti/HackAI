package ai

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dimajoyti/hackai/pkg/logger"
)

func TestAdvancedChain_ExecuteWithContext(t *testing.T) {
	// Create a test logger (nil is fine for testing)
	var testLogger *logger.Logger

	// Create test configuration
	config := ChainConfig{
		ID:            "test-chain",
		Name:          "Test Chain",
		Description:   "Test chain for unit testing",
		Type:          ChainTypeSequential,
		Enabled:       true,
		MaxRetries:    3,
		Timeout:       30 * time.Second,
		SecurityLevel: SecurityLevelMedium,
	}

	// Create advanced chain
	chain := NewAdvancedChain(config, testLogger)
	require.NotNil(t, chain)

	// Test execution context
	execCtx := ChainExecutionContext{
		RequestID:     "test-request-123",
		UserID:        "test-user",
		SessionID:     "test-session",
		SecurityLevel: SecurityLevelMedium,
		StartTime:     time.Now(),
		Timeout:       30 * time.Second,
		Metadata:      map[string]interface{}{"test": true},
	}

	// Test input
	input := map[string]interface{}{
		"query": "test query",
		"data":  "test data",
	}

	t.Run("successful execution", func(t *testing.T) {
		result, err := chain.ExecuteWithContext(context.Background(), execCtx, input)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.NotNil(t, result.Output)
		assert.Greater(t, result.ExecutionTime, time.Duration(0))
		assert.NotNil(t, result.Steps)
		assert.NotNil(t, result.Metadata)
	})

	t.Run("execution with middleware", func(t *testing.T) {
		// Add security middleware
		securityMiddleware := NewSecurityMiddleware("test-security", SecurityLevelHigh, testLogger)
		err := chain.AddMiddleware(securityMiddleware)
		require.NoError(t, err)

		// Add metrics middleware
		metricsMiddleware := NewMetricsMiddleware("test-metrics", testLogger)
		err = chain.AddMiddleware(metricsMiddleware)
		require.NoError(t, err)

		result, err := chain.ExecuteWithContext(context.Background(), execCtx, input)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
	})

	t.Run("security level validation", func(t *testing.T) {
		// Create execution context with higher security level than middleware
		highSecExecCtx := execCtx
		highSecExecCtx.SecurityLevel = SecurityLevelCritical

		result, err := chain.ExecuteWithContext(context.Background(), highSecExecCtx, input)

		// Should fail due to security level mismatch
		require.Error(t, err)
		require.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Contains(t, err.Error(), "security level")
	})

	t.Run("async execution", func(t *testing.T) {
		resultChan, err := chain.ExecuteAsync(context.Background(), execCtx, input)
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
			_, err := chain.ExecuteWithContext(context.Background(), execCtx, input)
			require.NoError(t, err)
		}

		history := chain.GetExecutionHistory()
		assert.GreaterOrEqual(t, len(history), 3)
	})

	t.Run("middleware management", func(t *testing.T) {
		// Test adding duplicate middleware
		securityMiddleware := NewSecurityMiddleware("test-security", SecurityLevelMedium, testLogger)
		err := chain.AddMiddleware(securityMiddleware)
		assert.Error(t, err) // Should fail because middleware with same ID already exists

		// Test removing middleware
		err = chain.RemoveMiddleware("test-security")
		assert.NoError(t, err)

		// Test removing non-existent middleware
		err = chain.RemoveMiddleware("non-existent")
		assert.Error(t, err)
	})
}

func TestSecurityMiddleware(t *testing.T) {
	var testLogger *logger.Logger // nil logger for testing
	middleware := NewSecurityMiddleware("test-security", SecurityLevelHigh, testLogger)

	execCtx := ChainExecutionContext{
		SecurityLevel: SecurityLevelMedium,
	}

	t.Run("valid input", func(t *testing.T) {
		input := map[string]interface{}{
			"query": "test query",
			"data":  123,
		}

		err := middleware.PreExecute(context.Background(), execCtx, input)
		assert.NoError(t, err)
	})

	t.Run("security level validation", func(t *testing.T) {
		highSecExecCtx := ChainExecutionContext{
			SecurityLevel: SecurityLevelCritical,
		}

		input := map[string]interface{}{
			"query": "test query",
		}

		err := middleware.PreExecute(context.Background(), highSecExecCtx, input)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "security level")
	})

	t.Run("input size validation", func(t *testing.T) {
		// Create large input
		largeData := make([]byte, 2*1024*1024) // 2MB
		input := map[string]interface{}{
			"large_data": string(largeData),
		}

		err := middleware.PreExecute(context.Background(), execCtx, input)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "input size")
	})

	t.Run("injection pattern detection", func(t *testing.T) {
		input := map[string]interface{}{
			"query": "test <script>alert('xss')</script>",
		}

		err := middleware.PreExecute(context.Background(), execCtx, input)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "suspicious pattern")
	})

	t.Run("post execution validation", func(t *testing.T) {
		result := &ChainExecutionResult{
			Success: true,
			Output: map[string]interface{}{
				"result": "test result",
			},
		}

		err := middleware.PostExecute(context.Background(), execCtx, result)
		assert.NoError(t, err)
	})

	t.Run("sensitive data detection", func(t *testing.T) {
		result := &ChainExecutionResult{
			Success: true,
			Output: map[string]interface{}{
				"password": "secret123",
			},
		}

		err := middleware.PostExecute(context.Background(), execCtx, result)
		// Should not fail execution but log warning
		assert.NoError(t, err)
	})
}

func TestMetricsMiddleware(t *testing.T) {
	var testLogger *logger.Logger // nil logger for testing
	middleware := NewMetricsMiddleware("test-metrics", testLogger)

	execCtx := ChainExecutionContext{
		RequestID: "test-request",
		UserID:    "test-user",
	}

	t.Run("pre execution metrics", func(t *testing.T) {
		input := map[string]interface{}{
			"query": "test query",
		}

		err := middleware.PreExecute(context.Background(), execCtx, input)
		assert.NoError(t, err)
	})

	t.Run("post execution metrics", func(t *testing.T) {
		result := &ChainExecutionResult{
			Success:       true,
			ExecutionTime: 100 * time.Millisecond,
			TokensUsed:    50,
			Cost:          0.01,
			Steps:         []ChainExecutionStep{{StepID: "step1"}},
		}

		err := middleware.PostExecute(context.Background(), execCtx, result)
		assert.NoError(t, err)
	})
}

func TestChainInputValidation(t *testing.T) {
	var testLogger *logger.Logger // nil logger for testing

	config := ChainConfig{
		ID:            "test-chain",
		Name:          "Test Chain",
		SecurityLevel: SecurityLevelMedium,
	}

	chain := NewAdvancedChain(config, testLogger)

	t.Run("valid input", func(t *testing.T) {
		input := map[string]interface{}{
			"query": "test query",
			"data":  123,
		}

		err := chain.ValidateInput(input)
		assert.NoError(t, err)
	})

	t.Run("nil input", func(t *testing.T) {
		err := chain.ValidateInput(nil)
		assert.NoError(t, err) // Should pass when no validator is set
	})
}

// MockChainInputValidator for testing
type MockChainInputValidator struct {
	shouldFail bool
}

func (v *MockChainInputValidator) Validate(input map[string]interface{}) error {
	if v.shouldFail {
		return fmt.Errorf("validation failed")
	}
	return nil
}

func TestChainWithValidator(t *testing.T) {
	var testLogger *logger.Logger // nil logger for testing

	config := ChainConfig{
		ID:            "test-chain",
		Name:          "Test Chain",
		SecurityLevel: SecurityLevelMedium,
	}

	chain := NewAdvancedChain(config, testLogger)

	// Set a mock validator
	validator := &MockChainInputValidator{shouldFail: true}
	chain.validator = validator

	execCtx := ChainExecutionContext{
		RequestID:     "test-request",
		SecurityLevel: SecurityLevelMedium,
		StartTime:     time.Now(),
	}

	input := map[string]interface{}{
		"query": "test query",
	}

	t.Run("validation failure", func(t *testing.T) {
		result, err := chain.ExecuteWithContext(context.Background(), execCtx, input)

		require.Error(t, err)
		require.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Contains(t, err.Error(), "validation failed")
	})

	t.Run("validation success", func(t *testing.T) {
		validator.shouldFail = false

		result, err := chain.ExecuteWithContext(context.Background(), execCtx, input)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
	})
}
