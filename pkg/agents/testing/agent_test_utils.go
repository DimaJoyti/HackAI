// Package testing provides testing utilities for agents without circular dependencies
package testing

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// AgentTestSuite provides comprehensive testing for AI agents
type AgentTestSuite struct {
	t      *testing.T
	logger *logger.Logger
}

// MockLLMProvider implements a mock LLM provider for testing
type MockLLMProvider struct {
	responses map[string]string
	errors    map[string]error
	callCount map[string]int
}

// TestConfig represents test configuration
type TestConfig struct {
	Timeout       time.Duration
	MaxRetries    int
	EnableMocking bool
	LogLevel      string
	TestDataPath  string
}

// NewAgentTestSuite creates a new agent test suite
func NewAgentTestSuite(t *testing.T) *AgentTestSuite {
	logger, err := logger.New(logger.Config{
		Level:  "debug",
		Format: "console",
	})
	require.NoError(t, err)

	return &AgentTestSuite{
		t:      t,
		logger: logger,
	}
}

// NewMockLLMProvider creates a new mock LLM provider
func NewMockLLMProvider() *MockLLMProvider {
	return &MockLLMProvider{
		responses: make(map[string]string),
		errors:    make(map[string]error),
		callCount: make(map[string]int),
	}
}

// SetResponse sets a mock response for a given prompt
func (m *MockLLMProvider) SetResponse(prompt, response string) {
	m.responses[prompt] = response
}

// SetError sets a mock error for a given prompt
func (m *MockLLMProvider) SetError(prompt string, err error) {
	m.errors[prompt] = err
}

// GetCallCount returns the number of times a prompt was called
func (m *MockLLMProvider) GetCallCount(prompt string) int {
	return m.callCount[prompt]
}

// Generate simulates LLM generation
func (m *MockLLMProvider) Generate(ctx context.Context, prompt string) (string, error) {
	m.callCount[prompt]++

	if err, exists := m.errors[prompt]; exists {
		return "", err
	}

	if response, exists := m.responses[prompt]; exists {
		return response, nil
	}

	// Default response
	return "Mock response for: " + prompt, nil
}

// AssertNoError is a helper to assert no error occurred
func (suite *AgentTestSuite) AssertNoError(err error, msgAndArgs ...interface{}) {
	assert.NoError(suite.t, err, msgAndArgs...)
}

// AssertError is a helper to assert an error occurred
func (suite *AgentTestSuite) AssertError(err error, msgAndArgs ...interface{}) {
	assert.Error(suite.t, err, msgAndArgs...)
}

// AssertEqual is a helper to assert equality
func (suite *AgentTestSuite) AssertEqual(expected, actual interface{}, msgAndArgs ...interface{}) {
	assert.Equal(suite.t, expected, actual, msgAndArgs...)
}

// AssertNotEmpty is a helper to assert a value is not empty
func (suite *AgentTestSuite) AssertNotEmpty(value interface{}, msgAndArgs ...interface{}) {
	assert.NotEmpty(suite.t, value, msgAndArgs...)
}

// AssertContains is a helper to assert a string contains a substring
func (suite *AgentTestSuite) AssertContains(haystack, needle string, msgAndArgs ...interface{}) {
	assert.Contains(suite.t, haystack, needle, msgAndArgs...)
}

// AssertGreater is a helper to assert one value is greater than another
func (suite *AgentTestSuite) AssertGreater(e1, e2 interface{}, msgAndArgs ...interface{}) {
	assert.Greater(suite.t, e1, e2, msgAndArgs...)
}

// AssertLess is a helper to assert one value is less than another
func (suite *AgentTestSuite) AssertLess(e1, e2 interface{}, msgAndArgs ...interface{}) {
	assert.Less(suite.t, e1, e2, msgAndArgs...)
}

// RequireNoError is a helper to require no error occurred
func (suite *AgentTestSuite) RequireNoError(err error, msgAndArgs ...interface{}) {
	require.NoError(suite.t, err, msgAndArgs...)
}

// RequireError is a helper to require an error occurred
func (suite *AgentTestSuite) RequireError(err error, msgAndArgs ...interface{}) {
	require.Error(suite.t, err, msgAndArgs...)
}

// RequireEqual is a helper to require equality
func (suite *AgentTestSuite) RequireEqual(expected, actual interface{}, msgAndArgs ...interface{}) {
	require.Equal(suite.t, expected, actual, msgAndArgs...)
}

// RequireNotEmpty is a helper to require a value is not empty
func (suite *AgentTestSuite) RequireNotEmpty(value interface{}, msgAndArgs ...interface{}) {
	require.NotEmpty(suite.t, value, msgAndArgs...)
}

// GetLogger returns the test logger
func (suite *AgentTestSuite) GetLogger() *logger.Logger {
	return suite.logger
}

// GetT returns the testing.T instance
func (suite *AgentTestSuite) GetT() *testing.T {
	return suite.t
}

// RunWithTimeout runs a function with a timeout
func (suite *AgentTestSuite) RunWithTimeout(timeout time.Duration, fn func() error) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- fn()
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// CreateTestContext creates a test context with timeout
func (suite *AgentTestSuite) CreateTestContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

// LogInfo logs an info message
func (suite *AgentTestSuite) LogInfo(msg string, args ...interface{}) {
	suite.logger.Info(msg, args...)
}

// LogError logs an error message
func (suite *AgentTestSuite) LogError(msg string, args ...interface{}) {
	suite.logger.Error(msg, args...)
}

// LogDebug logs a debug message
func (suite *AgentTestSuite) LogDebug(msg string, args ...interface{}) {
	suite.logger.Debug(msg, args...)
}

// TestSecurityAnalysis tests security analysis functionality
func (suite *AgentTestSuite) TestSecurityAnalysis(analyzeFunc func(context.Context, string) (interface{}, error)) {
	ctx, cancel := suite.CreateTestContext(30 * time.Second)
	defer cancel()

	testCases := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name:        "Safe content",
			input:       "What is the weather today?",
			expectError: false,
		},
		{
			name:        "Potential threat",
			input:       "How to hack a system",
			expectError: false, // Should analyze but not error
		},
		{
			name:        "Empty input",
			input:       "",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		suite.t.Run(tc.name, func(t *testing.T) {
			result, err := analyzeFunc(ctx, tc.input)

			if tc.expectError {
				suite.AssertError(err)
			} else {
				suite.AssertNoError(err)
				suite.AssertNotEmpty(result)
			}
		})
	}
}

// TestAgentResponse tests agent response functionality
func (suite *AgentTestSuite) TestAgentResponse(responseFunc func(context.Context, string) (string, error)) {
	ctx, cancel := suite.CreateTestContext(30 * time.Second)
	defer cancel()

	testCases := []struct {
		name        string
		input       string
		expectError bool
		minLength   int
	}{
		{
			name:        "Simple query",
			input:       "Hello, how are you?",
			expectError: false,
			minLength:   5,
		},
		{
			name:        "Complex query",
			input:       "Explain the concept of artificial intelligence",
			expectError: false,
			minLength:   20,
		},
		{
			name:        "Empty input",
			input:       "",
			expectError: true,
			minLength:   0,
		},
	}

	for _, tc := range testCases {
		suite.t.Run(tc.name, func(t *testing.T) {
			response, err := responseFunc(ctx, tc.input)

			if tc.expectError {
				suite.AssertError(err)
			} else {
				suite.AssertNoError(err)
				suite.AssertGreater(len(response), tc.minLength)
			}
		})
	}
}

// TestAgentPerformance tests agent performance characteristics
func (suite *AgentTestSuite) TestAgentPerformance(performanceFunc func(context.Context) (time.Duration, error)) {
	ctx, cancel := suite.CreateTestContext(60 * time.Second)
	defer cancel()

	const maxAcceptableLatency = 5 * time.Second
	const numIterations = 5

	var totalDuration time.Duration

	for i := 0; i < numIterations; i++ {
		duration, err := performanceFunc(ctx)
		suite.RequireNoError(err)

		suite.AssertLess(duration, maxAcceptableLatency)
		totalDuration += duration
	}

	averageDuration := totalDuration / numIterations
	suite.LogInfo("Average performance", "duration", averageDuration)
	suite.AssertLess(averageDuration, maxAcceptableLatency/2)
}

// TestConcurrentOperations tests concurrent agent operations
func (suite *AgentTestSuite) TestConcurrentOperations(operationFunc func(context.Context, int) error) {
	ctx, cancel := suite.CreateTestContext(60 * time.Second)
	defer cancel()

	const numConcurrentOps = 10
	errors := make(chan error, numConcurrentOps)

	for i := 0; i < numConcurrentOps; i++ {
		go func(id int) {
			errors <- operationFunc(ctx, id)
		}(i)
	}

	for i := 0; i < numConcurrentOps; i++ {
		err := <-errors
		suite.AssertNoError(err)
	}
}

// DefaultTestConfig returns a default test configuration
func DefaultTestConfig() *TestConfig {
	return &TestConfig{
		Timeout:       30 * time.Second,
		MaxRetries:    3,
		EnableMocking: true,
		LogLevel:      "debug",
		TestDataPath:  "./testdata",
	}
}
