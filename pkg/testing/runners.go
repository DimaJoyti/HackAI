package testing

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// UnitTestRunner executes unit tests
type UnitTestRunner struct {
	logger *logger.Logger
}

// IntegrationTestRunner executes integration tests
type IntegrationTestRunner struct {
	logger *logger.Logger
}

// SecurityTestRunner executes security tests
type SecurityTestRunner struct {
	logger *logger.Logger
}

// PerformanceTestRunner executes performance tests
type PerformanceTestRunner struct {
	logger *logger.Logger
}

// AssertionHelper provides assertion utilities for tests
type AssertionHelper struct {
	testContext *TestContext
	results     []*AssertionResult
	mu          sync.Mutex
}

// AssertionResult represents the result of an assertion
type AssertionResult struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Expected    interface{} `json:"expected"`
	Actual      interface{} `json:"actual"`
	Passed      bool        `json:"passed"`
	Message     string      `json:"message"`
	Timestamp   time.Time   `json:"timestamp"`
}

// MockManager manages test mocks
type MockManager struct {
	mocks map[string]interface{}
	mu    sync.RWMutex
}

// FixtureManager manages test fixtures
type FixtureManager struct {
	fixtures map[string]interface{}
	mu       sync.RWMutex
}

// CoverageInfo represents code coverage information
type CoverageInfo struct {
	TotalLines       int                `json:"total_lines"`
	CoveredLines     int                `json:"covered_lines"`
	CoverageRate     float64            `json:"coverage_rate"`
	PackageCoverage  map[string]float64 `json:"package_coverage"`
	FileCoverage     map[string]float64 `json:"file_coverage"`
	FunctionCoverage map[string]float64 `json:"function_coverage"`
	UncoveredLines   []string           `json:"uncovered_lines"`
}

// UnitTestRunner implementation

// Run executes unit tests
func (utr *UnitTestRunner) Run(ctx context.Context, suite *TestSuite) (*SuiteResult, error) {
	utr.logger.WithField("suite", suite.Name).Info("Running unit test suite")

	startTime := time.Now()
	result := &SuiteResult{
		SuiteID:     suite.ID,
		Name:        suite.Name,
		Status:      TestStatusRunning,
		StartTime:   startTime,
		TestResults: make([]*TestResult, 0, len(suite.Tests)),
		Metadata:    make(map[string]interface{}),
	}

	// Setup suite
	if suite.SetupFunc != nil {
		if err := suite.SetupFunc(); err != nil {
			utr.logger.WithError(err).Error("Suite setup failed")
			result.Status = TestStatusError
			return result, fmt.Errorf("suite setup failed: %w", err)
		}
	}

	// Execute tests
	if suite.Parallel {
		utr.runTestsParallel(ctx, suite, result)
	} else {
		utr.runTestsSequential(ctx, suite, result)
	}

	// Teardown suite
	if suite.TeardownFunc != nil {
		if err := suite.TeardownFunc(); err != nil {
			utr.logger.WithError(err).Error("Suite teardown failed")
		}
	}

	// Calculate final results
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Summary = utr.calculateSummary(result.TestResults)
	result.Status = utr.determineSuiteStatus(result.TestResults)

	return result, nil
}

// CanHandle returns true if this runner can handle the test type
func (utr *UnitTestRunner) CanHandle(testType string) bool {
	return testType == "unit" || testType == "unittest"
}

// GetName returns the runner name
func (utr *UnitTestRunner) GetName() string {
	return "unit_test_runner"
}

// runTestsSequential runs tests sequentially
func (utr *UnitTestRunner) runTestsSequential(ctx context.Context, suite *TestSuite, result *SuiteResult) {
	for _, test := range suite.Tests {
		testResult := utr.runSingleTest(ctx, test, suite)
		result.TestResults = append(result.TestResults, testResult)
	}
}

// runTestsParallel runs tests in parallel
func (utr *UnitTestRunner) runTestsParallel(ctx context.Context, suite *TestSuite, result *SuiteResult) {
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, test := range suite.Tests {
		wg.Add(1)
		go func(t *Test) {
			defer wg.Done()
			testResult := utr.runSingleTest(ctx, t, suite)

			mu.Lock()
			result.TestResults = append(result.TestResults, testResult)
			mu.Unlock()
		}(test)
	}

	wg.Wait()
}

// runSingleTest executes a single test
func (utr *UnitTestRunner) runSingleTest(ctx context.Context, test *Test, suite *TestSuite) *TestResult {
	startTime := time.Now()

	testResult := &TestResult{
		TestID:     test.ID,
		SuiteID:    suite.ID,
		Name:       test.Name,
		Status:     TestStatusRunning,
		StartTime:  startTime,
		Logs:       []string{},
		Assertions: []*AssertionResult{},
		Metadata:   make(map[string]interface{}),
	}

	// Create test context
	testCtx, cancel := context.WithTimeout(ctx, test.Timeout)
	defer cancel()

	testContext := &TestContext{
		TestID:     test.ID,
		SuiteID:    suite.ID,
		Logger:     utr.logger,
		StartTime:  startTime,
		Timeout:    test.Timeout,
		Data:       make(map[string]interface{}),
		Assertions: NewAssertionHelper(testResult),
		Mocks:      NewMockManager(),
		Fixtures:   NewFixtureManager(),
		Context:    testCtx,
		Cancel:     cancel,
	}

	// Setup test
	if test.SetupFunc != nil {
		if err := test.SetupFunc(testContext); err != nil {
			testResult.Status = TestStatusError
			testResult.Error = fmt.Sprintf("Test setup failed: %v", err)
			testResult.EndTime = time.Now()
			testResult.Duration = testResult.EndTime.Sub(testResult.StartTime)
			return testResult
		}
	}

	// Execute test with retry logic
	var testErr error
	for attempt := 0; attempt <= test.Retries; attempt++ {
		if attempt > 0 {
			utr.logger.WithFields(map[string]interface{}{
				"test":    test.Name,
				"attempt": attempt + 1,
			}).Info("Retrying test")
		}

		testErr = test.TestFunc(testContext)
		if testErr == nil {
			break
		}
	}

	// Teardown test
	if test.TeardownFunc != nil {
		if err := test.TeardownFunc(testContext); err != nil {
			utr.logger.WithError(err).Error("Test teardown failed")
		}
	}

	// Set final result
	testResult.EndTime = time.Now()
	testResult.Duration = testResult.EndTime.Sub(testResult.StartTime)
	testResult.Assertions = testContext.Assertions.GetResults()

	if testErr != nil {
		testResult.Status = TestStatusFailed
		testResult.Error = testErr.Error()
	} else if utr.hasFailedAssertions(testResult.Assertions) {
		testResult.Status = TestStatusFailed
		testResult.Error = "One or more assertions failed"
	} else {
		testResult.Status = TestStatusPassed
	}

	return testResult
}

// hasFailedAssertions checks if any assertions failed
func (utr *UnitTestRunner) hasFailedAssertions(assertions []*AssertionResult) bool {
	for _, assertion := range assertions {
		if !assertion.Passed {
			return true
		}
	}
	return false
}

// calculateSummary calculates test summary
func (utr *UnitTestRunner) calculateSummary(testResults []*TestResult) *TestSummary {
	summary := &TestSummary{}

	var totalDuration time.Duration
	for _, result := range testResults {
		summary.TotalTests++
		totalDuration += result.Duration

		switch result.Status {
		case TestStatusPassed:
			summary.PassedTests++
		case TestStatusFailed:
			summary.FailedTests++
		case TestStatusSkipped:
			summary.SkippedTests++
		case TestStatusTimeout:
			summary.TimeoutTests++
		case TestStatusError:
			summary.ErrorTests++
		}
	}

	summary.TotalDuration = totalDuration
	if summary.TotalTests > 0 {
		summary.AverageDuration = totalDuration / time.Duration(summary.TotalTests)
		summary.SuccessRate = float64(summary.PassedTests) / float64(summary.TotalTests) * 100
	}

	return summary
}

// determineSuiteStatus determines the overall suite status
func (utr *UnitTestRunner) determineSuiteStatus(testResults []*TestResult) TestStatus {
	hasFailures := false
	hasErrors := false

	for _, result := range testResults {
		switch result.Status {
		case TestStatusFailed:
			hasFailures = true
		case TestStatusError:
			hasErrors = true
		}
	}

	if hasErrors {
		return TestStatusError
	} else if hasFailures {
		return TestStatusFailed
	}

	return TestStatusPassed
}

// IntegrationTestRunner implementation

// Run executes integration tests
func (itr *IntegrationTestRunner) Run(ctx context.Context, suite *TestSuite) (*SuiteResult, error) {
	itr.logger.WithField("suite", suite.Name).Info("Running integration test suite")

	// Integration tests typically run sequentially due to shared resources
	unitRunner := &UnitTestRunner{logger: itr.logger}
	return unitRunner.Run(ctx, suite)
}

// CanHandle returns true if this runner can handle the test type
func (itr *IntegrationTestRunner) CanHandle(testType string) bool {
	return testType == "integration" || testType == "integrationtest"
}

// GetName returns the runner name
func (itr *IntegrationTestRunner) GetName() string {
	return "integration_test_runner"
}

// SecurityTestRunner implementation

// Run executes security tests
func (str *SecurityTestRunner) Run(ctx context.Context, suite *TestSuite) (*SuiteResult, error) {
	str.logger.WithField("suite", suite.Name).Info("Running security test suite")

	unitRunner := &UnitTestRunner{logger: str.logger}
	result, err := unitRunner.Run(ctx, suite)

	if err != nil {
		return result, err
	}

	// Add security-specific processing
	str.addSecurityMetrics(result)

	return result, nil
}

// CanHandle returns true if this runner can handle the test type
func (str *SecurityTestRunner) CanHandle(testType string) bool {
	return testType == "security" || testType == "securitytest"
}

// GetName returns the runner name
func (str *SecurityTestRunner) GetName() string {
	return "security_test_runner"
}

// addSecurityMetrics adds security-specific metrics to the result
func (str *SecurityTestRunner) addSecurityMetrics(result *SuiteResult) {
	// Add security-specific metadata
	result.Metadata["security_checks"] = len(result.TestResults)
	result.Metadata["vulnerability_tests"] = 0
	result.Metadata["compliance_tests"] = 0

	for _, testResult := range result.TestResults {
		if testResult.Metadata == nil {
			testResult.Metadata = make(map[string]interface{})
		}
		testResult.Metadata["security_test"] = true
	}
}

// PerformanceTestRunner implementation

// Run executes performance tests
func (ptr *PerformanceTestRunner) Run(ctx context.Context, suite *TestSuite) (*SuiteResult, error) {
	ptr.logger.WithField("suite", suite.Name).Info("Running performance test suite")

	unitRunner := &UnitTestRunner{logger: ptr.logger}
	result, err := unitRunner.Run(ctx, suite)

	if err != nil {
		return result, err
	}

	// Add performance-specific processing
	ptr.addPerformanceMetrics(result)

	return result, nil
}

// CanHandle returns true if this runner can handle the test type
func (ptr *PerformanceTestRunner) CanHandle(testType string) bool {
	return testType == "performance" || testType == "performancetest" || testType == "load"
}

// GetName returns the runner name
func (ptr *PerformanceTestRunner) GetName() string {
	return "performance_test_runner"
}

// addPerformanceMetrics adds performance-specific metrics to the result
func (ptr *PerformanceTestRunner) addPerformanceMetrics(result *SuiteResult) {
	// Calculate performance metrics
	var totalDuration time.Duration
	var maxDuration time.Duration
	var minDuration time.Duration = time.Hour // Initialize to a large value

	for _, testResult := range result.TestResults {
		totalDuration += testResult.Duration
		if testResult.Duration > maxDuration {
			maxDuration = testResult.Duration
		}
		if testResult.Duration < minDuration {
			minDuration = testResult.Duration
		}

		if testResult.Metadata == nil {
			testResult.Metadata = make(map[string]interface{})
		}
		testResult.Metadata["performance_test"] = true
	}

	// Add performance metadata
	result.Metadata["total_duration"] = totalDuration
	result.Metadata["max_duration"] = maxDuration
	result.Metadata["min_duration"] = minDuration
	if len(result.TestResults) > 0 {
		result.Metadata["avg_duration"] = totalDuration / time.Duration(len(result.TestResults))
	}
}

// AssertionHelper implementation

// NewAssertionHelper creates a new assertion helper
func NewAssertionHelper(testResult *TestResult) *AssertionHelper {
	return &AssertionHelper{
		results: []*AssertionResult{},
	}
}

// Equal asserts that two values are equal
func (ah *AssertionHelper) Equal(expected, actual interface{}, description string) {
	ah.mu.Lock()
	defer ah.mu.Unlock()

	passed := expected == actual
	result := &AssertionResult{
		Type:        "equal",
		Description: description,
		Expected:    expected,
		Actual:      actual,
		Passed:      passed,
		Timestamp:   time.Now(),
	}

	if !passed {
		result.Message = fmt.Sprintf("Expected %v, but got %v", expected, actual)
	}

	ah.results = append(ah.results, result)
}

// NotEqual asserts that two values are not equal
func (ah *AssertionHelper) NotEqual(expected, actual interface{}, description string) {
	ah.mu.Lock()
	defer ah.mu.Unlock()

	passed := expected != actual
	result := &AssertionResult{
		Type:        "not_equal",
		Description: description,
		Expected:    expected,
		Actual:      actual,
		Passed:      passed,
		Timestamp:   time.Now(),
	}

	if !passed {
		result.Message = fmt.Sprintf("Expected %v to not equal %v", actual, expected)
	}

	ah.results = append(ah.results, result)
}

// True asserts that a value is true
func (ah *AssertionHelper) True(value bool, description string) {
	ah.Equal(true, value, description)
}

// False asserts that a value is false
func (ah *AssertionHelper) False(value bool, description string) {
	ah.Equal(false, value, description)
}

// Nil asserts that a value is nil
func (ah *AssertionHelper) Nil(value interface{}, description string) {
	ah.Equal(nil, value, description)
}

// NotNil asserts that a value is not nil
func (ah *AssertionHelper) NotNil(value interface{}, description string) {
	ah.NotEqual(nil, value, description)
}

// GetResults returns all assertion results
func (ah *AssertionHelper) GetResults() []*AssertionResult {
	ah.mu.Lock()
	defer ah.mu.Unlock()

	results := make([]*AssertionResult, len(ah.results))
	copy(results, ah.results)
	return results
}

// MockManager implementation

// NewMockManager creates a new mock manager
func NewMockManager() *MockManager {
	return &MockManager{
		mocks: make(map[string]interface{}),
	}
}

// Register registers a mock
func (mm *MockManager) Register(name string, mock interface{}) {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	mm.mocks[name] = mock
}

// Get retrieves a mock
func (mm *MockManager) Get(name string) (interface{}, bool) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()
	mock, exists := mm.mocks[name]
	return mock, exists
}

// Clear clears all mocks
func (mm *MockManager) Clear() {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	mm.mocks = make(map[string]interface{})
}

// FixtureManager implementation

// NewFixtureManager creates a new fixture manager
func NewFixtureManager() *FixtureManager {
	return &FixtureManager{
		fixtures: make(map[string]interface{}),
	}
}

// Load loads a fixture
func (fm *FixtureManager) Load(name string, fixture interface{}) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.fixtures[name] = fixture
}

// Get retrieves a fixture
func (fm *FixtureManager) Get(name string) (interface{}, bool) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	fixture, exists := fm.fixtures[name]
	return fixture, exists
}

// Clear clears all fixtures
func (fm *FixtureManager) Clear() {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.fixtures = make(map[string]interface{})
}
