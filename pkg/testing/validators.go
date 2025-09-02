package testing

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// TestStructureValidator validates test structure and configuration
type TestStructureValidator struct{}

// SecurityTestValidator validates security test configuration
type SecurityTestValidator struct{}

// PerformanceTestValidator validates performance test configuration
type PerformanceTestValidator struct{}

// TestStructureValidator implementation

// Validate validates test structure
func (tsv *TestStructureValidator) Validate(test *Test) error {
	if test == nil {
		return fmt.Errorf("test cannot be nil")
	}

	// Validate required fields
	if test.ID == "" {
		return fmt.Errorf("test ID is required")
	}

	if test.Name == "" {
		return fmt.Errorf("test name is required")
	}

	if test.TestFunc == nil {
		return fmt.Errorf("test function is required")
	}

	// Validate test ID format
	if !isValidTestID(test.ID) {
		return fmt.Errorf("test ID must be alphanumeric with hyphens and underscores only")
	}

	// Validate test name
	if len(test.Name) > 100 {
		return fmt.Errorf("test name must be 100 characters or less")
	}

	// Validate timeout
	if test.Timeout <= 0 {
		test.Timeout = 5 * time.Minute // Set default timeout
	}

	if test.Timeout > 30*time.Minute {
		return fmt.Errorf("test timeout cannot exceed 30 minutes")
	}

	// Validate retries
	if test.Retries < 0 {
		return fmt.Errorf("test retries cannot be negative")
	}

	if test.Retries > 5 {
		return fmt.Errorf("test retries cannot exceed 5")
	}

	// Validate tags
	for _, tag := range test.Tags {
		if !isValidTag(tag) {
			return fmt.Errorf("invalid tag format: %s", tag)
		}
	}

	// Validate dependencies
	for _, dep := range test.Dependencies {
		if dep == "" {
			return fmt.Errorf("dependency cannot be empty")
		}
	}

	return nil
}

// GetType returns the validator type
func (tsv *TestStructureValidator) GetType() string {
	return "structure"
}

// SecurityTestValidator implementation

// Validate validates security test configuration
func (stv *SecurityTestValidator) Validate(test *Test) error {
	// Only validate security tests
	if test.Type != "security" && test.Category != "security" {
		return nil
	}

	// Security tests must have specific tags
	hasSecurityTag := false
	for _, tag := range test.Tags {
		if strings.HasPrefix(tag, "security:") {
			hasSecurityTag = true
			break
		}
	}

	if !hasSecurityTag {
		return fmt.Errorf("security tests must have at least one security: tag")
	}

	// Security tests should have longer timeouts
	if test.Timeout < 2*time.Minute {
		return fmt.Errorf("security tests should have timeout of at least 2 minutes")
	}

	// Validate security-specific metadata
	if test.Metadata != nil {
		if severity, exists := test.Metadata["severity"]; exists {
			if !isValidSeverity(severity.(string)) {
				return fmt.Errorf("invalid security severity: %v", severity)
			}
		}

		if vulnType, exists := test.Metadata["vulnerability_type"]; exists {
			if !isValidVulnerabilityType(vulnType.(string)) {
				return fmt.Errorf("invalid vulnerability type: %v", vulnType)
			}
		}
	}

	return nil
}

// GetType returns the validator type
func (stv *SecurityTestValidator) GetType() string {
	return "security"
}

// PerformanceTestValidator implementation

// Validate validates performance test configuration
func (ptv *PerformanceTestValidator) Validate(test *Test) error {
	// Only validate performance tests
	if test.Type != "performance" && test.Category != "performance" {
		return nil
	}

	// Performance tests must have specific tags
	hasPerformanceTag := false
	for _, tag := range test.Tags {
		if strings.HasPrefix(tag, "performance:") || strings.HasPrefix(tag, "load:") {
			hasPerformanceTag = true
			break
		}
	}

	if !hasPerformanceTag {
		return fmt.Errorf("performance tests must have at least one performance: or load: tag")
	}

	// Performance tests should have longer timeouts
	if test.Timeout < 5*time.Minute {
		return fmt.Errorf("performance tests should have timeout of at least 5 minutes")
	}

	// Validate performance-specific metadata
	if test.Metadata != nil {
		if loadType, exists := test.Metadata["load_type"]; exists {
			if !isValidLoadType(loadType.(string)) {
				return fmt.Errorf("invalid load type: %v", loadType)
			}
		}

		if expectedThroughput, exists := test.Metadata["expected_throughput"]; exists {
			if throughput, ok := expectedThroughput.(float64); ok {
				if throughput <= 0 {
					return fmt.Errorf("expected throughput must be positive")
				}
			}
		}

		if maxResponseTime, exists := test.Metadata["max_response_time"]; exists {
			if responseTime, ok := maxResponseTime.(string); ok {
				if _, err := time.ParseDuration(responseTime); err != nil {
					return fmt.Errorf("invalid max response time format: %v", responseTime)
				}
			}
		}
	}

	return nil
}

// GetType returns the validator type
func (ptv *PerformanceTestValidator) GetType() string {
	return "performance"
}

// Helper functions

// isValidTestID validates test ID format
func isValidTestID(id string) bool {
	// Test ID should be alphanumeric with hyphens and underscores
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, id)
	return matched && len(id) > 0 && len(id) <= 50
}

// isValidTag validates tag format
func isValidTag(tag string) bool {
	// Tags should be lowercase alphanumeric with colons, hyphens, and underscores
	matched, _ := regexp.MatchString(`^[a-z0-9:_-]+$`, tag)
	return matched && len(tag) > 0 && len(tag) <= 30
}

// isValidSeverity validates security severity levels
func isValidSeverity(severity string) bool {
	validSeverities := []string{"low", "medium", "high", "critical"}
	for _, valid := range validSeverities {
		if severity == valid {
			return true
		}
	}
	return false
}

// isValidVulnerabilityType validates vulnerability types
func isValidVulnerabilityType(vulnType string) bool {
	validTypes := []string{
		"injection", "broken_auth", "sensitive_data", "xxe", "broken_access",
		"security_misconfig", "xss", "insecure_deserialization", "known_vulns",
		"insufficient_logging", "prompt_injection", "model_extraction",
		"data_poisoning", "adversarial_attack", "privacy_leak",
	}
	for _, valid := range validTypes {
		if vulnType == valid {
			return true
		}
	}
	return false
}

// isValidLoadType validates performance load types
func isValidLoadType(loadType string) bool {
	validTypes := []string{"load", "stress", "spike", "volume", "endurance"}
	for _, valid := range validTypes {
		if loadType == valid {
			return true
		}
	}
	return false
}

// TestSuiteValidator validates entire test suites
type TestSuiteValidator struct {
	validators []Validator
}

// NewTestSuiteValidator creates a new test suite validator
func NewTestSuiteValidator() *TestSuiteValidator {
	return &TestSuiteValidator{
		validators: []Validator{
			&TestStructureValidator{},
			&SecurityTestValidator{},
			&PerformanceTestValidator{},
		},
	}
}

// ValidateSuite validates an entire test suite
func (tsv *TestSuiteValidator) ValidateSuite(suite *TestSuite) error {
	if suite == nil {
		return fmt.Errorf("test suite cannot be nil")
	}

	// Validate suite structure
	if suite.ID == "" {
		return fmt.Errorf("suite ID is required")
	}

	if suite.Name == "" {
		return fmt.Errorf("suite name is required")
	}

	if len(suite.Tests) == 0 {
		return fmt.Errorf("suite must contain at least one test")
	}

	// Validate suite timeout
	if suite.Timeout > 0 && suite.Timeout > 2*time.Hour {
		return fmt.Errorf("suite timeout cannot exceed 2 hours")
	}

	// Validate test dependencies within suite
	testIDs := make(map[string]bool)
	for _, test := range suite.Tests {
		testIDs[test.ID] = true
	}

	for _, test := range suite.Tests {
		for _, dep := range test.Dependencies {
			if !testIDs[dep] {
				return fmt.Errorf("test %s depends on %s which is not in this suite", test.ID, dep)
			}
		}
	}

	// Validate individual tests
	for _, test := range suite.Tests {
		for _, validator := range tsv.validators {
			if err := validator.Validate(test); err != nil {
				return fmt.Errorf("test %s validation failed: %w", test.Name, err)
			}
		}
	}

	// Validate suite-specific constraints
	if err := tsv.validateSuiteConstraints(suite); err != nil {
		return err
	}

	return nil
}

// validateSuiteConstraints validates suite-specific constraints
func (tsv *TestSuiteValidator) validateSuiteConstraints(suite *TestSuite) error {
	// Check for duplicate test IDs
	testIDs := make(map[string]bool)
	for _, test := range suite.Tests {
		if testIDs[test.ID] {
			return fmt.Errorf("duplicate test ID: %s", test.ID)
		}
		testIDs[test.ID] = true
	}

	// Check for duplicate test names
	testNames := make(map[string]bool)
	for _, test := range suite.Tests {
		if testNames[test.Name] {
			return fmt.Errorf("duplicate test name: %s", test.Name)
		}
		testNames[test.Name] = true
	}

	// Validate parallel execution constraints
	if suite.Parallel {
		// Check that parallel tests don't have conflicting dependencies
		for _, test := range suite.Tests {
			if len(test.Dependencies) > 0 {
				return fmt.Errorf("test %s has dependencies but suite is configured for parallel execution", test.Name)
			}
		}
	}

	// Validate category consistency
	categories := make(map[string]int)
	for _, test := range suite.Tests {
		categories[test.Category]++
	}

	// If suite has a specific category, all tests should match
	if suite.Category != "" {
		for _, test := range suite.Tests {
			if test.Category != suite.Category {
				return fmt.Errorf("test %s category (%s) doesn't match suite category (%s)",
					test.Name, test.Category, suite.Category)
			}
		}
	}

	return nil
}

// TestConfigValidator validates test framework configuration
type TestConfigValidator struct{}

// ValidateConfig validates test framework configuration
func (tcv *TestConfigValidator) ValidateConfig(config *TestConfig) error {
	if config == nil {
		return fmt.Errorf("test config cannot be nil")
	}

	// Validate concurrent test limits
	if config.MaxConcurrentTests <= 0 {
		return fmt.Errorf("max concurrent tests must be positive")
	}

	if config.MaxConcurrentTests > 100 {
		return fmt.Errorf("max concurrent tests cannot exceed 100")
	}

	// Validate timeout
	if config.TestTimeout <= 0 {
		return fmt.Errorf("test timeout must be positive")
	}

	if config.TestTimeout > 1*time.Hour {
		return fmt.Errorf("test timeout cannot exceed 1 hour")
	}

	// Validate output directory
	if config.OutputDirectory == "" {
		return fmt.Errorf("output directory is required")
	}

	// Validate report formats
	validFormats := map[string]bool{
		"json": true, "html": true, "junit": true, "console": true,
	}

	for _, format := range config.ReportFormats {
		if !validFormats[format] {
			return fmt.Errorf("invalid report format: %s", format)
		}
	}

	return nil
}

// TestEnvironmentValidator validates test environment setup
type TestEnvironmentValidator struct{}

// ValidateEnvironment validates test environment
func (tev *TestEnvironmentValidator) ValidateEnvironment(env *TestEnvironment) error {
	if env == nil {
		return fmt.Errorf("test environment cannot be nil")
	}

	// Validate required fields
	if env.Platform == "" {
		return fmt.Errorf("platform is required")
	}

	if env.Architecture == "" {
		return fmt.Errorf("architecture is required")
	}

	if env.GoVersion == "" {
		return fmt.Errorf("Go version is required")
	}

	// Validate Go version format
	if !isValidGoVersion(env.GoVersion) {
		return fmt.Errorf("invalid Go version format: %s", env.GoVersion)
	}

	// Validate environment variables
	for key, value := range env.Variables {
		if key == "" {
			return fmt.Errorf("environment variable key cannot be empty")
		}
		if strings.Contains(key, " ") {
			return fmt.Errorf("environment variable key cannot contain spaces: %s", key)
		}
		if len(value) > 1000 {
			return fmt.Errorf("environment variable value too long: %s", key)
		}
	}

	return nil
}

// isValidGoVersion validates Go version format
func isValidGoVersion(version string) bool {
	// Go version should be in format like "1.21", "1.21.0", etc.
	matched, _ := regexp.MatchString(`^1\.\d+(\.\d+)?$`, version)
	return matched
}

// ComprehensiveValidator combines all validators
type ComprehensiveValidator struct {
	structureValidator   *TestStructureValidator
	securityValidator    *SecurityTestValidator
	performanceValidator *PerformanceTestValidator
	suiteValidator       *TestSuiteValidator
	configValidator      *TestConfigValidator
	environmentValidator *TestEnvironmentValidator
}

// NewComprehensiveValidator creates a new comprehensive validator
func NewComprehensiveValidator() *ComprehensiveValidator {
	return &ComprehensiveValidator{
		structureValidator:   &TestStructureValidator{},
		securityValidator:    &SecurityTestValidator{},
		performanceValidator: &PerformanceTestValidator{},
		suiteValidator:       NewTestSuiteValidator(),
		configValidator:      &TestConfigValidator{},
		environmentValidator: &TestEnvironmentValidator{},
	}
}

// ValidateAll validates all aspects of the test framework
func (cv *ComprehensiveValidator) ValidateAll(config *TestConfig, env *TestEnvironment, suites []*TestSuite) error {
	// Validate configuration
	if err := cv.configValidator.ValidateConfig(config); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	// Validate environment
	if err := cv.environmentValidator.ValidateEnvironment(env); err != nil {
		return fmt.Errorf("environment validation failed: %w", err)
	}

	// Validate test suites
	for _, suite := range suites {
		if err := cv.suiteValidator.ValidateSuite(suite); err != nil {
			return fmt.Errorf("suite %s validation failed: %w", suite.Name, err)
		}
	}

	// Cross-suite validation
	if err := cv.validateCrossSuite(suites); err != nil {
		return fmt.Errorf("cross-suite validation failed: %w", err)
	}

	return nil
}

// validateCrossSuite validates constraints across multiple test suites
func (cv *ComprehensiveValidator) validateCrossSuite(suites []*TestSuite) error {
	// Check for duplicate suite IDs
	suiteIDs := make(map[string]bool)
	for _, suite := range suites {
		if suiteIDs[suite.ID] {
			return fmt.Errorf("duplicate suite ID: %s", suite.ID)
		}
		suiteIDs[suite.ID] = true
	}

	// Check for duplicate suite names
	suiteNames := make(map[string]bool)
	for _, suite := range suites {
		if suiteNames[suite.Name] {
			return fmt.Errorf("duplicate suite name: %s", suite.Name)
		}
		suiteNames[suite.Name] = true
	}

	// Validate cross-suite dependencies
	allTestIDs := make(map[string]string) // testID -> suiteID
	for _, suite := range suites {
		for _, test := range suite.Tests {
			allTestIDs[test.ID] = suite.ID
		}
	}

	for _, suite := range suites {
		for _, test := range suite.Tests {
			for _, dep := range test.Dependencies {
				if depSuiteID, exists := allTestIDs[dep]; exists {
					if depSuiteID != suite.ID {
						return fmt.Errorf("test %s in suite %s depends on test %s in different suite %s",
							test.ID, suite.ID, dep, depSuiteID)
					}
				}
			}
		}
	}

	return nil
}
