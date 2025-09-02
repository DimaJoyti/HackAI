package testing

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// SecurityTestingFramework provides comprehensive security testing capabilities
type SecurityTestingFramework struct {
	config *SecurityTestConfig
	logger Logger

	// Test suites
	penetrationTester    *PenetrationTester
	vulnerabilityScanner *VulnerabilityScanner
	complianceTester     *ComplianceTester
	fuzzTester           *FuzzTester

	// Test orchestration
	testOrchestrator *TestOrchestrator

	// Results management
	testResults  map[string]*TestResult
	testSessions map[string]*SecurityTestSession

	// Synchronization
	mu sync.RWMutex
}

// Note: SecurityTestConfig is defined in security_tester.go

// Note: TestResult is defined in framework.go

// SecurityTestSession represents a security testing session
type SecurityTestSession struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	StartTime time.Time  `json:"start_time"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Status    string     `json:"status"`

	// Configuration
	TestSuites []string `json:"test_suites"`
	TargetURL  string   `json:"target_url"`

	// Results
	TotalTests   int `json:"total_tests"`
	PassedTests  int `json:"passed_tests"`
	FailedTests  int `json:"failed_tests"`
	SkippedTests int `json:"skipped_tests"`

	// Findings summary
	CriticalFindings int `json:"critical_findings"`
	HighFindings     int `json:"high_findings"`
	MediumFindings   int `json:"medium_findings"`
	LowFindings      int `json:"low_findings"`

	// Test results
	TestResults []*TestResult `json:"test_results"`

	// Reports
	Reports []*TestReport `json:"reports"`
}

// Note: Vulnerability is defined in security_tester.go

// ComplianceIssue represents a compliance violation
type ComplianceIssue struct {
	ID             string `json:"id"`
	Standard       string `json:"standard"`
	Control        string `json:"control"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Evidence       string `json:"evidence"`
	Recommendation string `json:"recommendation"`
	Status         string `json:"status"`
}

// SecurityFinding represents a general security finding
type SecurityFinding struct {
	ID             string  `json:"id"`
	Category       string  `json:"category"`
	Severity       string  `json:"severity"`
	Title          string  `json:"title"`
	Description    string  `json:"description"`
	Evidence       string  `json:"evidence"`
	Recommendation string  `json:"recommendation"`
	Confidence     float64 `json:"confidence"`
	RiskScore      float64 `json:"risk_score"`
}

// TestMetrics contains test execution metrics
type TestMetrics struct {
	RequestsSent        int           `json:"requests_sent"`
	ResponsesReceived   int           `json:"responses_received"`
	ErrorsEncountered   int           `json:"errors_encountered"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	MaxResponseTime     time.Duration `json:"max_response_time"`
	MinResponseTime     time.Duration `json:"min_response_time"`
	ThroughputRPS       float64       `json:"throughput_rps"`
	DataTransferred     int64         `json:"data_transferred"`
}

// CVSSScore represents CVSS vulnerability scoring
type CVSSScore struct {
	Version            string  `json:"version"`
	BaseScore          float64 `json:"base_score"`
	TemporalScore      float64 `json:"temporal_score"`
	EnvironmentalScore float64 `json:"environmental_score"`
	Vector             string  `json:"vector"`
}

// TestReport represents a test report
type TestReport struct {
	ID          string    `json:"id"`
	Format      string    `json:"format"`
	Title       string    `json:"title"`
	GeneratedAt time.Time `json:"generated_at"`
	Content     string    `json:"content"`
	FilePath    string    `json:"file_path"`
	Size        int64     `json:"size"`
}

// Logger interface for testing framework
type Logger interface {
	Info(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Debug(msg string, fields ...interface{})
}

// NewSecurityTestingFramework creates a new security testing framework
func NewSecurityTestingFramework(config *SecurityTestConfig, logger Logger) *SecurityTestingFramework {
	framework := &SecurityTestingFramework{
		config:       config,
		logger:       logger,
		testResults:  make(map[string]*TestResult),
		testSessions: make(map[string]*SecurityTestSession),
	}

	// Initialize test components with default configurations
	if config.EnablePenetrationTesting {
		framework.penetrationTester = NewPenetrationTester(nil, logger) // Uses default config
	}
	if config.EnableVulnerabilityScanning {
		framework.vulnerabilityScanner = NewVulnerabilityScanner(nil, logger) // Uses default config
	}
	if config.EnableComplianceChecking {
		framework.complianceTester = NewComplianceTester(nil, logger) // Uses default config
	}
	// Always initialize fuzz tester with default config
	framework.fuzzTester = NewFuzzTester(nil, logger)
	// Create a simple logger for the test orchestrator
	// For now, skip the test orchestrator to avoid type conflicts
	// framework.testOrchestrator = nil

	return framework
}

// StartSecurityTestSession starts a new testing session
func (stf *SecurityTestingFramework) StartSecurityTestSession(name, targetURL string, testSuites []string) (*SecurityTestSession, error) {
	// Note: SecurityTestConfig doesn't have Enabled field, so we check if any testing is enabled
	if !stf.config.EnableVulnerabilityScanning && !stf.config.EnablePenetrationTesting && !stf.config.EnableComplianceChecking {
		return nil, fmt.Errorf("all security testing is disabled")
	}

	sessionID := fmt.Sprintf("session_%d", time.Now().UnixNano())

	session := &SecurityTestSession{
		ID:          sessionID,
		Name:        name,
		StartTime:   time.Now(),
		Status:      "running",
		TestSuites:  testSuites,
		TargetURL:   targetURL,
		TestResults: make([]*TestResult, 0),
		Reports:     make([]*TestReport, 0),
	}

	stf.mu.Lock()
	stf.testSessions[sessionID] = session
	stf.mu.Unlock()

	stf.logger.Info("Started security test session", "session_id", sessionID, "target", targetURL)

	// Start test orchestration
	go stf.runSecurityTestSession(session)

	return session, nil
}

// runSecurityTestSession executes a test session
func (stf *SecurityTestingFramework) runSecurityTestSession(session *SecurityTestSession) {
	defer func() {
		endTime := time.Now()
		session.EndTime = &endTime
		session.Status = "completed"

		stf.logger.Info("Completed security test session",
			"session_id", session.ID,
			"duration", endTime.Sub(session.StartTime),
			"total_tests", session.TotalTests,
			"passed", session.PassedTests,
			"failed", session.FailedTests)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), stf.config.MaxScanDuration)
	defer cancel()

	// Execute test suites
	for _, testSuite := range session.TestSuites {
		stf.logger.Info("Running test suite", "suite", testSuite, "session_id", session.ID)

		switch testSuite {
		case "penetration":
			results := stf.runPenetrationTests(ctx, session.TargetURL)
			stf.addTestResults(session, results)

		case "vulnerability":
			results := stf.runVulnerabilityScans(ctx, session.TargetURL)
			stf.addTestResults(session, results)

		case "compliance":
			results := stf.runComplianceTests(ctx, session.TargetURL)
			stf.addTestResults(session, results)

		case "fuzzing":
			results := stf.runFuzzTests(ctx, session.TargetURL)
			stf.addTestResults(session, results)

		case "all":
			// Run all test suites
			allResults := make([]*TestResult, 0)
			allResults = append(allResults, stf.runPenetrationTests(ctx, session.TargetURL)...)
			allResults = append(allResults, stf.runVulnerabilityScans(ctx, session.TargetURL)...)
			allResults = append(allResults, stf.runComplianceTests(ctx, session.TargetURL)...)
			allResults = append(allResults, stf.runFuzzTests(ctx, session.TargetURL)...)
			stf.addTestResults(session, allResults)

		default:
			stf.logger.Warn("Unknown test suite", "suite", testSuite)
		}
	}

	// Generate reports
	stf.generateReports(session)
}

// addTestResults adds test results to a session
func (stf *SecurityTestingFramework) addTestResults(session *SecurityTestSession, results []*TestResult) {
	stf.mu.Lock()
	defer stf.mu.Unlock()

	for _, result := range results {
		session.TestResults = append(session.TestResults, result)
		session.TotalTests++

		if result.Status == TestStatusPassed {
			session.PassedTests++
		} else {
			session.FailedTests++
		}

		// Count findings by severity from security results
		if result.Security != nil {
			for _, vuln := range result.Security.Vulnerabilities {
				switch vuln.Severity {
				case "critical":
					session.CriticalFindings++
				case "high":
					session.HighFindings++
				case "medium":
					session.MediumFindings++
				case "low":
					session.LowFindings++
				}
			}
		}

		// Store result
		stf.testResults[result.TestID] = result
	}
}

// runPenetrationTests runs penetration tests
func (stf *SecurityTestingFramework) runPenetrationTests(ctx context.Context, targetURL string) []*TestResult {
	if stf.penetrationTester == nil {
		return []*TestResult{}
	}

	return stf.penetrationTester.RunTests(ctx, targetURL)
}

// runVulnerabilityScans runs vulnerability scans
func (stf *SecurityTestingFramework) runVulnerabilityScans(ctx context.Context, targetURL string) []*TestResult {
	if stf.vulnerabilityScanner == nil {
		return []*TestResult{}
	}

	return stf.vulnerabilityScanner.RunScans(ctx, targetURL)
}

// runComplianceTests runs compliance tests
func (stf *SecurityTestingFramework) runComplianceTests(ctx context.Context, targetURL string) []*TestResult {
	if stf.complianceTester == nil {
		return []*TestResult{}
	}

	return stf.complianceTester.RunTests(ctx, targetURL)
}

// runFuzzTests runs fuzz tests
func (stf *SecurityTestingFramework) runFuzzTests(ctx context.Context, targetURL string) []*TestResult {
	if stf.fuzzTester == nil {
		return []*TestResult{}
	}

	return stf.fuzzTester.RunTests(ctx, targetURL)
}

// generateReports generates test reports
func (stf *SecurityTestingFramework) generateReports(session *SecurityTestSession) {
	// Generate JSON report
	jsonReport := stf.generateJSONReport(session)
	session.Reports = append(session.Reports, jsonReport)

	// Generate HTML report
	htmlReport := stf.generateHTMLReport(session)
	session.Reports = append(session.Reports, htmlReport)

	// Generate CSV report
	csvReport := stf.generateCSVReport(session)
	session.Reports = append(session.Reports, csvReport)
}

// generateJSONReport generates a JSON report
func (stf *SecurityTestingFramework) generateJSONReport(session *SecurityTestSession) *TestReport {
	content, _ := json.MarshalIndent(session, "", "  ")

	return &TestReport{
		ID:          fmt.Sprintf("json_report_%s", session.ID),
		Format:      "json",
		Title:       fmt.Sprintf("Security Test Report - %s", session.Name),
		GeneratedAt: time.Now(),
		Content:     string(content),
		FilePath:    fmt.Sprintf("./reports/%s_report.json", session.ID),
		Size:        int64(len(content)),
	}
}

// generateHTMLReport generates an HTML report
func (stf *SecurityTestingFramework) generateHTMLReport(session *SecurityTestSession) *TestReport {
	// This would generate a comprehensive HTML report
	// For now, we'll create a basic HTML structure
	content := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Security Test Report - %s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .summary { margin: 20px 0; }
        .findings { margin: 20px 0; }
        .critical { color: #d32f2f; }
        .high { color: #f57c00; }
        .medium { color: #fbc02d; }
        .low { color: #388e3c; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Test Report</h1>
        <h2>%s</h2>
        <p>Generated: %s</p>
        <p>Target: %s</p>
    </div>
    
    <div class="summary">
        <h3>Test Summary</h3>
        <p>Total Tests: %d</p>
        <p>Passed: %d</p>
        <p>Failed: %d</p>
        <p>Duration: %v</p>
    </div>
    
    <div class="findings">
        <h3>Security Findings</h3>
        <p><span class="critical">Critical: %d</span></p>
        <p><span class="high">High: %d</span></p>
        <p><span class="medium">Medium: %d</span></p>
        <p><span class="low">Low: %d</span></p>
    </div>
</body>
</html>`,
		session.Name,
		session.Name,
		time.Now().Format(time.RFC3339),
		session.TargetURL,
		session.TotalTests,
		session.PassedTests,
		session.FailedTests,
		func() time.Duration {
			if session.EndTime != nil {
				return session.EndTime.Sub(session.StartTime)
			}
			return time.Since(session.StartTime)
		}(),
		session.CriticalFindings,
		session.HighFindings,
		session.MediumFindings,
		session.LowFindings)

	return &TestReport{
		ID:          fmt.Sprintf("html_report_%s", session.ID),
		Format:      "html",
		Title:       fmt.Sprintf("Security Test Report - %s", session.Name),
		GeneratedAt: time.Now(),
		Content:     content,
		FilePath:    fmt.Sprintf("./reports/%s_report.html", session.ID),
		Size:        int64(len(content)),
	}
}

// generateCSVReport generates a CSV report
func (stf *SecurityTestingFramework) generateCSVReport(session *SecurityTestSession) *TestReport {
	content := "Test ID,Test Type,Test Name,Status,Severity,Duration,Vulnerabilities,Findings\n"

	for _, result := range session.TestResults {
		vulnCount := 0
		if result.Security != nil {
			vulnCount = len(result.Security.Vulnerabilities)
		}
		content += fmt.Sprintf("%s,%s,%s,%s,%v,%d\n",
			result.TestID,
			result.Name,
			result.Status,
			result.Duration,
			vulnCount,
			len(result.Assertions))
	}

	return &TestReport{
		ID:          fmt.Sprintf("csv_report_%s", session.ID),
		Format:      "csv",
		Title:       fmt.Sprintf("Security Test Report - %s", session.Name),
		GeneratedAt: time.Now(),
		Content:     content,
		FilePath:    fmt.Sprintf("./reports/%s_report.csv", session.ID),
		Size:        int64(len(content)),
	}
}

// GetSecurityTestSession retrieves a test session
func (stf *SecurityTestingFramework) GetSecurityTestSession(sessionID string) (*SecurityTestSession, error) {
	stf.mu.RLock()
	defer stf.mu.RUnlock()

	session, exists := stf.testSessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("test session not found: %s", sessionID)
	}

	return session, nil
}

// GetTestResult retrieves a test result
func (stf *SecurityTestingFramework) GetTestResult(resultID string) (*TestResult, error) {
	stf.mu.RLock()
	defer stf.mu.RUnlock()

	result, exists := stf.testResults[resultID]
	if !exists {
		return nil, fmt.Errorf("test result not found: %s", resultID)
	}

	return result, nil
}

// ListSecurityTestSessions lists all test sessions
func (stf *SecurityTestingFramework) ListSecurityTestSessions() []*SecurityTestSession {
	stf.mu.RLock()
	defer stf.mu.RUnlock()

	sessions := make([]*SecurityTestSession, 0, len(stf.testSessions))
	for _, session := range stf.testSessions {
		sessions = append(sessions, session)
	}

	return sessions
}

// GetTestStatistics returns testing statistics
func (stf *SecurityTestingFramework) GetTestStatistics() map[string]interface{} {
	stf.mu.RLock()
	defer stf.mu.RUnlock()

	totalSessions := len(stf.testSessions)
	totalTests := len(stf.testResults)

	passedTests := 0
	failedTests := 0
	criticalFindings := 0
	highFindings := 0
	mediumFindings := 0
	lowFindings := 0

	for _, result := range stf.testResults {
		if result.Status == TestStatusPassed {
			passedTests++
		} else {
			failedTests++
		}

		if result.Security != nil {
			for _, vuln := range result.Security.Vulnerabilities {
				switch vuln.Severity {
				case "critical":
					criticalFindings++
				case "high":
					highFindings++
				case "medium":
					mediumFindings++
				case "low":
					lowFindings++
				}
			}
		}
	}

	return map[string]interface{}{
		"total_sessions":    totalSessions,
		"total_tests":       totalTests,
		"passed_tests":      passedTests,
		"failed_tests":      failedTests,
		"critical_findings": criticalFindings,
		"high_findings":     highFindings,
		"medium_findings":   mediumFindings,
		"low_findings":      lowFindings,
		"success_rate":      float64(passedTests) / float64(totalTests) * 100,
	}
}
