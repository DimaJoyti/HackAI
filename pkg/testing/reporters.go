package testing

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// JSONReporter generates JSON test reports
type JSONReporter struct {
	OutputPath string
}

// HTMLReporter generates HTML test reports
type HTMLReporter struct {
	OutputPath string
}

// JUnitReporter generates JUnit XML test reports
type JUnitReporter struct {
	OutputPath string
}

// ConsoleReporter outputs test results to console
type ConsoleReporter struct{}

// JUnitTestSuite represents a JUnit test suite
type JUnitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Skipped   int             `xml:"skipped,attr"`
	Time      float64         `xml:"time,attr"`
	Timestamp string          `xml:"timestamp,attr"`
	TestCases []JUnitTestCase `xml:"testcase"`
}

// JUnitTestCase represents a JUnit test case
type JUnitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
	Error     *JUnitError   `xml:"error,omitempty"`
	Skipped   *JUnitSkipped `xml:"skipped,omitempty"`
}

// JUnitFailure represents a test failure
type JUnitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

// JUnitError represents a test error
type JUnitError struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

// JUnitSkipped represents a skipped test
type JUnitSkipped struct {
	Message string `xml:"message,attr"`
}

// JSONReporter implementation

// Report generates a JSON test report
func (jr *JSONReporter) Report(results *TestResults) error {
	outputPath := jr.OutputPath
	if outputPath == "" {
		outputPath = "./test-results/results.json"
	}

	// Ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Marshal results to JSON
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results to JSON: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}

	return nil
}

// GetFormat returns the report format
func (jr *JSONReporter) GetFormat() string {
	return "json"
}

// HTMLReporter implementation

// Report generates an HTML test report
func (hr *HTMLReporter) Report(results *TestResults) error {
	outputPath := hr.OutputPath
	if outputPath == "" {
		outputPath = "./test-results/report.html"
	}

	// Ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate HTML content
	htmlContent, err := hr.generateHTML(results)
	if err != nil {
		return fmt.Errorf("failed to generate HTML content: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, []byte(htmlContent), 0644); err != nil {
		return fmt.Errorf("failed to write HTML report: %w", err)
	}

	return nil
}

// GetFormat returns the report format
func (hr *HTMLReporter) GetFormat() string {
	return "html"
}

// generateHTML generates HTML content for the test report
func (hr *HTMLReporter) generateHTML(results *TestResults) (string, error) {
	tmpl := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HackAI Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; }
        .metric-value { font-size: 2em; font-weight: bold; margin-bottom: 5px; }
        .metric-label { color: #666; font-size: 0.9em; }
        .passed { color: #28a745; }
        .failed { color: #dc3545; }
        .skipped { color: #ffc107; }
        .suite { margin-bottom: 30px; border: 1px solid #ddd; border-radius: 6px; }
        .suite-header { background: #f8f9fa; padding: 15px; border-bottom: 1px solid #ddd; }
        .suite-name { font-size: 1.2em; font-weight: bold; margin-bottom: 5px; }
        .suite-summary { color: #666; font-size: 0.9em; }
        .test-list { padding: 0; }
        .test-item { padding: 10px 15px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
        .test-item:last-child { border-bottom: none; }
        .test-name { font-weight: 500; }
        .test-status { padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
        .status-passed { background: #d4edda; color: #155724; }
        .status-failed { background: #f8d7da; color: #721c24; }
        .status-skipped { background: #fff3cd; color: #856404; }
        .test-duration { color: #666; font-size: 0.9em; margin-left: 10px; }
        .error-details { background: #f8d7da; color: #721c24; padding: 10px; margin-top: 10px; border-radius: 4px; font-family: monospace; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ HackAI Test Report</h1>
            <p>Execution ID: {{.ExecutionID}}</p>
            <p>Generated: {{.EndTime.Format "2006-01-02 15:04:05"}}</p>
        </div>

        <div class="summary">
            <div class="metric">
                <div class="metric-value">{{.Summary.TotalTests}}</div>
                <div class="metric-label">Total Tests</div>
            </div>
            <div class="metric">
                <div class="metric-value passed">{{.Summary.PassedTests}}</div>
                <div class="metric-label">Passed</div>
            </div>
            <div class="metric">
                <div class="metric-value failed">{{.Summary.FailedTests}}</div>
                <div class="metric-label">Failed</div>
            </div>
            <div class="metric">
                <div class="metric-value skipped">{{.Summary.SkippedTests}}</div>
                <div class="metric-label">Skipped</div>
            </div>
            <div class="metric">
                <div class="metric-value">{{printf "%.1f%%" .Summary.SuccessRate}}</div>
                <div class="metric-label">Success Rate</div>
            </div>
            <div class="metric">
                <div class="metric-value">{{.Duration}}</div>
                <div class="metric-label">Duration</div>
            </div>
        </div>

        {{range .SuiteResults}}
        <div class="suite">
            <div class="suite-header">
                <div class="suite-name">{{.Name}}</div>
                <div class="suite-summary">
                    {{.Summary.TotalTests}} tests, 
                    {{.Summary.PassedTests}} passed, 
                    {{.Summary.FailedTests}} failed, 
                    {{.Summary.SkippedTests}} skipped
                    ({{.Duration}})
                </div>
            </div>
            <div class="test-list">
                {{range .TestResults}}
                <div class="test-item">
                    <div>
                        <span class="test-name">{{.Name}}</span>
                        <span class="test-duration">{{.Duration}}</span>
                    </div>
                    <div>
                        <span class="test-status status-{{.Status}}">{{.Status}}</span>
                    </div>
                </div>
                {{if .Error}}
                <div class="error-details">{{.Error}}</div>
                {{end}}
                {{end}}
            </div>
        </div>
        {{end}}
    </div>
</body>
</html>
`

	t, err := template.New("report").Parse(tmpl)
	if err != nil {
		return "", err
	}

	var buf strings.Builder
	if err := t.Execute(&buf, results); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// JUnitReporter implementation

// Report generates a JUnit XML test report
func (jr *JUnitReporter) Report(results *TestResults) error {
	outputPath := jr.OutputPath
	if outputPath == "" {
		outputPath = "./test-results/junit.xml"
	}

	// Ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Convert to JUnit format
	junitSuites := jr.convertToJUnit(results)

	// Marshal to XML
	xmlData, err := xml.MarshalIndent(junitSuites, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal to XML: %w", err)
	}

	// Add XML header
	xmlContent := xml.Header + string(xmlData)

	// Write to file
	if err := os.WriteFile(outputPath, []byte(xmlContent), 0644); err != nil {
		return fmt.Errorf("failed to write JUnit report: %w", err)
	}

	return nil
}

// GetFormat returns the report format
func (jr *JUnitReporter) GetFormat() string {
	return "junit"
}

// convertToJUnit converts test results to JUnit format
func (jr *JUnitReporter) convertToJUnit(results *TestResults) []JUnitTestSuite {
	var junitSuites []JUnitTestSuite

	for _, suiteResult := range results.SuiteResults {
		junitSuite := JUnitTestSuite{
			Name:      suiteResult.Name,
			Tests:     len(suiteResult.TestResults),
			Failures:  0,
			Errors:    0,
			Skipped:   0,
			Time:      suiteResult.Duration.Seconds(),
			Timestamp: suiteResult.StartTime.Format(time.RFC3339),
			TestCases: make([]JUnitTestCase, 0, len(suiteResult.TestResults)),
		}

		for _, testResult := range suiteResult.TestResults {
			testCase := JUnitTestCase{
				Name:      testResult.Name,
				ClassName: suiteResult.Name,
				Time:      testResult.Duration.Seconds(),
			}

			switch testResult.Status {
			case TestStatusFailed:
				junitSuite.Failures++
				testCase.Failure = &JUnitFailure{
					Message: "Test failed",
					Type:    "failure",
					Content: testResult.Error,
				}
			case TestStatusError:
				junitSuite.Errors++
				testCase.Error = &JUnitError{
					Message: "Test error",
					Type:    "error",
					Content: testResult.Error,
				}
			case TestStatusSkipped:
				junitSuite.Skipped++
				testCase.Skipped = &JUnitSkipped{
					Message: "Test skipped",
				}
			}

			junitSuite.TestCases = append(junitSuite.TestCases, testCase)
		}

		junitSuites = append(junitSuites, junitSuite)
	}

	return junitSuites
}

// ConsoleReporter implementation

// Report outputs test results to console
func (cr *ConsoleReporter) Report(results *TestResults) error {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("🛡️  HackAI Test Results")
	fmt.Println(strings.Repeat("=", 80))

	fmt.Printf("Execution ID: %s\n", results.ExecutionID)
	fmt.Printf("Duration: %v\n", results.Duration)
	fmt.Printf("Environment: %s\n", results.Environment.Environment)
	fmt.Println()

	// Summary
	fmt.Println("📊 Summary:")
	fmt.Printf("  Total Tests: %d\n", results.Summary.TotalTests)
	fmt.Printf("  ✅ Passed: %d\n", results.Summary.PassedTests)
	fmt.Printf("  ❌ Failed: %d\n", results.Summary.FailedTests)
	fmt.Printf("  ⏭️  Skipped: %d\n", results.Summary.SkippedTests)
	fmt.Printf("  ⚠️  Errors: %d\n", results.Summary.ErrorTests)
	fmt.Printf("  📈 Success Rate: %.1f%%\n", results.Summary.SuccessRate)
	fmt.Println()

	// Suite results
	for _, suiteResult := range results.SuiteResults {
		fmt.Printf("📦 Suite: %s\n", suiteResult.Name)
		fmt.Printf("   Duration: %v\n", suiteResult.Duration)
		fmt.Printf("   Tests: %d passed, %d failed, %d skipped\n",
			suiteResult.Summary.PassedTests,
			suiteResult.Summary.FailedTests,
			suiteResult.Summary.SkippedTests)

		// Show failed tests
		for _, testResult := range suiteResult.TestResults {
			if testResult.Status == TestStatusFailed || testResult.Status == TestStatusError {
				fmt.Printf("   ❌ %s: %s\n", testResult.Name, testResult.Error)
			}
		}
		fmt.Println()
	}

	// Coverage information
	if results.Coverage != nil {
		fmt.Println("📊 Coverage:")
		fmt.Printf("  Lines: %d/%d (%.1f%%)\n",
			results.Coverage.CoveredLines,
			results.Coverage.TotalLines,
			results.Coverage.CoverageRate)
		fmt.Println()
	}

	// Performance information
	if results.Performance != nil {
		fmt.Println("⚡ Performance:")
		fmt.Printf("  Average Response Time: %v\n", results.Performance.AverageResponseTime)
		fmt.Printf("  Max Response Time: %v\n", results.Performance.MaxResponseTime)
		fmt.Printf("  Throughput: %.2f req/s\n", results.Performance.Throughput)
		fmt.Printf("  Error Rate: %.2f%%\n", results.Performance.ErrorRate)
		fmt.Println()
	}

	// Security information
	if results.Security != nil {
		fmt.Println("🔒 Security:")
		fmt.Printf("  Vulnerabilities Found: %d\n", results.Security.VulnerabilitiesFound)
		fmt.Printf("  Security Score: %.1f\n", results.Security.SecurityScore)
		fmt.Printf("  Compliance Status: %s\n", results.Security.ComplianceStatus)
		fmt.Println()
	}

	fmt.Println(strings.Repeat("=", 80))

	return nil
}

// GetFormat returns the report format
func (cr *ConsoleReporter) GetFormat() string {
	return "console"
}
