package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/testing"
)

// SimpleLogger implements the testing.Logger interface
type SimpleLogger struct{}

func (l *SimpleLogger) Info(msg string, fields ...interface{}) {
	fmt.Printf("[INFO] %s", msg)
	if len(fields) > 0 {
		fmt.Printf(" %v", fields)
	}
	fmt.Println()
}

func (l *SimpleLogger) Error(msg string, fields ...interface{}) {
	fmt.Printf("[ERROR] %s", msg)
	if len(fields) > 0 {
		fmt.Printf(" %v", fields)
	}
	fmt.Println()
}

func (l *SimpleLogger) Warn(msg string, fields ...interface{}) {
	fmt.Printf("[WARN] %s", msg)
	if len(fields) > 0 {
		fmt.Printf(" %v", fields)
	}
	fmt.Println()
}

func (l *SimpleLogger) Debug(msg string, fields ...interface{}) {
	fmt.Printf("[DEBUG] %s", msg)
	if len(fields) > 0 {
		fmt.Printf(" %v", fields)
	}
	fmt.Println()
}

func main() {
	var (
		command     = flag.String("command", "test", "Command to execute (test, list, report, stats)")
		target      = flag.String("target", "", "Target URL to test")
		testSuites  = flag.String("suites", "all", "Test suites to run (penetration,vulnerability,compliance,fuzzing,all)")
		sessionName = flag.String("name", "Security Test", "Name for the test session")
		sessionID   = flag.String("session", "", "Session ID for report/status commands")
		format      = flag.String("format", "json", "Output format (json, table)")
		timeout     = flag.Duration("timeout", 5*time.Minute, "Test timeout duration")
		output      = flag.String("output", "./security-test-reports", "Output directory for reports")
		help        = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help {
		showHelp()
		return
	}

	logger := &SimpleLogger{}

	switch *command {
	case "test":
		if *target == "" {
			fmt.Println("Error: target URL is required for testing")
			showHelp()
			os.Exit(1)
		}
		runSecurityTest(logger, *target, *testSuites, *sessionName, *timeout, *output)
	case "list":
		listTestSessions(logger, *format)
	case "report":
		if *sessionID == "" {
			fmt.Println("Error: session ID is required for report command")
			showHelp()
			os.Exit(1)
		}
		showTestReport(logger, *sessionID, *format)
	case "stats":
		showTestStatistics(logger, *format)
	default:
		fmt.Printf("Unknown command: %s\n", *command)
		showHelp()
		os.Exit(1)
	}
}

func showHelp() {
	fmt.Println("Security Testing Framework CLI Tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  security-test [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  test      Run security tests against a target")
	fmt.Println("  list      List all test sessions")
	fmt.Println("  report    Show detailed report for a test session")
	fmt.Println("  stats     Show testing statistics")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -command     Command to execute (default: test)")
	fmt.Println("  -target      Target URL to test (required for test command)")
	fmt.Println("  -suites      Test suites: penetration,vulnerability,compliance,fuzzing,all (default: all)")
	fmt.Println("  -name        Name for the test session (default: Security Test)")
	fmt.Println("  -session     Session ID for report/status commands")
	fmt.Println("  -format      Output format: json, table (default: json)")
	fmt.Println("  -timeout     Test timeout duration (default: 5m)")
	fmt.Println("  -output      Output directory for reports (default: ./security-test-reports)")
	fmt.Println("  -help        Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  security-test -command=test -target=https://example.com -suites=penetration")
	fmt.Println("  security-test -command=test -target=https://api.example.com -suites=all -name=\"API Security Test\"")
	fmt.Println("  security-test -command=list -format=table")
	fmt.Println("  security-test -command=report -session=session_123456 -format=json")
	fmt.Println("  security-test -command=stats -format=table")
}

func runSecurityTest(logger testing.Logger, targetURL, testSuitesStr, sessionName string, timeout time.Duration, outputDir string) {
	fmt.Printf("[INFO] Starting security test against: %s\n", targetURL)
	fmt.Printf("[INFO] Test suites: %s\n", testSuitesStr)
	fmt.Printf("[INFO] Session name: %s\n", sessionName)
	fmt.Printf("[INFO] Timeout: %v\n", timeout)

	// Parse test suites
	var testSuites []string
	if testSuitesStr == "all" {
		testSuites = []string{"all"}
	} else {
		testSuites = strings.Split(testSuitesStr, ",")
		for i, suite := range testSuites {
			testSuites[i] = strings.TrimSpace(suite)
		}
	}

	// Create security testing framework
	config := &testing.SecurityTestConfig{
		EnableVulnerabilityScanning: true,
		EnablePenetrationTesting:    true,
		EnableComplianceChecking:    true,
		EnableThreatModeling:        true,
		ScanDepth:                   "medium",
		MaxScanDuration:             timeout,
		TargetEndpoints:             []string{targetURL},
		ExcludedPaths:               []string{},
		AuthenticationTokens:        make(map[string]string),
		ComplianceFrameworks:        []string{"OWASP", "NIST", "CIS"},
	}

	framework := testing.NewSecurityTestingFramework(config, logger)

	// Start test session
	session, err := framework.StartTestSession(sessionName, targetURL, testSuites)
	if err != nil {
		fmt.Printf("[ERROR] Failed to start test session: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[INFO] Test session started: %s\n", session.ID)
	fmt.Printf("[INFO] Waiting for tests to complete...\n")

	// Wait for session to complete
	for {
		updatedSession, err := framework.GetTestSession(session.ID)
		if err != nil {
			fmt.Printf("[ERROR] Failed to get session status: %v\n", err)
			break
		}

		if updatedSession.Status == "completed" {
			session = updatedSession
			break
		}

		fmt.Printf("[INFO] Tests running... (%d/%d completed)\n",
			updatedSession.PassedTests+updatedSession.FailedTests,
			updatedSession.TotalTests)
		time.Sleep(2 * time.Second)
	}

	// Show results
	fmt.Printf("\n[INFO] Security test completed!\n")
	fmt.Printf("Session ID: %s\n", session.ID)
	fmt.Printf("Total Tests: %d\n", session.TotalTests)
	fmt.Printf("Passed: %d\n", session.PassedTests)
	fmt.Printf("Failed: %d\n", session.FailedTests)
	fmt.Printf("Duration: %v\n", session.EndTime.Sub(session.StartTime))

	fmt.Printf("\nSecurity Findings:\n")
	fmt.Printf("  Critical: %d\n", session.CriticalFindings)
	fmt.Printf("  High: %d\n", session.HighFindings)
	fmt.Printf("  Medium: %d\n", session.MediumFindings)
	fmt.Printf("  Low: %d\n", session.LowFindings)

	if len(session.Reports) > 0 {
		fmt.Printf("\nReports generated:\n")
		for _, report := range session.Reports {
			fmt.Printf("  %s: %s\n", report.Format, report.FilePath)
		}
	}

	// Show critical and high severity findings
	if session.CriticalFindings > 0 || session.HighFindings > 0 {
		fmt.Printf("\n[WARN] Critical or high severity findings detected!\n")

		for _, result := range session.TestResults {
			if result.Security != nil && len(result.Security.Vulnerabilities) > 0 {
				for _, vuln := range result.Security.Vulnerabilities {
					if vuln.Severity == "critical" || vuln.Severity == "high" {
						fmt.Printf("  [%s] %s: %s\n", strings.ToUpper(vuln.Severity), vuln.Type, vuln.Title)
						fmt.Printf("    Location: %s\n", vuln.Location)
						fmt.Printf("    Remediation: %s\n", vuln.Remediation)
						fmt.Println()
					}
				}
			}
		}
	}

	if session.CriticalFindings > 0 {
		os.Exit(1) // Exit with error code for critical findings
	}
}

func listTestSessions(logger testing.Logger, format string) {
	// Create framework to access sessions
	config := &testing.SecurityTestConfig{
		EnableVulnerabilityScanning: true,
		EnablePenetrationTesting:    true,
		EnableComplianceChecking:    true,
		EnableThreatModeling:        true,
		ScanDepth:                   "medium",
		MaxScanDuration:             1 * time.Minute,
		TargetEndpoints:             []string{},
		ExcludedPaths:               []string{},
		AuthenticationTokens:        make(map[string]string),
		ComplianceFrameworks:        []string{},
	}

	framework := testing.NewSecurityTestingFramework(config, logger)
	sessions := framework.ListTestSessions()

	if format == "json" {
		data, _ := json.MarshalIndent(sessions, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("Test Sessions\n")
		fmt.Printf("=============\n")

		if len(sessions) == 0 {
			fmt.Printf("No test sessions found.\n")
			return
		}

		fmt.Printf("%-20s %-30s %-20s %-10s %-8s %-8s %-8s\n",
			"Session ID", "Name", "Target", "Status", "Total", "Passed", "Failed")
		fmt.Printf("%-20s %-30s %-20s %-10s %-8s %-8s %-8s\n",
			"----------", "----", "------", "------", "-----", "------", "------")

		for _, session := range sessions {
			sessionID := session.ID
			if len(sessionID) > 18 {
				sessionID = sessionID[:18] + ".."
			}

			name := session.Name
			if len(name) > 28 {
				name = name[:28] + ".."
			}

			target := session.TargetURL
			if len(target) > 18 {
				target = target[:18] + ".."
			}

			fmt.Printf("%-20s %-30s %-20s %-10s %-8d %-8d %-8d\n",
				sessionID, name, target, session.Status,
				session.TotalTests, session.PassedTests, session.FailedTests)
		}
	}
}

func showTestReport(logger testing.Logger, sessionID, format string) {
	// Create framework to access session
	config := &testing.SecurityTestConfig{
		EnableVulnerabilityScanning: true,
		EnablePenetrationTesting:    true,
		EnableComplianceChecking:    true,
		EnableThreatModeling:        true,
		ScanDepth:                   "medium",
		MaxScanDuration:             1 * time.Minute,
		TargetEndpoints:             []string{},
		ExcludedPaths:               []string{},
		AuthenticationTokens:        make(map[string]string),
		ComplianceFrameworks:        []string{},
	}

	framework := testing.NewSecurityTestingFramework(config, logger)
	session, err := framework.GetTestSession(sessionID)
	if err != nil {
		fmt.Printf("[ERROR] Session not found: %s\n", sessionID)
		os.Exit(1)
	}

	if format == "json" {
		data, _ := json.MarshalIndent(session, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("Security Test Report\n")
		fmt.Printf("====================\n")
		fmt.Printf("Session ID: %s\n", session.ID)
		fmt.Printf("Name: %s\n", session.Name)
		fmt.Printf("Target: %s\n", session.TargetURL)
		fmt.Printf("Status: %s\n", session.Status)
		fmt.Printf("Start Time: %s\n", session.StartTime.Format(time.RFC3339))
		if session.EndTime != nil {
			fmt.Printf("End Time: %s\n", session.EndTime.Format(time.RFC3339))
			fmt.Printf("Duration: %v\n", session.EndTime.Sub(session.StartTime))
		}

		fmt.Printf("\nTest Summary:\n")
		fmt.Printf("  Total Tests: %d\n", session.TotalTests)
		fmt.Printf("  Passed: %d\n", session.PassedTests)
		fmt.Printf("  Failed: %d\n", session.FailedTests)
		fmt.Printf("  Skipped: %d\n", session.SkippedTests)

		fmt.Printf("\nSecurity Findings:\n")
		fmt.Printf("  Critical: %d\n", session.CriticalFindings)
		fmt.Printf("  High: %d\n", session.HighFindings)
		fmt.Printf("  Medium: %d\n", session.MediumFindings)
		fmt.Printf("  Low: %d\n", session.LowFindings)

		if len(session.TestResults) > 0 {
			fmt.Printf("\nTest Results:\n")
			for _, result := range session.TestResults {
				status := "✅"
				if result.Status != "passed" {
					status = "❌"
				}

				fmt.Printf("  %s %s (%s) - Duration: %v\n",
					status, result.Name, result.Status, result.Duration)

				if result.Security != nil && len(result.Security.Vulnerabilities) > 0 {
					fmt.Printf("    Vulnerabilities:\n")
					for _, vuln := range result.Security.Vulnerabilities {
						fmt.Printf("      - [%s] %s: %s\n",
							strings.ToUpper(vuln.Severity), vuln.Type, vuln.Title)
					}
				}
			}
		}

		if len(session.Reports) > 0 {
			fmt.Printf("\nGenerated Reports:\n")
			for _, report := range session.Reports {
				fmt.Printf("  %s: %s (%d bytes)\n",
					strings.ToUpper(report.Format), report.FilePath, report.Size)
			}
		}
	}
}

func showTestStatistics(logger testing.Logger, format string) {
	// Create framework to access statistics
	config := &testing.SecurityTestConfig{
		EnableVulnerabilityScanning: true,
		EnablePenetrationTesting:    true,
		EnableComplianceChecking:    true,
		EnableThreatModeling:        true,
		ScanDepth:                   "medium",
		MaxScanDuration:             1 * time.Minute,
		TargetEndpoints:             []string{},
		ExcludedPaths:               []string{},
		AuthenticationTokens:        make(map[string]string),
		ComplianceFrameworks:        []string{},
	}

	framework := testing.NewSecurityTestingFramework(config, logger)
	stats := framework.GetTestStatistics()

	if format == "json" {
		data, _ := json.MarshalIndent(stats, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("Security Testing Statistics\n")
		fmt.Printf("===========================\n")
		fmt.Printf("Total Sessions: %v\n", stats["total_sessions"])
		fmt.Printf("Total Tests: %v\n", stats["total_tests"])
		fmt.Printf("Passed Tests: %v\n", stats["passed_tests"])
		fmt.Printf("Failed Tests: %v\n", stats["failed_tests"])
		fmt.Printf("Success Rate: %.1f%%\n", stats["success_rate"])

		fmt.Printf("\nFindings by Severity:\n")
		fmt.Printf("  Critical: %v\n", stats["critical_findings"])
		fmt.Printf("  High: %v\n", stats["high_findings"])
		fmt.Printf("  Medium: %v\n", stats["medium_findings"])
		fmt.Printf("  Low: %v\n", stats["low_findings"])
	}
}
