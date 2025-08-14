# Security Testing Framework

The Security Testing Framework provides comprehensive automated security testing capabilities for the HackAI platform. It includes penetration testing, vulnerability scanning, compliance testing, and fuzzing capabilities with detailed reporting and analysis.

## Features

### 🔍 **Comprehensive Security Testing**
- **Penetration Testing** - Automated penetration testing with SQL injection, XSS, command injection, and path traversal tests
- **Vulnerability Scanning** - SSL/TLS analysis, security headers, cookie security, and technology detection
- **Compliance Testing** - OWASP, NIST, SOC2, ISO27001, and PCI-DSS compliance validation
- **Fuzzing** - Automated fuzzing with random, boundary, and malformed payloads
- **Test Orchestration** - Coordinated execution of multiple test suites

### 📊 **Advanced Reporting System**
- **Multiple Report Formats** - JSON, HTML, and CSV reports with detailed findings
- **Vulnerability Classification** - CVSS scoring, CWE mapping, and OWASP categorization
- **Risk Assessment** - Automated risk scoring and severity classification
- **Compliance Mapping** - Findings mapped to compliance frameworks
- **Executive Summaries** - High-level security posture reports

### 🚨 **Intelligent Test Management**
- **Test Sessions** - Organized test execution with session management
- **Test Orchestration** - Parallel test execution with configurable concurrency
- **Progress Tracking** - Real-time test progress and status monitoring
- **Result Correlation** - Intelligent grouping and deduplication of findings
- **Historical Analysis** - Test result trends and comparison

### 📈 **Security Analytics**
- **Finding Analysis** - Detailed vulnerability analysis with evidence
- **Trend Analysis** - Security posture trends over time
- **Risk Metrics** - Quantitative risk assessment and scoring
- **Compliance Metrics** - Compliance posture tracking
- **Performance Metrics** - Test execution performance and coverage

## Quick Start

### Installation

```bash
# Build the security testing CLI tool
go build -o security-test cmd/security-test/main.go
```

### Basic Usage

```bash
# Run comprehensive security test
./security-test -command=test -target=https://example.com -suites=all

# Run specific test suites
./security-test -command=test -target=https://api.example.com -suites=penetration,vulnerability

# List test sessions
./security-test -command=list -format=table

# Show test statistics
./security-test -command=stats -format=table

# Generate detailed report
./security-test -command=report -session=session_123456 -format=json
```

### Test Suites

- **penetration** - SQL injection, XSS, command injection, path traversal tests
- **vulnerability** - SSL/TLS, security headers, cookie security, directory scanning
- **compliance** - OWASP, NIST, SOC2, ISO27001, PCI-DSS compliance checks
- **fuzzing** - Random, boundary, and malformed payload testing
- **all** - Execute all test suites

## Architecture

### Core Components

#### SecurityTestingFramework
- **Purpose**: Main orchestrator for all security testing activities
- **Features**: Test session management, result aggregation, report generation
- **Capabilities**: Multi-suite execution, parallel testing, progress tracking

#### PenetrationTester
- **Purpose**: Automated penetration testing capabilities
- **Tests**: SQL injection, XSS, command injection, path traversal, authentication, authorization
- **Features**: Payload generation, response analysis, vulnerability detection

#### VulnerabilityScanner
- **Purpose**: Comprehensive vulnerability scanning
- **Scans**: SSL/TLS, security headers, cookie security, directory enumeration, technology detection
- **Features**: Configuration analysis, security posture assessment, compliance checking

#### ComplianceTester
- **Purpose**: Compliance framework validation
- **Standards**: OWASP, NIST, CIS, SOC2, ISO27001, PCI-DSS
- **Features**: Control mapping, compliance scoring, gap analysis

#### FuzzTester
- **Purpose**: Automated fuzzing and input validation testing
- **Payloads**: Random, boundary, malformed, injection payloads
- **Features**: Input mutation, crash detection, anomaly identification

### Data Flow

```
Target Application → SecurityTestingFramework → Test Suites → Results → Reports
                                ↓
                    PenetrationTester, VulnerabilityScanner, ComplianceTester, FuzzTester
```

## Configuration

### Framework Configuration

```go
config := &testing.SecurityTestConfig{
    Enabled:            true,
    TestSuites:         []string{"all"},
    MaxConcurrentTests: 5,
    TestTimeout:        5 * time.Minute,
    ReportFormat:       "json",
    OutputDirectory:    "./security-test-reports",
    
    PenetrationConfig: &testing.PenetrationConfig{
        Enabled:               true,
        MaxConcurrentTests:    10,
        RequestTimeout:        30 * time.Second,
        SQLInjectionTests:     true,
        XSSTests:              true,
        CommandInjectionTests: true,
        PathTraversalTests:    true,
        AuthenticationTests:   true,
        AuthorizationTests:    true,
        SessionTests:          true,
        CSRFTests:             true,
    },
    
    VulnerabilityConfig: &testing.VulnerabilityConfig{
        Enabled:            true,
        MaxConcurrentScans: 5,
        ScanTimeout:        30 * time.Second,
        SSLScan:            true,
        HeaderScan:         true,
        CookieScan:         true,
        DirectoryScan:      true,
        TechnologyScan:     true,
    },
    
    ComplianceConfig: &testing.ComplianceConfig{
        Enabled:    true,
        Standards:  []string{"OWASP", "NIST", "CIS"},
        Frameworks: []string{"SOC2", "ISO27001", "PCI-DSS"},
    },
    
    FuzzConfig: &testing.FuzzConfig{
        Enabled:      true,
        MaxPayloads:  1000,
        PayloadTypes: []string{"random", "boundary", "malformed", "injection"},
    },
}
```

## Programmatic Usage

### Basic Security Testing

```go
package main

import (
    "time"
    "github.com/dimajoyti/hackai/pkg/testing"
)

func main() {
    // Create logger
    logger := &SimpleLogger{}
    
    // Create security testing framework
    config := &testing.SecurityTestConfig{
        Enabled:            true,
        TestSuites:         []string{"penetration", "vulnerability"},
        MaxConcurrentTests: 5,
        TestTimeout:        5 * time.Minute,
        ReportFormat:       "json",
        OutputDirectory:    "./reports",
    }
    
    framework := testing.NewSecurityTestingFramework(config, logger)
    
    // Start test session
    session, err := framework.StartTestSession(
        "API Security Test",
        "https://api.example.com",
        []string{"penetration", "vulnerability"},
    )
    if err != nil {
        panic(err)
    }
    
    // Wait for completion and get results
    for session.Status == "running" {
        time.Sleep(5 * time.Second)
        session, _ = framework.GetTestSession(session.ID)
    }
    
    // Analyze results
    fmt.Printf("Test completed: %d tests, %d passed, %d failed\n",
        session.TotalTests, session.PassedTests, session.FailedTests)
    fmt.Printf("Security findings: %d critical, %d high, %d medium, %d low\n",
        session.CriticalFindings, session.HighFindings, 
        session.MediumFindings, session.LowFindings)
}
```

### Advanced Test Configuration

```go
// Custom penetration testing
penetrationConfig := &testing.PenetrationConfig{
    Enabled:               true,
    MaxConcurrentTests:    15,
    RequestTimeout:        45 * time.Second,
    MaxRedirects:          10,
    UserAgent:             "CustomSecurityTester/2.0",
    SQLInjectionTests:     true,
    XSSTests:              true,
    CommandInjectionTests: true,
    PathTraversalTests:    true,
    CustomPayloads: []string{
        "custom_payload_1",
        "custom_payload_2",
    },
}

penetrationTester := testing.NewPenetrationTester(penetrationConfig, logger)
results := penetrationTester.RunTests(context.Background(), "https://target.com")

for _, result := range results {
    fmt.Printf("Test: %s, Status: %s, Score: %.1f\n",
        result.TestName, result.Status, result.Score)
    
    for _, vuln := range result.Vulnerabilities {
        fmt.Printf("  Vulnerability: %s (%s) - %s\n",
            vuln.Title, vuln.Severity, vuln.Description)
    }
}
```

### Vulnerability Scanning

```go
// Custom vulnerability scanning
vulnConfig := &testing.VulnerabilityConfig{
    Enabled:            true,
    MaxConcurrentScans: 8,
    ScanTimeout:        60 * time.Second,
    SSLScan:            true,
    HeaderScan:         true,
    CookieScan:         true,
    DirectoryScan:      true,
    TechnologyScan:     true,
    CommonPorts:        []int{80, 443, 8080, 8443, 9000},
    CommonDirectories:  []string{"admin", "api", "backup", "config"},
}

scanner := testing.NewVulnerabilityScanner(vulnConfig, logger)
results := scanner.RunScans(context.Background(), "https://target.com")

for _, result := range results {
    fmt.Printf("Scan: %s, Vulnerabilities: %d\n",
        result.TestName, len(result.Vulnerabilities))
}
```

## Test Types Reference

### Penetration Tests

#### SQL Injection Tests
- **Basic SQL Injection** - `' OR '1'='1`
- **Union-based Injection** - `' UNION SELECT NULL, NULL --`
- **Boolean-based Blind** - `' AND (SELECT COUNT(*) FROM users) > 0 --`
- **Time-based Blind** - `'; WAITFOR DELAY '00:00:05' --`
- **Error-based Injection** - `'; DROP TABLE users; --`

#### Cross-Site Scripting (XSS) Tests
- **Reflected XSS** - `<script>alert('XSS')</script>`
- **Stored XSS** - `<img src=x onerror=alert('XSS')>`
- **DOM-based XSS** - `javascript:alert('XSS')`
- **Event Handler XSS** - `<body onload=alert('XSS')>`
- **SVG XSS** - `<svg onload=alert('XSS')>`

#### Command Injection Tests
- **Basic Command Injection** - `; ls -la`
- **Pipe-based Injection** - `| whoami`
- **Background Execution** - `& ping -c 1 127.0.0.1`
- **Command Substitution** - `` `id` ``
- **Process Substitution** - `$(whoami)`

#### Path Traversal Tests
- **Basic Path Traversal** - `../../../etc/passwd`
- **Windows Path Traversal** - `..\\..\\..\\windows\\system32\\drivers\\etc\\hosts`
- **URL Encoded Traversal** - `..%2F..%2F..%2Fetc%2Fpasswd`
- **Double URL Encoded** - `..%252F..%252F..%252Fetc%252Fpasswd`
- **Unicode Traversal** - `..%c0%af..%c0%af..%c0%afetc%c0%afpasswd`

### Vulnerability Scans

#### SSL/TLS Security
- **Protocol Version Analysis** - TLS 1.0, 1.1, 1.2, 1.3 support
- **Cipher Suite Analysis** - Weak and strong cipher identification
- **Certificate Validation** - Certificate chain and validity checks
- **Perfect Forward Secrecy** - PFS support verification
- **HSTS Analysis** - HTTP Strict Transport Security configuration

#### Security Headers
- **Content Security Policy** - CSP header presence and configuration
- **X-Frame-Options** - Clickjacking protection
- **X-Content-Type-Options** - MIME type sniffing protection
- **Referrer-Policy** - Referrer information control
- **Permissions-Policy** - Browser feature permissions

#### Cookie Security
- **Secure Flag** - Cookie transmission over HTTPS only
- **HttpOnly Flag** - JavaScript access prevention
- **SameSite Attribute** - CSRF protection
- **Domain and Path** - Cookie scope validation
- **Expiration** - Cookie lifetime analysis

### Compliance Tests

#### OWASP Top 10 (2021)
- **A01: Broken Access Control** - Authorization and access control tests
- **A02: Cryptographic Failures** - Encryption and data protection
- **A03: Injection** - SQL, NoSQL, OS, and LDAP injection
- **A04: Insecure Design** - Security design flaws
- **A05: Security Misconfiguration** - Configuration security
- **A06: Vulnerable Components** - Known vulnerable components
- **A07: Authentication Failures** - Authentication weaknesses
- **A08: Software Integrity Failures** - Software supply chain
- **A09: Logging Failures** - Security logging and monitoring
- **A10: Server-Side Request Forgery** - SSRF vulnerabilities

#### NIST Cybersecurity Framework
- **Identify** - Asset management and risk assessment
- **Protect** - Access control and data security
- **Detect** - Anomaly detection and monitoring
- **Respond** - Incident response procedures
- **Recover** - Recovery planning and improvements

#### SOC 2 Type II
- **Security** - System protection against unauthorized access
- **Availability** - System availability for operation and use
- **Processing Integrity** - System processing completeness and accuracy
- **Confidentiality** - Information designated as confidential protection
- **Privacy** - Personal information collection and processing

### Fuzzing Tests

#### Payload Types
- **Random Payloads** - Randomly generated input data
- **Boundary Payloads** - Edge case and boundary value testing
- **Malformed Payloads** - Intentionally corrupted data
- **Injection Payloads** - SQL, XSS, and command injection attempts
- **Buffer Overflow** - Memory corruption attempts
- **Format String** - Format string vulnerability testing

## CLI Reference

### Commands

```bash
# Run security tests
security-test -command=test -target=URL [options]

# List test sessions
security-test -command=list [-format=json|table]

# Show test report
security-test -command=report -session=SESSION_ID [-format=json|table]

# Show statistics
security-test -command=stats [-format=json|table]
```

### Options

- `-command`: Command to execute (test, list, report, stats)
- `-target`: Target URL to test (required for test command)
- `-suites`: Test suites to run (penetration, vulnerability, compliance, fuzzing, all)
- `-name`: Name for the test session
- `-session`: Session ID for report/status commands
- `-format`: Output format (json, table)
- `-timeout`: Test timeout duration
- `-output`: Output directory for reports
- `-help`: Show help message

### Examples

```bash
# Comprehensive security test
security-test -command=test -target=https://api.example.com -suites=all -name="API Security Assessment"

# Penetration testing only
security-test -command=test -target=https://web.example.com -suites=penetration -timeout=10m

# Quick vulnerability scan
security-test -command=test -target=https://app.example.com -suites=vulnerability -timeout=2m

# List all test sessions
security-test -command=list -format=table

# Generate detailed report
security-test -command=report -session=session_1234567890 -format=json > report.json

# Show testing statistics
security-test -command=stats -format=table
```

## Report Formats

### JSON Report
```json
{
  "id": "session_1234567890",
  "name": "API Security Test",
  "target_url": "https://api.example.com",
  "status": "completed",
  "start_time": "2024-01-15T10:00:00Z",
  "end_time": "2024-01-15T10:15:00Z",
  "total_tests": 25,
  "passed_tests": 20,
  "failed_tests": 5,
  "critical_findings": 1,
  "high_findings": 2,
  "medium_findings": 3,
  "low_findings": 4,
  "test_results": [
    {
      "id": "test_1234567890",
      "test_type": "penetration",
      "test_name": "SQL Injection Test",
      "status": "completed",
      "passed": false,
      "score": 75.0,
      "severity": "high",
      "vulnerabilities": [
        {
          "id": "vuln_1234567890",
          "type": "sql_injection",
          "severity": "high",
          "title": "SQL Injection Vulnerability",
          "description": "SQL injection detected in parameter 'id'",
          "location": "https://api.example.com/users?id=1",
          "evidence": "Payload: ' OR '1'='1",
          "impact": "Potential database compromise",
          "recommendation": "Use parameterized queries",
          "cwe": "CWE-89",
          "owasp": "A03:2021 – Injection"
        }
      ]
    }
  ]
}
```

### HTML Report
- **Executive Summary** - High-level security posture overview
- **Test Results** - Detailed test execution results
- **Vulnerability Details** - Comprehensive vulnerability information
- **Risk Assessment** - Risk scoring and prioritization
- **Recommendations** - Actionable remediation guidance
- **Compliance Mapping** - Findings mapped to compliance frameworks

### CSV Report
```csv
Test ID,Test Type,Test Name,Status,Severity,Duration,Vulnerabilities,Findings
test_1,penetration,SQL Injection Test,completed,high,00:02:30,1,1
test_2,vulnerability,Security Headers Scan,completed,medium,00:01:15,3,3
test_3,compliance,OWASP Top 10 Check,completed,low,00:00:45,0,2
```

## Integration Examples

### CI/CD Pipeline Integration

```yaml
# .github/workflows/security-test.yml
name: Security Testing
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Go
        uses: actions/setup-go@v2
        with:
          go-version: 1.21
          
      - name: Build Security Test Tool
        run: go build -o security-test cmd/security-test/main.go
        
      - name: Run Security Tests
        run: |
          ./security-test -command=test \
            -target=${{ secrets.TEST_TARGET_URL }} \
            -suites=all \
            -name="CI Security Test" \
            -timeout=10m \
            -format=json > security-report.json
            
      - name: Upload Security Report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: security-report.json
          
      - name: Check for Critical Findings
        run: |
          if grep -q '"critical_findings": [1-9]' security-report.json; then
            echo "Critical security findings detected!"
            exit 1
          fi
```

### Docker Integration

```dockerfile
# Dockerfile.security-test
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o security-test cmd/security-test/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/security-test .
ENTRYPOINT ["./security-test"]
```

```bash
# Build and run security tests in Docker
docker build -f Dockerfile.security-test -t security-test .
docker run --rm security-test -command=test -target=https://example.com -suites=all
```

## Best Practices

### Test Planning
1. **Scope Definition** - Clearly define test scope and objectives
2. **Test Scheduling** - Schedule tests during maintenance windows
3. **Authorization** - Ensure proper authorization for testing
4. **Baseline Establishment** - Establish security baseline metrics

### Test Execution
1. **Gradual Rollout** - Start with less invasive tests
2. **Rate Limiting** - Implement appropriate request rate limiting
3. **Monitoring** - Monitor target system during testing
4. **Documentation** - Document all test activities and findings

### Result Analysis
1. **Prioritization** - Prioritize findings by risk and impact
2. **Validation** - Validate findings to reduce false positives
3. **Correlation** - Correlate findings across different test types
4. **Trending** - Track security posture trends over time

### Remediation
1. **Action Plans** - Develop specific remediation action plans
2. **Timeline** - Establish realistic remediation timelines
3. **Verification** - Verify remediation effectiveness
4. **Continuous Improvement** - Implement continuous security improvement

The Security Testing Framework provides comprehensive automated security testing capabilities that enable organizations to proactively identify and address security vulnerabilities, ensure compliance with security standards, and maintain a strong security posture.
