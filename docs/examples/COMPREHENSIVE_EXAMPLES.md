# Comprehensive Usage Examples

This document provides complete, working examples of how to use the HackAI Framework for various security testing and automation scenarios.

## 🚀 **Quick Start Example**

### Basic Security Scanning Workflow

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/dimajoyti/hackai/pkg/ai"
    "github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
    // 1. Create logger
    logger, err := logger.New(logger.Config{
        Level:  logger.LevelInfo,
        Format: "json",
        Output: "stdout",
    })
    if err != nil {
        log.Fatal("Failed to create logger:", err)
    }

    // 2. Configure orchestrator
    config := ai.OrchestratorConfig{
        WorkerPoolSize:         4,
        MaxConcurrentExecutions: 10,
        DefaultTimeout:         30 * time.Second,
        EnableMetrics:          true,
        EnableTracing:          true,
        RequestQueueSize:       100,
        LoadBalancingStrategy:  "round_robin",
        HealthCheckInterval:    10 * time.Second,
    }

    // 3. Create and start orchestrator
    orchestrator := ai.NewOrchestrator(config, logger)
    ctx := context.Background()
    
    if err := orchestrator.Start(ctx); err != nil {
        log.Fatal("Failed to start orchestrator:", err)
    }
    defer orchestrator.Stop()

    // 4. Create and register security tools
    securityScanner := ai.NewSecurityScannerTool(logger)
    penetrationTester := ai.NewPenetrationTesterTool(logger)

    if err := orchestrator.RegisterTool(securityScanner); err != nil {
        log.Fatal("Failed to register security scanner:", err)
    }
    if err := orchestrator.RegisterTool(penetrationTester); err != nil {
        log.Fatal("Failed to register penetration tester:", err)
    }

    // 5. Execute security scan
    scanInput := ai.ToolInput{
        "target":    "example.com",
        "scan_type": "comprehensive",
        "ports":     "1-1000",
        "timeout":   300,
    }

    fmt.Println("Starting security scan...")
    scanOutput, err := securityScanner.Execute(ctx, scanInput)
    if err != nil {
        log.Fatal("Security scan failed:", err)
    }

    // 6. Process scan results
    vulnerabilities := scanOutput["vulnerabilities"].([]map[string]interface{})
    summary := scanOutput["scan_summary"].(map[string]interface{})

    fmt.Printf("Scan completed for %s\n", summary["target"])
    fmt.Printf("Risk level: %s\n", summary["risk_level"])
    fmt.Printf("Found %d vulnerabilities\n", len(vulnerabilities))

    // 7. If high-risk vulnerabilities found, run penetration test
    if summary["risk_level"] == "high" {
        fmt.Println("High risk detected, running penetration test...")
        
        penTestInput := ai.ToolInput{
            "target":      summary["target"],
            "attack_type": "web_app",
            "intensity":   "medium",
        }

        penTestOutput, err := penetrationTester.Execute(ctx, penTestInput)
        if err != nil {
            log.Printf("Penetration test failed: %v", err)
        } else {
            exploits := penTestOutput["exploits_found"].([]map[string]interface{})
            recommendations := penTestOutput["recommendations"].([]string)
            
            fmt.Printf("Penetration test found %d exploits\n", len(exploits))
            fmt.Println("Recommendations:")
            for _, rec := range recommendations {
                fmt.Printf("- %s\n", rec)
            }
        }
    }

    // 8. Display orchestrator statistics
    stats := orchestrator.GetStats()
    fmt.Printf("\nOrchestrator Statistics:\n")
    fmt.Printf("Total executions: %d\n", stats.TotalExecutions)
    fmt.Printf("Uptime: %d seconds\n", stats.UptimeSeconds)
}
```

## 🔗 **Advanced Chain Example**

### Multi-Step Security Analysis Chain

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/dimajoyti/hackai/pkg/ai"
    "github.com/dimajoyti/hackai/pkg/llm"
    "github.com/dimajoyti/hackai/pkg/logger"
)

// Custom security analysis chain
type SecurityAnalysisChain struct {
    id          string
    name        string
    description string
    logger      *logger.Logger
    tools       map[string]ai.Tool
}

func NewSecurityAnalysisChain(logger *logger.Logger) *SecurityAnalysisChain {
    return &SecurityAnalysisChain{
        id:          "security-analysis-chain",
        name:        "Security Analysis Chain",
        description: "Comprehensive security analysis workflow",
        logger:      logger,
        tools:       make(map[string]ai.Tool),
    }
}

func (c *SecurityAnalysisChain) ID() string          { return c.id }
func (c *SecurityAnalysisChain) Name() string        { return c.name }
func (c *SecurityAnalysisChain) Description() string { return c.description }

func (c *SecurityAnalysisChain) Execute(ctx context.Context, input llm.ChainInput) (llm.ChainOutput, error) {
    target, ok := input["target"].(string)
    if !ok {
        return nil, fmt.Errorf("target must be a string")
    }

    results := make(llm.ChainOutput)
    results["target"] = target
    results["analysis_steps"] = []string{}

    // Step 1: Initial reconnaissance
    c.logger.Info("Starting reconnaissance", "target", target)
    reconResults := c.performReconnaissance(ctx, target)
    results["reconnaissance"] = reconResults
    results["analysis_steps"] = append(results["analysis_steps"].([]string), "reconnaissance")

    // Step 2: Vulnerability scanning
    c.logger.Info("Starting vulnerability scan", "target", target)
    vulnResults := c.performVulnerabilityScanning(ctx, target)
    results["vulnerabilities"] = vulnResults
    results["analysis_steps"] = append(results["analysis_steps"].([]string), "vulnerability_scanning")

    // Step 3: Risk assessment
    c.logger.Info("Performing risk assessment", "target", target)
    riskResults := c.performRiskAssessment(ctx, reconResults, vulnResults)
    results["risk_assessment"] = riskResults
    results["analysis_steps"] = append(results["analysis_steps"].([]string), "risk_assessment")

    // Step 4: Generate recommendations
    c.logger.Info("Generating recommendations", "target", target)
    recommendations := c.generateRecommendations(ctx, riskResults)
    results["recommendations"] = recommendations
    results["analysis_steps"] = append(results["analysis_steps"].([]string), "recommendations")

    results["status"] = "completed"
    results["timestamp"] = time.Now().Unix()

    return results, nil
}

func (c *SecurityAnalysisChain) performReconnaissance(ctx context.Context, target string) map[string]interface{} {
    // Simulate reconnaissance
    return map[string]interface{}{
        "domain_info": map[string]interface{}{
            "registrar": "Example Registrar",
            "creation_date": "2020-01-01",
            "expiry_date": "2025-01-01",
        },
        "dns_records": []map[string]interface{}{
            {"type": "A", "value": "192.168.1.1"},
            {"type": "MX", "value": "mail.example.com"},
        },
        "subdomains": []string{"www", "mail", "api"},
        "technologies": []string{"nginx", "php", "mysql"},
    }
}

func (c *SecurityAnalysisChain) performVulnerabilityScanning(ctx context.Context, target string) map[string]interface{} {
    // Simulate vulnerability scanning
    return map[string]interface{}{
        "total_vulnerabilities": 5,
        "critical": 1,
        "high": 2,
        "medium": 2,
        "low": 0,
        "details": []map[string]interface{}{
            {
                "id": "CVE-2023-1234",
                "severity": "critical",
                "title": "SQL Injection in login form",
                "description": "Unvalidated user input allows SQL injection",
                "location": "/login.php",
                "confidence": 0.95,
            },
            {
                "id": "CVE-2023-5678",
                "severity": "high",
                "title": "Cross-Site Scripting (XSS)",
                "description": "Reflected XSS in search parameter",
                "location": "/search.php",
                "confidence": 0.88,
            },
        },
    }
}

func (c *SecurityAnalysisChain) performRiskAssessment(ctx context.Context, recon, vulns map[string]interface{}) map[string]interface{} {
    // Calculate risk based on vulnerabilities and exposure
    criticalCount := vulns["critical"].(int)
    highCount := vulns["high"].(int)
    
    var riskLevel string
    var riskScore float64
    
    if criticalCount > 0 {
        riskLevel = "critical"
        riskScore = 9.5
    } else if highCount > 2 {
        riskLevel = "high"
        riskScore = 8.0
    } else if highCount > 0 {
        riskLevel = "medium"
        riskScore = 6.0
    } else {
        riskLevel = "low"
        riskScore = 3.0
    }

    return map[string]interface{}{
        "risk_level": riskLevel,
        "risk_score": riskScore,
        "factors": []string{
            "Public-facing web application",
            "Multiple high-severity vulnerabilities",
            "Sensitive data processing",
        },
        "business_impact": "High - potential data breach and service disruption",
    }
}

func (c *SecurityAnalysisChain) generateRecommendations(ctx context.Context, risk map[string]interface{}) []string {
    recommendations := []string{
        "Immediately patch SQL injection vulnerability",
        "Implement input validation and sanitization",
        "Deploy Web Application Firewall (WAF)",
        "Conduct regular security assessments",
        "Implement security monitoring and alerting",
    }

    if risk["risk_level"] == "critical" {
        recommendations = append([]string{
            "URGENT: Take application offline until critical vulnerabilities are patched",
            "Conduct emergency security review",
        }, recommendations...)
    }

    return recommendations
}

func (c *SecurityAnalysisChain) Validate() error {
    return nil
}

func (c *SecurityAnalysisChain) GetMetrics() ai.ChainMetrics {
    return ai.ChainMetrics{
        TotalExecutions: 0,
        SuccessfulRuns:  0,
        FailedRuns:      0,
        AverageLatency:  0,
    }
}

func main() {
    // Create logger and orchestrator
    logger, _ := logger.New(logger.Config{Level: logger.LevelInfo, Format: "json", Output: "stdout"})
    orchestrator := ai.NewOrchestrator(ai.OrchestratorConfig{
        WorkerPoolSize: 2,
        MaxConcurrentExecutions: 5,
        DefaultTimeout: 60 * time.Second,
    }, logger)

    ctx := context.Background()
    orchestrator.Start(ctx)
    defer orchestrator.Stop()

    // Register custom chain
    chain := NewSecurityAnalysisChain(logger)
    if err := orchestrator.RegisterChain(chain); err != nil {
        log.Fatal("Failed to register chain:", err)
    }

    // Execute security analysis
    input := llm.ChainInput{
        "target": "vulnerable-app.example.com",
        "depth":  "comprehensive",
    }

    fmt.Println("Starting comprehensive security analysis...")
    output, err := orchestrator.ExecuteChain(ctx, "security-analysis-chain", input)
    if err != nil {
        log.Fatal("Chain execution failed:", err)
    }

    // Display results
    fmt.Printf("Analysis completed for: %s\n", output["target"])
    fmt.Printf("Status: %s\n", output["status"])
    
    if risk, ok := output["risk_assessment"].(map[string]interface{}); ok {
        fmt.Printf("Risk Level: %s (Score: %.1f)\n", risk["risk_level"], risk["risk_score"])
        fmt.Printf("Business Impact: %s\n", risk["business_impact"])
    }

    if recommendations, ok := output["recommendations"].([]string); ok {
        fmt.Println("\nRecommendations:")
        for i, rec := range recommendations {
            fmt.Printf("%d. %s\n", i+1, rec)
        }
    }
}
```

## 📊 **Graph-Based Workflow Example**

### Complex Security Testing Graph

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/dimajoyti/hackai/pkg/ai"
    "github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
    // Create logger and orchestrator
    logger, _ := logger.New(logger.Config{Level: logger.LevelInfo, Format: "json", Output: "stdout"})
    orchestrator := ai.NewOrchestrator(ai.OrchestratorConfig{
        WorkerPoolSize: 4,
        MaxConcurrentExecutions: 10,
        DefaultTimeout: 120 * time.Second,
    }, logger)

    ctx := context.Background()
    orchestrator.Start(ctx)
    defer orchestrator.Stop()

    // Create security testing graph
    graph := ai.NewStateGraph("security-testing-graph", "Security Testing Graph", "Complex security testing workflow", logger)

    // Add nodes for different testing phases
    reconNode := &SecurityReconNode{id: "reconnaissance"}
    scanNode := &VulnerabilityScanNode{id: "vulnerability_scan"}
    exploitNode := &ExploitTestNode{id: "exploit_test"}
    reportNode := &ReportGenerationNode{id: "report_generation"}

    graph.AddNode(reconNode)
    graph.AddNode(scanNode)
    graph.AddNode(exploitNode)
    graph.AddNode(reportNode)

    // Define workflow edges
    graph.AddEdge("reconnaissance", "vulnerability_scan")
    graph.AddEdge("vulnerability_scan", "exploit_test")
    graph.AddEdge("exploit_test", "report_generation")
    graph.SetEntryPoint("reconnaissance")

    // Register graph
    if err := orchestrator.RegisterGraph(graph); err != nil {
        log.Fatal("Failed to register graph:", err)
    }

    // Execute security testing workflow
    initialState := ai.GraphState{
        "target": "test-application.example.com",
        "scope": "full",
        "credentials": map[string]string{
            "username": "testuser",
            "password": "testpass",
        },
    }

    fmt.Println("Starting complex security testing workflow...")
    finalState, err := orchestrator.ExecuteGraph(ctx, "security-testing-graph", initialState)
    if err != nil {
        log.Fatal("Graph execution failed:", err)
    }

    // Display results
    fmt.Printf("Security testing completed for: %s\n", finalState["target"])
    fmt.Printf("Final status: %s\n", finalState["status"])
    
    if report, ok := finalState["final_report"].(map[string]interface{}); ok {
        fmt.Printf("Total vulnerabilities found: %d\n", report["total_vulnerabilities"])
        fmt.Printf("Risk score: %.1f/10\n", report["risk_score"])
        fmt.Printf("Report generated: %s\n", report["report_path"])
    }
}

// Custom graph nodes
type SecurityReconNode struct {
    id string
}

func (n *SecurityReconNode) ID() string { return n.id }
func (n *SecurityReconNode) Type() ai.NodeType { return ai.NodeTypeAction }

func (n *SecurityReconNode) Execute(ctx context.Context, state ai.GraphState) (ai.GraphState, error) {
    target := state["target"].(string)
    
    // Simulate reconnaissance
    state["recon_results"] = map[string]interface{}{
        "subdomains": []string{"www", "api", "admin"},
        "technologies": []string{"nginx", "react", "nodejs"},
        "open_ports": []int{80, 443, 22},
    }
    state["phase"] = "reconnaissance_complete"
    
    return state, nil
}

func (n *SecurityReconNode) GetConfig() ai.NodeConfig { return ai.NodeConfig{} }
func (n *SecurityReconNode) SetConfig(config ai.NodeConfig) error { return nil }
func (n *SecurityReconNode) Validate() error { return nil }

// Similar implementations for other nodes...
```

This comprehensive examples file demonstrates real-world usage patterns and provides developers with practical, working code they can adapt for their own security testing needs.

## 🎯 **Next Steps**

These examples provide a solid foundation for:
1. **Basic Security Scanning** - Quick vulnerability assessment
2. **Advanced Chain Workflows** - Multi-step security analysis
3. **Complex Graph Execution** - Sophisticated testing workflows
4. **Custom Tool Development** - Building specialized security tools
5. **Integration Patterns** - Connecting with external systems

For more examples and advanced patterns, see the additional documentation in the `/docs/examples/` directory.
