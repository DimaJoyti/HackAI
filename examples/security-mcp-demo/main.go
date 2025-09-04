package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/mcp"
)

// SecurityMCPDemo demonstrates the Security MCP service capabilities
type SecurityMCPDemo struct {
	client *mcp.SecurityMCPClient
	logger *logger.Logger
}

// NewSecurityMCPDemo creates a new demo instance
func NewSecurityMCPDemo() (*SecurityMCPDemo, error) {
	// Create logger
	log, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "text",
		Output: "stdout",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	// Create MCP client
	config := &mcp.SecurityMCPClientConfig{
		ClientName:    "Security MCP Demo Client",
		ClientVersion: "1.0.0",
		Timeout:       30 * time.Second,
		MaxRetries:    3,
		RetryDelay:    1 * time.Second,
		EnableTracing: true,
		EnableMetrics: true,
	}

	client := mcp.NewSecurityMCPClient(config, log)

	return &SecurityMCPDemo{
		client: client,
		logger: log,
	}, nil
}

// Run executes the demo
func (demo *SecurityMCPDemo) Run() error {
	ctx := context.Background()

	// Get server URL from environment or use default
	serverURL := os.Getenv("SECURITY_MCP_URL")
	if serverURL == "" {
		serverURL = "http://localhost:9087/mcp"
	}

	demo.logger.Info("Connecting to Security MCP server", "url", serverURL)

	// Connect to server
	if err := demo.client.Connect(ctx, serverURL); err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer demo.client.Disconnect(ctx)

	demo.logger.Info("Connected successfully!")

	// Run demo scenarios
	if err := demo.demonstrateCapabilities(ctx); err != nil {
		return fmt.Errorf("failed to demonstrate capabilities: %w", err)
	}

	if err := demo.demonstrateThreatAnalysis(ctx); err != nil {
		return fmt.Errorf("failed to demonstrate threat analysis: %w", err)
	}

	if err := demo.demonstrateVulnerabilityScanning(ctx); err != nil {
		return fmt.Errorf("failed to demonstrate vulnerability scanning: %w", err)
	}

	if err := demo.demonstrateComplianceChecking(ctx); err != nil {
		return fmt.Errorf("failed to demonstrate compliance checking: %w", err)
	}

	if err := demo.demonstrateIncidentResponse(ctx); err != nil {
		return fmt.Errorf("failed to demonstrate incident response: %w", err)
	}

	if err := demo.demonstrateThreatIntelligence(ctx); err != nil {
		return fmt.Errorf("failed to demonstrate threat intelligence: %w", err)
	}

	if err := demo.demonstrateResourceAccess(ctx); err != nil {
		return fmt.Errorf("failed to demonstrate resource access: %w", err)
	}

	if err := demo.demonstratePromptGeneration(ctx); err != nil {
		return fmt.Errorf("failed to demonstrate prompt generation: %w", err)
	}

	demo.logger.Info("Demo completed successfully!")
	return nil
}

// demonstrateCapabilities shows available tools, resources, and prompts
func (demo *SecurityMCPDemo) demonstrateCapabilities(ctx context.Context) error {
	demo.logger.Info("=== Demonstrating Server Capabilities ===")

	// List available tools
	tools, err := demo.client.ListTools(ctx)
	if err != nil {
		return err
	}

	demo.logger.Info("Available Security Tools:")
	for _, tool := range tools.Tools {
		demo.logger.Info(fmt.Sprintf("  - %s: %s", tool.Name, tool.Description))
	}

	// List available resources
	resources, err := demo.client.ListResources(ctx)
	if err != nil {
		return err
	}

	demo.logger.Info("Available Security Resources:")
	for _, resource := range resources.Resources {
		demo.logger.Info(fmt.Sprintf("  - %s: %s", resource.URI, resource.Description))
	}

	// List available prompts
	prompts, err := demo.client.ListPrompts(ctx)
	if err != nil {
		return err
	}

	demo.logger.Info("Available Security Prompts:")
	for _, prompt := range prompts.Prompts {
		demo.logger.Info(fmt.Sprintf("  - %s: %s", prompt.Name, prompt.Description))
	}

	return nil
}

// demonstrateThreatAnalysis shows threat analysis capabilities
func (demo *SecurityMCPDemo) demonstrateThreatAnalysis(ctx context.Context) error {
	demo.logger.Info("=== Demonstrating Threat Analysis ===")

	testInputs := []string{
		"SELECT * FROM users WHERE id = 1; DROP TABLE users;", // SQL injection
		"<script>alert('XSS')</script>",                       // XSS attempt
		"../../../../etc/passwd",                               // Path traversal
		"Hello, this is a normal message",                     // Benign input
	}

	for i, input := range testInputs {
		demo.logger.Info(fmt.Sprintf("Analyzing input %d: %s", i+1, input))

		securityContext := map[string]interface{}{
			"user_id":    fmt.Sprintf("demo-user-%d", i+1),
			"session_id": fmt.Sprintf("demo-session-%d", i+1),
			"ip_address": "192.168.1.100",
			"user_agent": "Security MCP Demo Client/1.0.0",
		}

		result, err := demo.client.AnalyzeThreat(ctx, input, securityContext)
		if err != nil {
			demo.logger.Error("Threat analysis failed", "error", err)
			continue
		}

		demo.printResult("Threat Analysis", result)
	}

	return nil
}

// demonstrateVulnerabilityScanning shows vulnerability scanning capabilities
func (demo *SecurityMCPDemo) demonstrateVulnerabilityScanning(ctx context.Context) error {
	demo.logger.Info("=== Demonstrating Vulnerability Scanning ===")

	scanTargets := []struct {
		target   string
		scanType string
		options  map[string]interface{}
	}{
		{
			target:   "https://example.com",
			scanType: "web",
			options:  map[string]interface{}{"depth": "basic"},
		},
		{
			target:   "192.168.1.1",
			scanType: "network",
			options:  map[string]interface{}{"ports": "80,443,22"},
		},
		{
			target:   "api.example.com",
			scanType: "api",
			options:  map[string]interface{}{"swagger_url": "/swagger.json"},
		},
	}

	for _, scan := range scanTargets {
		demo.logger.Info(fmt.Sprintf("Scanning %s (%s)", scan.target, scan.scanType))

		result, err := demo.client.ScanVulnerabilities(ctx, scan.target, scan.scanType, scan.options)
		if err != nil {
			demo.logger.Error("Vulnerability scan failed", "error", err)
			continue
		}

		demo.printResult("Vulnerability Scan", result)
	}

	return nil
}

// demonstrateComplianceChecking shows compliance checking capabilities
func (demo *SecurityMCPDemo) demonstrateComplianceChecking(ctx context.Context) error {
	demo.logger.Info("=== Demonstrating Compliance Checking ===")

	complianceChecks := []struct {
		framework string
		target    string
		scope     []string
	}{
		{
			framework: "OWASP",
			target:    "web-application",
			scope:     []string{"authentication", "authorization", "input_validation"},
		},
		{
			framework: "NIST",
			target:    "infrastructure",
			scope:     []string{"access_control", "audit_logging"},
		},
		{
			framework: "SOC2",
			target:    "data_processing",
			scope:     []string{"security", "availability"},
		},
	}

	for _, check := range complianceChecks {
		demo.logger.Info(fmt.Sprintf("Checking %s compliance for %s", check.framework, check.target))

		result, err := demo.client.CheckCompliance(ctx, check.framework, check.target, check.scope)
		if err != nil {
			demo.logger.Error("Compliance check failed", "error", err)
			continue
		}

		demo.printResult("Compliance Check", result)
	}

	return nil
}

// demonstrateIncidentResponse shows incident response capabilities
func (demo *SecurityMCPDemo) demonstrateIncidentResponse(ctx context.Context) error {
	demo.logger.Info("=== Demonstrating Incident Response ===")

	// Create incident
	demo.logger.Info("Creating security incident")
	createResult, err := demo.client.ManageIncident(ctx, "create", "", map[string]interface{}{
		"title":       "Demo Security Incident",
		"description": "This is a demonstration incident for testing purposes",
		"severity":    "medium",
		"category":    "security_breach",
	})
	if err != nil {
		return err
	}

	demo.printResult("Create Incident", createResult)

	// Extract incident ID from result (simplified for demo)
	incidentID := "demo-incident-123"

	// Update incident
	demo.logger.Info("Updating incident")
	updateResult, err := demo.client.ManageIncident(ctx, "update", incidentID, map[string]interface{}{
		"status":      "investigating",
		"assigned_to": "security-team",
	})
	if err != nil {
		return err
	}

	demo.printResult("Update Incident", updateResult)

	// Investigate incident
	demo.logger.Info("Starting investigation")
	investigateResult, err := demo.client.ManageIncident(ctx, "investigate", incidentID, map[string]interface{}{
		"investigation_notes": "Beginning forensic analysis",
	})
	if err != nil {
		return err
	}

	demo.printResult("Investigate Incident", investigateResult)

	// Resolve incident
	demo.logger.Info("Resolving incident")
	resolveResult, err := demo.client.ManageIncident(ctx, "resolve", incidentID, map[string]interface{}{
		"resolution":  "False positive - no actual security breach detected",
		"resolved_by": "security-analyst",
	})
	if err != nil {
		return err
	}

	demo.printResult("Resolve Incident", resolveResult)

	return nil
}

// demonstrateThreatIntelligence shows threat intelligence capabilities
func (demo *SecurityMCPDemo) demonstrateThreatIntelligence(ctx context.Context) error {
	demo.logger.Info("=== Demonstrating Threat Intelligence ===")

	queries := []struct {
		queryType  string
		indicators []string
		sources    []string
	}{
		{
			queryType:  "ioc",
			indicators: []string{"192.168.1.1", "malicious.example.com", "bad-hash-123"},
			sources:    []string{"internal_feeds", "public_feeds"},
		},
		{
			queryType:  "cve",
			indicators: []string{"CVE-2023-1234", "CVE-2023-5678"},
			sources:    []string{"nvd", "mitre"},
		},
		{
			queryType: "reputation",
			indicators: []string{"suspicious.domain.com"},
			sources:   []string{"reputation_db"},
		},
	}

	for _, query := range queries {
		demo.logger.Info(fmt.Sprintf("Querying threat intelligence: %s", query.queryType))

		result, err := demo.client.QueryThreatIntelligence(ctx, query.queryType, query.indicators, query.sources)
		if err != nil {
			demo.logger.Error("Threat intelligence query failed", "error", err)
			continue
		}

		demo.printResult("Threat Intelligence", result)
	}

	return nil
}

// demonstrateResourceAccess shows resource access capabilities
func (demo *SecurityMCPDemo) demonstrateResourceAccess(ctx context.Context) error {
	demo.logger.Info("=== Demonstrating Resource Access ===")

	resources := []string{
		"security://reports",
		"security://threat-intel",
		"security://compliance",
		"security://metrics",
	}

	for _, resourceURI := range resources {
		demo.logger.Info(fmt.Sprintf("Reading resource: %s", resourceURI))

		result, err := demo.client.ReadResource(ctx, resourceURI)
		if err != nil {
			demo.logger.Error("Resource read failed", "error", err)
			continue
		}

		demo.logger.Info(fmt.Sprintf("Resource %s content:", resourceURI))
		for _, content := range result.Contents {
			demo.logger.Info(fmt.Sprintf("  Type: %s, Size: %d bytes", content.MimeType, len(content.Text)))
		}
	}

	return nil
}

// demonstratePromptGeneration shows prompt generation capabilities
func (demo *SecurityMCPDemo) demonstratePromptGeneration(ctx context.Context) error {
	demo.logger.Info("=== Demonstrating Prompt Generation ===")

	promptRequests := []struct {
		name      string
		arguments map[string]interface{}
	}{
		{
			name: "threat_analysis_prompt",
			arguments: map[string]interface{}{
				"input_type":     "code",
				"analysis_depth": "comprehensive",
			},
		},
		{
			name: "security_assessment_prompt",
			arguments: map[string]interface{}{
				"target_type": "web_app",
				"framework":   "OWASP",
			},
		},
		{
			name: "incident_response_prompt",
			arguments: map[string]interface{}{
				"incident_type": "data_breach",
				"severity":      "high",
			},
		},
	}

	for _, req := range promptRequests {
		demo.logger.Info(fmt.Sprintf("Generating prompt: %s", req.name))

		result, err := demo.client.GetPrompt(ctx, req.name, req.arguments)
		if err != nil {
			demo.logger.Error("Prompt generation failed", "error", err)
			continue
		}

		demo.logger.Info(fmt.Sprintf("Generated prompt for %s:", req.name))
		demo.logger.Info(fmt.Sprintf("  Description: %s", result.Description))
		demo.logger.Info(fmt.Sprintf("  Messages: %d", len(result.Messages)))
		if len(result.Messages) > 0 {
			demo.logger.Info(fmt.Sprintf("  First message: %s", result.Messages[0].Content.Text[:100]+"..."))
		}
	}

	return nil
}

// printResult prints a formatted result
func (demo *SecurityMCPDemo) printResult(operation string, result *mcp.CallToolResult) {
	demo.logger.Info(fmt.Sprintf("%s Result:", operation))
	demo.logger.Info(fmt.Sprintf("  Success: %t", !result.IsError))
	demo.logger.Info(fmt.Sprintf("  Content items: %d", len(result.Content)))

	for i, content := range result.Content {
		if content.Type == "text" {
			// Truncate long text for readability
			text := content.Text
			if len(text) > 200 {
				text = text[:200] + "..."
			}
			demo.logger.Info(fmt.Sprintf("  Content %d: %s", i+1, text))
		} else {
			demo.logger.Info(fmt.Sprintf("  Content %d: [%s data]", i+1, content.Type))
		}
	}
}

func main() {
	demo, err := NewSecurityMCPDemo()
	if err != nil {
		log.Fatalf("Failed to create demo: %v", err)
	}

	if err := demo.Run(); err != nil {
		log.Fatalf("Demo failed: %v", err)
	}
}
