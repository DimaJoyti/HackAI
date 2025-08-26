package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/tools"
	"github.com/dimajoyti/hackai/pkg/langgraph/tools/integration"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// DemoSecurityTool demonstrates a security-focused tool
type DemoSecurityTool struct {
	*tools.BaseTool
}

func NewDemoSecurityTool() *DemoSecurityTool {
	base := tools.NewBaseTool("security_scanner", "Security Scanner", "Performs security scans on targets", tools.CategorySecurity)
	return &DemoSecurityTool{BaseTool: base}
}

func (dst *DemoSecurityTool) Execute(ctx context.Context, input map[string]interface{}) (interface{}, error) {
	target, exists := input["target"]
	if !exists {
		return nil, fmt.Errorf("target parameter is required")
	}

	// Simulate security scan
	time.Sleep(2 * time.Second)

	return map[string]interface{}{
		"scan_completed":  true,
		"target":          target,
		"vulnerabilities": []string{"CVE-2023-1234", "CVE-2023-5678"},
		"risk_score":      7.5,
		"scan_duration":   "2 seconds",
		"recommendations": []string{"Update software", "Enable firewall"},
		"timestamp":       time.Now(),
	}, nil
}

func (dst *DemoSecurityTool) Validate(input map[string]interface{}) error {
	if _, exists := input["target"]; !exists {
		return fmt.Errorf("target parameter is required")
	}
	return nil
}

// DemoAnalyticsTool demonstrates an analytics tool
type DemoAnalyticsTool struct {
	*tools.BaseTool
}

func NewDemoAnalyticsTool() *DemoAnalyticsTool {
	base := tools.NewBaseTool("data_analyzer", "Data Analyzer", "Analyzes data and generates insights", tools.CategoryAnalysis)
	return &DemoAnalyticsTool{BaseTool: base}
}

func (dat *DemoAnalyticsTool) Execute(ctx context.Context, input map[string]interface{}) (interface{}, error) {
	dataset, exists := input["dataset"]
	if !exists {
		return nil, fmt.Errorf("dataset parameter is required")
	}

	// Simulate data analysis
	time.Sleep(1 * time.Second)

	return map[string]interface{}{
		"analysis_completed": true,
		"dataset":            dataset,
		"insights": []string{
			"Data shows 25% increase in activity",
			"Peak usage occurs at 2 PM",
			"Anomaly detected in sector 7",
		},
		"confidence_score": 0.92,
		"processing_time":  "1 second",
		"timestamp":        time.Now(),
	}, nil
}

func (dat *DemoAnalyticsTool) Validate(input map[string]interface{}) error {
	if _, exists := input["dataset"]; !exists {
		return fmt.Errorf("dataset parameter is required")
	}
	return nil
}

// DemoUtilityTool demonstrates a utility tool
type DemoUtilityTool struct {
	*tools.BaseTool
}

func NewDemoUtilityTool() *DemoUtilityTool {
	base := tools.NewBaseTool("text_processor", "Text Processor", "Processes and transforms text", tools.CategoryUtility)
	return &DemoUtilityTool{BaseTool: base}
}

func (dut *DemoUtilityTool) Execute(ctx context.Context, input map[string]interface{}) (interface{}, error) {
	text, exists := input["text"]
	if !exists {
		return nil, fmt.Errorf("text parameter is required")
	}

	textStr, ok := text.(string)
	if !ok {
		return nil, fmt.Errorf("text must be a string")
	}

	operation := "uppercase" // default
	if op, exists := input["operation"]; exists {
		if opStr, ok := op.(string); ok {
			operation = opStr
		}
	}

	var result string
	switch operation {
	case "uppercase":
		result = strings.ToUpper(textStr)
	case "lowercase":
		result = strings.ToLower(textStr)
	case "reverse":
		runes := []rune(textStr)
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
		result = string(runes)
	default:
		return nil, fmt.Errorf("unsupported operation: %s", operation)
	}

	return map[string]interface{}{
		"original_text":   textStr,
		"processed_text":  result,
		"operation":       operation,
		"character_count": len(textStr),
		"word_count":      len(strings.Fields(textStr)),
		"timestamp":       time.Now(),
	}, nil
}

func (dut *DemoUtilityTool) Validate(input map[string]interface{}) error {
	if _, exists := input["text"]; !exists {
		return fmt.Errorf("text parameter is required")
	}
	return nil
}

func main() {
	// Initialize logger
	logger := logger.NewDefault()
	logger.Info("Starting Tool Integration System Demo")

	fmt.Println("🔧 Tool Integration System Demo")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("Demonstrating advanced tool integration with security, validation, and monitoring")
	fmt.Println()

	ctx := context.Background()

	// Create tool integration system with full configuration
	config := &integration.IntegrationConfig{
		EnableSecurity:     true,
		EnableWorkflows:    true,
		EnablePlugins:      true,
		EnableDiscovery:    true,
		EnableProxying:     true,
		EnableMetrics:      true,
		MaxConcurrentTools: 5,
		DefaultTimeout:     30 * time.Second,
		RetryAttempts:      3,
		RetryDelay:         time.Second,
		SecurityLevel:      integration.SecurityLevelStandard,
		ValidationMode:     integration.ValidationModeStrict,
	}

	integrationSystem := integration.NewToolIntegrationSystem(config, logger)

	// Demo 1: Tool Registration with Advanced Configuration
	fmt.Println("📝 Demo 1: Advanced Tool Registration")
	fmt.Println(strings.Repeat("-", 60))

	// Create demo tools
	securityTool := NewDemoSecurityTool()
	analyticsTool := NewDemoAnalyticsTool()
	utilityTool := NewDemoUtilityTool()

	// Register security tool with advanced configuration
	securityConfig := &integration.ToolConfig{
		Timeout:       15 * time.Second,
		RetryAttempts: 2,
		RetryDelay:    2 * time.Second,
		RateLimit: &integration.RateLimit{
			RequestsPerSecond: 5,
			BurstSize:         10,
			WindowSize:        time.Minute,
		},
		CircuitBreaker: &integration.CircuitBreakerConfig{
			FailureThreshold: 3,
			RecoveryTimeout:  30 * time.Second,
			HalfOpenRequests: 2,
		},
		Caching: &integration.CachingConfig{
			Enabled:  true,
			TTL:      5 * time.Minute,
			MaxSize:  100,
			Strategy: "lru",
		},
		Monitoring: &integration.MonitoringConfig{
			Enabled:         true,
			MetricsInterval: time.Minute,
			AlertThresholds: map[string]float64{
				"error_rate": 0.1,
				"latency":    5.0,
			},
			HealthChecks: true,
		},
	}

	securityIntegration, err := integrationSystem.RegisterTool(ctx, securityTool, securityConfig)
	if err != nil {
		log.Printf("Failed to register security tool: %v", err)
	} else {
		fmt.Printf("✅ Security tool registered: %s\n", securityIntegration.ID)
		fmt.Printf("   Capabilities: %v\n", securityIntegration.Capabilities)
		fmt.Printf("   Security Level: %s\n", securityIntegration.Security.Level)
	}

	// Register analytics tool with different configuration
	analyticsConfig := &integration.ToolConfig{
		Timeout:       10 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    time.Second,
		Caching: &integration.CachingConfig{
			Enabled:  true,
			TTL:      10 * time.Minute,
			MaxSize:  50,
			Strategy: "lru",
		},
	}

	analyticsIntegration, err := integrationSystem.RegisterTool(ctx, analyticsTool, analyticsConfig)
	if err != nil {
		log.Printf("Failed to register analytics tool: %v", err)
	} else {
		fmt.Printf("✅ Analytics tool registered: %s\n", analyticsIntegration.ID)
	}

	// Register utility tool with minimal configuration
	utilityIntegration, err := integrationSystem.RegisterTool(ctx, utilityTool, nil)
	if err != nil {
		log.Printf("Failed to register utility tool: %v", err)
	} else {
		fmt.Printf("✅ Utility tool registered: %s\n", utilityIntegration.ID)
	}

	fmt.Println()

	// Demo 2: Security and Permissions
	fmt.Println("🔒 Demo 2: Security and Permissions")
	fmt.Println(strings.Repeat("-", 60))

	// Set up user permissions
	userPermissions := &integration.PermissionSet{
		UserID: "demo_user",
		Roles:  []string{"analyst", "security_user"},
		Permissions: []integration.Permission{
			integration.PermissionRead,
			integration.PermissionExecute,
		},
		Scopes: []string{"security_scan", "data_analysis"},
	}

	if err := integrationSystem.SetUserPermissions("demo_user", userPermissions); err != nil {
		log.Printf("Failed to set user permissions: %v", err)
		return
	}

	// Create security session
	session, err := integrationSystem.CreateSecuritySession(
		"demo_user",
		"192.168.1.100",
		"Tool-Integration-Demo/1.0",
		userPermissions,
	)

	if err != nil {
		log.Printf("Failed to create security session: %v", err)
	} else {
		fmt.Printf("✅ Security session created: %s\n", session.ID)
		fmt.Printf("   User: %s\n", session.UserID)
		fmt.Printf("   Expires: %s\n", session.ExpiresAt.Format("15:04:05"))
	}

	fmt.Println()

	// Demo 3: Tool Execution with Advanced Features
	fmt.Println("⚡ Demo 3: Advanced Tool Execution")
	fmt.Println(strings.Repeat("-", 60))

	// Execute security tool
	securityOptions := &integration.ExecutionOptions{
		UserID:   "demo_user",
		Priority: 1,
		Context: map[string]interface{}{
			"session_id": session.ID,
			"ip_address": "192.168.1.100",
			"user_agent": "Tool-Integration-Demo/1.0",
		},
		Metadata: map[string]interface{}{
			"request_source": "demo",
			"environment":    "development",
		},
	}

	securityInput := map[string]interface{}{
		"target": "example.com",
	}

	fmt.Printf("🎯 Executing security scan on: %s\n", securityInput["target"])
	securityResult, err := integrationSystem.ExecuteTool(ctx, securityTool.ID(), securityInput, securityOptions)
	if err != nil {
		log.Printf("Security tool execution failed: %v", err)
	} else {
		fmt.Printf("✅ Security scan completed successfully\n")
		fmt.Printf("   Duration: %v\n", securityResult.Duration)
		fmt.Printf("   Success: %v\n", securityResult.Success)
		if result, ok := securityResult.Result.(map[string]interface{}); ok {
			if vulns, exists := result["vulnerabilities"]; exists {
				fmt.Printf("   Vulnerabilities found: %v\n", vulns)
			}
		}
	}

	// Execute analytics tool
	analyticsInput := map[string]interface{}{
		"dataset": "user_activity_logs",
	}

	fmt.Printf("🎯 Executing data analysis on: %s\n", analyticsInput["dataset"])
	analyticsResult, err := integrationSystem.ExecuteTool(ctx, analyticsTool.ID(), analyticsInput, securityOptions)
	if err != nil {
		log.Printf("Analytics tool execution failed: %v", err)
	} else {
		fmt.Printf("✅ Data analysis completed successfully\n")
		fmt.Printf("   Duration: %v\n", analyticsResult.Duration)
		if result, ok := analyticsResult.Result.(map[string]interface{}); ok {
			if insights, exists := result["insights"]; exists {
				fmt.Printf("   Insights: %v\n", insights)
			}
		}
	}

	// Execute utility tool with different operations
	operations := []string{"uppercase", "lowercase", "reverse"}
	for _, operation := range operations {
		utilityInput := map[string]interface{}{
			"text":      "Hello, World!",
			"operation": operation,
		}

		fmt.Printf("🎯 Processing text with operation: %s\n", operation)
		utilityResult, err := integrationSystem.ExecuteTool(ctx, utilityTool.ID(), utilityInput, securityOptions)
		if err != nil {
			log.Printf("Utility tool execution failed: %v", err)
		} else {
			if result, ok := utilityResult.Result.(map[string]interface{}); ok {
				fmt.Printf("   Result: %s\n", result["processed_text"])
			}
		}
	}

	fmt.Println()

	// Demo 4: Tool Discovery and Registry
	fmt.Println("🔍 Demo 4: Tool Discovery and Registry")
	fmt.Println(strings.Repeat("-", 60))

	// Query tools by category
	securityQuery := integration.RegistryQuery{
		Categories: []string{"security"},
		Status:     []integration.IntegrationStatus{integration.StatusActive},
		Limit:      10,
	}

	securityTools, err := integrationSystem.QueryIntegrations(securityQuery)
	if err != nil {
		log.Printf("Failed to query security tools: %v", err)
	} else {
		fmt.Printf("✅ Found %d security tools\n", len(securityTools))
		for _, tool := range securityTools {
			fmt.Printf("   - %s: %s\n", tool.Tool.ID(), tool.Tool.Name())
		}
	}

	// Query tools by capabilities
	capabilityQuery := integration.RegistryQuery{
		Capabilities: []integration.ToolCapability{integration.CapabilityRetryable},
		SortBy:       "execution_count",
		SortOrder:    "desc",
	}

	retryableTools, err := integrationSystem.QueryIntegrations(capabilityQuery)
	if err != nil {
		log.Printf("Failed to query retryable tools: %v", err)
	} else {
		fmt.Printf("✅ Found %d retryable tools\n", len(retryableTools))
	}

	// Get registry statistics
	registryStats := integrationSystem.GetRegistryStats()
	fmt.Printf("✅ Registry Statistics:\n")
	fmt.Printf("   Total Integrations: %d\n", registryStats.TotalIntegrations)
	fmt.Printf("   Active Tools: %d\n", registryStats.IntegrationsByStatus[integration.StatusActive])
	fmt.Printf("   Categories: %d\n", len(registryStats.CategoriesCount))
	fmt.Printf("   Average Success Rate: %.1f%%\n", registryStats.AverageSuccessRate*100)

	fmt.Println()

	// Demo 5: Monitoring and Metrics
	fmt.Println("📊 Demo 5: Monitoring and Metrics")
	fmt.Println(strings.Repeat("-", 60))

	// Get system statistics
	systemStats := integrationSystem.GetSystemStats()
	fmt.Printf("✅ System Statistics:\n")
	fmt.Printf("   Total Tools: %d\n", systemStats.TotalTools)
	fmt.Printf("   Active Tools: %d\n", systemStats.ActiveTools)
	fmt.Printf("   Total Executions: %d\n", systemStats.TotalExecutions)
	fmt.Printf("   Success Rate: %.1f%%\n", systemStats.SuccessRate*100)
	fmt.Printf("   Average Latency: %v\n", systemStats.AverageLatency)

	// Get individual tool metrics
	fmt.Printf("✅ Individual Tool Metrics:\n")
	integrations := integrationSystem.GetIntegrations()
	for _, integration := range integrations {
		metrics := integration.Metrics
		fmt.Printf("   %s:\n", integration.Tool.Name())
		fmt.Printf("     Executions: %d\n", metrics.ExecutionCount)
		fmt.Printf("     Success Rate: %.1f%%\n", metrics.SuccessRate*100)
		fmt.Printf("     Average Latency: %v\n", metrics.AverageLatency)
	}

	// Get security statistics
	securityStats, err := integrationSystem.GetSecurityStats()
	if err != nil {
		log.Printf("Failed to get security statistics: %v", err)
	} else {
		fmt.Printf("✅ Security Statistics:\n")
		fmt.Printf("   Active Sessions: %d\n", securityStats.ActiveSessions)
		fmt.Printf("   Total Users: %d\n", securityStats.TotalUsers)
		fmt.Printf("   Audit Entries: %d\n", securityStats.AuditEntries)
		fmt.Printf("   Security Level: %s\n", securityStats.SecurityLevel)
	}

	fmt.Println()

	// Demo Summary
	fmt.Println("🎉 Tool Integration System Demo Summary")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("✅ Tool Registration: Advanced configuration with rate limiting, circuit breakers, and caching\n")
	fmt.Printf("✅ Security Management: User permissions, sessions, and audit logging\n")
	fmt.Printf("✅ Tool Execution: Retry logic, timeout handling, and error recovery\n")
	fmt.Printf("✅ Tool Discovery: Query by category, capabilities, and status\n")
	fmt.Printf("✅ Monitoring: Comprehensive metrics and performance tracking\n")
	fmt.Printf("✅ Validation: Input validation and tool interface checking\n")
	fmt.Printf("\n🚀 Tool Integration System demonstrated successfully!\n")
	fmt.Printf("   Features: Security, Validation, Monitoring, Discovery, Caching, Rate Limiting\n")
	fmt.Printf("   Tools Registered: %d\n", len(integrations))
	fmt.Printf("   Total Executions: %d\n", systemStats.TotalExecutions)
	fmt.Printf("   System Success Rate: %.1f%%\n", systemStats.SuccessRate*100)

	logger.Info("Tool Integration System Demo completed successfully")
}
