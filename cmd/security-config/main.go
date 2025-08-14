package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/dimajoyti/hackai/pkg/config"
	"gopkg.in/yaml.v3"
)

// SimpleLogger implements the config.Logger interface
type SimpleLogger struct{}

func (s *SimpleLogger) Info(msg string, fields ...interface{}) {
	fmt.Printf("[INFO] %s", msg)
	if len(fields) > 0 {
		fmt.Printf(" %v", fields)
	}
	fmt.Println()
}

func (s *SimpleLogger) Error(msg string, fields ...interface{}) {
	fmt.Printf("[ERROR] %s", msg)
	if len(fields) > 0 {
		fmt.Printf(" %v", fields)
	}
	fmt.Println()
}

func (s *SimpleLogger) Warn(msg string, fields ...interface{}) {
	fmt.Printf("[WARN] %s", msg)
	if len(fields) > 0 {
		fmt.Printf(" %v", fields)
	}
	fmt.Println()
}

func main() {
	var (
		configPath = flag.String("config", "configs/security.yaml", "Path to security configuration file")
		command    = flag.String("command", "", "Command to execute: generate, validate, show, update, watch")
		profile    = flag.String("profile", "production", "Security profile: development, staging, production, high_security, compliance")
		output     = flag.String("output", "", "Output file path (for generate command)")
		format     = flag.String("format", "yaml", "Output format: yaml, json")
		component  = flag.String("component", "", "Component name for updates")
		threshold  = flag.String("threshold", "", "Threshold name for updates")
		value      = flag.String("value", "", "New value for updates")
		feature    = flag.String("feature", "", "Feature toggle name")
		enabled    = flag.Bool("enabled", false, "Enable/disable feature toggle")
	)
	flag.Parse()

	if *command == "" {
		printUsage()
		os.Exit(1)
	}

	logger := &SimpleLogger{}

	switch *command {
	case "generate":
		generateConfig(*profile, *output, *format, logger)
	case "validate":
		validateConfig(*configPath, logger)
	case "show":
		showConfig(*configPath, *format, logger)
	case "update":
		updateConfig(*configPath, *component, *threshold, *value, logger)
	case "feature":
		updateFeature(*configPath, *feature, *enabled, logger)
	case "watch":
		watchConfig(*configPath, logger)
	case "env-vars":
		showEnvironmentVariables()
	default:
		fmt.Printf("Unknown command: %s\n", *command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Security Configuration Management Tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  security-config -command=generate -profile=production -output=security.yaml")
	fmt.Println("  security-config -command=validate -config=security.yaml")
	fmt.Println("  security-config -command=show -config=security.yaml -format=json")
	fmt.Println("  security-config -command=update -config=security.yaml -component=ai_firewall -threshold=block -value=0.8")
	fmt.Println("  security-config -command=feature -config=security.yaml -feature=advanced_threat_detection -enabled=true")
	fmt.Println("  security-config -command=watch -config=security.yaml")
	fmt.Println("  security-config -command=env-vars")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  generate   Generate configuration template")
	fmt.Println("  validate   Validate configuration file")
	fmt.Println("  show       Show current configuration")
	fmt.Println("  update     Update configuration threshold")
	fmt.Println("  feature    Update feature toggle")
	fmt.Println("  watch      Watch configuration for changes")
	fmt.Println("  env-vars   Show supported environment variables")
	fmt.Println()
	fmt.Println("Profiles:")
	fmt.Println("  development   Development environment (relaxed security)")
	fmt.Println("  staging       Staging environment (moderate security)")
	fmt.Println("  production    Production environment (standard security)")
	fmt.Println("  high_security High security environment (strict security)")
	fmt.Println("  compliance    Compliance-focused environment (audit-ready)")
}

func generateConfig(profile, output, format string, logger *SimpleLogger) {
	logger.Info("Generating security configuration", "profile", profile)

	// Get template
	securityProfile := config.SecurityProfile(profile)
	cfg := config.GetSecurityTemplate(securityProfile)

	if output == "" {
		output = fmt.Sprintf("security-%s.%s", profile, format)
	}

	// Save configuration
	loader := config.NewSecurityConfigLoader("", profile)
	if err := loader.SaveConfiguration(cfg, output); err != nil {
		logger.Error("Failed to save configuration", "error", err)
		os.Exit(1)
	}

	logger.Info("Configuration generated successfully", "output", output)
}

func validateConfig(configPath string, logger *SimpleLogger) {
	logger.Info("Validating security configuration", "path", configPath)

	loader := config.NewSecurityConfigLoader(configPath, "")
	_, err := loader.LoadSecurityConfig()
	if err != nil {
		logger.Error("Configuration validation failed", "error", err)
		os.Exit(1)
	}

	logger.Info("Configuration is valid")
}

func showConfig(configPath, format string, logger *SimpleLogger) {
	logger.Info("Loading security configuration", "path", configPath)

	loader := config.NewSecurityConfigLoader(configPath, "")
	cfg, err := loader.LoadSecurityConfig()
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	var output []byte
	switch format {
	case "json":
		output, err = json.MarshalIndent(cfg, "", "  ")
	case "yaml":
		output, err = yaml.Marshal(cfg)
	default:
		logger.Error("Unsupported format", "format", format)
		os.Exit(1)
	}

	if err != nil {
		logger.Error("Failed to marshal configuration", "error", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}

func updateConfig(configPath, component, threshold, valueStr string, logger *SimpleLogger) {
	if component == "" || threshold == "" || valueStr == "" {
		logger.Error("Component, threshold, and value are required for update command")
		os.Exit(1)
	}

	value, err := strconv.ParseFloat(valueStr, 64)
	if err != nil {
		logger.Error("Invalid value", "value", valueStr, "error", err)
		os.Exit(1)
	}

	logger.Info("Updating configuration threshold", "component", component, "threshold", threshold, "value", value)

	manager := config.NewSecurityConfigManager(configPath, logger)
	if err := manager.LoadConfig(); err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	if err := manager.UpdateThreshold(component, threshold, value); err != nil {
		logger.Error("Failed to update threshold", "error", err)
		os.Exit(1)
	}

	if err := manager.SaveConfig(); err != nil {
		logger.Error("Failed to save configuration", "error", err)
		os.Exit(1)
	}

	logger.Info("Configuration updated successfully")
}

func updateFeature(configPath, feature string, enabled bool, logger *SimpleLogger) {
	if feature == "" {
		logger.Error("Feature name is required for feature command")
		os.Exit(1)
	}

	logger.Info("Updating feature toggle", "feature", feature, "enabled", enabled)

	manager := config.NewSecurityConfigManager(configPath, logger)
	if err := manager.LoadConfig(); err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	if err := manager.UpdateFeatureToggle(feature, enabled); err != nil {
		logger.Error("Failed to update feature toggle", "error", err)
		os.Exit(1)
	}

	if err := manager.SaveConfig(); err != nil {
		logger.Error("Failed to save configuration", "error", err)
		os.Exit(1)
	}

	logger.Info("Feature toggle updated successfully")
}

func watchConfig(configPath string, logger *SimpleLogger) {
	logger.Info("Starting configuration watcher", "path", configPath)

	manager := config.NewSecurityConfigManager(configPath, logger)
	if err := manager.LoadConfig(); err != nil {
		logger.Error("Failed to load initial configuration", "error", err)
		os.Exit(1)
	}

	if err := manager.StartConfigWatcher(); err != nil {
		logger.Error("Failed to start config watcher", "error", err)
		os.Exit(1)
	}

	logger.Info("Configuration watcher started. Press Ctrl+C to stop.")

	// Keep the program running
	select {}
}

func showEnvironmentVariables() {
	fmt.Println("Supported Environment Variables:")
	fmt.Println()

	loader := config.NewSecurityConfigLoader("", "")
	envVars := loader.GetEnvironmentVariablesList()

	categories := map[string][]string{
		"Agentic Framework":   {},
		"AI Firewall":         {},
		"Input/Output Filter": {},
		"Prompt Guard":        {},
		"Web Layer":           {},
		"Authentication":      {},
		"Monitoring":          {},
		"Logging":             {},
		"Feature Toggles":     {},
		"Threat Intelligence": {},
	}

	for _, envVar := range envVars {
		switch {
		case strings.Contains(envVar, "AGENTIC"):
			categories["Agentic Framework"] = append(categories["Agentic Framework"], envVar)
		case strings.Contains(envVar, "FIREWALL"):
			categories["AI Firewall"] = append(categories["AI Firewall"], envVar)
		case strings.Contains(envVar, "FILTER"):
			categories["Input/Output Filter"] = append(categories["Input/Output Filter"], envVar)
		case strings.Contains(envVar, "PROMPT"):
			categories["Prompt Guard"] = append(categories["Prompt Guard"], envVar)
		case strings.Contains(envVar, "WEB_LAYER") || strings.Contains(envVar, "CSP") || strings.Contains(envVar, "HSTS"):
			categories["Web Layer"] = append(categories["Web Layer"], envVar)
		case strings.Contains(envVar, "PASSWORD") || strings.Contains(envVar, "MFA") || strings.Contains(envVar, "SESSION"):
			categories["Authentication"] = append(categories["Authentication"], envVar)
		case strings.Contains(envVar, "MONITORING") || strings.Contains(envVar, "METRICS") || strings.Contains(envVar, "TRACING"):
			categories["Monitoring"] = append(categories["Monitoring"], envVar)
		case strings.Contains(envVar, "LOG"):
			categories["Logging"] = append(categories["Logging"], envVar)
		case strings.Contains(envVar, "MAINTENANCE") || strings.Contains(envVar, "DEBUG"):
			categories["Feature Toggles"] = append(categories["Feature Toggles"], envVar)
		case strings.Contains(envVar, "THREAT_INTEL"):
			categories["Threat Intelligence"] = append(categories["Threat Intelligence"], envVar)
		}
	}

	for category, vars := range categories {
		if len(vars) > 0 {
			fmt.Printf("%s:\n", category)
			for _, envVar := range vars {
				fmt.Printf("  %s\n", envVar)
			}
			fmt.Println()
		}
	}

	fmt.Println("Examples:")
	fmt.Println("  export SECURITY_AGENTIC_ENABLED=true")
	fmt.Println("  export SECURITY_FIREWALL_BLOCK_THRESHOLD=0.8")
	fmt.Println("  export SECURITY_LOG_LEVEL=debug")
	fmt.Println("  export SECURITY_MAINTENANCE_MODE=false")
}
