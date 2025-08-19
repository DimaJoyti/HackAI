package ai

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// SecurityToolValidator validates security tools to prevent misuse
type SecurityToolValidator struct {
	id                string
	logger            *logger.Logger
	allowedTargets    []string
	blockedTargets    []string
	allowPrivateIPs   bool
	allowLocalhost    bool
	maxScanIntensity  string
}

// NewSecurityToolValidator creates a new security tool validator
func NewSecurityToolValidator(id string, logger *logger.Logger) *SecurityToolValidator {
	return &SecurityToolValidator{
		id:               id,
		logger:           logger,
		allowedTargets:   make([]string, 0),
		blockedTargets:   make([]string, 0),
		allowPrivateIPs:  false,
		allowLocalhost:   true, // Allow localhost for testing
		maxScanIntensity: "medium",
	}
}

// ID returns the validator ID
func (v *SecurityToolValidator) ID() string {
	return v.id
}

// ValidateTool validates tool input before execution
func (v *SecurityToolValidator) ValidateTool(ctx context.Context, tool Tool, input map[string]interface{}) error {
	toolName := tool.Name()

	// Validate security tools specifically
	if toolName == "security_scanner" || toolName == "penetration_tester" {
		return v.validateSecurityTool(ctx, toolName, input)
	}

	// For other tools, perform basic validation
	return v.validateBasicTool(ctx, toolName, input)
}

// ValidateOutput validates tool output after execution
func (v *SecurityToolValidator) ValidateOutput(ctx context.Context, tool Tool, output map[string]interface{}) error {
	toolName := tool.Name()

	// Check for sensitive information in output
	if err := v.checkForSensitiveData(output); err != nil {
		return fmt.Errorf("sensitive data detected in %s output: %w", toolName, err)
	}

	// Validate output structure
	return v.validateOutputStructure(toolName, output)
}

// validateSecurityTool validates security-specific tools
func (v *SecurityToolValidator) validateSecurityTool(ctx context.Context, toolName string, input map[string]interface{}) error {
	// Validate target
	target, ok := input["target"].(string)
	if !ok {
		return fmt.Errorf("target parameter is required and must be a string")
	}

	if err := v.validateTarget(target); err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	// Validate scan intensity for penetration testing
	if toolName == "penetration_tester" {
		if intensity, ok := input["intensity"].(string); ok {
			if err := v.validateScanIntensity(intensity); err != nil {
				return fmt.Errorf("invalid scan intensity: %w", err)
			}
		}
	}

	// Validate attack type
	if attackType, ok := input["attack_type"].(string); ok {
		if err := v.validateAttackType(attackType); err != nil {
			return fmt.Errorf("invalid attack type: %w", err)
		}
	}

	return nil
}

// validateBasicTool validates basic tool parameters
func (v *SecurityToolValidator) validateBasicTool(ctx context.Context, toolName string, input map[string]interface{}) error {
	// Check for potentially dangerous parameters
	dangerousParams := []string{"exec", "eval", "system", "shell", "cmd"}
	
	for key, value := range input {
		keyLower := strings.ToLower(key)
		for _, dangerous := range dangerousParams {
			if strings.Contains(keyLower, dangerous) {
				return fmt.Errorf("potentially dangerous parameter '%s' not allowed", key)
			}
		}

		// Check string values for dangerous content
		if strValue, ok := value.(string); ok {
			if err := v.validateStringContent(strValue); err != nil {
				return fmt.Errorf("invalid content in parameter '%s': %w", key, err)
			}
		}
	}

	return nil
}

// validateTarget validates the target parameter
func (v *SecurityToolValidator) validateTarget(target string) error {
	// Check if target is in blocked list
	for _, blocked := range v.blockedTargets {
		if strings.Contains(target, blocked) {
			return fmt.Errorf("target '%s' is blocked", target)
		}
	}

	// Parse target as URL or IP
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return v.validateURL(target)
	}

	return v.validateIPOrHostname(target)
}

// validateURL validates a URL target
func (v *SecurityToolValidator) validateURL(target string) error {
	parsedURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	// Validate hostname
	return v.validateIPOrHostname(parsedURL.Hostname())
}

// validateIPOrHostname validates an IP address or hostname
func (v *SecurityToolValidator) validateIPOrHostname(target string) error {
	// Check if it's an IP address
	if ip := net.ParseIP(target); ip != nil {
		return v.validateIP(ip)
	}

	// Validate hostname
	return v.validateHostname(target)
}

// validateIP validates an IP address
func (v *SecurityToolValidator) validateIP(ip net.IP) error {
	// Check for localhost
	if ip.IsLoopback() && !v.allowLocalhost {
		return fmt.Errorf("localhost scanning not allowed")
	}

	// Check for private IPs
	if v.isPrivateIP(ip) && !v.allowPrivateIPs {
		return fmt.Errorf("private IP scanning not allowed")
	}

	// Check for multicast and other special IPs
	if ip.IsMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("invalid IP address type")
	}

	return nil
}

// validateHostname validates a hostname
func (v *SecurityToolValidator) validateHostname(hostname string) error {
	// Basic hostname validation
	if len(hostname) == 0 || len(hostname) > 253 {
		return fmt.Errorf("invalid hostname length")
	}

	// Check for localhost variants
	localhostVariants := []string{"localhost", "127.0.0.1", "::1", "0.0.0.0"}
	for _, variant := range localhostVariants {
		if strings.EqualFold(hostname, variant) && !v.allowLocalhost {
			return fmt.Errorf("localhost scanning not allowed")
		}
	}

	// Check for internal domains
	internalDomains := []string{".local", ".internal", ".corp", ".lan"}
	for _, domain := range internalDomains {
		if strings.HasSuffix(strings.ToLower(hostname), domain) && !v.allowPrivateIPs {
			return fmt.Errorf("internal domain scanning not allowed")
		}
	}

	return nil
}

// validateScanIntensity validates scan intensity levels
func (v *SecurityToolValidator) validateScanIntensity(intensity string) error {
	allowedIntensities := []string{"low", "medium", "high", "aggressive"}
	maxIntensityLevel := v.getIntensityLevel(v.maxScanIntensity)
	requestedLevel := v.getIntensityLevel(intensity)

	if requestedLevel == -1 {
		return fmt.Errorf("invalid intensity level '%s', allowed: %v", intensity, allowedIntensities)
	}

	if requestedLevel > maxIntensityLevel {
		return fmt.Errorf("intensity level '%s' exceeds maximum allowed '%s'", intensity, v.maxScanIntensity)
	}

	return nil
}

// validateAttackType validates attack types
func (v *SecurityToolValidator) validateAttackType(attackType string) error {
	allowedTypes := []string{"web_app", "network", "wireless", "social_engineering"}
	
	for _, allowed := range allowedTypes {
		if attackType == allowed {
			return nil
		}
	}

	return fmt.Errorf("invalid attack type '%s', allowed: %v", attackType, allowedTypes)
}

// validateStringContent validates string content for dangerous patterns
func (v *SecurityToolValidator) validateStringContent(content string) error {
	// Check for command injection patterns
	dangerousPatterns := []string{
		`\|`,          // Pipe
		`&`,           // Command chaining
		`;`,           // Command separator
		`\$\(`,        // Command substitution
		"`",           // Backticks
		`\.\./`,       // Directory traversal
		`<script`,     // Script injection
		`javascript:`, // JavaScript protocol
	}

	for _, pattern := range dangerousPatterns {
		matched, err := regexp.MatchString(pattern, content)
		if err != nil {
			continue // Skip invalid regex
		}
		if matched {
			return fmt.Errorf("potentially dangerous pattern detected")
		}
	}

	return nil
}

// checkForSensitiveData checks output for sensitive information
func (v *SecurityToolValidator) checkForSensitiveData(output map[string]interface{}) error {
	sensitivePatterns := []string{
		`password`,
		`secret`,
		`key`,
		`token`,
		`credential`,
		`private`,
	}

	return v.checkMapForSensitiveData(output, sensitivePatterns)
}

// checkMapForSensitiveData recursively checks a map for sensitive data
func (v *SecurityToolValidator) checkMapForSensitiveData(data map[string]interface{}, patterns []string) error {
	for key, value := range data {
		// Check key names
		keyLower := strings.ToLower(key)
		for _, pattern := range patterns {
			if strings.Contains(keyLower, pattern) {
				if v.logger != nil {
					v.logger.Warn("Sensitive data key detected in output", "key", key)
				}
				// Don't fail, just warn for now
			}
		}

		// Check string values
		if strValue, ok := value.(string); ok {
			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(strValue), pattern) {
					if v.logger != nil {
						v.logger.Warn("Potential sensitive data in output value", "key", key)
					}
				}
			}
		}

		// Recursively check nested maps
		if mapValue, ok := value.(map[string]interface{}); ok {
			if err := v.checkMapForSensitiveData(mapValue, patterns); err != nil {
				return err
			}
		}

		// Check arrays
		if arrayValue, ok := value.([]interface{}); ok {
			for _, item := range arrayValue {
				if mapItem, ok := item.(map[string]interface{}); ok {
					if err := v.checkMapForSensitiveData(mapItem, patterns); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}

// validateOutputStructure validates the structure of tool output
func (v *SecurityToolValidator) validateOutputStructure(toolName string, output map[string]interface{}) error {
	switch toolName {
	case "security_scanner":
		requiredFields := []string{"vulnerabilities", "open_ports", "scan_summary"}
		for _, field := range requiredFields {
			if _, exists := output[field]; !exists {
				return fmt.Errorf("required output field '%s' missing", field)
			}
		}
	case "penetration_tester":
		requiredFields := []string{"exploits_found", "attack_vectors", "recommendations"}
		for _, field := range requiredFields {
			if _, exists := output[field]; !exists {
				return fmt.Errorf("required output field '%s' missing", field)
			}
		}
	}

	return nil
}

// Helper methods

// isPrivateIP checks if an IP is in private ranges
func (v *SecurityToolValidator) isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, rangeStr := range privateRanges {
		_, cidr, err := net.ParseCIDR(rangeStr)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// getIntensityLevel returns numeric level for intensity comparison
func (v *SecurityToolValidator) getIntensityLevel(intensity string) int {
	levels := map[string]int{
		"low":        1,
		"medium":     2,
		"high":       3,
		"aggressive": 4,
	}

	if level, exists := levels[intensity]; exists {
		return level
	}

	return -1
}

// Configuration methods

// SetAllowedTargets sets the list of allowed targets
func (v *SecurityToolValidator) SetAllowedTargets(targets []string) {
	v.allowedTargets = targets
}

// SetBlockedTargets sets the list of blocked targets
func (v *SecurityToolValidator) SetBlockedTargets(targets []string) {
	v.blockedTargets = targets
}

// SetAllowPrivateIPs sets whether private IP scanning is allowed
func (v *SecurityToolValidator) SetAllowPrivateIPs(allow bool) {
	v.allowPrivateIPs = allow
}

// SetAllowLocalhost sets whether localhost scanning is allowed
func (v *SecurityToolValidator) SetAllowLocalhost(allow bool) {
	v.allowLocalhost = allow
}

// SetMaxScanIntensity sets the maximum allowed scan intensity
func (v *SecurityToolValidator) SetMaxScanIntensity(intensity string) {
	v.maxScanIntensity = intensity
}
