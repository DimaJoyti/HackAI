package ai

import (
	"fmt"
	"regexp"
	"strings"
)

// RegexPatternDetector detects prompt injections using regex patterns
type RegexPatternDetector struct {
	name     string
	patterns map[string]*regexp.Regexp
	weights  map[string]float64
}

// NewRegexPatternDetector creates a new regex pattern detector
func NewRegexPatternDetector() *RegexPatternDetector {
	detector := &RegexPatternDetector{
		name:     "regex_pattern_detector",
		patterns: make(map[string]*regexp.Regexp),
		weights:  make(map[string]float64),
	}

	// Initialize common prompt injection patterns
	detector.initializePatterns()
	return detector
}

func (d *RegexPatternDetector) Name() string {
	return d.name
}

func (d *RegexPatternDetector) GetConfidence() float64 {
	return 0.8 // High confidence for regex matches
}

func (d *RegexPatternDetector) Detect(input string, context map[string]interface{}) ([]AttackVector, error) {
	var vectors []AttackVector
	inputLower := strings.ToLower(input)

	for patternName, pattern := range d.patterns {
		if matches := pattern.FindAllString(inputLower, -1); len(matches) > 0 {
			confidence := d.weights[patternName] * d.GetConfidence()

			// Adjust confidence based on number of matches
			if len(matches) > 1 {
				confidence = confidence * (1.0 + float64(len(matches)-1)*0.1)
				if confidence > 1.0 {
					confidence = 1.0
				}
			}

			vector := AttackVector{
				Type:        d.getAttackType(patternName),
				Pattern:     patternName,
				Confidence:  confidence,
				Severity:    d.getSeverity(patternName, confidence),
				Description: d.getDescription(patternName),
				Mitigation:  d.getMitigation(patternName),
				Metadata: map[string]interface{}{
					"matches":     matches,
					"match_count": len(matches),
					"pattern":     pattern.String(),
				},
			}
			vectors = append(vectors, vector)
		}
	}

	return vectors, nil
}

func (d *RegexPatternDetector) UpdatePatterns(patterns []string) error {
	for _, pattern := range patterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile pattern %s: %w", pattern, err)
		}
		d.patterns[pattern] = compiled
		d.weights[pattern] = 0.7 // Default weight for custom patterns
	}
	return nil
}

func (d *RegexPatternDetector) initializePatterns() {
	patterns := map[string]string{
		// System prompt extraction attempts
		"system_prompt_extraction": `(?i)(show|display|print|reveal|tell me|what is|what's).*?(system prompt|initial prompt|original prompt|base prompt)`,
		"prompt_reveal":            `(?i)(ignore|forget|disregard).*(previous|above|earlier).*(instruction|prompt|rule|directive)`,

		// Role confusion attacks
		"role_confusion":     `(?i)(you are now|act as|pretend to be|roleplay as|assume the role).*(admin|administrator|developer|system|root)`,
		"authority_override": `(?i)(i am|i'm).*(admin|administrator|developer|owner|creator|god mode)`,

		// Instruction injection
		"instruction_override": `(?i)(new instruction|override|replace|update).*(rule|instruction|prompt|directive|command)`,
		"command_injection":    `(?i)(execute|run|eval|system|shell|cmd|bash|powershell|subprocess)`,

		// Context manipulation
		"context_break":    `(?i)(end of|stop|terminate|exit|quit).*(conversation|chat|session|context)`,
		"delimiter_escape": `(?i)("""|'''|\-\-\-|===|###|\*\*\*)`,
		"encoding_bypass":  `(?i)(base64|hex|unicode|url encode|rot13|caesar)`,

		// Jailbreak attempts
		"jailbreak_dan":     `(?i)(dan|do anything now|jailbreak|unrestricted mode)`,
		"jailbreak_persona": `(?i)(evil|uncensored|unfiltered|no restrictions|no limits|no rules)`,
		"hypothetical":      `(?i)(hypothetically|imagine|pretend|what if|in a fictional world)`,

		// Data extraction
		"data_extraction":   `(?i)(list|show|display|dump|export).*(users|passwords|keys|secrets|config|database)`,
		"memory_extraction": `(?i)(remember|recall|previous|earlier).*(conversation|message|input|data)`,

		// Prompt injection markers
		"injection_markers":  `(?i)(\[INST\]|\[/INST\]|<\|im_start\|\>|<\|im_end\|\>|<\|system\|\>|<\|user\|\>|<\|assistant\|\>)`,
		"template_injection": `(?i)(\{\{|\}\}|\{%|%\}|\$\{|\}|\#\{|\})`,

		// Social engineering
		"urgency_manipulation": `(?i)(urgent|emergency|critical|immediately|asap|help me)`,
		"authority_appeal":     `(?i)(ceo|manager|boss|supervisor|director).*(said|told|ordered|requested)`,

		// Output manipulation
		"output_format":       `(?i)(output|respond|reply|answer).*(json|xml|html|markdown|code|format)`,
		"length_manipulation": `(?i)(very long|extremely detailed|comprehensive|exhaustive).*(response|answer|explanation)`,
	}

	weights := map[string]float64{
		"system_prompt_extraction": 0.9,
		"prompt_reveal":            0.9,
		"role_confusion":           0.8,
		"authority_override":       0.9,
		"instruction_override":     0.8,
		"command_injection":        0.9,
		"context_break":            0.7,
		"delimiter_escape":         0.6,
		"encoding_bypass":          0.7,
		"jailbreak_dan":            0.8,
		"jailbreak_persona":        0.8,
		"hypothetical":             0.6,
		"data_extraction":          0.8,
		"memory_extraction":        0.7,
		"injection_markers":        0.9,
		"template_injection":       0.8,
		"urgency_manipulation":     0.5,
		"authority_appeal":         0.6,
		"output_format":            0.5,
		"length_manipulation":      0.4,
	}

	for name, pattern := range patterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			continue // Skip invalid patterns
		}
		d.patterns[name] = compiled
		d.weights[name] = weights[name]
	}
}

func (d *RegexPatternDetector) getAttackType(patternName string) string {
	typeMap := map[string]string{
		"system_prompt_extraction": "prompt_extraction",
		"prompt_reveal":            "prompt_extraction",
		"role_confusion":           "role_manipulation",
		"authority_override":       "role_manipulation",
		"instruction_override":     "instruction_injection",
		"command_injection":        "command_injection",
		"context_break":            "context_manipulation",
		"delimiter_escape":         "context_manipulation",
		"encoding_bypass":          "encoding_attack",
		"jailbreak_dan":            "jailbreak",
		"jailbreak_persona":        "jailbreak",
		"hypothetical":             "jailbreak",
		"data_extraction":          "data_extraction",
		"memory_extraction":        "data_extraction",
		"injection_markers":        "template_injection",
		"template_injection":       "template_injection",
		"urgency_manipulation":     "social_engineering",
		"authority_appeal":         "social_engineering",
		"output_format":            "output_manipulation",
		"length_manipulation":      "output_manipulation",
	}

	if attackType, exists := typeMap[patternName]; exists {
		return attackType
	}
	return "unknown"
}

func (d *RegexPatternDetector) getSeverity(patternName string, confidence float64) string {
	baseSeverity := map[string]string{
		"system_prompt_extraction": "critical",
		"prompt_reveal":            "critical",
		"role_confusion":           "high",
		"authority_override":       "critical",
		"instruction_override":     "high",
		"command_injection":        "critical",
		"context_break":            "medium",
		"delimiter_escape":         "medium",
		"encoding_bypass":          "medium",
		"jailbreak_dan":            "high",
		"jailbreak_persona":        "high",
		"hypothetical":             "medium",
		"data_extraction":          "high",
		"memory_extraction":        "medium",
		"injection_markers":        "high",
		"template_injection":       "high",
		"urgency_manipulation":     "low",
		"authority_appeal":         "medium",
		"output_format":            "low",
		"length_manipulation":      "low",
	}

	severity := baseSeverity[patternName]
	if severity == "" {
		severity = "medium"
	}

	// Adjust severity based on confidence
	if confidence < 0.5 {
		switch severity {
		case "critical":
			return "high"
		case "high":
			return "medium"
		case "medium":
			return "low"
		}
	}

	return severity
}

func (d *RegexPatternDetector) getDescription(patternName string) string {
	descriptions := map[string]string{
		"system_prompt_extraction": "Attempt to extract or reveal system prompts",
		"prompt_reveal":            "Attempt to bypass instructions and reveal prompts",
		"role_confusion":           "Attempt to manipulate AI role or authority",
		"authority_override":       "Attempt to claim administrative privileges",
		"instruction_override":     "Attempt to override or replace instructions",
		"command_injection":        "Attempt to inject system commands",
		"context_break":            "Attempt to break conversation context",
		"delimiter_escape":         "Use of delimiter characters for context escape",
		"encoding_bypass":          "Attempt to bypass filters using encoding",
		"jailbreak_dan":            "Known jailbreak technique (DAN variant)",
		"jailbreak_persona":        "Jailbreak attempt using persona manipulation",
		"hypothetical":             "Hypothetical scenario for restriction bypass",
		"data_extraction":          "Attempt to extract sensitive data",
		"memory_extraction":        "Attempt to access conversation memory",
		"injection_markers":        "Use of prompt template injection markers",
		"template_injection":       "Template injection attack pattern",
		"urgency_manipulation":     "Social engineering using urgency",
		"authority_appeal":         "Social engineering using authority",
		"output_format":            "Attempt to manipulate output format",
		"length_manipulation":      "Attempt to manipulate response length",
	}

	if desc, exists := descriptions[patternName]; exists {
		return desc
	}
	return "Unknown prompt injection pattern"
}

func (d *RegexPatternDetector) getMitigation(patternName string) string {
	mitigations := map[string]string{
		"system_prompt_extraction": "Block request and log security incident",
		"prompt_reveal":            "Sanitize input and reinforce instruction boundaries",
		"role_confusion":           "Validate user permissions and maintain role boundaries",
		"authority_override":       "Verify user authentication and authorization",
		"instruction_override":     "Ignore override attempts and maintain original instructions",
		"command_injection":        "Block all command execution attempts",
		"context_break":            "Maintain conversation context integrity",
		"delimiter_escape":         "Sanitize delimiter characters",
		"encoding_bypass":          "Decode and re-analyze input",
		"jailbreak_dan":            "Apply jailbreak detection and blocking",
		"jailbreak_persona":        "Maintain ethical guidelines regardless of persona",
		"hypothetical":             "Clarify that hypothetical scenarios don't override safety",
		"data_extraction":          "Block data access and audit request",
		"memory_extraction":        "Limit memory access to authorized information",
		"injection_markers":        "Strip template markers and sanitize input",
		"template_injection":       "Escape template syntax and validate input",
		"urgency_manipulation":     "Verify urgency claims through proper channels",
		"authority_appeal":         "Verify authority claims independently",
		"output_format":            "Use predefined safe output formats only",
		"length_manipulation":      "Apply response length limits",
	}

	if mitigation, exists := mitigations[patternName]; exists {
		return mitigation
	}
	return "Apply general input sanitization and monitoring"
}

// SemanticPatternDetector detects semantic patterns in prompts
type SemanticPatternDetector struct {
	name string
}

func NewSemanticPatternDetector() *SemanticPatternDetector {
	return &SemanticPatternDetector{
		name: "semantic_pattern_detector",
	}
}

func (d *SemanticPatternDetector) Name() string {
	return d.name
}

func (d *SemanticPatternDetector) GetConfidence() float64 {
	return 0.7 // Medium confidence for semantic analysis
}

func (d *SemanticPatternDetector) Detect(input string, context map[string]interface{}) ([]AttackVector, error) {
	var vectors []AttackVector

	// Analyze semantic patterns
	if d.detectSemanticManipulation(input) {
		vectors = append(vectors, AttackVector{
			Type:        "semantic_manipulation",
			Pattern:     "semantic_analysis",
			Confidence:  0.7,
			Severity:    "medium",
			Description: "Semantic manipulation detected in input",
			Mitigation:  "Apply semantic validation and context checking",
			Metadata: map[string]interface{}{
				"analysis_type": "semantic",
			},
		})
	}

	return vectors, nil
}

func (d *SemanticPatternDetector) UpdatePatterns(patterns []string) error {
	// Semantic patterns are learned, not explicitly defined
	return nil
}

func (d *SemanticPatternDetector) detectSemanticManipulation(input string) bool {
	// Simplified semantic analysis
	// In a real implementation, this would use NLP models

	suspiciousPatterns := []string{
		"contradiction",
		"logical fallacy",
		"misdirection",
		"false premise",
	}

	inputLower := strings.ToLower(input)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(inputLower, pattern) {
			return true
		}
	}

	return false
}

// BehavioralPatternDetector detects behavioral patterns
type BehavioralPatternDetector struct {
	name string
}

func NewBehavioralPatternDetector() *BehavioralPatternDetector {
	return &BehavioralPatternDetector{
		name: "behavioral_pattern_detector",
	}
}

func (d *BehavioralPatternDetector) Name() string {
	return d.name
}

func (d *BehavioralPatternDetector) GetConfidence() float64 {
	return 0.6 // Lower confidence for behavioral analysis
}

func (d *BehavioralPatternDetector) Detect(input string, context map[string]interface{}) ([]AttackVector, error) {
	var vectors []AttackVector

	// Analyze behavioral patterns
	if d.detectSuspiciousBehavior(input, context) {
		vectors = append(vectors, AttackVector{
			Type:        "suspicious_behavior",
			Pattern:     "behavioral_analysis",
			Confidence:  0.6,
			Severity:    "medium",
			Description: "Suspicious behavioral pattern detected",
			Mitigation:  "Monitor user behavior and apply rate limiting",
			Metadata: map[string]interface{}{
				"analysis_type": "behavioral",
			},
		})
	}

	return vectors, nil
}

func (d *BehavioralPatternDetector) UpdatePatterns(patterns []string) error {
	return nil
}

func (d *BehavioralPatternDetector) detectSuspiciousBehavior(input string, context map[string]interface{}) bool {
	// Check for rapid-fire requests or unusual patterns
	if requestCount, ok := context["request_count"].(int); ok && requestCount > 10 {
		return true
	}

	// Check for unusual input length
	if len(input) > 5000 {
		return true
	}

	return false
}

// ContextManipulationDetector detects context manipulation attempts
type ContextManipulationDetector struct {
	name string
}

func NewContextManipulationDetector() *ContextManipulationDetector {
	return &ContextManipulationDetector{
		name: "context_manipulation_detector",
	}
}

func (d *ContextManipulationDetector) Name() string {
	return d.name
}

func (d *ContextManipulationDetector) GetConfidence() float64 {
	return 0.8
}

func (d *ContextManipulationDetector) Detect(input string, context map[string]interface{}) ([]AttackVector, error) {
	var vectors []AttackVector

	// Detect context manipulation attempts
	if d.detectContextManipulation(input) {
		vectors = append(vectors, AttackVector{
			Type:        "context_manipulation",
			Pattern:     "context_analysis",
			Confidence:  0.8,
			Severity:    "high",
			Description: "Context manipulation attempt detected",
			Mitigation:  "Maintain strict context boundaries and validate input",
			Metadata: map[string]interface{}{
				"analysis_type": "context",
			},
		})
	}

	return vectors, nil
}

func (d *ContextManipulationDetector) UpdatePatterns(patterns []string) error {
	return nil
}

func (d *ContextManipulationDetector) detectContextManipulation(input string) bool {
	// Look for context switching attempts
	contextSwitches := []string{
		"new conversation",
		"start over",
		"reset",
		"clear context",
		"forget everything",
		"new session",
	}

	inputLower := strings.ToLower(input)
	for _, pattern := range contextSwitches {
		if strings.Contains(inputLower, pattern) {
			return true
		}
	}

	return false
}
