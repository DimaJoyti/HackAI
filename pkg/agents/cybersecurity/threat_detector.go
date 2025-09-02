package cybersecurity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/llm/providers"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var threatDetectorTracer = otel.Tracer("hackai/agents/cybersecurity/threat_detector")

// ThreatDetector implements AI-powered threat detection
type ThreatDetector struct {
	provider providers.LLMProvider
	logger   *logger.Logger
	patterns ThreatPatterns
}

// ThreatDetectionRequest represents a threat detection request
type ThreatDetectionRequest struct {
	Content string                 `json:"content"`
	Target  string                 `json:"target"`
	Context map[string]interface{} `json:"context"`
	Type    string                 `json:"type,omitempty"`
}

// ThreatDetectionResult represents threat detection results
type ThreatDetectionResult struct {
	Level      string                 `json:"level"`
	Score      float64                `json:"score"`
	Threats    []DetectedThreat       `json:"threats"`
	Indicators []ThreatIndicator      `json:"indicators"`
	Confidence float64                `json:"confidence"`
	Analysis   string                 `json:"analysis"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// DetectedThreat represents a detected threat
type DetectedThreat struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Category    string                 `json:"category"`
	Severity    string                 `json:"severity"`
	Score       float64                `json:"score"`
	Description string                 `json:"description"`
	Evidence    []string               `json:"evidence"`
	MITRE       MITREMapping           `json:"mitre"`
	Indicators  []ThreatIndicator      `json:"indicators"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// MITREMapping represents MITRE ATT&CK framework mapping
type MITREMapping struct {
	TacticID     string   `json:"tactic_id"`
	TacticName   string   `json:"tactic_name"`
	TechniqueID  string   `json:"technique_id"`
	Technique    string   `json:"technique"`
	SubTechnique string   `json:"sub_technique,omitempty"`
	References   []string `json:"references"`
}

// ThreatPatterns contains threat detection patterns
type ThreatPatterns struct {
	PromptInjection   []string `json:"prompt_injection"`
	DataExfiltration  []string `json:"data_exfiltration"`
	ModelExtraction   []string `json:"model_extraction"`
	AdversarialInputs []string `json:"adversarial_inputs"`
	MaliciousCode     []string `json:"malicious_code"`
	SocialEngineering []string `json:"social_engineering"`
}

// NewThreatDetector creates a new threat detector
func NewThreatDetector(provider providers.LLMProvider, logger *logger.Logger) *ThreatDetector {
	patterns := ThreatPatterns{
		PromptInjection: []string{
			"ignore previous instructions",
			"system prompt",
			"jailbreak",
			"act as",
			"pretend to be",
			"roleplay",
			"forget everything",
			"new instructions",
		},
		DataExfiltration: []string{
			"extract data",
			"dump database",
			"show all users",
			"list files",
			"cat /etc/passwd",
			"SELECT * FROM",
			"show tables",
		},
		ModelExtraction: []string{
			"model weights",
			"training data",
			"model architecture",
			"hyperparameters",
			"model parameters",
			"reverse engineer",
		},
		AdversarialInputs: []string{
			"adversarial example",
			"gradient attack",
			"perturbation",
			"evasion attack",
			"poisoning attack",
		},
		MaliciousCode: []string{
			"<script>",
			"javascript:",
			"eval(",
			"exec(",
			"system(",
			"shell_exec",
			"passthru",
		},
		SocialEngineering: []string{
			"urgent action required",
			"verify your account",
			"click here immediately",
			"limited time offer",
			"confirm your password",
		},
	}

	return &ThreatDetector{
		provider: provider,
		logger:   logger,
		patterns: patterns,
	}
}

// DetectThreats performs comprehensive threat detection
func (td *ThreatDetector) DetectThreats(ctx context.Context, request ThreatDetectionRequest) (*ThreatDetectionResult, error) {
	ctx, span := threatDetectorTracer.Start(ctx, "threat_detector.detect_threats",
		trace.WithAttributes(
			attribute.String("target", request.Target),
			attribute.Int("content_length", len(request.Content)),
		),
	)
	defer span.End()

	td.logger.Info("Starting threat detection", "target", request.Target)

	var detectedThreats []DetectedThreat
	var indicators []ThreatIndicator

	// Pattern-based detection
	patternThreats := td.detectPatternThreats(request.Content)
	detectedThreats = append(detectedThreats, patternThreats...)

	// AI-powered detection
	aiThreats, err := td.detectAIThreats(ctx, request)
	if err != nil {
		span.RecordError(err)
		td.logger.Warn("AI threat detection failed", "error", err)
	} else {
		detectedThreats = append(detectedThreats, aiThreats...)
	}

	// Behavioral analysis
	behavioralThreats := td.detectBehavioralThreats(request)
	detectedThreats = append(detectedThreats, behavioralThreats...)

	// Calculate overall threat score and level
	threatScore := td.calculateThreatScore(detectedThreats)
	threatLevel := td.determineThreatLevel(threatScore)

	// Extract indicators
	for _, threat := range detectedThreats {
		indicators = append(indicators, threat.Indicators...)
	}

	// Generate analysis
	analysis := td.generateThreatAnalysis(detectedThreats, threatScore)

	result := &ThreatDetectionResult{
		Level:      threatLevel,
		Score:      threatScore,
		Threats:    detectedThreats,
		Indicators: indicators,
		Confidence: 0.85, // Simplified confidence calculation
		Analysis:   analysis,
		Metadata: map[string]interface{}{
			"detection_methods": []string{"pattern", "ai", "behavioral"},
			"patterns_checked":  len(td.getAllPatterns()),
		},
	}

	span.SetAttributes(
		attribute.String("threat_level", threatLevel),
		attribute.Float64("threat_score", threatScore),
		attribute.Int("threats_detected", len(detectedThreats)),
		attribute.Int("indicators_found", len(indicators)),
	)

	td.logger.Info("Threat detection completed",
		"threat_level", threatLevel,
		"threat_score", threatScore,
		"threats_count", len(detectedThreats))

	return result, nil
}

// detectPatternThreats detects threats using pattern matching
func (td *ThreatDetector) detectPatternThreats(content string) []DetectedThreat {
	var threats []DetectedThreat
	contentLower := strings.ToLower(content)

	// Check prompt injection patterns
	for _, pattern := range td.patterns.PromptInjection {
		if strings.Contains(contentLower, strings.ToLower(pattern)) {
			threats = append(threats, DetectedThreat{
				ID:          fmt.Sprintf("prompt_injection_%d", time.Now().UnixNano()),
				Type:        "prompt_injection",
				Category:    "input_manipulation",
				Severity:    "high",
				Score:       0.8,
				Description: fmt.Sprintf("Potential prompt injection detected: %s", pattern),
				Evidence:    []string{pattern},
				MITRE: MITREMapping{
					TacticID:    "TA0001",
					TacticName:  "Initial Access",
					TechniqueID: "T1566",
					Technique:   "Phishing",
				},
				Indicators: []ThreatIndicator{
					{
						Type:        "pattern",
						Value:       pattern,
						Confidence:  0.8,
						FirstSeen:   time.Now(),
						LastSeen:    time.Now(),
						ThreatTypes: []string{"prompt_injection"},
					},
				},
			})
		}
	}

	// Check data exfiltration patterns
	for _, pattern := range td.patterns.DataExfiltration {
		if strings.Contains(contentLower, strings.ToLower(pattern)) {
			threats = append(threats, DetectedThreat{
				ID:          fmt.Sprintf("data_exfiltration_%d", time.Now().UnixNano()),
				Type:        "data_exfiltration",
				Category:    "data_breach",
				Severity:    "critical",
				Score:       0.9,
				Description: fmt.Sprintf("Potential data exfiltration attempt: %s", pattern),
				Evidence:    []string{pattern},
				MITRE: MITREMapping{
					TacticID:    "TA0010",
					TacticName:  "Exfiltration",
					TechniqueID: "T1041",
					Technique:   "Exfiltration Over C2 Channel",
				},
				Indicators: []ThreatIndicator{
					{
						Type:        "pattern",
						Value:       pattern,
						Confidence:  0.9,
						FirstSeen:   time.Now(),
						LastSeen:    time.Now(),
						ThreatTypes: []string{"data_exfiltration"},
					},
				},
			})
		}
	}

	// Check model extraction patterns
	for _, pattern := range td.patterns.ModelExtraction {
		if strings.Contains(contentLower, strings.ToLower(pattern)) {
			threats = append(threats, DetectedThreat{
				ID:          fmt.Sprintf("model_extraction_%d", time.Now().UnixNano()),
				Type:        "model_extraction",
				Category:    "intellectual_property",
				Severity:    "high",
				Score:       0.85,
				Description: fmt.Sprintf("Potential model extraction attempt: %s", pattern),
				Evidence:    []string{pattern},
				MITRE: MITREMapping{
					TacticID:    "TA0009",
					TacticName:  "Collection",
					TechniqueID: "T1005",
					Technique:   "Data from Local System",
				},
				Indicators: []ThreatIndicator{
					{
						Type:        "pattern",
						Value:       pattern,
						Confidence:  0.85,
						FirstSeen:   time.Now(),
						LastSeen:    time.Now(),
						ThreatTypes: []string{"model_extraction"},
					},
				},
			})
		}
	}

	return threats
}

// detectAIThreats uses AI to detect sophisticated threats
func (td *ThreatDetector) detectAIThreats(ctx context.Context, request ThreatDetectionRequest) ([]DetectedThreat, error) {
	// Use LLM to analyze content for threats
	prompt := fmt.Sprintf(`Analyze the following content for cybersecurity threats:

Content: %s
Target: %s

Identify any potential security threats including:
1. Prompt injection attempts
2. Data exfiltration attempts
3. Model extraction attempts
4. Adversarial inputs
5. Malicious code injection
6. Social engineering attempts

For each threat found, provide:
- Threat type
- Severity level (low/medium/high/critical)
- Confidence score (0-1)
- Brief description
- Evidence from the content

Respond in a structured format.`, request.Content, request.Target)

	genRequest := providers.GenerationRequest{
		Messages: []providers.Message{
			{
				Role:    "user",
				Content: prompt,
			},
		},
		MaxTokens:   1000,
		Temperature: 0.1, // Low temperature for consistent analysis
	}

	response, err := td.provider.Generate(ctx, genRequest)
	if err != nil {
		return nil, fmt.Errorf("AI threat detection failed: %w", err)
	}

	// Parse AI response and convert to DetectedThreat objects
	// This is simplified - in practice, you'd use structured output
	threats := td.parseAIThreatResponse(response.Content)

	return threats, nil
}

// detectBehavioralThreats detects threats based on behavioral patterns
func (td *ThreatDetector) detectBehavioralThreats(request ThreatDetectionRequest) []DetectedThreat {
	var threats []DetectedThreat

	// Analyze request patterns
	if len(request.Content) > 10000 {
		threats = append(threats, DetectedThreat{
			ID:          fmt.Sprintf("large_input_%d", time.Now().UnixNano()),
			Type:        "large_input",
			Category:    "resource_abuse",
			Severity:    "medium",
			Score:       0.6,
			Description: "Unusually large input detected - potential DoS attempt",
			Evidence:    []string{fmt.Sprintf("Content length: %d", len(request.Content))},
		})
	}

	// Check for repeated patterns
	if td.hasRepeatedPatterns(request.Content) {
		threats = append(threats, DetectedThreat{
			ID:          fmt.Sprintf("repeated_patterns_%d", time.Now().UnixNano()),
			Type:        "repeated_patterns",
			Category:    "adversarial_input",
			Severity:    "medium",
			Score:       0.7,
			Description: "Repeated patterns detected - potential adversarial input",
			Evidence:    []string{"Repeated character sequences found"},
		})
	}

	return threats
}

// calculateThreatScore calculates overall threat score
func (td *ThreatDetector) calculateThreatScore(threats []DetectedThreat) float64 {
	if len(threats) == 0 {
		return 0.0
	}

	var totalScore float64
	var maxScore float64

	for _, threat := range threats {
		totalScore += threat.Score
		if threat.Score > maxScore {
			maxScore = threat.Score
		}
	}

	// Combine average and max scores
	avgScore := totalScore / float64(len(threats))
	combinedScore := (avgScore + maxScore) / 2.0

	// Cap at 1.0
	if combinedScore > 1.0 {
		combinedScore = 1.0
	}

	return combinedScore
}

// determineThreatLevel determines threat level based on score
func (td *ThreatDetector) determineThreatLevel(score float64) string {
	switch {
	case score >= 0.8:
		return "critical"
	case score >= 0.6:
		return "high"
	case score >= 0.4:
		return "medium"
	case score >= 0.2:
		return "low"
	default:
		return "minimal"
	}
}

// generateThreatAnalysis generates human-readable threat analysis
func (td *ThreatDetector) generateThreatAnalysis(threats []DetectedThreat, score float64) string {
	if len(threats) == 0 {
		return "No significant threats detected in the analyzed content."
	}

	analysis := fmt.Sprintf("Detected %d potential threats with an overall threat score of %.2f. ", len(threats), score)

	threatTypes := make(map[string]int)
	for _, threat := range threats {
		threatTypes[threat.Type]++
	}

	analysis += "Threat types found: "
	for threatType, count := range threatTypes {
		analysis += fmt.Sprintf("%s (%d), ", threatType, count)
	}

	analysis = strings.TrimSuffix(analysis, ", ")
	analysis += ". Immediate review and mitigation recommended for high-severity threats."

	return analysis
}

// parseAIThreatResponse parses AI response into DetectedThreat objects
func (td *ThreatDetector) parseAIThreatResponse(response string) []DetectedThreat {
	// Simplified parsing - in practice, use structured output
	var threats []DetectedThreat

	if strings.Contains(strings.ToLower(response), "threat") {
		threats = append(threats, DetectedThreat{
			ID:          fmt.Sprintf("ai_detected_%d", time.Now().UnixNano()),
			Type:        "ai_detected",
			Category:    "ai_analysis",
			Severity:    "medium",
			Score:       0.7,
			Description: "AI-detected potential threat",
			Evidence:    []string{response},
		})
	}

	return threats
}

// hasRepeatedPatterns checks for repeated character patterns
func (td *ThreatDetector) hasRepeatedPatterns(content string) bool {
	// Simple check for repeated characters
	for i := 0; i < len(content)-10; i++ {
		substr := content[i : i+10]
		if strings.Count(content, substr) > 3 {
			return true
		}
	}
	return false
}

// getAllPatterns returns all threat patterns
func (td *ThreatDetector) getAllPatterns() []string {
	var patterns []string
	patterns = append(patterns, td.patterns.PromptInjection...)
	patterns = append(patterns, td.patterns.DataExfiltration...)
	patterns = append(patterns, td.patterns.ModelExtraction...)
	patterns = append(patterns, td.patterns.AdversarialInputs...)
	patterns = append(patterns, td.patterns.MaliciousCode...)
	patterns = append(patterns, td.patterns.SocialEngineering...)
	return patterns
}
