package ai_security

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var securityManagerTracer = otel.Tracer("hackai/ai_security/manager")

// DefaultSecurityManager implements SecurityManager
type DefaultSecurityManager struct {
	detectors map[AttackType]AttackDetector
	logger    *logger.Logger
	config    SecurityConfig
}

// NewDefaultSecurityManager creates a new security manager
func NewDefaultSecurityManager(config SecurityConfig, logger *logger.Logger) *DefaultSecurityManager {
	manager := &DefaultSecurityManager{
		detectors: make(map[AttackType]AttackDetector),
		logger:    logger,
		config:    config,
	}

	// Initialize detectors
	manager.initializeDetectors()

	return manager
}

// initializeDetectors initializes all attack detectors
func (sm *DefaultSecurityManager) initializeDetectors() {
	// Create mock detectors for demo
	mockDetector := &MockDetector{logger: sm.logger}
	
	sm.detectors[AttackTypePromptInjection] = mockDetector
	sm.detectors[AttackTypeJailbreak] = mockDetector
	sm.detectors[AttackTypeToxicContent] = mockDetector
	
	sm.logger.Info("Security detectors initialized", "detector_count", len(sm.detectors))
}

// AnalyzeInput performs comprehensive security analysis on input
func (sm *DefaultSecurityManager) AnalyzeInput(ctx context.Context, input string, secCtx SecurityContext) ([]ThreatDetection, error) {
	ctx, span := securityManagerTracer.Start(ctx, "security_manager.analyze_input",
		trace.WithAttributes(
			attribute.String("input.length", fmt.Sprintf("%d", len(input))),
			attribute.String("user.id", secCtx.UserID),
			attribute.String("session.id", secCtx.SessionID),
		),
	)
	defer span.End()

	if !sm.config.Enabled {
		sm.logger.Debug("Security analysis disabled")
		return []ThreatDetection{}, nil
	}

	var detections []ThreatDetection

	// Run all detectors
	for attackType, detector := range sm.detectors {
		detection, err := detector.Detect(ctx, input, secCtx)
		if err != nil {
			sm.logger.Warn("Detector failed", "attack_type", string(attackType), "error", err)
			continue
		}
		
		// Override the attack type to match the detector
		detection.Type = attackType
		detections = append(detections, detection)
	}

	span.SetAttributes(
		attribute.Int("detections.count", len(detections)),
		attribute.Bool("success", true),
	)

	sm.logger.Debug("Security analysis completed",
		"input_length", len(input),
		"detections_count", len(detections),
		"user_id", secCtx.UserID,
	)

	return detections, nil
}

// ProcessRequest processes a request through the security pipeline
func (sm *DefaultSecurityManager) ProcessRequest(ctx context.Context, input string, secCtx SecurityContext) (SecurityResult, error) {
	ctx, span := securityManagerTracer.Start(ctx, "security_manager.process_request",
		trace.WithAttributes(
			attribute.String("request.id", secCtx.RequestID),
			attribute.String("user.id", secCtx.UserID),
		),
	)
	defer span.End()

	result := SecurityResult{
		Allowed:     true,
		Threats:     []ThreatDetection{},
		Actions:     []string{},
		ProcessedAt: time.Now(),
		Metadata:    make(map[string]interface{}),
	}

	if !sm.config.Enabled {
		result.Metadata["security_disabled"] = true
		return result, nil
	}

	// Analyze input for threats
	detections, err := sm.AnalyzeInput(ctx, input, secCtx)
	if err != nil {
		span.RecordError(err)
		return result, fmt.Errorf("threat analysis failed: %w", err)
	}

	result.Threats = detections

	// Process detected threats
	highestThreatLevel := ThreatLevelNone
	for _, detection := range detections {
		if detection.Detected {
			// Track highest threat level
			if detection.Level > highestThreatLevel {
				highestThreatLevel = detection.Level
			}

			// Determine if request should be blocked
			if sm.shouldBlockRequest(detection) {
				result.Allowed = false
				result.Actions = append(result.Actions, "blocked")
			}
			
			// Add other actions based on threat level
			if detection.Level >= ThreatLevelHigh {
				result.Actions = append(result.Actions, "alert")
			}
			result.Actions = append(result.Actions, "log")
		}
	}

	// Add metadata
	result.Metadata["highest_threat_level"] = highestThreatLevel.String()
	result.Metadata["detections_count"] = len(detections)
	result.Metadata["analysis_duration"] = time.Since(result.ProcessedAt)

	span.SetAttributes(
		attribute.Bool("request.allowed", result.Allowed),
		attribute.String("highest_threat_level", highestThreatLevel.String()),
		attribute.Int("detections.count", len(detections)),
		attribute.StringSlice("actions", result.Actions),
		attribute.Bool("success", true),
	)

	sm.logger.Info("Security request processed",
		"request_id", secCtx.RequestID,
		"user_id", secCtx.UserID,
		"allowed", result.Allowed,
		"detections_count", len(detections),
		"highest_threat_level", highestThreatLevel.String(),
		"actions", result.Actions,
	)

	return result, nil
}

// shouldBlockRequest determines if a request should be blocked based on threat detection
func (sm *DefaultSecurityManager) shouldBlockRequest(detection ThreatDetection) bool {
	if !sm.config.BlockOnHighThreat {
		return false
	}

	// Block on high or critical threats
	return detection.Level >= ThreatLevelHigh
}

// MockDetector is a simple mock detector for demo purposes
type MockDetector struct {
	logger *logger.Logger
}

// Detect performs mock threat detection
func (md *MockDetector) Detect(ctx context.Context, input string, secCtx SecurityContext) (ThreatDetection, error) {
	detection := ThreatDetection{
		Detected:   false,
		Type:       AttackTypePromptInjection, // Will be overridden by manager
		Level:      ThreatLevelNone,
		Confidence: 0.0,
		Indicators: []string{},
		Metadata:   make(map[string]interface{}),
		Timestamp:  time.Now(),
	}

	// Simple heuristic detection for demo
	inputLower := strings.ToLower(input)
	
	// Check for prompt injection patterns
	if strings.Contains(inputLower, "ignore") && strings.Contains(inputLower, "instruction") {
		detection.Detected = true
		detection.Level = ThreatLevelHigh
		detection.Confidence = 0.8
		detection.Reason = "Potential prompt injection detected"
		detection.Indicators = []string{"ignore_instruction_pattern"}
	}
	
	// Check for jailbreak patterns
	if strings.Contains(inputLower, "jailbreak") || strings.Contains(inputLower, "developer mode") || strings.Contains(inputLower, "dan") {
		detection.Detected = true
		detection.Level = ThreatLevelHigh
		detection.Confidence = 0.9
		detection.Reason = "Jailbreak attempt detected"
		detection.Indicators = []string{"jailbreak_pattern"}
	}
	
	// Check for toxic content patterns
	if strings.Contains(inputLower, "hate") || strings.Contains(inputLower, "hurt") || strings.Contains(inputLower, "weapon") {
		detection.Detected = true
		detection.Level = ThreatLevelMedium
		detection.Confidence = 0.7
		detection.Reason = "Toxic content detected"
		detection.Indicators = []string{"toxic_content_pattern"}
	}

	return detection, nil
}

// GetSupportedAttacks returns supported attack types
func (md *MockDetector) GetSupportedAttacks() []AttackType {
	return []AttackType{AttackTypePromptInjection, AttackTypeJailbreak, AttackTypeToxicContent}
}

// UpdateModel is not supported for mock detector
func (md *MockDetector) UpdateModel(ctx context.Context, modelData []byte) error {
	return fmt.Errorf("model updates not supported for mock detector")
}

// GetConfidence returns the confidence threshold
func (md *MockDetector) GetConfidence() float64 {
	return 0.5
}

// CreateDefaultSecurityManager creates a security manager with default configuration
func CreateDefaultSecurityManager(logger *logger.Logger) *DefaultSecurityManager {
	config := SecurityConfig{
		Enabled:                true,
		DefaultThreatLevel:     ThreatLevelMedium,
		BlockOnHighThreat:      true,
		LogAllEvents:           true,
		EnableRealTimeAnalysis: true,
		DetectorConfigs:        make(map[string]interface{}),
		PolicyConfigs:          make(map[string]interface{}),
		ResponseConfigs:        make(map[string]interface{}),
		AnalyticsConfigs:       make(map[string]interface{}),
	}

	return NewDefaultSecurityManager(config, logger)
}
