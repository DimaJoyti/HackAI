package fraud

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/ai"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var integrationTracer = otel.Tracer("hackai/fraud/integration")

// HackAIIntegration provides integration with the HackAI platform
type HackAIIntegration struct {
	fraudEngine       *FraudDetectionEngine
	aiOrchestrator    ai.Orchestrator
	securityFramework SecurityFramework
	logger            *logger.Logger
	tracer            trace.Tracer
}

// SecurityFramework interface for HackAI security integration
type SecurityFramework interface {
	ReportThreat(ctx context.Context, threat ThreatReport) error
	GetThreatIntelligence(ctx context.Context, indicators []string) (*ThreatIntelligence, error)
	ValidateRequest(ctx context.Context, request *FraudDetectionRequest) error
}

// ThreatReport represents a fraud threat report
type ThreatReport struct {
	ID              string                 `json:"id"`
	Type            string                 `json:"type"`
	Severity        string                 `json:"severity"`
	Description     string                 `json:"description"`
	Indicators      []string               `json:"indicators"`
	FraudScore      float64                `json:"fraud_score"`
	AffectedUser    string                 `json:"affected_user"`
	TransactionData map[string]interface{} `json:"transaction_data"`
	Timestamp       time.Time              `json:"timestamp"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ThreatIntelligence represents threat intelligence data
type ThreatIntelligence struct {
	Indicators  []ThreatIndicator      `json:"indicators"`
	RiskScore   float64                `json:"risk_score"`
	Confidence  float64                `json:"confidence"`
	Sources     []string               `json:"sources"`
	LastUpdated time.Time              `json:"last_updated"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ThreatIndicator represents a single threat indicator
type ThreatIndicator struct {
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	Confidence  float64   `json:"confidence"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Description string    `json:"description"`
}

// NewHackAIIntegration creates a new HackAI platform integration
func NewHackAIIntegration(
	fraudEngine *FraudDetectionEngine,
	aiOrchestrator ai.Orchestrator,
	securityFramework SecurityFramework,
	logger *logger.Logger,
) *HackAIIntegration {
	return &HackAIIntegration{
		fraudEngine:       fraudEngine,
		aiOrchestrator:    aiOrchestrator,
		securityFramework: securityFramework,
		logger:            logger,
		tracer:            integrationTracer,
	}
}

// ProcessFraudDetectionWithIntelligence processes fraud detection with threat intelligence
func (hai *HackAIIntegration) ProcessFraudDetectionWithIntelligence(ctx context.Context, request *FraudDetectionRequest) (*FraudDetectionResponse, error) {
	ctx, span := hai.tracer.Start(ctx, "hackai_integration.process_fraud_with_intelligence",
		trace.WithAttributes(
			attribute.String("request.id", request.ID),
			attribute.String("user.id", request.UserID),
		),
	)
	defer span.End()

	// Step 1: Validate request with security framework
	if err := hai.securityFramework.ValidateRequest(ctx, request); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("security validation failed: %w", err)
	}

	// Step 2: Gather threat intelligence
	indicators := hai.extractThreatIndicators(request)
	threatIntel, err := hai.securityFramework.GetThreatIntelligence(ctx, indicators)
	if err != nil {
		hai.logger.Warn("Failed to get threat intelligence", "error", err)
		// Continue without threat intelligence
	}

	// Step 3: Enhance request with threat intelligence
	if threatIntel != nil {
		hai.enhanceRequestWithThreatIntel(request, threatIntel)
	}

	// Step 4: Perform fraud detection
	response, err := hai.fraudEngine.DetectFraud(ctx, request)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("fraud detection failed: %w", err)
	}

	// Step 5: Enhance response with threat intelligence
	if threatIntel != nil {
		hai.enhanceResponseWithThreatIntel(response, threatIntel)
	}

	// Step 6: Report high-risk fraud as security threat
	if response.RiskLevel == RiskLevelCritical || response.RiskLevel == RiskLevelHigh {
		if err := hai.reportFraudThreat(ctx, request, response); err != nil {
			hai.logger.Error("Failed to report fraud threat", "error", err)
		}
	}

	span.SetAttributes(
		attribute.Float64("fraud.score", response.FraudScore),
		attribute.String("fraud.decision", string(response.Decision)),
		attribute.String("fraud.risk_level", string(response.RiskLevel)),
		attribute.Bool("threat_intel.available", threatIntel != nil),
	)

	return response, nil
}

// extractThreatIndicators extracts threat indicators from fraud request
func (hai *HackAIIntegration) extractThreatIndicators(request *FraudDetectionRequest) []string {
	var indicators []string

	// Extract IP address
	if deviceFingerprint := request.DeviceFingerprint; deviceFingerprint != nil {
		if ip, ok := deviceFingerprint["ip_address"].(string); ok && ip != "" {
			indicators = append(indicators, ip)
		}
	}

	// Extract user agent
	if deviceFingerprint := request.DeviceFingerprint; deviceFingerprint != nil {
		if userAgent, ok := deviceFingerprint["user_agent"].(string); ok && userAgent != "" {
			indicators = append(indicators, userAgent)
		}
	}

	// Extract merchant information
	if transactionData := request.TransactionData; transactionData != nil {
		if merchant, ok := transactionData["merchant"].(string); ok && merchant != "" {
			indicators = append(indicators, merchant)
		}
	}

	return indicators
}

// enhanceRequestWithThreatIntel enhances request with threat intelligence data
func (hai *HackAIIntegration) enhanceRequestWithThreatIntel(request *FraudDetectionRequest, threatIntel *ThreatIntelligence) {
	if request.Metadata == nil {
		request.Metadata = make(map[string]interface{})
	}

	request.Metadata["threat_intelligence"] = map[string]interface{}{
		"risk_score":   threatIntel.RiskScore,
		"confidence":   threatIntel.Confidence,
		"sources":      threatIntel.Sources,
		"indicators":   len(threatIntel.Indicators),
		"last_updated": threatIntel.LastUpdated,
	}
}

// enhanceResponseWithThreatIntel enhances response with threat intelligence data
func (hai *HackAIIntegration) enhanceResponseWithThreatIntel(response *FraudDetectionResponse, threatIntel *ThreatIntelligence) {
	if response.Metadata == nil {
		response.Metadata = make(map[string]interface{})
	}

	// Adjust fraud score based on threat intelligence
	if threatIntel.RiskScore > 0.7 {
		response.FraudScore = (response.FraudScore + threatIntel.RiskScore) / 2
		response.Reasons = append(response.Reasons, "High threat intelligence risk score detected")
	}

	response.Metadata["threat_intelligence"] = map[string]interface{}{
		"risk_score": threatIntel.RiskScore,
		"confidence": threatIntel.Confidence,
		"sources":    threatIntel.Sources,
	}
}

// reportFraudThreat reports fraud as a security threat
func (hai *HackAIIntegration) reportFraudThreat(ctx context.Context, request *FraudDetectionRequest, response *FraudDetectionResponse) error {
	threat := ThreatReport{
		ID:              fmt.Sprintf("fraud_%s", request.ID),
		Type:            "fraud_detection",
		Severity:        hai.mapRiskLevelToSeverity(response.RiskLevel),
		Description:     fmt.Sprintf("Fraud detected with score %.3f", response.FraudScore),
		Indicators:      hai.extractThreatIndicators(request),
		FraudScore:      response.FraudScore,
		AffectedUser:    request.UserID,
		TransactionData: request.TransactionData,
		Timestamp:       time.Now(),
		Metadata: map[string]interface{}{
			"decision":   response.Decision,
			"risk_level": response.RiskLevel,
			"confidence": response.Confidence,
			"reasons":    response.Reasons,
		},
	}

	return hai.securityFramework.ReportThreat(ctx, threat)
}

// mapRiskLevelToSeverity maps fraud risk level to security severity
func (hai *HackAIIntegration) mapRiskLevelToSeverity(riskLevel RiskLevel) string {
	switch riskLevel {
	case RiskLevelCritical:
		return "critical"
	case RiskLevelHigh:
		return "high"
	case RiskLevelMedium:
		return "medium"
	case RiskLevelLow:
		return "low"
	default:
		return "info"
	}
}

// Stub implementations for testing

// StubSecurityFramework provides a stub security framework
type StubSecurityFramework struct {
	logger *logger.Logger
}

// NewStubSecurityFramework creates a new stub security framework
func NewStubSecurityFramework(logger *logger.Logger) *StubSecurityFramework {
	return &StubSecurityFramework{logger: logger}
}

func (ssf *StubSecurityFramework) ReportThreat(ctx context.Context, threat ThreatReport) error {
	ssf.logger.Info("Threat reported", "threat_id", threat.ID, "severity", threat.Severity)
	return nil
}

func (ssf *StubSecurityFramework) GetThreatIntelligence(ctx context.Context, indicators []string) (*ThreatIntelligence, error) {
	// Return stub threat intelligence
	return &ThreatIntelligence{
		RiskScore:   0.3,
		Confidence:  0.8,
		Sources:     []string{"internal"},
		LastUpdated: time.Now(),
		Indicators:  []ThreatIndicator{},
	}, nil
}

func (ssf *StubSecurityFramework) ValidateRequest(ctx context.Context, request *FraudDetectionRequest) error {
	// Stub validation - always pass
	return nil
}
