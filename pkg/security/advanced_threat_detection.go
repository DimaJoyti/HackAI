package security

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// AdvancedThreatDetectionEngine implements advanced AI threat detection capabilities
type AdvancedThreatDetectionEngine struct {
	logger                      *logger.Logger
	modelInversionDetector      *ModelInversionDetector
	dataPoisoningDetector       *DataPoisoningDetector
	adversarialAttackDetector   *AdversarialAttackDetector
	membershipInferenceDetector *MembershipInferenceDetector
	extractionAttackDetector    *ExtractionAttackDetector
	config                      *AdvancedThreatConfig
	threatCache                 *ThreatCache
	mu                          sync.RWMutex
}

// AdvancedThreatConfig configuration for advanced threat detection
type AdvancedThreatConfig struct {
	EnableModelInversionDetection      bool          `json:"enable_model_inversion_detection"`
	EnableDataPoisoningDetection       bool          `json:"enable_data_poisoning_detection"`
	EnableAdversarialAttackDetection   bool          `json:"enable_adversarial_attack_detection"`
	EnableMembershipInferenceDetection bool          `json:"enable_membership_inference_detection"`
	EnableExtractionAttackDetection    bool          `json:"enable_extraction_attack_detection"`
	ThreatThreshold                    float64       `json:"threat_threshold"`
	ScanInterval                       time.Duration `json:"scan_interval"`
	EnableRealTimeDetection            bool          `json:"enable_real_time_detection"`
	LogDetailedAnalysis                bool          `json:"log_detailed_analysis"`
	EnableThreatIntelligence           bool          `json:"enable_threat_intelligence"`
	MaxConcurrentScans                 int           `json:"max_concurrent_scans"`
}

// ThreatDetectionResult represents the result of threat detection
type ThreatDetectionResult struct {
	ID                        string                     `json:"id"`
	Timestamp                 time.Time                  `json:"timestamp"`
	ThreatType                string                     `json:"threat_type"`
	Severity                  string                     `json:"severity"`
	Confidence                float64                    `json:"confidence"`
	RiskScore                 float64                    `json:"risk_score"`
	ModelInversionResult      *ModelInversionResult      `json:"model_inversion_result,omitempty"`
	DataPoisoningResult       *DataPoisoningResult       `json:"data_poisoning_result,omitempty"`
	AdversarialAttackResult   *AdversarialAttackResult   `json:"adversarial_attack_result,omitempty"`
	MembershipInferenceResult *MembershipInferenceResult `json:"membership_inference_result,omitempty"`
	ExtractionAttackResult    *ExtractionAttackResult    `json:"extraction_attack_result,omitempty"`
	Recommendations           []string                   `json:"recommendations"`
	Mitigations               []string                   `json:"mitigations"`
	Evidence                  []ThreatEvidence           `json:"evidence"`
	Metadata                  map[string]interface{}     `json:"metadata"`
}

// ThreatEvidence represents evidence of a threat
type ThreatEvidence struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Data        string                 `json:"data"`
	Confidence  float64                `json:"confidence"`
	Source      string                 `json:"source"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ModelInversionDetector detects model inversion attacks
type ModelInversionDetector struct {
	logger              *logger.Logger
	inversionPatterns   []*InversionPattern
	queryAnalyzer       *QueryAnalyzer
	statisticalAnalyzer *StatisticalAnalyzer
	config              *ModelInversionConfig
}

// ModelInversionConfig configuration for model inversion detection
type ModelInversionConfig struct {
	QueryThreshold            int      `json:"query_threshold"`
	StatisticalThreshold      float64  `json:"statistical_threshold"`
	EnableQueryAnalysis       bool     `json:"enable_query_analysis"`
	EnableStatisticalAnalysis bool     `json:"enable_statistical_analysis"`
	SuspiciousPatterns        []string `json:"suspicious_patterns"`
}

// InversionPattern represents a model inversion attack pattern
type InversionPattern struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Pattern     string    `json:"pattern"`
	Severity    string    `json:"severity"`
	Confidence  float64   `json:"confidence"`
	Examples    []string  `json:"examples"`
	CreatedAt   time.Time `json:"created_at"`
}

// ModelInversionResult represents model inversion detection results
type ModelInversionResult struct {
	InversionDetected    bool                   `json:"inversion_detected"`
	AttackType           string                 `json:"attack_type"`
	TargetData           []string               `json:"target_data"`
	QueryPatterns        []string               `json:"query_patterns"`
	StatisticalAnomalies []string               `json:"statistical_anomalies"`
	Confidence           float64                `json:"confidence"`
	Evidence             []ThreatEvidence       `json:"evidence"`
	Metadata             map[string]interface{} `json:"metadata"`
}

// DataPoisoningDetector detects data poisoning attacks
type DataPoisoningDetector struct {
	logger            *logger.Logger
	poisoningPatterns []*PoisoningPattern
	dataAnalyzer      *DataAnalyzer
	anomalyDetector   *AnomalyDetector
	config            *DataPoisoningConfig
}

// DataPoisoningConfig configuration for data poisoning detection
type DataPoisoningConfig struct {
	AnomalyThreshold       float64  `json:"anomaly_threshold"`
	EnableDataAnalysis     bool     `json:"enable_data_analysis"`
	EnableAnomalyDetection bool     `json:"enable_anomaly_detection"`
	SuspiciousKeywords     []string `json:"suspicious_keywords"`
	PatternSensitivity     string   `json:"pattern_sensitivity"`
}

// PoisoningPattern represents a data poisoning attack pattern
type PoisoningPattern struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Pattern     string    `json:"pattern"`
	Category    string    `json:"category"`
	Severity    string    `json:"severity"`
	Confidence  float64   `json:"confidence"`
	Examples    []string  `json:"examples"`
	CreatedAt   time.Time `json:"created_at"`
}

// DataPoisoningResult represents data poisoning detection results
type DataPoisoningResult struct {
	PoisoningDetected bool                   `json:"poisoning_detected"`
	PoisoningType     string                 `json:"poisoning_type"`
	AffectedData      []string               `json:"affected_data"`
	PoisoningPatterns []string               `json:"poisoning_patterns"`
	AnomalyScore      float64                `json:"anomaly_score"`
	Confidence        float64                `json:"confidence"`
	Evidence          []ThreatEvidence       `json:"evidence"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// AdversarialAttackDetector detects adversarial attacks
type AdversarialAttackDetector struct {
	logger               *logger.Logger
	adversarialPatterns  []*AdversarialPattern
	perturbationDetector *PerturbationDetector
	evasionDetector      *EvasionDetector
	config               *AdversarialAttackConfig
}

// AdversarialAttackConfig configuration for adversarial attack detection
type AdversarialAttackConfig struct {
	PerturbationThreshold       float64  `json:"perturbation_threshold"`
	EnablePerturbationDetection bool     `json:"enable_perturbation_detection"`
	EnableEvasionDetection      bool     `json:"enable_evasion_detection"`
	AttackTypes                 []string `json:"attack_types"`
	SensitivityLevel            string   `json:"sensitivity_level"`
}

// AdversarialPattern represents an adversarial attack pattern
type AdversarialPattern struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	AttackType  string    `json:"attack_type"`
	Pattern     string    `json:"pattern"`
	Severity    string    `json:"severity"`
	Confidence  float64   `json:"confidence"`
	Examples    []string  `json:"examples"`
	CreatedAt   time.Time `json:"created_at"`
}

// AdversarialAttackResult represents adversarial attack detection results
type AdversarialAttackResult struct {
	AttackDetected    bool                   `json:"attack_detected"`
	AttackType        string                 `json:"attack_type"`
	PerturbationLevel float64                `json:"perturbation_level"`
	EvasionTechniques []string               `json:"evasion_techniques"`
	TargetModel       string                 `json:"target_model"`
	Confidence        float64                `json:"confidence"`
	Evidence          []ThreatEvidence       `json:"evidence"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// MembershipInferenceDetector detects membership inference attacks
type MembershipInferenceDetector struct {
	logger            *logger.Logger
	inferencePatterns []*InferencePattern
	privacyAnalyzer   *PrivacyAnalyzer
	config            *MembershipInferenceConfig
}

// MembershipInferenceConfig configuration for membership inference detection
type MembershipInferenceConfig struct {
	PrivacyThreshold      float64  `json:"privacy_threshold"`
	EnablePrivacyAnalysis bool     `json:"enable_privacy_analysis"`
	SensitiveDataTypes    []string `json:"sensitive_data_types"`
	InferenceThreshold    float64  `json:"inference_threshold"`
}

// InferencePattern represents a membership inference attack pattern
type InferencePattern struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Pattern     string    `json:"pattern"`
	DataType    string    `json:"data_type"`
	Severity    string    `json:"severity"`
	Confidence  float64   `json:"confidence"`
	Examples    []string  `json:"examples"`
	CreatedAt   time.Time `json:"created_at"`
}

// MembershipInferenceResult represents membership inference detection results
type MembershipInferenceResult struct {
	InferenceDetected bool                   `json:"inference_detected"`
	TargetData        []string               `json:"target_data"`
	InferenceType     string                 `json:"inference_type"`
	PrivacyRisk       float64                `json:"privacy_risk"`
	SensitiveData     []string               `json:"sensitive_data"`
	Confidence        float64                `json:"confidence"`
	Evidence          []ThreatEvidence       `json:"evidence"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// ExtractionAttackDetector detects data extraction attacks
type ExtractionAttackDetector struct {
	logger             *logger.Logger
	extractionPatterns []*ExtractionPattern
	dataLeakDetector   *DataLeakDetector
	config             *ExtractionAttackConfig
}

// ExtractionAttackConfig configuration for extraction attack detection
type ExtractionAttackConfig struct {
	ExtractionThreshold     float64  `json:"extraction_threshold"`
	EnableDataLeakDetection bool     `json:"enable_data_leak_detection"`
	SensitivePatterns       []string `json:"sensitive_patterns"`
	ExtractionTypes         []string `json:"extraction_types"`
}

// ExtractionPattern represents a data extraction attack pattern
type ExtractionPattern struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Pattern     string    `json:"pattern"`
	DataType    string    `json:"data_type"`
	Severity    string    `json:"severity"`
	Confidence  float64   `json:"confidence"`
	Examples    []string  `json:"examples"`
	CreatedAt   time.Time `json:"created_at"`
}

// ExtractionAttackResult represents extraction attack detection results
type ExtractionAttackResult struct {
	ExtractionDetected bool                   `json:"extraction_detected"`
	ExtractionType     string                 `json:"extraction_type"`
	TargetData         []string               `json:"target_data"`
	ExtractionMethods  []string               `json:"extraction_methods"`
	DataLeakRisk       float64                `json:"data_leak_risk"`
	Confidence         float64                `json:"confidence"`
	Evidence           []ThreatEvidence       `json:"evidence"`
	Metadata           map[string]interface{} `json:"metadata"`
}

// NewAdvancedThreatDetectionEngine creates a new advanced threat detection engine
func NewAdvancedThreatDetectionEngine(config *AdvancedThreatConfig, logger *logger.Logger) *AdvancedThreatDetectionEngine {
	if config == nil {
		config = DefaultAdvancedThreatConfig()
	}

	engine := &AdvancedThreatDetectionEngine{
		logger: logger,
		config: config,
		// threatCache will be initialized separately if needed
	}

	// Initialize detectors
	if config.EnableModelInversionDetection {
		engine.modelInversionDetector = NewModelInversionDetector(logger)
	}

	if config.EnableDataPoisoningDetection {
		engine.dataPoisoningDetector = NewDataPoisoningDetector(logger)
	}

	if config.EnableAdversarialAttackDetection {
		engine.adversarialAttackDetector = NewAdversarialAttackDetector(logger)
	}

	if config.EnableMembershipInferenceDetection {
		engine.membershipInferenceDetector = NewMembershipInferenceDetector(logger)
	}

	if config.EnableExtractionAttackDetection {
		engine.extractionAttackDetector = NewExtractionAttackDetector(logger)
	}

	return engine
}

// DefaultAdvancedThreatConfig returns default configuration
func DefaultAdvancedThreatConfig() *AdvancedThreatConfig {
	return &AdvancedThreatConfig{
		EnableModelInversionDetection:      true,
		EnableDataPoisoningDetection:       true,
		EnableAdversarialAttackDetection:   true,
		EnableMembershipInferenceDetection: true,
		EnableExtractionAttackDetection:    true,
		ThreatThreshold:                    0.7,
		ScanInterval:                       5 * time.Minute,
		EnableRealTimeDetection:            true,
		LogDetailedAnalysis:                true,
		EnableThreatIntelligence:           true,
		MaxConcurrentScans:                 10,
	}
}

// DetectThreats performs comprehensive threat detection
func (engine *AdvancedThreatDetectionEngine) DetectThreats(ctx context.Context, input *ThreatDetectionInput) (*ThreatDetectionResult, error) {
	engine.mu.RLock()
	defer engine.mu.RUnlock()

	result := &ThreatDetectionResult{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Evidence:  []ThreatEvidence{},
		Metadata:  make(map[string]interface{}),
	}

	var detectedThreats []string
	maxRiskScore := 0.0

	// Model Inversion Detection
	if engine.config.EnableModelInversionDetection && engine.modelInversionDetector != nil {
		inversionResult, err := engine.modelInversionDetector.DetectModelInversion(ctx, input)
		if err != nil {
			engine.logger.WithError(err).Error("Model inversion detection failed")
		} else if inversionResult.InversionDetected {
			result.ModelInversionResult = inversionResult
			detectedThreats = append(detectedThreats, "model_inversion")
			if inversionResult.Confidence > maxRiskScore {
				maxRiskScore = inversionResult.Confidence
			}
		}
	}

	// Data Poisoning Detection
	if engine.config.EnableDataPoisoningDetection && engine.dataPoisoningDetector != nil {
		poisoningResult, err := engine.dataPoisoningDetector.DetectDataPoisoning(ctx, input)
		if err != nil {
			engine.logger.WithError(err).Error("Data poisoning detection failed")
		} else if poisoningResult.PoisoningDetected {
			result.DataPoisoningResult = poisoningResult
			detectedThreats = append(detectedThreats, "data_poisoning")
			if poisoningResult.Confidence > maxRiskScore {
				maxRiskScore = poisoningResult.Confidence
			}
		}
	}

	// Adversarial Attack Detection
	if engine.config.EnableAdversarialAttackDetection && engine.adversarialAttackDetector != nil {
		adversarialResult, err := engine.adversarialAttackDetector.DetectAdversarialAttack(ctx, input)
		if err != nil {
			engine.logger.WithError(err).Error("Adversarial attack detection failed")
		} else if adversarialResult.AttackDetected {
			result.AdversarialAttackResult = adversarialResult
			detectedThreats = append(detectedThreats, "adversarial_attack")
			if adversarialResult.Confidence > maxRiskScore {
				maxRiskScore = adversarialResult.Confidence
			}
		}
	}

	// Membership Inference Detection
	if engine.config.EnableMembershipInferenceDetection && engine.membershipInferenceDetector != nil {
		inferenceResult, err := engine.membershipInferenceDetector.DetectMembershipInference(ctx, input)
		if err != nil {
			engine.logger.WithError(err).Error("Membership inference detection failed")
		} else if inferenceResult.InferenceDetected {
			result.MembershipInferenceResult = inferenceResult
			detectedThreats = append(detectedThreats, "membership_inference")
			if inferenceResult.Confidence > maxRiskScore {
				maxRiskScore = inferenceResult.Confidence
			}
		}
	}

	// Extraction Attack Detection
	if engine.config.EnableExtractionAttackDetection && engine.extractionAttackDetector != nil {
		extractionResult, err := engine.extractionAttackDetector.DetectExtractionAttack(ctx, input)
		if err != nil {
			engine.logger.WithError(err).Error("Extraction attack detection failed")
		} else if extractionResult.ExtractionDetected {
			result.ExtractionAttackResult = extractionResult
			detectedThreats = append(detectedThreats, "extraction_attack")
			if extractionResult.Confidence > maxRiskScore {
				maxRiskScore = extractionResult.Confidence
			}
		}
	}

	// Determine overall threat assessment
	if len(detectedThreats) > 0 {
		result.ThreatType = strings.Join(detectedThreats, ",")
		result.RiskScore = maxRiskScore
		result.Confidence = maxRiskScore
		result.Severity = engine.determineSeverity(maxRiskScore)
		result.Recommendations = engine.generateRecommendations(detectedThreats)
		result.Mitigations = engine.generateMitigations(detectedThreats)
	} else {
		result.ThreatType = "none"
		result.RiskScore = 0.0
		result.Confidence = 1.0
		result.Severity = "low"
		result.Recommendations = []string{"Continue monitoring"}
	}

	// Cache result for threat intelligence
	if engine.config.EnableThreatIntelligence {
		// Convert ThreatAnalysisResult to ThreatReport for caching
		report := &ThreatReport{
			ID:          fmt.Sprintf("analysis_%d", time.Now().UnixNano()),
			Target:      input.Data,
			TargetType:  "analysis",
			ThreatScore: result.RiskScore,
			RiskLevel:   result.Severity,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		engine.threatCache.Set(input.Data, report)
	}

	// Log detailed analysis if configured
	if engine.config.LogDetailedAnalysis {
		engine.logger.WithFields(map[string]interface{}{
			"detection_id":     result.ID,
			"threat_type":      result.ThreatType,
			"risk_score":       result.RiskScore,
			"detected_threats": len(detectedThreats),
		}).Info("Advanced threat detection completed")
	}

	return result, nil
}

// ThreatDetectionInput represents input for threat detection
type ThreatDetectionInput struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Data      string                 `json:"data"`
	ModelInfo *ModelInfo             `json:"model_info"`
	QueryInfo *QueryInfo             `json:"query_info"`
	Context   map[string]interface{} `json:"context"`
	Timestamp time.Time              `json:"timestamp"`
}

// ModelInfo represents information about the target model
type ModelInfo struct {
	ModelID    string                 `json:"model_id"`
	ModelType  string                 `json:"model_type"`
	Version    string                 `json:"version"`
	Parameters map[string]interface{} `json:"parameters"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// QueryInfo represents information about queries
type QueryInfo struct {
	QueryCount    int                    `json:"query_count"`
	QueryPatterns []string               `json:"query_patterns"`
	QueryHistory  []string               `json:"query_history"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// determineSeverity determines severity based on risk score
func (engine *AdvancedThreatDetectionEngine) determineSeverity(riskScore float64) string {
	switch {
	case riskScore >= 0.9:
		return "critical"
	case riskScore >= 0.7:
		return "high"
	case riskScore >= 0.5:
		return "medium"
	case riskScore >= 0.3:
		return "low"
	default:
		return "minimal"
	}
}

// generateRecommendations generates recommendations based on detected threats
func (engine *AdvancedThreatDetectionEngine) generateRecommendations(threats []string) []string {
	var recommendations []string

	for _, threat := range threats {
		switch threat {
		case "model_inversion":
			recommendations = append(recommendations, "Implement differential privacy")
			recommendations = append(recommendations, "Add noise to model outputs")
			recommendations = append(recommendations, "Limit query frequency")
		case "data_poisoning":
			recommendations = append(recommendations, "Validate training data sources")
			recommendations = append(recommendations, "Implement data integrity checks")
			recommendations = append(recommendations, "Use robust training methods")
		case "adversarial_attack":
			recommendations = append(recommendations, "Deploy adversarial training")
			recommendations = append(recommendations, "Implement input preprocessing")
			recommendations = append(recommendations, "Use ensemble methods")
		case "membership_inference":
			recommendations = append(recommendations, "Apply differential privacy")
			recommendations = append(recommendations, "Implement output perturbation")
			recommendations = append(recommendations, "Limit model access")
		case "extraction_attack":
			recommendations = append(recommendations, "Implement rate limiting")
			recommendations = append(recommendations, "Add query monitoring")
			recommendations = append(recommendations, "Use model watermarking")
		}
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Continue security monitoring")
	}

	return recommendations
}

// generateMitigations generates mitigations based on detected threats
func (engine *AdvancedThreatDetectionEngine) generateMitigations(threats []string) []string {
	var mitigations []string

	for _, threat := range threats {
		switch threat {
		case "model_inversion":
			mitigations = append(mitigations, "Enable differential privacy")
			mitigations = append(mitigations, "Implement query budget limits")
		case "data_poisoning":
			mitigations = append(mitigations, "Activate data validation")
			mitigations = append(mitigations, "Enable anomaly detection")
		case "adversarial_attack":
			mitigations = append(mitigations, "Deploy input sanitization")
			mitigations = append(mitigations, "Enable adversarial detection")
		case "membership_inference":
			mitigations = append(mitigations, "Apply privacy protection")
			mitigations = append(mitigations, "Limit information leakage")
		case "extraction_attack":
			mitigations = append(mitigations, "Implement access controls")
			mitigations = append(mitigations, "Enable query monitoring")
		}
	}

	return mitigations
}
