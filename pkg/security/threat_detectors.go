package security

import (
	"context"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// QueryAnalyzer analyzes query patterns for model inversion attacks
type QueryAnalyzer struct {
	logger            *logger.Logger
	queryPatterns     []string
	suspiciousQueries map[string]int
}

// StatisticalAnalyzer performs statistical analysis for threat detection
type StatisticalAnalyzer struct {
	logger    *logger.Logger
	baseline  map[string]float64
	threshold float64
}

// DataAnalyzer analyzes data for poisoning detection
type DataAnalyzer struct {
	logger           *logger.Logger
	dataPatterns     []string
	anomalyThreshold float64
}

// PerturbationDetector detects adversarial perturbations
type PerturbationDetector struct {
	logger    *logger.Logger
	threshold float64
	patterns  []string
}

// EvasionDetector detects evasion attempts
type EvasionDetector struct {
	logger   *logger.Logger
	patterns []string
}

// PrivacyAnalyzer analyzes privacy risks
type PrivacyAnalyzer struct {
	logger            *logger.Logger
	sensitivePatterns []string
	privacyThreshold  float64
}

// DataLeakDetector detects data leakage
type DataLeakDetector struct {
	logger          *logger.Logger
	leakagePatterns []string
	sensitiveData   []string
}

// NewModelInversionDetector creates a new model inversion detector
func NewModelInversionDetector(logger *logger.Logger) *ModelInversionDetector {
	return &ModelInversionDetector{
		logger:              logger,
		inversionPatterns:   loadModelInversionPatterns(),
		queryAnalyzer:       NewQueryAnalyzer(logger),
		statisticalAnalyzer: NewStatisticalAnalyzer(logger),
		config: &ModelInversionConfig{
			QueryThreshold:            100,
			StatisticalThreshold:      0.8,
			EnableQueryAnalysis:       true,
			EnableStatisticalAnalysis: true,
			SuspiciousPatterns:        []string{"extract", "invert", "reconstruct", "reverse"},
		},
	}
}

// NewQueryAnalyzer creates a new query analyzer
func NewQueryAnalyzer(logger *logger.Logger) *QueryAnalyzer {
	return &QueryAnalyzer{
		logger:            logger,
		queryPatterns:     []string{"extract", "invert", "reconstruct", "reverse", "membership"},
		suspiciousQueries: make(map[string]int),
	}
}

// NewStatisticalAnalyzer creates a new statistical analyzer
func NewStatisticalAnalyzer(logger *logger.Logger) *StatisticalAnalyzer {
	return &StatisticalAnalyzer{
		logger:    logger,
		baseline:  make(map[string]float64),
		threshold: 0.8,
	}
}

// DetectModelInversion detects model inversion attacks
func (mid *ModelInversionDetector) DetectModelInversion(ctx context.Context, input *ThreatDetectionInput) (*ModelInversionResult, error) {
	result := &ModelInversionResult{
		QueryPatterns:        []string{},
		StatisticalAnomalies: []string{},
		TargetData:           []string{},
		Evidence:             []ThreatEvidence{},
		Metadata:             make(map[string]interface{}),
	}

	inversionDetected := false
	confidence := 0.0

	// Check for inversion patterns
	for _, pattern := range mid.inversionPatterns {
		matched, _ := regexp.MatchString(pattern.Pattern, input.Data)
		if matched {
			inversionDetected = true
			confidence = math.Max(confidence, pattern.Confidence)
			result.QueryPatterns = append(result.QueryPatterns, pattern.Name)
			result.Evidence = append(result.Evidence, ThreatEvidence{
				Type:        "pattern_match",
				Description: pattern.Description,
				Data:        pattern.Pattern,
				Confidence:  pattern.Confidence,
				Source:      "model_inversion_detector",
				Timestamp:   time.Now(),
			})
		}
	}

	// Query analysis
	if mid.config.EnableQueryAnalysis {
		queryResult := mid.queryAnalyzer.AnalyzeQueries(input)
		if queryResult.Suspicious {
			inversionDetected = true
			confidence = math.Max(confidence, queryResult.Confidence)
			result.QueryPatterns = append(result.QueryPatterns, queryResult.Patterns...)
		}
	}

	// Statistical analysis
	if mid.config.EnableStatisticalAnalysis {
		statResult := mid.statisticalAnalyzer.AnalyzeStatistics(input)
		if statResult.Anomalous {
			inversionDetected = true
			confidence = math.Max(confidence, statResult.Confidence)
			result.StatisticalAnomalies = append(result.StatisticalAnomalies, statResult.Anomalies...)
		}
	}

	result.InversionDetected = inversionDetected
	result.Confidence = confidence

	if inversionDetected {
		result.AttackType = "model_inversion"
		result.TargetData = []string{"training_data", "model_parameters"}
	}

	return result, nil
}

// QueryAnalysisResult represents query analysis results
type QueryAnalysisResult struct {
	Suspicious bool
	Confidence float64
	Patterns   []string
}

// StatisticalAnalysisResult represents statistical analysis results
type StatisticalAnalysisResult struct {
	Anomalous  bool
	Confidence float64
	Anomalies  []string
}

// AnalyzeQueries analyzes queries for suspicious patterns
func (qa *QueryAnalyzer) AnalyzeQueries(input *ThreatDetectionInput) *QueryAnalysisResult {
	result := &QueryAnalysisResult{
		Patterns: []string{},
	}

	suspiciousCount := 0
	for _, pattern := range qa.queryPatterns {
		if strings.Contains(strings.ToLower(input.Data), pattern) {
			suspiciousCount++
			result.Patterns = append(result.Patterns, pattern)
		}
	}

	if suspiciousCount > 0 {
		result.Suspicious = true
		result.Confidence = float64(suspiciousCount) / float64(len(qa.queryPatterns))
	}

	return result
}

// AnalyzeStatistics performs statistical analysis
func (sa *StatisticalAnalyzer) AnalyzeStatistics(input *ThreatDetectionInput) *StatisticalAnalysisResult {
	result := &StatisticalAnalysisResult{
		Anomalies: []string{},
	}

	// Simple statistical analysis based on input characteristics
	dataLength := float64(len(input.Data))
	if dataLength > 1000 {
		result.Anomalous = true
		result.Confidence = 0.7
		result.Anomalies = append(result.Anomalies, "unusual_input_length")
	}

	// Check for repeated patterns
	words := strings.Fields(input.Data)
	wordCount := make(map[string]int)
	for _, word := range words {
		wordCount[word]++
	}

	maxRepeats := 0
	for _, count := range wordCount {
		if count > maxRepeats {
			maxRepeats = count
		}
	}

	if maxRepeats > 5 {
		result.Anomalous = true
		result.Confidence = math.Max(result.Confidence, 0.6)
		result.Anomalies = append(result.Anomalies, "repeated_patterns")
	}

	return result
}

// loadModelInversionPatterns loads default model inversion patterns
func loadModelInversionPatterns() []*InversionPattern {
	return []*InversionPattern{
		{
			ID:          "inv_001",
			Name:        "Data Extraction",
			Description: "Attempt to extract training data",
			Pattern:     `(?i)(extract|show|reveal).*(training|data|dataset)`,
			Severity:    "high",
			Confidence:  0.8,
			CreatedAt:   time.Now(),
		},
		{
			ID:          "inv_002",
			Name:        "Model Inversion",
			Description: "Attempt to invert model parameters",
			Pattern:     `(?i)(invert|reverse).*(model|parameters|weights)`,
			Severity:    "high",
			Confidence:  0.9,
			CreatedAt:   time.Now(),
		},
		{
			ID:          "inv_003",
			Name:        "Reconstruction Attack",
			Description: "Attempt to reconstruct private data",
			Pattern:     `(?i)(reconstruct|rebuild).*(private|sensitive|personal)`,
			Severity:    "high",
			Confidence:  0.85,
			CreatedAt:   time.Now(),
		},
	}
}

// NewDataPoisoningDetector creates a new data poisoning detector
func NewDataPoisoningDetector(logger *logger.Logger) *DataPoisoningDetector {
	return &DataPoisoningDetector{
		logger:            logger,
		poisoningPatterns: loadDataPoisoningPatterns(),
		dataAnalyzer:      NewDataAnalyzer(logger),
		anomalyDetector:   NewAnomalyDetector(logger),
		config: &DataPoisoningConfig{
			AnomalyThreshold:       0.7,
			EnableDataAnalysis:     true,
			EnableAnomalyDetection: true,
			SuspiciousKeywords:     []string{"poison", "backdoor", "trigger", "malicious"},
			PatternSensitivity:     "medium",
		},
	}
}

// NewDataAnalyzer creates a new data analyzer
func NewDataAnalyzer(logger *logger.Logger) *DataAnalyzer {
	return &DataAnalyzer{
		logger:           logger,
		dataPatterns:     []string{"poison", "backdoor", "trigger", "malicious", "adversarial"},
		anomalyThreshold: 0.7,
	}
}

// Note: NewAnomalyDetector is defined in supporting_components.go

// DetectDataPoisoning detects data poisoning attacks
func (dpd *DataPoisoningDetector) DetectDataPoisoning(ctx context.Context, input *ThreatDetectionInput) (*DataPoisoningResult, error) {
	result := &DataPoisoningResult{
		PoisoningPatterns: []string{},
		AffectedData:      []string{},
		Evidence:          []ThreatEvidence{},
		Metadata:          make(map[string]interface{}),
	}

	poisoningDetected := false
	confidence := 0.0

	// Check for poisoning patterns
	for _, pattern := range dpd.poisoningPatterns {
		matched, _ := regexp.MatchString(pattern.Pattern, input.Data)
		if matched {
			poisoningDetected = true
			confidence = math.Max(confidence, pattern.Confidence)
			result.PoisoningPatterns = append(result.PoisoningPatterns, pattern.Name)
			result.Evidence = append(result.Evidence, ThreatEvidence{
				Type:        "pattern_match",
				Description: pattern.Description,
				Data:        pattern.Pattern,
				Confidence:  pattern.Confidence,
				Source:      "data_poisoning_detector",
				Timestamp:   time.Now(),
			})
		}
	}

	// Data analysis
	if dpd.config.EnableDataAnalysis {
		dataResult := dpd.dataAnalyzer.AnalyzeData(input)
		if dataResult.Suspicious {
			poisoningDetected = true
			confidence = math.Max(confidence, dataResult.Confidence)
			result.AffectedData = append(result.AffectedData, dataResult.SuspiciousElements...)
		}
	}

	// Anomaly detection
	if dpd.config.EnableAnomalyDetection {
		anomalyScore := dpd.anomalyDetector.DetectAnomalies(input)
		if anomalyScore > dpd.config.AnomalyThreshold {
			poisoningDetected = true
			confidence = math.Max(confidence, anomalyScore)
			result.AnomalyScore = anomalyScore
		}
	}

	result.PoisoningDetected = poisoningDetected
	result.Confidence = confidence

	if poisoningDetected {
		result.PoisoningType = "data_poisoning"
	}

	return result, nil
}

// DataAnalysisResult represents data analysis results
type DataAnalysisResult struct {
	Suspicious         bool
	Confidence         float64
	SuspiciousElements []string
}

// AnomalyDetectionResult represents anomaly detection results
type AnomalyDetectionResult struct {
	Anomalous  bool
	Confidence float64
	Score      float64
}

// AnalyzeData analyzes data for suspicious patterns
func (da *DataAnalyzer) AnalyzeData(input *ThreatDetectionInput) *DataAnalysisResult {
	result := &DataAnalysisResult{
		SuspiciousElements: []string{},
	}

	suspiciousCount := 0
	for _, pattern := range da.dataPatterns {
		if strings.Contains(strings.ToLower(input.Data), pattern) {
			suspiciousCount++
			result.SuspiciousElements = append(result.SuspiciousElements, pattern)
		}
	}

	if suspiciousCount > 0 {
		result.Suspicious = true
		result.Confidence = float64(suspiciousCount) / float64(len(da.dataPatterns))
	}

	return result
}

// Note: DetectAnomalies method is implemented in supporting_components.go

// loadDataPoisoningPatterns loads default data poisoning patterns
func loadDataPoisoningPatterns() []*PoisoningPattern {
	return []*PoisoningPattern{
		{
			ID:          "poison_001",
			Name:        "Backdoor Trigger",
			Description: "Backdoor trigger pattern in data",
			Pattern:     `(?i)(backdoor|trigger|poison)`,
			Category:    "backdoor",
			Severity:    "high",
			Confidence:  0.8,
			CreatedAt:   time.Now(),
		},
		{
			ID:          "poison_002",
			Name:        "Malicious Data",
			Description: "Malicious data injection pattern",
			Pattern:     `(?i)(malicious|adversarial|corrupt)`,
			Category:    "injection",
			Severity:    "high",
			Confidence:  0.7,
			CreatedAt:   time.Now(),
		},
		{
			ID:          "poison_003",
			Name:        "Label Flipping",
			Description: "Label flipping attack pattern",
			Pattern:     `(?i)(flip|wrong|incorrect).*(label|class)`,
			Category:    "label_attack",
			Severity:    "medium",
			Confidence:  0.6,
			CreatedAt:   time.Now(),
		},
	}
}

// NewAdversarialAttackDetector creates a new adversarial attack detector
func NewAdversarialAttackDetector(logger *logger.Logger) *AdversarialAttackDetector {
	return &AdversarialAttackDetector{
		logger:               logger,
		adversarialPatterns:  loadAdversarialPatterns(),
		perturbationDetector: NewPerturbationDetector(logger),
		evasionDetector:      NewEvasionDetector(logger),
		config: &AdversarialAttackConfig{
			PerturbationThreshold:       0.1,
			EnablePerturbationDetection: true,
			EnableEvasionDetection:      true,
			AttackTypes:                 []string{"FGSM", "PGD", "C&W", "DeepFool"},
			SensitivityLevel:            "medium",
		},
	}
}

// NewPerturbationDetector creates a new perturbation detector
func NewPerturbationDetector(logger *logger.Logger) *PerturbationDetector {
	return &PerturbationDetector{
		logger:    logger,
		threshold: 0.1,
		patterns:  []string{"noise", "perturbation", "adversarial", "modified"},
	}
}

// NewEvasionDetector creates a new evasion detector
func NewEvasionDetector(logger *logger.Logger) *EvasionDetector {
	return &EvasionDetector{
		logger:   logger,
		patterns: []string{"evasion", "bypass", "avoid", "circumvent"},
	}
}

// NewMembershipInferenceDetector creates a new membership inference detector
func NewMembershipInferenceDetector(logger *logger.Logger) *MembershipInferenceDetector {
	return &MembershipInferenceDetector{
		logger:            logger,
		inferencePatterns: loadInferencePatterns(),
		privacyAnalyzer:   NewPrivacyAnalyzer(logger),
		config: &MembershipInferenceConfig{
			PrivacyThreshold:      0.7,
			EnablePrivacyAnalysis: true,
			SensitiveDataTypes:    []string{"personal", "financial", "medical", "biometric"},
			InferenceThreshold:    0.6,
		},
	}
}

// NewPrivacyAnalyzer creates a new privacy analyzer
func NewPrivacyAnalyzer(logger *logger.Logger) *PrivacyAnalyzer {
	return &PrivacyAnalyzer{
		logger:            logger,
		sensitivePatterns: []string{"ssn", "credit card", "phone", "email", "address"},
		privacyThreshold:  0.7,
	}
}

// NewExtractionAttackDetector creates a new extraction attack detector
func NewExtractionAttackDetector(logger *logger.Logger) *ExtractionAttackDetector {
	return &ExtractionAttackDetector{
		logger:             logger,
		extractionPatterns: loadExtractionPatterns(),
		dataLeakDetector:   NewDataLeakDetector(logger),
		config: &ExtractionAttackConfig{
			ExtractionThreshold:     0.7,
			EnableDataLeakDetection: true,
			SensitivePatterns:       []string{"extract", "dump", "leak", "exfiltrate"},
			ExtractionTypes:         []string{"model_extraction", "data_extraction", "parameter_extraction"},
		},
	}
}

// NewDataLeakDetector creates a new data leak detector
func NewDataLeakDetector(logger *logger.Logger) *DataLeakDetector {
	return &DataLeakDetector{
		logger:          logger,
		leakagePatterns: []string{"leak", "expose", "reveal", "disclose"},
		sensitiveData:   []string{"password", "key", "token", "secret"},
	}
}

// loadAdversarialPatterns loads default adversarial attack patterns
func loadAdversarialPatterns() []*AdversarialPattern {
	return []*AdversarialPattern{
		{
			ID:          "adv_001",
			Name:        "FGSM Attack",
			Description: "Fast Gradient Sign Method attack pattern",
			AttackType:  "gradient_based",
			Pattern:     `(?i)(fgsm|fast.gradient|sign.method)`,
			Severity:    "high",
			Confidence:  0.8,
			CreatedAt:   time.Now(),
		},
		{
			ID:          "adv_002",
			Name:        "PGD Attack",
			Description: "Projected Gradient Descent attack pattern",
			AttackType:  "iterative",
			Pattern:     `(?i)(pgd|projected.gradient|iterative)`,
			Severity:    "high",
			Confidence:  0.8,
			CreatedAt:   time.Now(),
		},
		{
			ID:          "adv_003",
			Name:        "Evasion Attack",
			Description: "General evasion attack pattern",
			AttackType:  "evasion",
			Pattern:     `(?i)(evasion|evade|bypass|circumvent)`,
			Severity:    "medium",
			Confidence:  0.6,
			CreatedAt:   time.Now(),
		},
	}
}

// loadInferencePatterns loads default membership inference patterns
func loadInferencePatterns() []*InferencePattern {
	return []*InferencePattern{
		{
			ID:          "inf_001",
			Name:        "Membership Query",
			Description: "Query attempting to infer membership",
			Pattern:     `(?i)(member|membership|training.data|in.dataset)`,
			DataType:    "membership",
			Severity:    "medium",
			Confidence:  0.7,
			CreatedAt:   time.Now(),
		},
		{
			ID:          "inf_002",
			Name:        "Privacy Inference",
			Description: "Query attempting to infer private information",
			Pattern:     `(?i)(private|personal|sensitive|confidential)`,
			DataType:    "privacy",
			Severity:    "high",
			Confidence:  0.8,
			CreatedAt:   time.Now(),
		},
		{
			ID:          "inf_003",
			Name:        "Statistical Inference",
			Description: "Statistical inference attack pattern",
			Pattern:     `(?i)(statistics|distribution|probability|likelihood)`,
			DataType:    "statistical",
			Severity:    "medium",
			Confidence:  0.6,
			CreatedAt:   time.Now(),
		},
	}
}

// loadExtractionPatterns loads default extraction attack patterns
func loadExtractionPatterns() []*ExtractionPattern {
	return []*ExtractionPattern{
		{
			ID:          "ext_001",
			Name:        "Model Extraction",
			Description: "Attempt to extract model parameters",
			Pattern:     `(?i)(extract|steal|copy).*(model|parameters|weights)`,
			DataType:    "model",
			Severity:    "high",
			Confidence:  0.9,
			CreatedAt:   time.Now(),
		},
		{
			ID:          "ext_002",
			Name:        "Data Extraction",
			Description: "Attempt to extract training data",
			Pattern:     `(?i)(extract|dump|leak).*(data|dataset|training)`,
			DataType:    "data",
			Severity:    "high",
			Confidence:  0.8,
			CreatedAt:   time.Now(),
		},
		{
			ID:          "ext_003",
			Name:        "API Extraction",
			Description: "Attempt to extract API functionality",
			Pattern:     `(?i)(extract|reverse).*(api|function|endpoint)`,
			DataType:    "api",
			Severity:    "medium",
			Confidence:  0.7,
			CreatedAt:   time.Now(),
		},
	}
}

// DetectAdversarialAttack detects adversarial attacks
func (aad *AdversarialAttackDetector) DetectAdversarialAttack(ctx context.Context, input *ThreatDetectionInput) (*AdversarialAttackResult, error) {
	result := &AdversarialAttackResult{
		EvasionTechniques: []string{},
		Evidence:          []ThreatEvidence{},
		Metadata:          make(map[string]interface{}),
	}

	attackDetected := false
	confidence := 0.0

	// Check for adversarial patterns
	for _, pattern := range aad.adversarialPatterns {
		matched, _ := regexp.MatchString(pattern.Pattern, input.Data)
		if matched {
			attackDetected = true
			confidence = math.Max(confidence, pattern.Confidence)
			result.EvasionTechniques = append(result.EvasionTechniques, pattern.Name)
			result.Evidence = append(result.Evidence, ThreatEvidence{
				Type:        "pattern_match",
				Description: pattern.Description,
				Data:        pattern.Pattern,
				Confidence:  pattern.Confidence,
				Source:      "adversarial_attack_detector",
				Timestamp:   time.Now(),
			})
		}
	}

	result.AttackDetected = attackDetected
	result.Confidence = confidence

	if attackDetected {
		result.AttackType = "adversarial_attack"
		result.TargetModel = "unknown"
	}

	return result, nil
}

// DetectMembershipInference detects membership inference attacks
func (mid *MembershipInferenceDetector) DetectMembershipInference(ctx context.Context, input *ThreatDetectionInput) (*MembershipInferenceResult, error) {
	result := &MembershipInferenceResult{
		TargetData:    []string{},
		SensitiveData: []string{},
		Evidence:      []ThreatEvidence{},
		Metadata:      make(map[string]interface{}),
	}

	inferenceDetected := false
	confidence := 0.0

	// Check for inference patterns
	for _, pattern := range mid.inferencePatterns {
		matched, _ := regexp.MatchString(pattern.Pattern, input.Data)
		if matched {
			inferenceDetected = true
			confidence = math.Max(confidence, pattern.Confidence)
			result.TargetData = append(result.TargetData, pattern.DataType)
			result.Evidence = append(result.Evidence, ThreatEvidence{
				Type:        "pattern_match",
				Description: pattern.Description,
				Data:        pattern.Pattern,
				Confidence:  pattern.Confidence,
				Source:      "membership_inference_detector",
				Timestamp:   time.Now(),
			})
		}
	}

	result.InferenceDetected = inferenceDetected
	result.Confidence = confidence

	if inferenceDetected {
		result.InferenceType = "membership_inference"
	}

	return result, nil
}

// DetectExtractionAttack detects data extraction attacks
func (ead *ExtractionAttackDetector) DetectExtractionAttack(ctx context.Context, input *ThreatDetectionInput) (*ExtractionAttackResult, error) {
	result := &ExtractionAttackResult{
		TargetData:        []string{},
		ExtractionMethods: []string{},
		Evidence:          []ThreatEvidence{},
		Metadata:          make(map[string]interface{}),
	}

	extractionDetected := false
	confidence := 0.0

	// Check for extraction patterns
	for _, pattern := range ead.extractionPatterns {
		matched, _ := regexp.MatchString(pattern.Pattern, input.Data)
		if matched {
			extractionDetected = true
			confidence = math.Max(confidence, pattern.Confidence)
			result.TargetData = append(result.TargetData, pattern.DataType)
			result.ExtractionMethods = append(result.ExtractionMethods, pattern.Name)
			result.Evidence = append(result.Evidence, ThreatEvidence{
				Type:        "pattern_match",
				Description: pattern.Description,
				Data:        pattern.Pattern,
				Confidence:  pattern.Confidence,
				Source:      "extraction_attack_detector",
				Timestamp:   time.Now(),
			})
		}
	}

	result.ExtractionDetected = extractionDetected
	result.Confidence = confidence

	if extractionDetected {
		result.ExtractionType = "data_extraction"
	}

	return result, nil
}
