package usecase

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// AIModelService coordinates all AI-powered security analysis
type AIModelService struct {
	vulnScanner     *VulnerabilityScannerUseCase
	networkAnalyzer *NetworkAnalyzerUseCase
	threatIntel     *ThreatIntelligenceUseCase
	logAnalyzer     *LogAnalyzerUseCase
	repo            domain.SecurityRepository
	logger          *logger.Logger
}

// AIAnalysisRequest represents a comprehensive AI analysis request
type AIAnalysisRequest struct {
	ID        uuid.UUID              `json:"id"`
	UserID    uuid.UUID              `json:"user_id"`
	Type      string                 `json:"type"`     // comprehensive, vulnerability, network, threat, logs
	Targets   []string               `json:"targets"`  // URLs, IPs, domains, etc.
	Config    map[string]interface{} `json:"config"`   // Analysis configuration
	Priority  string                 `json:"priority"` // low, medium, high, critical
	CreatedAt time.Time              `json:"created_at"`
}

// AIAnalysisResult represents comprehensive AI analysis results
type AIAnalysisResult struct {
	ID                   uuid.UUID                    `json:"id"`
	RequestID            uuid.UUID                    `json:"request_id"`
	OverallRiskScore     float64                      `json:"overall_risk_score"` // 0-10
	OverallConfidence    float64                      `json:"overall_confidence"` // 0-1
	ThreatLevel          string                       `json:"threat_level"`       // low, medium, high, critical
	VulnerabilityResults []VulnerabilityAnalysis      `json:"vulnerability_results"`
	NetworkResults       []NetworkAnalysis            `json:"network_results"`
	ThreatIntelResults   []ThreatIntelligenceAnalysis `json:"threat_intel_results"`
	LogAnalysisResults   []*LogAnalysisReport         `json:"log_analysis_results"`
	CorrelatedFindings   []CorrelatedFinding          `json:"correlated_findings"`
	AIInsights           []AIInsight                  `json:"ai_insights"`
	Recommendations      []AIRecommendation           `json:"recommendations"`
	ExecutionTime        time.Duration                `json:"execution_time"`
	CompletedAt          time.Time                    `json:"completed_at"`
}

// VulnerabilityAnalysis represents AI-enhanced vulnerability analysis
type VulnerabilityAnalysis struct {
	Target             string                  `json:"target"`
	Vulnerabilities    []*domain.Vulnerability `json:"vulnerabilities"`
	RiskScore          float64                 `json:"risk_score"`
	AIConfidence       float64                 `json:"ai_confidence"`
	ExploitProbability float64                 `json:"exploit_probability"`
	BusinessImpact     string                  `json:"business_impact"`
}

// NetworkAnalysis represents AI-enhanced network analysis
type NetworkAnalysis struct {
	Target          string                `json:"target"`
	Hosts           []*domain.NetworkHost `json:"hosts"`
	RiskScore       float64               `json:"risk_score"`
	AIConfidence    float64               `json:"ai_confidence"`
	AttackSurface   AttackSurfaceAnalysis `json:"attack_surface"`
	SecurityPosture string                `json:"security_posture"`
}

// ThreatIntelligenceAnalysis represents AI-enhanced threat intelligence
type ThreatIntelligenceAnalysis struct {
	Target      string            `json:"target"`
	Report      *ThreatReport     `json:"report"`
	RiskScore   float64           `json:"risk_score"`
	Indicators  []ThreatIndicator `json:"indicators"`
	Attribution string            `json:"attribution"`
}

// AttackSurfaceAnalysis represents attack surface analysis
type AttackSurfaceAnalysis struct {
	OpenPorts       int     `json:"open_ports"`
	Services        int     `json:"services"`
	Vulnerabilities int     `json:"vulnerabilities"`
	ExposureScore   float64 `json:"exposure_score"`
	CriticalAssets  int     `json:"critical_assets"`
}

// CorrelatedFinding represents correlated security findings across different analysis types
type CorrelatedFinding struct {
	ID          uuid.UUID       `json:"id"`
	Type        string          `json:"type"` // cross_reference, pattern_match, temporal_correlation
	Severity    string          `json:"severity"`
	Confidence  float64         `json:"confidence"`
	Description string          `json:"description"`
	Evidence    []string        `json:"evidence"`
	Sources     []string        `json:"sources"` // vulnerability, network, threat_intel, logs
	Timeline    []TimelineEvent `json:"timeline"`
}

// TimelineEvent represents events in a security timeline
type TimelineEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Source      string    `json:"source"`
	Event       string    `json:"event"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
}

// AIInsight represents AI-generated security insights
type AIInsight struct {
	ID          uuid.UUID   `json:"id"`
	Type        string      `json:"type"`     // pattern, trend, prediction, anomaly
	Category    string      `json:"category"` // security, performance, compliance
	Confidence  float64     `json:"confidence"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Impact      string      `json:"impact"`
	Evidence    []string    `json:"evidence"`
	Prediction  *Prediction `json:"prediction,omitempty"`
}

// Prediction represents AI predictions about future security events
type Prediction struct {
	Event       string   `json:"event"`
	Probability float64  `json:"probability"`
	Timeframe   string   `json:"timeframe"`
	Confidence  float64  `json:"confidence"`
	Mitigation  []string `json:"mitigation"`
}

// AIRecommendation represents AI-generated security recommendations
type AIRecommendation struct {
	ID          uuid.UUID `json:"id"`
	Priority    string    `json:"priority"` // critical, high, medium, low
	Category    string    `json:"category"` // immediate, short_term, long_term
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Actions     []string  `json:"actions"`
	Resources   []string  `json:"resources"`
	Timeline    string    `json:"timeline"`
	Cost        string    `json:"cost"`   // low, medium, high
	Effort      string    `json:"effort"` // low, medium, high
	Impact      string    `json:"impact"` // low, medium, high
}

// NewAIModelService creates a new AI model service
func NewAIModelService(
	vulnScanner *VulnerabilityScannerUseCase,
	networkAnalyzer *NetworkAnalyzerUseCase,
	threatIntel *ThreatIntelligenceUseCase,
	logAnalyzer *LogAnalyzerUseCase,
	repo domain.SecurityRepository,
	log *logger.Logger,
) *AIModelService {
	return &AIModelService{
		vulnScanner:     vulnScanner,
		networkAnalyzer: networkAnalyzer,
		threatIntel:     threatIntel,
		logAnalyzer:     logAnalyzer,
		repo:            repo,
		logger:          log,
	}
}

// PerformComprehensiveAnalysis performs AI-powered comprehensive security analysis
func (ai *AIModelService) PerformComprehensiveAnalysis(ctx context.Context, request *AIAnalysisRequest) (*AIAnalysisResult, error) {
	startTime := time.Now()

	result := &AIAnalysisResult{
		ID:        uuid.New(),
		RequestID: request.ID,
	}

	ai.logger.WithContext(ctx).WithFields(logger.Fields{
		"request_id": request.ID,
		"user_id":    request.UserID,
		"targets":    len(request.Targets),
		"type":       request.Type,
	}).Info("Starting comprehensive AI security analysis")

	// Perform parallel analysis across all domains
	vulnResults := ai.performVulnerabilityAnalysis(ctx, request.Targets)
	networkResults := ai.performNetworkAnalysis(ctx, request.Targets)
	threatResults := ai.performThreatIntelligenceAnalysis(ctx, request.Targets)

	result.VulnerabilityResults = vulnResults
	result.NetworkResults = networkResults
	result.ThreatIntelResults = threatResults

	// Perform AI correlation and analysis
	result.CorrelatedFindings = ai.correlateFindings(vulnResults, networkResults, threatResults)
	result.AIInsights = ai.generateAIInsights(vulnResults, networkResults, threatResults)
	result.Recommendations = ai.generateAIRecommendations(result.CorrelatedFindings, result.AIInsights)

	// Calculate overall risk metrics
	result.OverallRiskScore = ai.calculateOverallRiskScore(vulnResults, networkResults, threatResults)
	result.OverallConfidence = ai.calculateOverallConfidence(vulnResults, networkResults, threatResults)
	result.ThreatLevel = ai.determineThreatLevel(result.OverallRiskScore)

	result.ExecutionTime = time.Since(startTime)
	result.CompletedAt = time.Now()

	ai.logger.WithContext(ctx).WithFields(logger.Fields{
		"request_id":         request.ID,
		"overall_risk_score": result.OverallRiskScore,
		"threat_level":       result.ThreatLevel,
		"execution_time":     result.ExecutionTime,
		"findings":           len(result.CorrelatedFindings),
		"insights":           len(result.AIInsights),
	}).Info("Comprehensive AI security analysis completed")

	return result, nil
}

// performVulnerabilityAnalysis performs AI-enhanced vulnerability analysis
func (ai *AIModelService) performVulnerabilityAnalysis(ctx context.Context, targets []string) []VulnerabilityAnalysis {
	var results []VulnerabilityAnalysis

	for _, target := range targets {
		// Simulate vulnerability scanning (in real implementation, would call actual scanner)
		analysis := VulnerabilityAnalysis{
			Target: target,
			Vulnerabilities: []*domain.Vulnerability{
				{
					Type:        domain.VulnTypeSQLInjection,
					Severity:    domain.SeverityCritical,
					Title:       "SQL Injection in Login Form",
					Description: "Potential SQL injection vulnerability detected",
					URL:         target,
					Solution:    "Use parameterized queries",
				},
			},
			RiskScore:          8.5,
			AIConfidence:       0.9,
			ExploitProbability: 0.8,
			BusinessImpact:     "High - potential data breach",
		}
		results = append(results, analysis)
	}

	return results
}

// performNetworkAnalysis performs AI-enhanced network analysis
func (ai *AIModelService) performNetworkAnalysis(ctx context.Context, targets []string) []NetworkAnalysis {
	var results []NetworkAnalysis

	for _, target := range targets {
		analysis := NetworkAnalysis{
			Target: target,
			Hosts: []*domain.NetworkHost{
				{
					IPAddress: target,
					Status:    "up",
					OS:        "Linux",
					Ports: []domain.NetworkPort{
						{Port: 22, Protocol: "tcp", State: "open", Service: "SSH"},
						{Port: 80, Protocol: "tcp", State: "open", Service: "HTTP"},
						{Port: 443, Protocol: "tcp", State: "open", Service: "HTTPS"},
					},
				},
			},
			RiskScore:    6.5,
			AIConfidence: 0.85,
			AttackSurface: AttackSurfaceAnalysis{
				OpenPorts:       3,
				Services:        3,
				Vulnerabilities: 1,
				ExposureScore:   6.5,
				CriticalAssets:  1,
			},
			SecurityPosture: "Moderate - some security controls in place",
		}
		results = append(results, analysis)
	}

	return results
}

// performThreatIntelligenceAnalysis performs AI-enhanced threat intelligence analysis
func (ai *AIModelService) performThreatIntelligenceAnalysis(ctx context.Context, targets []string) []ThreatIntelligenceAnalysis {
	var results []ThreatIntelligenceAnalysis

	for _, target := range targets {
		// Simulate threat intelligence analysis
		report := &ThreatReport{
			ID:         uuid.New(),
			Target:     target,
			RiskScore:  5.0,
			Confidence: 0.7,
			Summary:    "No significant threat indicators found",
			Indicators: []ThreatIndicator{},
			CreatedAt:  time.Now(),
		}

		analysis := ThreatIntelligenceAnalysis{
			Target:      target,
			Report:      report,
			RiskScore:   5.0,
			Indicators:  []ThreatIndicator{},
			Attribution: "Unknown",
		}
		results = append(results, analysis)
	}

	return results
}

// correlateFindings performs AI-powered correlation of findings across different analysis types
func (ai *AIModelService) correlateFindings(
	vulnResults []VulnerabilityAnalysis,
	networkResults []NetworkAnalysis,
	threatResults []ThreatIntelligenceAnalysis,
) []CorrelatedFinding {
	var findings []CorrelatedFinding

	// Cross-reference vulnerability and network findings
	for _, vulnResult := range vulnResults {
		for _, networkResult := range networkResults {
			if vulnResult.Target == networkResult.Target {
				// Check for correlation between open ports and vulnerabilities
				for _, vuln := range vulnResult.Vulnerabilities {
					for _, host := range networkResult.Hosts {
						for _, port := range host.Ports {
							if ai.isVulnerabilityRelatedToPort(vuln, &port) {
								finding := CorrelatedFinding{
									ID:          uuid.New(),
									Type:        "cross_reference",
									Severity:    string(vuln.Severity),
									Confidence:  0.8,
									Description: fmt.Sprintf("Vulnerability %s correlates with open port %d", vuln.Title, port.Port),
									Evidence:    []string{vuln.Title, fmt.Sprintf("Open port %d/%s", port.Port, port.Protocol)},
									Sources:     []string{"vulnerability", "network"},
									Timeline:    []TimelineEvent{},
								}
								findings = append(findings, finding)
							}
						}
					}
				}
			}
		}
	}

	// Pattern matching across threat intelligence and vulnerabilities
	for _, vulnResult := range vulnResults {
		for _, threatResult := range threatResults {
			if vulnResult.Target == threatResult.Target {
				if len(threatResult.Indicators) > 0 && len(vulnResult.Vulnerabilities) > 0 {
					finding := CorrelatedFinding{
						ID:          uuid.New(),
						Type:        "pattern_match",
						Severity:    "high",
						Confidence:  0.75,
						Description: "Target has both vulnerabilities and threat indicators",
						Evidence:    []string{"Multiple vulnerabilities", "Threat indicators present"},
						Sources:     []string{"vulnerability", "threat_intel"},
						Timeline:    []TimelineEvent{},
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

// generateAIInsights generates AI-powered security insights
func (ai *AIModelService) generateAIInsights(
	vulnResults []VulnerabilityAnalysis,
	networkResults []NetworkAnalysis,
	threatResults []ThreatIntelligenceAnalysis,
) []AIInsight {
	var insights []AIInsight

	// Analyze vulnerability patterns
	vulnTypes := make(map[domain.VulnerabilityType]int)
	for _, result := range vulnResults {
		for _, vuln := range result.Vulnerabilities {
			vulnTypes[vuln.Type]++
		}
	}

	if len(vulnTypes) > 0 {
		mostCommon := ai.findMostCommonVulnerability(vulnTypes)
		insight := AIInsight{
			ID:          uuid.New(),
			Type:        "pattern",
			Category:    "security",
			Confidence:  0.85,
			Title:       "Vulnerability Pattern Analysis",
			Description: fmt.Sprintf("Most common vulnerability type: %s", mostCommon),
			Impact:      "High - indicates systematic security issues",
			Evidence:    []string{fmt.Sprintf("%s vulnerabilities detected", mostCommon)},
		}
		insights = append(insights, insight)
	}

	// Analyze attack surface trends
	totalOpenPorts := 0
	for _, result := range networkResults {
		totalOpenPorts += result.AttackSurface.OpenPorts
	}

	if totalOpenPorts > 10 {
		insight := AIInsight{
			ID:          uuid.New(),
			Type:        "trend",
			Category:    "security",
			Confidence:  0.8,
			Title:       "Large Attack Surface Detected",
			Description: fmt.Sprintf("Total of %d open ports detected across targets", totalOpenPorts),
			Impact:      "Medium - increased attack surface",
			Evidence:    []string{fmt.Sprintf("%d open ports", totalOpenPorts)},
		}
		insights = append(insights, insight)
	}

	// Generate security predictions
	if ai.shouldGeneratePrediction(vulnResults, networkResults) {
		prediction := &Prediction{
			Event:       "Potential security incident",
			Probability: 0.7,
			Timeframe:   "30 days",
			Confidence:  0.75,
			Mitigation:  []string{"Patch critical vulnerabilities", "Implement monitoring"},
		}

		insight := AIInsight{
			ID:          uuid.New(),
			Type:        "prediction",
			Category:    "security",
			Confidence:  0.75,
			Title:       "Security Incident Prediction",
			Description: "AI model predicts potential security incident based on current vulnerabilities",
			Impact:      "High - proactive security measures needed",
			Evidence:    []string{"Multiple critical vulnerabilities", "Large attack surface"},
			Prediction:  prediction,
		}
		insights = append(insights, insight)
	}

	return insights
}

// generateAIRecommendations generates AI-powered security recommendations
func (ai *AIModelService) generateAIRecommendations(findings []CorrelatedFinding, insights []AIInsight) []AIRecommendation {
	var recommendations []AIRecommendation

	// Critical immediate actions
	hasCriticalFindings := false
	for _, finding := range findings {
		if finding.Severity == "critical" {
			hasCriticalFindings = true
			break
		}
	}

	if hasCriticalFindings {
		rec := AIRecommendation{
			ID:          uuid.New(),
			Priority:    "critical",
			Category:    "immediate",
			Title:       "Address Critical Security Findings",
			Description: "Critical security issues require immediate attention",
			Actions: []string{
				"Patch critical vulnerabilities immediately",
				"Block suspicious IP addresses",
				"Implement emergency monitoring",
			},
			Resources: []string{"Security team", "System administrators"},
			Timeline:  "24 hours",
			Cost:      "medium",
			Effort:    "high",
			Impact:    "high",
		}
		recommendations = append(recommendations, rec)
	}

	// Network security improvements
	rec := AIRecommendation{
		ID:          uuid.New(),
		Priority:    "high",
		Category:    "short_term",
		Title:       "Improve Network Security Posture",
		Description: "Reduce attack surface and improve network defenses",
		Actions: []string{
			"Close unnecessary ports",
			"Implement network segmentation",
			"Deploy intrusion detection system",
		},
		Resources: []string{"Network team", "Security tools"},
		Timeline:  "2 weeks",
		Cost:      "medium",
		Effort:    "medium",
		Impact:    "high",
	}
	recommendations = append(recommendations, rec)

	// Long-term security strategy
	rec = AIRecommendation{
		ID:          uuid.New(),
		Priority:    "medium",
		Category:    "long_term",
		Title:       "Implement Comprehensive Security Program",
		Description: "Establish ongoing security practices and monitoring",
		Actions: []string{
			"Implement regular vulnerability assessments",
			"Establish security awareness training",
			"Deploy SIEM solution",
			"Create incident response plan",
		},
		Resources: []string{"Security team", "Management", "Training budget"},
		Timeline:  "3 months",
		Cost:      "high",
		Effort:    "high",
		Impact:    "high",
	}
	recommendations = append(recommendations, rec)

	// Sort recommendations by priority
	sort.Slice(recommendations, func(i, j int) bool {
		priorityOrder := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
		return priorityOrder[recommendations[i].Priority] > priorityOrder[recommendations[j].Priority]
	})

	return recommendations
}

// Helper methods for AI analysis

func (ai *AIModelService) calculateOverallRiskScore(
	vulnResults []VulnerabilityAnalysis,
	networkResults []NetworkAnalysis,
	threatResults []ThreatIntelligenceAnalysis,
) float64 {
	var scores []float64

	for _, result := range vulnResults {
		scores = append(scores, result.RiskScore)
	}
	for _, result := range networkResults {
		scores = append(scores, result.RiskScore)
	}
	for _, result := range threatResults {
		scores = append(scores, result.RiskScore)
	}

	if len(scores) == 0 {
		return 0.0
	}

	// Calculate weighted average with emphasis on highest scores
	sort.Float64s(scores)

	total := 0.0
	weight := 1.0
	totalWeight := 0.0

	// Give more weight to higher scores
	for i := len(scores) - 1; i >= 0; i-- {
		total += scores[i] * weight
		totalWeight += weight
		weight *= 0.8 // Decrease weight for lower scores
	}

	return math.Min(total/totalWeight, 10.0)
}

func (ai *AIModelService) calculateOverallConfidence(
	vulnResults []VulnerabilityAnalysis,
	networkResults []NetworkAnalysis,
	threatResults []ThreatIntelligenceAnalysis,
) float64 {
	var confidences []float64

	for _, result := range vulnResults {
		confidences = append(confidences, result.AIConfidence)
	}
	for _, result := range networkResults {
		confidences = append(confidences, result.AIConfidence)
	}
	for _, result := range threatResults {
		confidences = append(confidences, result.Report.Confidence)
	}

	if len(confidences) == 0 {
		return 0.0
	}

	total := 0.0
	for _, conf := range confidences {
		total += conf
	}

	return total / float64(len(confidences))
}

func (ai *AIModelService) determineThreatLevel(riskScore float64) string {
	if riskScore >= 8.0 {
		return "critical"
	} else if riskScore >= 6.0 {
		return "high"
	} else if riskScore >= 4.0 {
		return "medium"
	}
	return "low"
}

func (ai *AIModelService) isVulnerabilityRelatedToPort(vuln *domain.Vulnerability, port *domain.NetworkPort) bool {
	// Simple correlation logic - in real implementation, this would be more sophisticated
	if vuln.Type == domain.VulnTypeSQLInjection && (port.Port == 80 || port.Port == 443) {
		return true
	}
	if vuln.Type == domain.VulnTypeXSS && (port.Port == 80 || port.Port == 443) {
		return true
	}
	return false
}

func (ai *AIModelService) findMostCommonVulnerability(vulnTypes map[domain.VulnerabilityType]int) string {
	maxCount := 0
	var mostCommon domain.VulnerabilityType

	for vulnType, count := range vulnTypes {
		if count > maxCount {
			maxCount = count
			mostCommon = vulnType
		}
	}

	return string(mostCommon)
}

func (ai *AIModelService) shouldGeneratePrediction(vulnResults []VulnerabilityAnalysis, networkResults []NetworkAnalysis) bool {
	// Generate prediction if there are critical vulnerabilities and large attack surface
	criticalVulns := 0
	totalPorts := 0

	for _, result := range vulnResults {
		for _, vuln := range result.Vulnerabilities {
			if vuln.Severity == domain.SeverityCritical {
				criticalVulns++
			}
		}
	}

	for _, result := range networkResults {
		totalPorts += result.AttackSurface.OpenPorts
	}

	return criticalVulns > 0 && totalPorts > 5
}
