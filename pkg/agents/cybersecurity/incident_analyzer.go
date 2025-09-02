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
	"github.com/dimajoyti/hackai/pkg/llm/retrieval"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var incidentAnalyzerTracer = otel.Tracer("hackai/agents/cybersecurity/incident_analyzer")

// IncidentAnalyzer implements AI-powered security incident analysis
type IncidentAnalyzer struct {
	provider  providers.LLMProvider
	retriever *retrieval.HybridRetriever
	logger    *logger.Logger
	playbooks IncidentPlaybooks
}

// IncidentAnalysisRequest represents an incident analysis request
type IncidentAnalysisRequest struct {
	Content string                 `json:"content"`
	Context map[string]interface{} `json:"context"`
	Type    string                 `json:"type,omitempty"`
}

// IncidentPlaybooks contains incident response playbooks
type IncidentPlaybooks struct {
	DataBreach       IncidentPlaybook `json:"data_breach"`
	MalwareInfection IncidentPlaybook `json:"malware_infection"`
	PhishingAttack   IncidentPlaybook `json:"phishing_attack"`
	DDoSAttack       IncidentPlaybook `json:"ddos_attack"`
	InsiderThreat    IncidentPlaybook `json:"insider_threat"`
	AIModelAttack    IncidentPlaybook `json:"ai_model_attack"`
}

// IncidentPlaybook represents an incident response playbook
type IncidentPlaybook struct {
	Name         string              `json:"name"`
	Type         string              `json:"type"`
	Description  string              `json:"description"`
	Phases       []IncidentPhase     `json:"phases"`
	Indicators   []string            `json:"indicators"`
	Actions      []ResponseAction    `json:"actions"`
	Stakeholders []string            `json:"stakeholders"`
	Timeline     map[string]string   `json:"timeline"`
	Escalation   EscalationProcedure `json:"escalation"`
}

// IncidentPhase represents a phase in incident response
type IncidentPhase struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Actions     []string `json:"actions"`
	Duration    string   `json:"duration"`
	Criteria    []string `json:"criteria"`
}

// EscalationProcedure represents escalation procedures
type EscalationProcedure struct {
	Triggers   []string `json:"triggers"`
	Contacts   []string `json:"contacts"`
	Timeline   string   `json:"timeline"`
	Procedures []string `json:"procedures"`
}

// NewIncidentAnalyzer creates a new incident analyzer
func NewIncidentAnalyzer(
	provider providers.LLMProvider,
	retriever *retrieval.HybridRetriever,
	logger *logger.Logger,
) *IncidentAnalyzer {
	playbooks := IncidentPlaybooks{
		DataBreach: IncidentPlaybook{
			Name:        "Data Breach Response",
			Type:        "data_breach",
			Description: "Response procedures for data breach incidents",
			Phases: []IncidentPhase{
				{
					Name:        "Detection and Analysis",
					Description: "Identify and analyze the breach",
					Actions:     []string{"Confirm breach", "Assess scope", "Preserve evidence"},
					Duration:    "1-4 hours",
					Criteria:    []string{"Breach confirmed", "Initial scope assessed"},
				},
				{
					Name:        "Containment",
					Description: "Contain the breach to prevent further damage",
					Actions:     []string{"Isolate affected systems", "Revoke compromised credentials", "Apply patches"},
					Duration:    "4-24 hours",
					Criteria:    []string{"Breach contained", "No further data loss"},
				},
				{
					Name:        "Recovery",
					Description: "Restore systems and operations",
					Actions:     []string{"Restore from backups", "Implement additional controls", "Monitor for recurrence"},
					Duration:    "1-7 days",
					Criteria:    []string{"Systems restored", "Operations normalized"},
				},
			},
			Indicators:   []string{"unauthorized access", "data exfiltration", "credential compromise"},
			Stakeholders: []string{"CISO", "Legal", "PR", "IT", "Management"},
		},
		AIModelAttack: IncidentPlaybook{
			Name:        "AI Model Attack Response",
			Type:        "ai_model_attack",
			Description: "Response procedures for AI model security incidents",
			Phases: []IncidentPhase{
				{
					Name:        "Detection and Classification",
					Description: "Identify and classify the AI attack",
					Actions:     []string{"Analyze attack patterns", "Classify attack type", "Assess model integrity"},
					Duration:    "30 minutes - 2 hours",
					Criteria:    []string{"Attack type identified", "Model status assessed"},
				},
				{
					Name:        "Model Protection",
					Description: "Protect the AI model from further attacks",
					Actions:     []string{"Enable additional filtering", "Implement rate limiting", "Switch to backup model"},
					Duration:    "1-4 hours",
					Criteria:    []string{"Model protected", "Attack mitigated"},
				},
				{
					Name:        "Model Recovery",
					Description: "Restore model operations and improve defenses",
					Actions:     []string{"Retrain if necessary", "Update security controls", "Enhance monitoring"},
					Duration:    "1-3 days",
					Criteria:    []string{"Model operational", "Defenses enhanced"},
				},
			},
			Indicators:   []string{"prompt injection", "model extraction", "adversarial inputs", "data poisoning"},
			Stakeholders: []string{"AI Team", "Security Team", "Data Science", "Engineering"},
		},
	}

	return &IncidentAnalyzer{
		provider:  provider,
		retriever: retriever,
		logger:    logger,
		playbooks: playbooks,
	}
}

// AnalyzeIncidents performs comprehensive incident analysis
func (ia *IncidentAnalyzer) AnalyzeIncidents(ctx context.Context, request IncidentAnalysisRequest) ([]SecurityIncident, error) {
	ctx, span := incidentAnalyzerTracer.Start(ctx, "incident_analyzer.analyze_incidents",
		trace.WithAttributes(
			attribute.Int("content_length", len(request.Content)),
		),
	)
	defer span.End()

	ia.logger.Info("Starting incident analysis")

	var incidents []SecurityIncident

	// Pattern-based incident detection
	patternIncidents := ia.detectPatternIncidents(request)
	incidents = append(incidents, patternIncidents...)

	// AI-powered incident analysis
	aiIncidents, err := ia.analyzeAIIncidents(ctx, request)
	if err != nil {
		span.RecordError(err)
		ia.logger.Warn("AI incident analysis failed", "error", err)
	} else {
		incidents = append(incidents, aiIncidents...)
	}

	// Knowledge base incident correlation
	kbIncidents, err := ia.correlateKnowledgeBaseIncidents(ctx, request)
	if err != nil {
		span.RecordError(err)
		ia.logger.Warn("Knowledge base correlation failed", "error", err)
	} else {
		incidents = append(incidents, kbIncidents...)
	}

	// Enrich incidents with response plans
	for i := range incidents {
		ia.enrichIncidentWithResponse(&incidents[i])
	}

	span.SetAttributes(
		attribute.Int("incidents_detected", len(incidents)),
	)

	ia.logger.Info("Incident analysis completed", "incidents_detected", len(incidents))

	return incidents, nil
}

// detectPatternIncidents detects incidents using pattern matching
func (ia *IncidentAnalyzer) detectPatternIncidents(request IncidentAnalysisRequest) []SecurityIncident {
	var incidents []SecurityIncident
	content := strings.ToLower(request.Content)

	// Check for data breach indicators
	dataBreachIndicators := []string{"data breach", "unauthorized access", "data leak", "credential compromise"}
	for _, indicator := range dataBreachIndicators {
		if strings.Contains(content, indicator) {
			incidents = append(incidents, SecurityIncident{
				ID:          fmt.Sprintf("data_breach_%d", time.Now().UnixNano()),
				Type:        "data_breach",
				Severity:    "high",
				Status:      "detected",
				Description: fmt.Sprintf("Potential data breach detected: %s", indicator),
				Timeline: []IncidentEvent{
					{
						Timestamp:   time.Now(),
						Type:        "detection",
						Description: fmt.Sprintf("Pattern detected: %s", indicator),
						Source:      "pattern_analysis",
					},
				},
				Indicators: []ThreatIndicator{
					{
						Type:        "pattern",
						Value:       indicator,
						Confidence:  0.7,
						FirstSeen:   time.Now(),
						LastSeen:    time.Now(),
						ThreatTypes: []string{"data_breach"},
					},
				},
			})
		}
	}

	// Check for AI model attack indicators
	aiAttackIndicators := []string{"prompt injection", "model extraction", "adversarial input", "data poisoning"}
	for _, indicator := range aiAttackIndicators {
		if strings.Contains(content, indicator) {
			incidents = append(incidents, SecurityIncident{
				ID:          fmt.Sprintf("ai_attack_%d", time.Now().UnixNano()),
				Type:        "ai_model_attack",
				Severity:    "high",
				Status:      "detected",
				Description: fmt.Sprintf("Potential AI model attack detected: %s", indicator),
				Timeline: []IncidentEvent{
					{
						Timestamp:   time.Now(),
						Type:        "detection",
						Description: fmt.Sprintf("AI attack pattern detected: %s", indicator),
						Source:      "pattern_analysis",
					},
				},
				Indicators: []ThreatIndicator{
					{
						Type:        "pattern",
						Value:       indicator,
						Confidence:  0.8,
						FirstSeen:   time.Now(),
						LastSeen:    time.Now(),
						ThreatTypes: []string{"ai_attack"},
					},
				},
			})
		}
	}

	return incidents
}

// analyzeAIIncidents uses AI to analyze potential incidents
func (ia *IncidentAnalyzer) analyzeAIIncidents(ctx context.Context, request IncidentAnalysisRequest) ([]SecurityIncident, error) {
	prompt := fmt.Sprintf(`Analyze the following content for security incidents:

Content: %s

Identify potential security incidents including:
1. Data breaches or unauthorized access
2. Malware infections or suspicious activity
3. Phishing or social engineering attacks
4. DDoS or availability issues
5. Insider threats or policy violations
6. AI model attacks or manipulation attempts

For each incident found, provide:
- Incident type
- Severity level (low/medium/high/critical)
- Current status (detected/investigating/contained/resolved)
- Brief description
- Potential indicators of compromise
- Recommended immediate actions

Respond in a structured format.`, request.Content)

	genRequest := providers.GenerationRequest{
		Messages: []providers.Message{
			{
				Role:    "user",
				Content: prompt,
			},
		},
		MaxTokens:   1500,
		Temperature: 0.1,
	}

	response, err := ia.provider.Generate(ctx, genRequest)
	if err != nil {
		return nil, fmt.Errorf("AI incident analysis failed: %w", err)
	}

	// Parse AI response
	incidents := ia.parseAIIncidentResponse(response.Content)

	return incidents, nil
}

// correlateKnowledgeBaseIncidents correlates with known incident patterns
func (ia *IncidentAnalyzer) correlateKnowledgeBaseIncidents(ctx context.Context, request IncidentAnalysisRequest) ([]SecurityIncident, error) {
	if ia.retriever == nil {
		return []SecurityIncident{}, nil
	}

	// Search for similar incident patterns
	query := retrieval.RetrievalQuery{
		Text:       fmt.Sprintf("security incident %s", request.Content),
		MaxResults: 5,
		MinScore:   0.7,
	}

	result, err := ia.retriever.Retrieve(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("knowledge base search failed: %w", err)
	}

	var incidents []SecurityIncident
	for _, doc := range result.Documents {
		incident := ia.extractIncidentFromDocument(doc)
		if incident.ID != "" {
			incidents = append(incidents, incident)
		}
	}

	return incidents, nil
}

// enrichIncidentWithResponse enriches incident with response plan
func (ia *IncidentAnalyzer) enrichIncidentWithResponse(incident *SecurityIncident) {
	var playbook IncidentPlaybook
	var found bool

	// Select appropriate playbook
	switch incident.Type {
	case "data_breach":
		playbook = ia.playbooks.DataBreach
		found = true
	case "ai_model_attack":
		playbook = ia.playbooks.AIModelAttack
		found = true
	}

	if !found {
		// Use generic response plan
		playbook = IncidentPlaybook{
			Name:        "Generic Incident Response",
			Type:        "generic",
			Description: "Generic incident response procedures",
			Phases: []IncidentPhase{
				{
					Name:        "Assessment",
					Description: "Assess the incident",
					Actions:     []string{"Gather information", "Assess impact", "Classify incident"},
					Duration:    "1-2 hours",
				},
				{
					Name:        "Response",
					Description: "Respond to the incident",
					Actions:     []string{"Implement containment", "Mitigate impact", "Preserve evidence"},
					Duration:    "2-8 hours",
				},
				{
					Name:        "Recovery",
					Description: "Recover from the incident",
					Actions:     []string{"Restore operations", "Implement improvements", "Document lessons learned"},
					Duration:    "1-3 days",
				},
			},
		}
	}

	// Generate response plan
	incident.Response = IncidentResponse{
		Status: "planned",
		Actions: []ResponseAction{
			{
				ID:          fmt.Sprintf("action_%d", time.Now().UnixNano()),
				Type:        "immediate",
				Description: "Begin incident response procedures",
				Status:      "pending",
				Timestamp:   time.Now(),
				Assignee:    "incident_commander",
			},
		},
		Containment: ContainmentStrategy{
			Type:      "immediate",
			Actions:   []string{"Isolate affected systems", "Preserve evidence", "Notify stakeholders"},
			Timeline:  "1-4 hours",
			Resources: []string{"Security team", "IT operations", "Management"},
		},
		Recovery: RecoveryPlan{
			Steps: []RecoveryStep{
				{
					ID:          "recovery_1",
					Description: "Assess damage and plan recovery",
					Status:      "pending",
					Timeline:    "1-2 hours",
				},
				{
					ID:           "recovery_2",
					Description:  "Implement recovery procedures",
					Status:       "pending",
					Dependencies: []string{"recovery_1"},
					Timeline:     "2-8 hours",
				},
			},
			Timeline:   "1-3 days",
			Validation: []string{"System functionality verified", "Security controls validated"},
			Rollback:   []string{"Restore from backup", "Revert configuration changes"},
		},
	}

	// Add playbook metadata
	incident.Metadata = map[string]interface{}{
		"playbook":     playbook.Name,
		"phases":       len(playbook.Phases),
		"stakeholders": playbook.Stakeholders,
		"enriched_at":  time.Now(),
	}
}

// parseAIIncidentResponse parses AI response into incidents
func (ia *IncidentAnalyzer) parseAIIncidentResponse(response string) []SecurityIncident {
	// Simplified parsing - in practice, use structured output
	var incidents []SecurityIncident

	if strings.Contains(strings.ToLower(response), "incident") {
		incidents = append(incidents, SecurityIncident{
			ID:          fmt.Sprintf("ai_incident_%d", time.Now().UnixNano()),
			Type:        "ai_detected",
			Severity:    "medium",
			Status:      "detected",
			Description: "AI-detected potential security incident",
			Timeline: []IncidentEvent{
				{
					Timestamp:   time.Now(),
					Type:        "detection",
					Description: "Incident detected by AI analysis",
					Source:      "ai_analysis",
				},
			},
			Metadata: map[string]interface{}{
				"ai_response": response,
				"detected_at": time.Now(),
			},
		})
	}

	return incidents
}

// extractIncidentFromDocument extracts incident info from retrieved document
func (ia *IncidentAnalyzer) extractIncidentFromDocument(doc retrieval.ScoredDocument) SecurityIncident {
	// Simplified extraction - in practice, use NLP techniques
	if strings.Contains(strings.ToLower(doc.Content), "incident") {
		return SecurityIncident{
			ID:          fmt.Sprintf("kb_incident_%s_%d", doc.ID, time.Now().UnixNano()),
			Type:        "knowledge_base",
			Severity:    "medium",
			Status:      "detected",
			Description: "Incident pattern identified from knowledge base",
			Timeline: []IncidentEvent{
				{
					Timestamp:   time.Now(),
					Type:        "correlation",
					Description: "Similar incident pattern found in knowledge base",
					Source:      "knowledge_base",
				},
			},
			Metadata: map[string]interface{}{
				"source_doc":  doc.ID,
				"score":       doc.FinalScore,
				"detected_at": time.Now(),
			},
		}
	}

	return SecurityIncident{}
}
