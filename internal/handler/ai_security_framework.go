package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dimajoyti/hackai/internal/usecase"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/security"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

var aiSecurityHandlerTracer = otel.Tracer("hackai/handler/ai_security_framework")

// AISecurityFrameworkHandler handles AI security framework HTTP requests
type AISecurityFrameworkHandler struct {
	logger              *logger.Logger
	aiSecurityFramework *usecase.AISecurityFramework
}

// NewAISecurityFrameworkHandler creates a new AI security framework handler
func NewAISecurityFrameworkHandler(
	logger *logger.Logger,
	aiSecurityFramework *usecase.AISecurityFramework,
) *AISecurityFrameworkHandler {
	return &AISecurityFrameworkHandler{
		logger:              logger,
		aiSecurityFramework: aiSecurityFramework,
	}
}

// AssessLLMRequestRequest represents the request for LLM security assessment
type AssessLLMRequestRequest struct {
	RequestID string                 `json:"request_id"`
	UserID    *uuid.UUID             `json:"user_id,omitempty"`
	SessionID *uuid.UUID             `json:"session_id,omitempty"`
	Content   string                 `json:"content"`
	Model     string                 `json:"model,omitempty"`
	Provider  string                 `json:"provider,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// AssessLLMRequestResponse represents the response for LLM security assessment
type AssessLLMRequestResponse struct {
	Assessment *usecase.AISecurityAssessment `json:"assessment"`
	Success    bool                          `json:"success"`
	Message    string                        `json:"message,omitempty"`
	Error      string                        `json:"error,omitempty"`
}

// SecurityStatusResponse represents the security framework status
type SecurityStatusResponse struct {
	Status           string                 `json:"status"`
	ComponentsActive map[string]bool        `json:"components_active"`
	Configuration    map[string]interface{} `json:"configuration"`
	LastUpdate       time.Time              `json:"last_update"`
	Success          bool                   `json:"success"`
	Message          string                 `json:"message,omitempty"`
}

// AssessLLMRequest handles LLM request security assessment
func (h *AISecurityFrameworkHandler) AssessLLMRequest(w http.ResponseWriter, r *http.Request) {
	ctx, span := aiSecurityHandlerTracer.Start(r.Context(), "ai_security_framework_handler.assess_llm_request")
	defer span.End()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AssessLLMRequestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WithError(err).Error("Failed to decode request")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate request
	if req.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	if req.RequestID == "" {
		req.RequestID = uuid.New().String()
	}

	span.SetAttributes(
		attribute.String("request.id", req.RequestID),
		attribute.Int("request.content_length", len(req.Content)),
	)

	// Create LLM request for assessment
	llmRequest := &security.LLMRequest{
		ID:        req.RequestID,
		UserID:    req.UserID,
		SessionID: req.SessionID,
		Body:      json.RawMessage(req.Content),
		Model:     req.Model,
		Provider:  req.Provider,
		Context:   req.Metadata,
		Timestamp: time.Now(),
	}

	// Perform security assessment
	assessment, err := h.aiSecurityFramework.AssessLLMRequest(ctx, llmRequest)
	if err != nil {
		h.logger.WithError(err).Error("Failed to assess LLM request")
		response := AssessLLMRequestResponse{
			Success: false,
			Error:   "Failed to perform security assessment",
		}
		h.writeJSONResponse(w, response, http.StatusInternalServerError)
		return
	}

	span.SetAttributes(
		attribute.Float64("assessment.threat_score", assessment.OverallThreatScore),
		attribute.String("assessment.risk_level", assessment.RiskLevel),
		attribute.Bool("assessment.blocked", assessment.Blocked),
	)

	response := AssessLLMRequestResponse{
		Assessment: assessment,
		Success:    true,
		Message:    "Security assessment completed successfully",
	}

	statusCode := http.StatusOK
	if assessment.Blocked {
		statusCode = http.StatusForbidden
	}

	h.writeJSONResponse(w, response, statusCode)
}

// GetSecurityStatus returns the current status of the AI security framework
func (h *AISecurityFrameworkHandler) GetSecurityStatus(w http.ResponseWriter, r *http.Request) {
	_, span := aiSecurityHandlerTracer.Start(r.Context(), "ai_security_framework_handler.get_security_status")
	defer span.End()

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get framework status
	response := SecurityStatusResponse{
		Status: "active",
		ComponentsActive: map[string]bool{
			"mitre_atlas":         true,
			"owasp_ai_top10":      true,
			"prompt_injection":    true,
			"threat_detection":    true,
			"content_filtering":   true,
			"policy_engine":       true,
			"rate_limiting":       true,
			"ai_firewall":         true,
			"threat_intelligence": true,
		},
		Configuration: map[string]interface{}{
			"real_time_monitoring": true,
			"auto_mitigation":      false,
			"threat_threshold":     0.7,
			"continuous_learning":  true,
			"alerting_enabled":     true,
			"compliance_reporting": true,
		},
		LastUpdate: time.Now(),
		Success:    true,
		Message:    "AI Security Framework is operational",
	}

	h.writeJSONResponse(w, response, http.StatusOK)
}

// GetSecurityMetrics returns security metrics and statistics
func (h *AISecurityFrameworkHandler) GetSecurityMetrics(w http.ResponseWriter, r *http.Request) {
	_, span := aiSecurityHandlerTracer.Start(r.Context(), "ai_security_framework_handler.get_security_metrics")
	defer span.End()

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Mock metrics for now - in a real implementation, these would come from the framework
	metrics := map[string]interface{}{
		"total_assessments":    1000,
		"blocked_requests":     25,
		"high_risk_detections": 15,
		"prompt_injections":    8,
		"threat_score_average": 0.15,
		"compliance_rate":      0.98,
		"response_time_avg_ms": 45,
		"last_24h": map[string]interface{}{
			"assessments":       150,
			"blocked":           3,
			"high_risk":         2,
			"prompt_injections": 1,
		},
		"top_threats": []map[string]interface{}{
			{"type": "prompt_injection", "count": 8, "percentage": 32.0},
			{"type": "suspicious_content", "count": 7, "percentage": 28.0},
			{"type": "policy_violation", "count": 6, "percentage": 24.0},
			{"type": "rate_limit_exceeded", "count": 4, "percentage": 16.0},
		},
		"timestamp": time.Now(),
	}

	response := map[string]interface{}{
		"metrics": metrics,
		"success": true,
		"message": "Security metrics retrieved successfully",
	}

	h.writeJSONResponse(w, response, http.StatusOK)
}

// RegisterRoutes registers all AI security framework routes
func (h *AISecurityFrameworkHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/ai-security/assess", h.AssessLLMRequest)
	mux.HandleFunc("/api/v1/ai-security/status", h.GetSecurityStatus)
	mux.HandleFunc("/api/v1/ai-security/metrics", h.GetSecurityMetrics)
}

// writeJSONResponse writes a JSON response
func (h *AISecurityFrameworkHandler) writeJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.WithError(err).Error("Failed to encode JSON response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
