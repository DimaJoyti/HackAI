package fraud

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var handlerTracer = otel.Tracer("hackai/fraud/handler")

// FraudDetectionHandler handles HTTP requests for fraud detection
type FraudDetectionHandler struct {
	engine *FraudDetectionEngine
	logger *logger.Logger
	tracer trace.Tracer
}

// NewFraudDetectionHandler creates a new fraud detection HTTP handler
func NewFraudDetectionHandler(engine *FraudDetectionEngine, logger *logger.Logger) *FraudDetectionHandler {
	return &FraudDetectionHandler{
		engine: engine,
		logger: logger,
		tracer: handlerTracer,
	}
}

// DetectFraud handles fraud detection HTTP requests
func (h *FraudDetectionHandler) DetectFraud(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "fraud_handler.detect_fraud",
		trace.WithAttributes(
			attribute.String("http.method", r.Method),
			attribute.String("http.url", r.URL.String()),
		),
	)
	defer span.End()

	// Only allow POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var request FraudDetectionRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		span.RecordError(err)
		h.logger.Error("Failed to decode request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Set request timestamp if not provided
	if request.Timestamp.IsZero() {
		request.Timestamp = time.Now()
	}

	// Generate request ID if not provided
	if request.ID == "" {
		request.ID = fmt.Sprintf("req_%d", time.Now().UnixNano())
	}

	// Perform fraud detection
	response, err := h.engine.DetectFraud(ctx, &request)
	if err != nil {
		span.RecordError(err)
		h.logger.Error("Fraud detection failed", "error", err, "request_id", request.ID)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-ID", request.ID)

	// Encode and send response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		span.RecordError(err)
		h.logger.Error("Failed to encode response", "error", err, "request_id", request.ID)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	span.SetAttributes(
		attribute.String("request.id", request.ID),
		attribute.String("user.id", request.UserID),
		attribute.Float64("fraud.score", response.FraudScore),
		attribute.String("fraud.decision", string(response.Decision)),
		attribute.Int64("processing.time_ms", response.ProcessingTime.Milliseconds()),
	)

	h.logger.Info("Fraud detection completed",
		"request_id", request.ID,
		"user_id", request.UserID,
		"fraud_score", response.FraudScore,
		"decision", string(response.Decision),
		"processing_time_ms", response.ProcessingTime.Milliseconds(),
	)
}

// HealthCheck handles health check requests
func (h *FraudDetectionHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	_, span := h.tracer.Start(r.Context(), "fraud_handler.health_check")
	defer span.End()

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"engine":    h.engine.GetStats(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(health); err != nil {
		span.RecordError(err)
		h.logger.Error("Failed to encode health response", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// GetStats handles statistics requests
func (h *FraudDetectionHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	_, span := h.tracer.Start(r.Context(), "fraud_handler.get_stats")
	defer span.End()

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := h.engine.GetStats()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		span.RecordError(err)
		h.logger.Error("Failed to encode stats response", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// RegisterRoutes registers fraud detection routes with the provided mux
func (h *FraudDetectionHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/fraud/detect", h.DetectFraud)
	mux.HandleFunc("/api/v1/fraud/health", h.HealthCheck)
	mux.HandleFunc("/api/v1/fraud/stats", h.GetStats)
}
