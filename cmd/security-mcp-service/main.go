package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"

	"github.com/dimajoyti/hackai/internal/repository"
	"github.com/dimajoyti/hackai/internal/usecase"
	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/database"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/mcp"
	"github.com/dimajoyti/hackai/pkg/middleware"
	"github.com/dimajoyti/hackai/pkg/observability"
	"github.com/dimajoyti/hackai/pkg/security"
)

var securityMCPServiceTracer = otel.Tracer("hackai/cmd/security-mcp-service")

const (
	contentTypeJSON   = "application/json"
	contentTypeHeader = "Content-Type"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log, err := logger.New(logger.Config{
		Level:      logger.LogLevel(cfg.Observability.Logging.Level),
		Format:     cfg.Observability.Logging.Format,
		Output:     cfg.Observability.Logging.Output,
		FilePath:   cfg.Observability.Logging.FilePath,
		AddSource:  true,
		TimeFormat: time.RFC3339,
	})
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	log.Info("Starting HackAI Security MCP Service", "version", "1.0.0")

	// Initialize observability
	obs, err := observability.NewProvider(&cfg.Observability, "hackai-security-mcp-service", "1.0.0", log)
	if err != nil {
		log.Error("Failed to initialize observability", "error", err)
		os.Exit(1)
	}
	defer obs.Shutdown(context.Background())

	// Initialize database
	db, err := database.New(&cfg.Database, log)
	if err != nil {
		log.Fatal("Failed to initialize database", "error", err)
	}
	defer db.Close()

	// Initialize repositories
	securityRepo := repository.NewLLMSecurityRepository(db.DB, log)
	auditRepo := repository.NewAuditRepository(db.DB, log)

	// Initialize AI Security Framework
	aiSecurityConfig := &usecase.AISecurityConfig{
		EnableMITREATLAS:         true,
		EnableOWASPAITop10:       true,
		EnablePromptInjection:    true,
		EnableThreatDetection:    true,
		EnableContentFiltering:   true,
		EnablePolicyEngine:       true,
		EnableRateLimiting:       true,
		EnableAIFirewall:         true,
		EnableThreatIntelligence: true,
		RealTimeMonitoring:       true,
		AutoMitigation:           false, // Set to false for safety in production
		ThreatThreshold:          0.7,
		ScanInterval:             5 * time.Minute,
		LogDetailedAnalysis:      true,
		EnableContinuousLearning: true,
		MaxConcurrentScans:       10,
		AlertingEnabled:          true,
		ComplianceReporting:      true,
	}

	_, err = usecase.NewAISecurityFramework(
		log,
		securityRepo,
		auditRepo,
		aiSecurityConfig,
	)
	if err != nil {
		log.Error("Failed to initialize AI Security Framework", "error", err)
		os.Exit(1)
	}

	// Initialize security components
	agenticConfig := security.DefaultAgenticConfig()
	agenticFramework := security.NewAgenticSecurityFramework(agenticConfig, log)

	// Use default threat orchestrator config and create with proper constructor
	threatOrchestratorConfig := security.DefaultThreatOrchestratorConfig()
	threatIntelligence := security.NewThreatIntelligenceOrchestrator(
		threatOrchestratorConfig,
		nil, // mitreConnector - will be initialized internally
		nil, // cveConnector - will be initialized internally
		nil, // threatEngine - will be initialized internally
		nil, // feedManager - will be initialized internally
		nil, // iocDatabase - will be initialized internally
		nil, // reputationEngine - will be initialized internally
		nil, // threatCache - will be initialized internally
		log,
	)

	// Initialize Security MCP Server
	mcpConfig := &mcp.SecurityMCPConfig{
		ServerName:           "HackAI Security MCP Server",
		ServerVersion:        "1.0.0",
		MaxConcurrentScans:   10,
		ScanTimeout:          5 * time.Minute,
		EnableRealTimeAlerts: true,
		ThreatThreshold:      0.7,
		LogLevel:             mcp.LogLevelInfo,
		EnableAuditLogging:   true,
	}

	mcpServer := mcp.NewSecurityMCPServer(
		mcpConfig,
		log,
		agenticFramework,
		threatIntelligence,
	)

	// Initialize HTTP handler for MCP
	mcpHandler := NewSecurityMCPHandler(mcpServer, log)

	// Setup HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Server.Host, "9087"), // Security MCP service port
		Handler:      setupRoutes(cfg, log, mcpHandler),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in a goroutine
	go func() {
		log.Info("Security MCP service starting", "address", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Security MCP service shutting down...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown MCP server
	if err := mcpServer.Shutdown(ctx); err != nil {
		log.Error("Failed to shutdown MCP server", "error", err)
	}

	// Shutdown HTTP server
	if err := server.Shutdown(ctx); err != nil {
		log.Error("Failed to gracefully shutdown server", "error", err)
	}

	log.Info("Security MCP service stopped")
}

// SecurityMCPHandler handles HTTP requests for the Security MCP service
type SecurityMCPHandler struct {
	mcpServer *mcp.SecurityMCPServer
	logger    *logger.Logger
}

// NewSecurityMCPHandler creates a new Security MCP HTTP handler
func NewSecurityMCPHandler(mcpServer *mcp.SecurityMCPServer, logger *logger.Logger) *SecurityMCPHandler {
	return &SecurityMCPHandler{
		mcpServer: mcpServer,
		logger:    logger,
	}
}

// HandleMCPRequest handles MCP protocol requests
func (h *SecurityMCPHandler) HandleMCPRequest(w http.ResponseWriter, r *http.Request) {
	ctx, span := securityMCPServiceTracer.Start(r.Context(), "security_mcp_service.handle_mcp_request")
	defer span.End()

	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse MCP message
	var mcpMessage mcp.MCPMessage
	if err := parseJSONBody(r, &mcpMessage); err != nil {
		h.logger.WithError(err).Error("Failed to parse MCP message")
		h.writeErrorResponse(w, &mcp.MCPError{
			Code:    mcp.ErrorCodeParseError,
			Message: "Failed to parse request",
		})
		return
	}

	// Route MCP request
	var result interface{}
	var err error

	switch mcpMessage.Method {
	case "initialize":
		var params mcp.InitializeParams
		if err := parseParams(mcpMessage.Params, &params); err != nil {
			h.writeErrorResponse(w, &mcp.MCPError{
				Code:    mcp.ErrorCodeInvalidParams,
				Message: "Invalid initialize parameters",
			})
			return
		}
		result, err = h.mcpServer.Initialize(ctx, &params)

	case "tools/list":
		var params mcp.ListToolsParams
		if err := parseParams(mcpMessage.Params, &params); err != nil {
			h.writeErrorResponse(w, &mcp.MCPError{
				Code:    mcp.ErrorCodeInvalidParams,
				Message: "Invalid list tools parameters",
			})
			return
		}
		result, err = h.mcpServer.ListTools(ctx, &params)

	case "tools/call":
		var params mcp.CallToolParams
		if err := parseParams(mcpMessage.Params, &params); err != nil {
			h.writeErrorResponse(w, &mcp.MCPError{
				Code:    mcp.ErrorCodeInvalidParams,
				Message: "Invalid call tool parameters",
			})
			return
		}
		result, err = h.mcpServer.CallTool(ctx, &params)

	case "resources/list":
		var params mcp.ListResourcesParams
		if err := parseParams(mcpMessage.Params, &params); err != nil {
			h.writeErrorResponse(w, &mcp.MCPError{
				Code:    mcp.ErrorCodeInvalidParams,
				Message: "Invalid list resources parameters",
			})
			return
		}
		result, err = h.mcpServer.ListResources(ctx, &params)

	case "resources/read":
		var params mcp.ReadResourceParams
		if err := parseParams(mcpMessage.Params, &params); err != nil {
			h.writeErrorResponse(w, &mcp.MCPError{
				Code:    mcp.ErrorCodeInvalidParams,
				Message: "Invalid read resource parameters",
			})
			return
		}
		result, err = h.mcpServer.ReadResource(ctx, &params)

	case "prompts/list":
		var params mcp.ListPromptsParams
		if err := parseParams(mcpMessage.Params, &params); err != nil {
			h.writeErrorResponse(w, &mcp.MCPError{
				Code:    mcp.ErrorCodeInvalidParams,
				Message: "Invalid list prompts parameters",
			})
			return
		}
		result, err = h.mcpServer.ListPrompts(ctx, &params)

	case "prompts/get":
		var params mcp.GetPromptParams
		if err := parseParams(mcpMessage.Params, &params); err != nil {
			h.writeErrorResponse(w, &mcp.MCPError{
				Code:    mcp.ErrorCodeInvalidParams,
				Message: "Invalid get prompt parameters",
			})
			return
		}
		result, err = h.mcpServer.GetPrompt(ctx, &params)

	case "logging/setLevel":
		var params mcp.SetLogLevelParams
		if err := parseParams(mcpMessage.Params, &params); err != nil {
			h.writeErrorResponse(w, &mcp.MCPError{
				Code:    mcp.ErrorCodeInvalidParams,
				Message: "Invalid set log level parameters",
			})
			return
		}
		err = h.mcpServer.SetLogLevel(ctx, &params)

	default:
		h.writeErrorResponse(w, &mcp.MCPError{
			Code:    mcp.ErrorCodeMethodNotFound,
			Message: fmt.Sprintf("Method not found: %s", mcpMessage.Method),
		})
		return
	}

	// Handle errors
	if err != nil {
		h.logger.WithError(err).Error("MCP method execution failed", "method", mcpMessage.Method)
		if mcpErr, ok := err.(*mcp.MCPError); ok {
			h.writeErrorResponse(w, mcpErr)
		} else {
			h.writeErrorResponse(w, &mcp.MCPError{
				Code:    mcp.ErrorCodeInternalError,
				Message: "Internal server error",
			})
		}
		return
	}

	// Write success response
	response := mcp.MCPMessage{
		JSONRPC: "2.0",
		ID:      mcpMessage.ID,
		Result:  result,
	}

	w.Header().Set(contentTypeHeader, contentTypeJSON)
	w.WriteHeader(http.StatusOK)
	if err := writeJSONResponse(w, response); err != nil {
		h.logger.WithError(err).Error("Failed to write response")
	}
}

// Health handles health check requests
func (h *SecurityMCPHandler) Health(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":    "healthy",
		"service":   "security-mcp-service",
		"version":   "1.0.0",
		"timestamp": time.Now().Format(time.RFC3339),
	}

	w.Header().Set(contentTypeHeader, contentTypeJSON)
	w.WriteHeader(http.StatusOK)
	writeJSONResponse(w, response)
}

// Ready handles readiness check requests
func (h *SecurityMCPHandler) Ready(w http.ResponseWriter, r *http.Request) {
	// Check if MCP server is initialized
	// In a real implementation, you would check various dependencies
	response := map[string]interface{}{
		"status":    "ready",
		"service":   "security-mcp-service",
		"version":   "1.0.0",
		"timestamp": time.Now().Format(time.RFC3339),
	}

	w.Header().Set(contentTypeHeader, contentTypeJSON)
	w.WriteHeader(http.StatusOK)
	writeJSONResponse(w, response)
}

// writeErrorResponse writes an MCP error response
func (h *SecurityMCPHandler) writeErrorResponse(w http.ResponseWriter, mcpError *mcp.MCPError) {
	response := mcp.MCPMessage{
		JSONRPC: "2.0",
		Error:   mcpError,
	}

	w.Header().Set(contentTypeHeader, contentTypeJSON)
	w.WriteHeader(http.StatusOK) // MCP errors are still HTTP 200
	writeJSONResponse(w, response)
}

// setupRoutes sets up the HTTP routes
func setupRoutes(cfg *config.Config, log *logger.Logger, mcpHandler *SecurityMCPHandler) http.Handler {
	router := mux.NewRouter()

	// Apply middleware
	router.Use(func(next http.Handler) http.Handler {
		return middleware.RequestID(next)
	})
	router.Use(func(next http.Handler) http.Handler {
		return middleware.Logging(log)(next)
	})
	router.Use(func(next http.Handler) http.Handler {
		return middleware.Recovery(log)(next)
	})
	router.Use(func(next http.Handler) http.Handler {
		return middleware.CORS(cfg.Server.CORS)(next)
	})

	// Health endpoints
	router.HandleFunc("/health", mcpHandler.Health).Methods("GET")
	router.HandleFunc("/ready", mcpHandler.Ready).Methods("GET")

	// MCP endpoint
	router.HandleFunc("/mcp", mcpHandler.HandleMCPRequest).Methods("POST", "OPTIONS")

	// API versioned endpoints
	api := router.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/mcp", mcpHandler.HandleMCPRequest).Methods("POST", "OPTIONS")

	return router
}

// Helper functions

func parseJSONBody(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

func parseParams(params interface{}, v interface{}) error {
	if params == nil {
		return nil
	}

	data, err := json.Marshal(params)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, v)
}

func writeJSONResponse(w http.ResponseWriter, v interface{}) error {
	return json.NewEncoder(w).Encode(v)
}
