package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/internal/usecase"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// ScannerHandler handles scanner-related HTTP requests
type ScannerHandler struct {
	vulnScanner     *usecase.VulnerabilityScannerUseCase
	networkAnalyzer *usecase.NetworkAnalyzerUseCase
	aiService       *usecase.AIModelService
	logger          *logger.Logger
}

// NewScannerHandler creates a new scanner handler
func NewScannerHandler(
	vulnScanner *usecase.VulnerabilityScannerUseCase,
	networkAnalyzer *usecase.NetworkAnalyzerUseCase,
	aiService *usecase.AIModelService,
	log *logger.Logger,
) *ScannerHandler {
	return &ScannerHandler{
		vulnScanner:     vulnScanner,
		networkAnalyzer: networkAnalyzer,
		aiService:       aiService,
		logger:          log,
	}
}

// StartVulnerabilityScanRequest represents the request to start a vulnerability scan
type StartVulnerabilityScanRequest struct {
	Target      string                 `json:"target"`
	ScanType    string                 `json:"scan_type"`
	Description string                 `json:"description,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
}

// StartNetworkScanRequest represents the request to start a network scan
type StartNetworkScanRequest struct {
	Target      string                   `json:"target"`
	ScanType    string                   `json:"scan_type"`
	Description string                   `json:"description,omitempty"`
	Config      domain.NetworkScanConfig `json:"config,omitempty"`
}

// AIAnalysisRequest represents the request for AI analysis
type AIAnalysisRequest struct {
	Targets  []string               `json:"targets"`
	Type     string                 `json:"type"`
	Priority string                 `json:"priority,omitempty"`
	Config   map[string]interface{} `json:"config,omitempty"`
}

// StartVulnerabilityScan handles POST /api/v1/scans/vulnerability
func (h *ScannerHandler) StartVulnerabilityScan(w http.ResponseWriter, r *http.Request) {
	var req StartVulnerabilityScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if req.Target == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Target is required", nil)
		return
	}

	if req.ScanType == "" {
		req.ScanType = "web" // Default scan type
	}

	// Get user ID from context (set by auth middleware)
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}

	// Convert scan type
	scanType := domain.ScanType(req.ScanType)

	// Create scan config
	config := domain.ScanConfig{
		Timeout:         30,
		MaxDepth:        3,
		UserAgent:       "HackAI-Scanner/1.0",
		FollowRedirects: true,
	}

	// Start vulnerability scan
	scan, err := h.vulnScanner.StartScan(r.Context(), userID, req.Target, scanType, config)
	if err != nil {
		h.logger.WithError(err).Error("Failed to start vulnerability scan")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to start scan", err)
		return
	}

	h.logger.WithFields(logger.Fields{
		"scan_id":   scan.ID,
		"user_id":   userID,
		"target":    req.Target,
		"scan_type": req.ScanType,
	}).Info("Vulnerability scan started")

	h.writeJSONResponse(w, http.StatusCreated, scan)
}

// ListVulnerabilityScans handles GET /api/v1/scans/vulnerability
func (h *ScannerHandler) ListVulnerabilityScans(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}

	// Use userID for logging
	h.logger.Info("Listing vulnerability scans", map[string]interface{}{
		"user_id": userID,
	})

	// Parse query parameters
	limit := h.parseIntQuery(r, "limit", 20)
	offset := h.parseIntQuery(r, "offset", 0)
	status := r.URL.Query().Get("status")

	h.logger.Info("Listing vulnerability scans with filters", map[string]interface{}{
		"user_id": userID,
		"limit":   limit,
		"offset":  offset,
		"status":  status,
	})

	// TODO: Implement repository method to list scans
	// For now, return empty list
	scans := []domain.VulnerabilityScan{}

	response := map[string]interface{}{
		"scans":  scans,
		"total":  len(scans),
		"limit":  limit,
		"offset": offset,
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GetVulnerabilityScan handles GET /api/v1/scans/vulnerability/{id}
func (h *ScannerHandler) GetVulnerabilityScan(w http.ResponseWriter, r *http.Request) {
	// Extract scan ID from URL path
	scanID, err := h.extractUUIDFromPath(r.URL.Path, "/api/v1/scans/vulnerability/")
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid scan ID", err)
		return
	}

	// Get user ID from context
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}

	h.logger.Info("Getting vulnerability scan", map[string]interface{}{
		"user_id": userID,
		"scan_id": scanID,
	})

	// TODO: Implement repository method to get scan by ID
	// For now, return not found
	h.writeErrorResponse(w, http.StatusNotFound, "Scan not found", nil)
}

// CancelVulnerabilityScan handles DELETE /api/v1/scans/vulnerability/{id}
func (h *ScannerHandler) CancelVulnerabilityScan(w http.ResponseWriter, r *http.Request) {
	// Extract scan ID from URL path
	scanID, err := h.extractUUIDFromPath(r.URL.Path, "/api/v1/scans/vulnerability/")
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid scan ID", err)
		return
	}

	// Get user ID from context
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}

	// TODO: Implement scan cancellation
	h.logger.WithFields(logger.Fields{
		"scan_id": scanID,
		"user_id": userID,
	}).Info("Vulnerability scan cancelled")

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Scan cancelled successfully"})
}

// StartNetworkScan handles POST /api/v1/scans/network
func (h *ScannerHandler) StartNetworkScan(w http.ResponseWriter, r *http.Request) {
	var req StartNetworkScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if req.Target == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Target is required", nil)
		return
	}

	if req.ScanType == "" {
		req.ScanType = "ping" // Default scan type
	}

	// Get user ID from context
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}

	// Convert scan type
	scanType := domain.NetworkScanType(req.ScanType)

	// Set default config if not provided
	if req.Config.Timeout == 0 {
		req.Config.Timeout = 5
	}
	if req.Config.Threads == 0 {
		req.Config.Threads = 10
	}
	if req.Config.PortRange == "" {
		req.Config.PortRange = "1-1000"
	}
	req.Config.ScanTCP = true

	// Start network scan
	scan, err := h.networkAnalyzer.StartScan(r.Context(), userID, req.Target, scanType, req.Config)
	if err != nil {
		h.logger.WithError(err).Error("Failed to start network scan")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to start scan", err)
		return
	}

	h.logger.WithFields(logger.Fields{
		"scan_id":   scan.ID,
		"user_id":   userID,
		"target":    req.Target,
		"scan_type": req.ScanType,
	}).Info("Network scan started")

	h.writeJSONResponse(w, http.StatusCreated, scan)
}

// ListNetworkScans handles GET /api/v1/scans/network
func (h *ScannerHandler) ListNetworkScans(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}

	h.logger.Info("Listing network scans", map[string]interface{}{
		"user_id": userID,
	})

	// Parse query parameters
	limit := h.parseIntQuery(r, "limit", 20)
	offset := h.parseIntQuery(r, "offset", 0)

	// TODO: Implement repository method to list network scans
	scans := []domain.NetworkScan{}

	response := map[string]interface{}{
		"scans":  scans,
		"total":  len(scans),
		"limit":  limit,
		"offset": offset,
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GetNetworkScan handles GET /api/v1/scans/network/{id}
func (h *ScannerHandler) GetNetworkScan(w http.ResponseWriter, r *http.Request) {
	// Extract scan ID from URL path
	scanID, err := h.extractUUIDFromPath(r.URL.Path, "/api/v1/scans/network/")
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid scan ID", err)
		return
	}

	h.logger.Info("Getting network scan", map[string]interface{}{
		"scan_id": scanID,
	})

	// TODO: Implement repository method to get network scan by ID
	h.writeErrorResponse(w, http.StatusNotFound, "Scan not found", nil)
}

// CancelNetworkScan handles DELETE /api/v1/scans/network/{id}
func (h *ScannerHandler) CancelNetworkScan(w http.ResponseWriter, r *http.Request) {
	// Extract scan ID from URL path
	scanID, err := h.extractUUIDFromPath(r.URL.Path, "/api/v1/scans/network/")
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid scan ID", err)
		return
	}

	// Get user ID from context
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}

	h.logger.WithFields(logger.Fields{
		"scan_id": scanID,
		"user_id": userID,
	}).Info("Network scan cancelled")

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Scan cancelled successfully"})
}

// PerformAIAnalysis handles POST /api/v1/ai/analyze
func (h *ScannerHandler) PerformAIAnalysis(w http.ResponseWriter, r *http.Request) {
	var req AIAnalysisRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if len(req.Targets) == 0 {
		h.writeErrorResponse(w, http.StatusBadRequest, "At least one target is required", nil)
		return
	}

	if req.Type == "" {
		req.Type = "comprehensive"
	}

	if req.Priority == "" {
		req.Priority = "medium"
	}

	// Get user ID from context
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}

	// Create AI analysis request
	analysisReq := &usecase.AIAnalysisRequest{
		ID:       uuid.New(),
		UserID:   userID,
		Type:     req.Type,
		Targets:  req.Targets,
		Config:   req.Config,
		Priority: req.Priority,
	}

	// Perform AI analysis
	result, err := h.aiService.PerformComprehensiveAnalysis(r.Context(), analysisReq)
	if err != nil {
		h.logger.WithError(err).Error("Failed to perform AI analysis")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to perform analysis", err)
		return
	}

	h.logger.WithFields(logger.Fields{
		"analysis_id":        result.ID,
		"user_id":            userID,
		"targets":            len(req.Targets),
		"overall_risk_score": result.OverallRiskScore,
		"threat_level":       result.ThreatLevel,
	}).Info("AI analysis completed")

	h.writeJSONResponse(w, http.StatusOK, result)
}

// GetAIAnalysis handles GET /api/v1/ai/analysis/{id}
func (h *ScannerHandler) GetAIAnalysis(w http.ResponseWriter, r *http.Request) {
	// Extract analysis ID from URL path
	analysisID, err := h.extractUUIDFromPath(r.URL.Path, "/api/v1/ai/analysis/")
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid analysis ID", err)
		return
	}

	h.logger.Info("Getting AI analysis", map[string]interface{}{
		"analysis_id": analysisID,
	})

	// TODO: Implement repository method to get AI analysis by ID
	h.writeErrorResponse(w, http.StatusNotFound, "Analysis not found", nil)
}

// ListVulnerabilities handles GET /api/v1/vulnerabilities
func (h *ScannerHandler) ListVulnerabilities(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}

	h.logger.Info("Listing vulnerabilities", map[string]interface{}{
		"user_id": userID,
	})

	// Parse query parameters
	limit := h.parseIntQuery(r, "limit", 20)
	offset := h.parseIntQuery(r, "offset", 0)
	severity := r.URL.Query().Get("severity")
	status := r.URL.Query().Get("status")

	// TODO: Implement repository method to list vulnerabilities
	vulnerabilities := []domain.Vulnerability{}

	response := map[string]interface{}{
		"vulnerabilities": vulnerabilities,
		"total":           len(vulnerabilities),
		"limit":           limit,
		"offset":          offset,
		"filters": map[string]string{
			"severity": severity,
			"status":   status,
		},
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GetVulnerability handles GET /api/v1/vulnerabilities/{id}
func (h *ScannerHandler) GetVulnerability(w http.ResponseWriter, r *http.Request) {
	// Extract vulnerability ID from URL path
	vulnID, err := h.extractUUIDFromPath(r.URL.Path, "/api/v1/vulnerabilities/")
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid vulnerability ID", err)
		return
	}

	h.logger.Info("Getting vulnerability", map[string]interface{}{
		"vulnerability_id": vulnID,
	})

	// TODO: Implement repository method to get vulnerability by ID
	h.writeErrorResponse(w, http.StatusNotFound, "Vulnerability not found", nil)
}

// UpdateVulnerabilityStatus handles PUT /api/v1/vulnerabilities/{id}/status
func (h *ScannerHandler) UpdateVulnerabilityStatus(w http.ResponseWriter, r *http.Request) {
	// Extract vulnerability ID from URL path
	vulnID, err := h.extractUUIDFromPath(r.URL.Path, "/api/v1/vulnerabilities/")
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid vulnerability ID", err)
		return
	}

	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate status
	validStatuses := []string{"open", "fixed", "verified", "ignored", "false_positive"}
	isValid := false
	for _, status := range validStatuses {
		if req.Status == status {
			isValid = true
			break
		}
	}

	if !isValid {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid status", nil)
		return
	}

	// TODO: Implement repository method to update vulnerability status
	h.logger.WithFields(logger.Fields{
		"vulnerability_id": vulnID,
		"new_status":       req.Status,
	}).Info("Vulnerability status updated")

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Status updated successfully"})
}

// Helper methods

func (h *ScannerHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.WithError(err).Error("Failed to encode JSON response")
	}
}

func (h *ScannerHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	response := map[string]interface{}{
		"error":  message,
		"status": statusCode,
	}

	if err != nil {
		h.logger.WithError(err).Error(message)
		response["details"] = err.Error()
	}

	h.writeJSONResponse(w, statusCode, response)
}

func (h *ScannerHandler) parseIntQuery(r *http.Request, key string, defaultValue int) int {
	value := r.URL.Query().Get(key)
	if value == "" {
		return defaultValue
	}

	if intValue, err := strconv.Atoi(value); err == nil {
		return intValue
	}

	return defaultValue
}

func (h *ScannerHandler) extractUUIDFromPath(path, prefix string) (uuid.UUID, error) {
	if !strings.HasPrefix(path, prefix) {
		return uuid.Nil, fmt.Errorf("invalid path format")
	}

	idStr := strings.TrimPrefix(path, prefix)
	idStr = strings.Split(idStr, "/")[0] // Handle paths like /api/v1/scans/vulnerability/{id}/status

	return uuid.Parse(idStr)
}
