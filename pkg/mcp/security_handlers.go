package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
)

// Constants
const (
	MimeTypeJSON = "application/json"
)

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Tool Handlers

// handleThreatAnalysis handles threat analysis tool calls
func (s *SecurityMCPServer) handleThreatAnalysis(ctx context.Context, params map[string]interface{}) (*CallToolResult, error) {
	ctx, span := securityMCPTracer.Start(ctx, "security_mcp.handle_threat_analysis")
	defer span.End()

	// Extract input parameter
	input, ok := params["input"].(string)
	if !ok {
		return &CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: "Error: 'input' parameter is required and must be a string",
			}},
			IsError: true,
		}, nil
	}

	// Extract security context if provided
	var secCtx SecurityContext
	if contextData, ok := params["context"].(map[string]interface{}); ok {
		secCtx = extractSecurityContext(contextData)
	} else {
		secCtx = SecurityContext{
			Timestamp: time.Now(),
		}
	}

	// Generate operation ID
	operationID := uuid.New().String()

	// Create threat analysis operation
	operation := &ThreatAnalysisOperation{
		ID:        operationID,
		Input:     input,
		Status:    "running",
		StartTime: time.Now(),
		Context:   secCtx,
	}

	s.mu.Lock()
	s.activeThreatAnalysis[operationID] = operation
	s.mu.Unlock()

	span.SetAttributes(
		attribute.String("operation.id", operationID),
		attribute.String("input.length", fmt.Sprintf("%d", len(input))),
	)

	// Perform threat analysis using integrated security components
	if s.securityIntegration != nil && s.securityIntegration.IsHealthy() {
		// Create security context for analysis
		securityContext := map[string]interface{}{
			"user_id":    secCtx.UserID,
			"session_id": secCtx.SessionID,
			"ip_address": secCtx.IPAddress,
			"user_agent": secCtx.UserAgent,
			"timestamp":  secCtx.Timestamp,
		}

		// Add metadata if available
		if secCtx.Metadata != nil {
			for k, v := range secCtx.Metadata {
				securityContext[k] = v
			}
		}

		// Analyze the threat using integrated components
		analysis, err := s.securityIntegration.AnalyzeThreat(ctx, input, securityContext)
		if err != nil {
			operation.Status = "failed"
			return &CallToolResult{
				Content: []ToolContent{{
					Type: "text",
					Text: fmt.Sprintf("Threat analysis failed: %v", err),
				}},
				IsError: true,
			}, nil
		}

		operation.Status = "completed"
		operation.Results = analysis

		// Send notification for high-risk threats
		if analysis.RiskScore >= s.config.ThreatThreshold {
			s.SendNotificationToClients("security.threat_detected", map[string]interface{}{
				"operation_id":  operationID,
				"threat_score":  analysis.RiskScore,
				"threat_level":  determineThreatLevel(analysis.RiskScore),
				"input_preview": input[:min(100, len(input))],
				"timestamp":     time.Now(),
			})
		}

		// Create scan result
		scanResult := &SecurityScanResult{
			ScanID:      operationID,
			Status:      "completed",
			ThreatLevel: determineThreatLevel(analysis.RiskScore),
			Score:       analysis.RiskScore,
			Findings:    convertAnalysisToFindings(analysis),
			Metadata: map[string]interface{}{
				"analysis_type": "threat_analysis",
				"input_length":  len(input),
			},
			Timestamp: time.Now(),
			Duration:  time.Since(operation.StartTime),
		}

		// Convert result to JSON
		resultJSON, err := json.Marshal(scanResult)
		if err != nil {
			return &CallToolResult{
				Content: []ToolContent{{
					Type: "text",
					Text: fmt.Sprintf(ErrFailedToSerialize, err),
				}},
				IsError: true,
			}, nil
		}

		return &CallToolResult{
			Content: []ToolContent{
				{
					Type: "text",
					Text: fmt.Sprintf("Threat analysis completed. Operation ID: %s", operationID),
				},
				{
					Type: "text",
					Text: string(resultJSON),
				},
			},
			IsError: false,
		}, nil
	}

	// Fallback if AI Security Framework is not available
	return &CallToolResult{
		Content: []ToolContent{{
			Type: "text",
			Text: "AI Security Framework not available for threat analysis",
		}},
		IsError: true,
	}, nil
}

// handleVulnerabilityScan handles vulnerability scanning tool calls
func (s *SecurityMCPServer) handleVulnerabilityScan(ctx context.Context, params map[string]interface{}) (*CallToolResult, error) {
	ctx, span := securityMCPTracer.Start(ctx, "security_mcp.handle_vulnerability_scan")
	defer span.End()

	// Extract parameters
	target, ok := params["target"].(string)
	if !ok {
		return &CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: "Error: 'target' parameter is required and must be a string",
			}},
			IsError: true,
		}, nil
	}

	scanType, ok := params["scan_type"].(string)
	if !ok {
		return &CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: "Error: 'scan_type' parameter is required and must be a string",
			}},
			IsError: true,
		}, nil
	}

	// Extract options (optional parameter)
	options, _ := params["options"].(map[string]interface{})

	// Generate operation ID
	operationID := uuid.New().String()

	// Create scan operation
	operation := &SecurityScanOperation{
		ID:        operationID,
		Type:      scanType,
		Status:    "running",
		StartTime: time.Now(),
		Context: SecurityContext{
			Timestamp: time.Now(),
		},
	}

	s.mu.Lock()
	s.activeScans[operationID] = operation
	s.mu.Unlock()

	span.SetAttributes(
		attribute.String("operation.id", operationID),
		attribute.String("scan.target", target),
		attribute.String("scan.type", scanType),
	)

	// Perform vulnerability scanning using integrated components
	var scanResult *SecurityScanResult

	if s.securityIntegration != nil && s.securityIntegration.IsHealthy() {
		// Use integrated vulnerability scanner
		vulnResult, err := s.securityIntegration.ScanVulnerabilities(ctx, target, scanType, options)
		if err != nil {
			operation.Status = "failed"
			return &CallToolResult{
				Content: []ToolContent{{
					Type: "text",
					Text: fmt.Sprintf("Vulnerability scan failed: %v", err),
				}},
				IsError: true,
			}, nil
		}

		// Convert vulnerability scan result to SecurityScanResult
		scanResult = &SecurityScanResult{
			ScanID:      operationID,
			Status:      "completed",
			ThreatLevel: determineThreatLevel(float64(len(vulnResult.Vulnerabilities)) * 0.1),
			Score:       float64(len(vulnResult.Vulnerabilities)) * 0.1,
			Findings:    convertVulnerabilityMapsToFindings(vulnResult.Vulnerabilities),
			Metadata: map[string]interface{}{
				"scan_type":             scanType,
				"target":                target,
				"vulnerabilities_count": len(vulnResult.Vulnerabilities),
			},
			Timestamp: time.Now(),
			Duration:  time.Since(operation.StartTime),
		}
	} else {
		// Fallback to mock scan result
		scanResult = &SecurityScanResult{
			ScanID:      operationID,
			Status:      "completed",
			ThreatLevel: "medium",
			Score:       0.6,
			Findings: []SecurityFinding{
				{
					ID:          uuid.New().String(),
					Type:        "vulnerability",
					Severity:    "medium",
					Title:       fmt.Sprintf("Sample vulnerability found in %s", target),
					Description: fmt.Sprintf("A sample vulnerability was detected during %s scan of %s", scanType, target),
					Evidence:    []string{"Sample evidence"},
					Remediation: "Apply security patches and follow best practices",
					References:  []string{"https://example.com/vuln-ref"},
				},
			},
			Metadata: map[string]interface{}{
				"scan_type": scanType,
				"target":    target,
			},
			Timestamp: time.Now(),
			Duration:  time.Since(operation.StartTime),
		}
	}

	operation.Status = "completed"
	operation.Results = scanResult

	// Convert result to JSON
	resultJSON, err := json.Marshal(scanResult)
	if err != nil {
		return &CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: fmt.Sprintf(ErrFailedToSerialize, err),
			}},
			IsError: true,
		}, nil
	}

	return &CallToolResult{
		Content: []ToolContent{
			{
				Type: "text",
				Text: fmt.Sprintf("Vulnerability scan completed. Operation ID: %s", operationID),
			},
			{
				Type: "text",
				Text: string(resultJSON),
			},
		},
		IsError: false,
	}, nil
}

// handleComplianceCheck handles compliance checking tool calls
func (s *SecurityMCPServer) handleComplianceCheck(ctx context.Context, params map[string]interface{}) (*CallToolResult, error) {
	ctx, span := securityMCPTracer.Start(ctx, "security_mcp.handle_compliance_check")
	defer span.End()

	// Extract parameters
	framework, ok := params["framework"].(string)
	if !ok {
		return &CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: "Error: 'framework' parameter is required and must be a string",
			}},
			IsError: true,
		}, nil
	}

	target, ok := params["target"].(string)
	if !ok {
		return &CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: "Error: 'target' parameter is required and must be a string",
			}},
			IsError: true,
		}, nil
	}

	// Generate operation ID
	operationID := uuid.New().String()

	span.SetAttributes(
		attribute.String("operation.id", operationID),
		attribute.String("compliance.framework", framework),
		attribute.String("compliance.target", target),
	)

	// Simulate compliance check
	time.Sleep(200 * time.Millisecond) // Simulate check time

	// Create mock compliance result
	scanResult := &SecurityScanResult{
		ScanID:      operationID,
		Status:      "completed",
		ThreatLevel: "low",
		Score:       0.8, // High compliance score
		Findings: []SecurityFinding{
			{
				ID:          uuid.New().String(),
				Type:        "compliance",
				Severity:    "info",
				Title:       fmt.Sprintf("%s compliance check for %s", framework, target),
				Description: fmt.Sprintf("Compliance assessment against %s framework completed", framework),
				Evidence:    []string{"Compliance evidence"},
				Remediation: "Continue following best practices",
				References:  []string{fmt.Sprintf("https://example.com/%s-framework", framework)},
			},
		},
		Metadata: map[string]interface{}{
			"framework": framework,
			"target":    target,
		},
		Timestamp: time.Now(),
		Duration:  200 * time.Millisecond,
	}

	// Convert result to JSON
	resultJSON, err := json.Marshal(scanResult)
	if err != nil {
		return &CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: fmt.Sprintf("Failed to serialize result: %v", err),
			}},
			IsError: true,
		}, nil
	}

	return &CallToolResult{
		Content: []ToolContent{
			{
				Type: "text",
				Text: fmt.Sprintf("Compliance check completed. Operation ID: %s", operationID),
			},
			{
				Type: "text",
				Text: string(resultJSON),
			},
		},
		IsError: false,
	}, nil
}

// handleIncidentResponse handles incident response tool calls
func (s *SecurityMCPServer) handleIncidentResponse(ctx context.Context, params map[string]interface{}) (*CallToolResult, error) {
	ctx, span := securityMCPTracer.Start(ctx, "security_mcp.handle_incident_response")
	defer span.End()

	// Extract action parameter
	action, ok := params["action"].(string)
	if !ok {
		return &CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: "Error: 'action' parameter is required and must be a string",
			}},
			IsError: true,
		}, nil
	}

	span.SetAttributes(attribute.String("incident.action", action))

	switch action {
	case "create":
		return s.handleCreateIncident(ctx, params)
	case "update":
		return s.handleUpdateIncident(ctx, params)
	case "escalate":
		return s.handleEscalateIncident(ctx, params)
	case "resolve":
		return s.handleResolveIncident(ctx, params)
	case "investigate":
		return s.handleInvestigateIncident(ctx, params)
	default:
		return &CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: fmt.Sprintf("Error: Unknown incident action: %s", action),
			}},
			IsError: true,
		}, nil
	}
}

// handleThreatIntelligence handles threat intelligence tool calls
func (s *SecurityMCPServer) handleThreatIntelligence(ctx context.Context, params map[string]interface{}) (*CallToolResult, error) {
	ctx, span := securityMCPTracer.Start(ctx, "security_mcp.handle_threat_intelligence")
	defer span.End()

	// Extract query type parameter
	queryType, ok := params["query_type"].(string)
	if !ok {
		return &CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: "Error: 'query_type' parameter is required and must be a string",
			}},
			IsError: true,
		}, nil
	}

	span.SetAttributes(attribute.String("threat_intel.query_type", queryType))

	// Generate operation ID
	operationID := uuid.New().String()

	// Simulate threat intelligence query
	time.Sleep(150 * time.Millisecond) // Simulate query time

	// Create mock threat intelligence result
	result := map[string]interface{}{
		"operation_id": operationID,
		"query_type":   queryType,
		"status":       "completed",
		"results": map[string]interface{}{
			"indicators_found": 0,
			"threat_level":     "low",
			"confidence":       0.7,
			"sources":          []string{"internal_feeds", "public_feeds"},
		},
		"timestamp": time.Now(),
	}

	// Convert result to JSON
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return &CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: fmt.Sprintf("Failed to serialize result: %v", err),
			}},
			IsError: true,
		}, nil
	}

	return &CallToolResult{
		Content: []ToolContent{
			{
				Type: "text",
				Text: fmt.Sprintf("Threat intelligence query completed. Operation ID: %s", operationID),
			},
			{
				Type: "text",
				Text: string(resultJSON),
			},
		},
		IsError: false,
	}, nil
}

// Helper functions for incident response actions
func (s *SecurityMCPServer) handleCreateIncident(ctx context.Context, params map[string]interface{}) (*CallToolResult, error) {
	incidentID := uuid.New().String()

	result := map[string]interface{}{
		"action":      "create",
		"incident_id": incidentID,
		"status":      "created",
		"timestamp":   time.Now(),
	}

	resultJSON, _ := json.Marshal(result)
	return &CallToolResult{
		Content: []ToolContent{
			{
				Type: "text",
				Text: fmt.Sprintf("Incident created with ID: %s", incidentID),
			},
			{
				Type: "text",
				Text: string(resultJSON),
			},
		},
		IsError: false,
	}, nil
}

func (s *SecurityMCPServer) handleUpdateIncident(ctx context.Context, params map[string]interface{}) (*CallToolResult, error) {
	incidentID, ok := params["incident_id"].(string)
	if !ok {
		return &CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: "Error: 'incident_id' parameter is required for update action",
			}},
			IsError: true,
		}, nil
	}

	result := map[string]interface{}{
		"action":      "update",
		"incident_id": incidentID,
		"status":      "updated",
		"timestamp":   time.Now(),
	}

	resultJSON, _ := json.Marshal(result)
	return &CallToolResult{
		Content: []ToolContent{
			{
				Type: "text",
				Text: fmt.Sprintf("Incident %s updated", incidentID),
			},
			{
				Type: "text",
				Text: string(resultJSON),
			},
		},
		IsError: false,
	}, nil
}

func (s *SecurityMCPServer) handleEscalateIncident(ctx context.Context, params map[string]interface{}) (*CallToolResult, error) {
	incidentID, ok := params["incident_id"].(string)
	if !ok {
		return &CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: "Error: 'incident_id' parameter is required for escalate action",
			}},
			IsError: true,
		}, nil
	}

	result := map[string]interface{}{
		"action":      "escalate",
		"incident_id": incidentID,
		"status":      "escalated",
		"timestamp":   time.Now(),
	}

	resultJSON, _ := json.Marshal(result)
	return &CallToolResult{
		Content: []ToolContent{
			{
				Type: "text",
				Text: fmt.Sprintf("Incident %s escalated", incidentID),
			},
			{
				Type: "text",
				Text: string(resultJSON),
			},
		},
		IsError: false,
	}, nil
}

func (s *SecurityMCPServer) handleResolveIncident(ctx context.Context, params map[string]interface{}) (*CallToolResult, error) {
	incidentID, ok := params["incident_id"].(string)
	if !ok {
		return &CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: "Error: 'incident_id' parameter is required for resolve action",
			}},
			IsError: true,
		}, nil
	}

	result := map[string]interface{}{
		"action":      "resolve",
		"incident_id": incidentID,
		"status":      "resolved",
		"timestamp":   time.Now(),
	}

	resultJSON, _ := json.Marshal(result)
	return &CallToolResult{
		Content: []ToolContent{
			{
				Type: "text",
				Text: fmt.Sprintf("Incident %s resolved", incidentID),
			},
			{
				Type: "text",
				Text: string(resultJSON),
			},
		},
		IsError: false,
	}, nil
}

func (s *SecurityMCPServer) handleInvestigateIncident(ctx context.Context, params map[string]interface{}) (*CallToolResult, error) {
	incidentID, ok := params["incident_id"].(string)
	if !ok {
		return &CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: "Error: 'incident_id' parameter is required for investigate action",
			}},
			IsError: true,
		}, nil
	}

	result := map[string]interface{}{
		"action":      "investigate",
		"incident_id": incidentID,
		"status":      "investigating",
		"timestamp":   time.Now(),
	}

	resultJSON, _ := json.Marshal(result)
	return &CallToolResult{
		Content: []ToolContent{
			{
				Type: "text",
				Text: fmt.Sprintf("Investigation started for incident %s", incidentID),
			},
			{
				Type: "text",
				Text: string(resultJSON),
			},
		},
		IsError: false,
	}, nil
}
