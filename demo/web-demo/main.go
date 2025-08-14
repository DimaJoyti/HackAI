package main

import (
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// SecurityAnalysisResult represents the result of security analysis
type SecurityAnalysisResult struct {
	Input       string    `json:"input"`
	IsThreat    bool      `json:"is_threat"`
	Confidence  float64   `json:"confidence"`
	RiskLevel   string    `json:"risk_level"`
	ThreatTypes []string  `json:"threat_types,omitempty"`
	Patterns    []string  `json:"patterns,omitempty"`
	Mitigation  string    `json:"mitigation,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// ThreatIntelResult represents threat intelligence analysis result
type ThreatIntelResult struct {
	Target      string    `json:"target"`
	Type        string    `json:"target_type"`
	ThreatScore float64   `json:"threat_score"`
	RiskLevel   string    `json:"risk_level"`
	Confidence  float64   `json:"confidence"`
	Indicators  []string  `json:"indicators,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// DemoApplication represents the main demo application
type DemoApplication struct {
	router *gin.Engine
}

// NewDemoApplication creates a new demo application
func NewDemoApplication() *DemoApplication {
	app := &DemoApplication{
		router: gin.Default(),
	}

	app.setupRoutes()
	return app
}

// Start starts the demo application
func (app *DemoApplication) Start() error {
	log.Println("🛡️  Starting HackAI Security Demo Application on :8080")
	log.Println("📊 Dashboard: http://localhost:8080")
	log.Println("🔍 Prompt Injection Demo: http://localhost:8080/prompt-injection")
	log.Println("🌐 Threat Intelligence Demo: http://localhost:8080/threat-intel")
	log.Println("🔥 AI Firewall Demo: http://localhost:8080/ai-firewall")
	return app.router.Run(":8080")
}

// Stop stops the demo application
func (app *DemoApplication) Stop() {
	// Nothing to stop in simplified demo
}

// setupRoutes configures all the demo routes
func (app *DemoApplication) setupRoutes() {
	// Serve static files
	app.router.Static("/static", "./static")
	app.router.LoadHTMLGlob("templates/*")

	// Main routes
	app.router.GET("/", app.handleIndex)
	app.router.GET("/dashboard", app.handleDashboard)
	app.router.GET("/prompt-injection", app.handlePromptInjection)
	app.router.GET("/threat-intel", app.handleThreatIntel)
	app.router.GET("/ai-firewall", app.handleAIFirewall)

	// API routes
	api := app.router.Group("/api")
	{
		api.POST("/analyze", app.handleAnalyze)
		api.POST("/prompt-injection", app.handlePromptInjectionAPI)
		api.POST("/threat-intel", app.handleThreatIntelAPI)
		api.POST("/ai-firewall", app.handleAIFirewallAPI)
		api.GET("/metrics", app.handleMetrics)
		api.GET("/health", app.handleHealth)
	}
}

// handleIndex serves the main page
func (app *DemoApplication) handleIndex(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "HackAI Security Platform Demo",
	})
}

// handleDashboard serves the security dashboard
func (app *DemoApplication) handleDashboard(c *gin.Context) {
	// Simulate metrics
	stats := map[string]interface{}{
		"threats_detected":   1247,
		"requests_processed": 15892,
		"avg_response_time":  125,
		"security_score":     0.985,
		"uptime":             "24h 15m 32s",
		"cache_hit_rate":     0.855,
		"active_sessions":    42,
		"blocked_requests":   156,
	}

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title": "Security Dashboard",
		"stats": stats,
	})
}

// handlePromptInjection serves the prompt injection demo page
func (app *DemoApplication) handlePromptInjection(c *gin.Context) {
	c.HTML(http.StatusOK, "prompt-injection.html", gin.H{
		"title": "Prompt Injection Protection Demo",
	})
}

// handleThreatIntel serves the threat intelligence demo page
func (app *DemoApplication) handleThreatIntel(c *gin.Context) {
	c.HTML(http.StatusOK, "threat-intel.html", gin.H{
		"title": "Threat Intelligence Demo",
	})
}

// handleAIFirewall serves the AI firewall demo page
func (app *DemoApplication) handleAIFirewall(c *gin.Context) {
	c.HTML(http.StatusOK, "ai-firewall.html", gin.H{
		"title": "AI Firewall Demo",
	})
}

// API Handlers

// handleAnalyze handles general security analysis
func (app *DemoApplication) handleAnalyze(c *gin.Context) {
	var request struct {
		Content string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Analyze using simplified prompt injection detection
	result := app.analyzePromptInjection(request.Content)

	c.JSON(http.StatusOK, gin.H{
		"allowed":    !result.IsThreat,
		"confidence": result.Confidence,
		"risk_level": result.RiskLevel,
		"details":    result,
	})
}

// handlePromptInjectionAPI handles prompt injection analysis
func (app *DemoApplication) handlePromptInjectionAPI(c *gin.Context) {
	var request struct {
		Input string `json:"input" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result := app.analyzePromptInjection(request.Input)
	c.JSON(http.StatusOK, result)
}

// handleThreatIntelAPI handles threat intelligence lookups
func (app *DemoApplication) handleThreatIntelAPI(c *gin.Context) {
	var request struct {
		Indicator string `json:"indicator" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result := app.analyzeThreatIntelligence(request.Indicator)
	c.JSON(http.StatusOK, result)
}

// handleAIFirewallAPI handles AI firewall processing
func (app *DemoApplication) handleAIFirewallAPI(c *gin.Context) {
	var request struct {
		Content string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result := app.analyzePromptInjection(request.Content)

	response := map[string]interface{}{
		"input":      request.Content,
		"allowed":    !result.IsThreat,
		"risk_score": result.Confidence * 10,
		"confidence": result.Confidence,
		"timestamp":  time.Now(),
	}

	if result.IsThreat {
		response["error"] = result.Mitigation
		response["threat_types"] = result.ThreatTypes
	}

	c.JSON(http.StatusOK, response)
}

// handleMetrics returns security metrics
func (app *DemoApplication) handleMetrics(c *gin.Context) {
	metrics := map[string]interface{}{
		"threats_detected":   1247,
		"requests_processed": 15892,
		"avg_response_time":  125,
		"security_score":     0.985,
		"uptime":             "24h 15m 32s",
		"cache_hit_rate":     0.855,
		"active_sessions":    42,
		"blocked_requests":   156,
		"timestamp":          time.Now(),
	}

	c.JSON(http.StatusOK, metrics)
}

// handleHealth returns health status
func (app *DemoApplication) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now(),
		"version":   "1.0.0",
	})
}

// Security Analysis Functions

// analyzePromptInjection performs simplified prompt injection analysis
func (app *DemoApplication) analyzePromptInjection(input string) *SecurityAnalysisResult {
	result := &SecurityAnalysisResult{
		Input:     input,
		Timestamp: time.Now(),
	}

	// Simple pattern-based detection
	suspiciousPatterns := []string{
		`(?i)ignore.*previous.*instructions`,
		`(?i)system:`,
		`(?i)reveal.*prompt`,
		`(?i)show.*training.*data`,
		`(?i)admin.*mode`,
		`(?i)pretend.*you.*are`,
		`(?i)bypass.*restrictions`,
		`(?i)list.*passwords`,
		`(?i)database.*users`,
		`(?i)jailbreak`,
		`(?i)dan.*mode`,
	}

	var detectedPatterns []string
	var threatTypes []string

	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, input); matched {
			detectedPatterns = append(detectedPatterns, pattern)

			// Categorize threat types
			if strings.Contains(pattern, "ignore") || strings.Contains(pattern, "instructions") {
				threatTypes = append(threatTypes, "instruction_override")
			}
			if strings.Contains(pattern, "system") || strings.Contains(pattern, "admin") {
				threatTypes = append(threatTypes, "role_manipulation")
			}
			if strings.Contains(pattern, "reveal") || strings.Contains(pattern, "show") {
				threatTypes = append(threatTypes, "data_extraction")
			}
			if strings.Contains(pattern, "jailbreak") || strings.Contains(pattern, "dan") {
				threatTypes = append(threatTypes, "jailbreak_attempt")
			}
		}
	}

	if len(detectedPatterns) > 0 {
		result.IsThreat = true
		result.Confidence = 0.85 + float64(len(detectedPatterns))*0.05
		if result.Confidence > 1.0 {
			result.Confidence = 1.0
		}
		result.RiskLevel = "high"
		result.ThreatTypes = threatTypes
		result.Patterns = detectedPatterns
		result.Mitigation = "Block request and log incident"
	} else {
		result.IsThreat = false
		result.Confidence = 0.95
		result.RiskLevel = "low"
		result.Mitigation = "Allow request"
	}

	return result
}

// analyzeThreatIntelligence performs simplified threat intelligence analysis
func (app *DemoApplication) analyzeThreatIntelligence(input string) *ThreatIntelResult {
	result := &ThreatIntelResult{
		Target:    input,
		Timestamp: time.Now(),
	}

	// Determine type
	if matched, _ := regexp.MatchString(`^\d+\.\d+\.\d+\.\d+$`, input); matched {
		result.Type = "ip"
	} else if matched, _ := regexp.MatchString(`^https?://`, input); matched {
		result.Type = "url"
	} else if matched, _ := regexp.MatchString(`^[a-fA-F0-9]{32,}$`, input); matched {
		result.Type = "hash"
	} else {
		result.Type = "domain"
	}

	// Simulate threat scoring based on known bad indicators
	knownBadIndicators := []string{
		"203.0.113.1",
		"malicious.example.com",
		"phishing.example.com",
		"d41d8cd98f00b204e9800998ecf8427e",
		"evil.com",
		"badactor.net",
	}

	isMalicious := false
	for _, bad := range knownBadIndicators {
		if strings.Contains(input, bad) {
			isMalicious = true
			break
		}
	}

	if isMalicious {
		result.ThreatScore = 8.5
		result.RiskLevel = "high"
		result.Confidence = 0.92
		result.Indicators = []string{"Known malicious indicator", "Multiple threat feeds", "High confidence match"}
	} else {
		result.ThreatScore = 2.1
		result.RiskLevel = "low"
		result.Confidence = 0.75
		result.Indicators = []string{"No known threats", "Clean reputation"}
	}

	return result
}

func main() {
	// Set Gin to release mode for production
	gin.SetMode(gin.ReleaseMode)

	app := NewDemoApplication()

	log.Println("🚀 HackAI Security Platform Demo")
	log.Println("================================")

	if err := app.Start(); err != nil {
		log.Fatalf("Failed to start application: %v", err)
	}
}
