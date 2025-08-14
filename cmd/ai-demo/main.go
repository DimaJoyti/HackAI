package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/internal/repository"
	"github.com/dimajoyti/hackai/internal/usecase"
	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/database"
	"github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
	fmt.Println("🤖 HackAI - AI Security Tools Demo")
	fmt.Println("===================================")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	loggerInstance, err := logger.New(logger.Config{
		Level:      logger.LogLevel(cfg.Observability.Logging.Level),
		Format:     cfg.Observability.Logging.Format,
		Output:     "console",
		AddSource:  true,
		TimeFormat: time.RFC3339,
	})
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// Initialize database
	db, err := database.New(&cfg.Database, loggerInstance)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Initialize repository
	repo := repository.NewSecurityRepository(db.DB, loggerInstance)

	// Initialize AI security tools
	vulnScanner := usecase.NewVulnerabilityScannerUseCase(repo, loggerInstance)
	networkAnalyzer := usecase.NewNetworkAnalyzerUseCase(repo, loggerInstance)
	threatIntel := usecase.NewThreatIntelligenceUseCase(repo, loggerInstance)
	logAnalyzer := usecase.NewLogAnalyzerUseCase(repo, loggerInstance)
	aiService := usecase.NewAIModelService(vulnScanner, networkAnalyzer, threatIntel, logAnalyzer, repo, loggerInstance)

	ctx := context.Background()
	userID := uuid.New()

	// Demo 1: Vulnerability Scanning with AI
	fmt.Println("\n🔍 Demo 1: AI-Powered Vulnerability Scanning")
	fmt.Println("--------------------------------------------")
	demoVulnerabilityScanning(ctx, vulnScanner, userID)

	// Demo 2: Network Analysis with AI
	fmt.Println("\n🌐 Demo 2: AI-Powered Network Analysis")
	fmt.Println("-------------------------------------")
	demoNetworkAnalysis(ctx, networkAnalyzer, userID)

	// Demo 3: Threat Intelligence with AI
	fmt.Println("\n🛡️  Demo 3: AI-Powered Threat Intelligence")
	fmt.Println("------------------------------------------")
	demoThreatIntelligence(ctx, threatIntel)

	// Demo 4: Log Analysis with AI/NLP
	fmt.Println("\n📊 Demo 4: AI-Powered Log Analysis")
	fmt.Println("----------------------------------")
	demoLogAnalysis(ctx, logAnalyzer)

	// Demo 5: Comprehensive AI Analysis
	fmt.Println("\n🧠 Demo 5: Comprehensive AI Security Analysis")
	fmt.Println("---------------------------------------------")
	demoComprehensiveAIAnalysis(ctx, aiService, userID)

	fmt.Println("\n✅ All AI Security Tools Demo Completed!")
	fmt.Println("========================================")
}

func demoVulnerabilityScanning(ctx context.Context, scanner *usecase.VulnerabilityScannerUseCase, userID uuid.UUID) {
	targets := []string{
		"https://example.com",
		"https://test-site.com",
		"https://vulnerable-app.com",
	}

	for i, target := range targets {
		fmt.Printf("  %d. Scanning %s...\n", i+1, target)
		
		config := domain.ScanConfig{
			Timeout:         30,
			MaxDepth:        3,
			UserAgent:       "HackAI-Scanner/1.0",
			FollowRedirects: true,
		}

		scan, err := scanner.StartScan(ctx, userID, target, domain.ScanTypeWeb, config)
		if err != nil {
			fmt.Printf("     ❌ Error: %v\n", err)
			continue
		}

		fmt.Printf("     ✅ Scan started (ID: %s)\n", scan.ID.String()[:8])
		fmt.Printf("     📊 Status: %s, Progress: %d%%\n", scan.Status, scan.Progress)
		
		// Simulate waiting for scan completion
		time.Sleep(2 * time.Second)
		fmt.Printf("     🔍 AI Analysis: Detected SQL injection patterns\n")
		fmt.Printf("     ⚠️  Risk Score: 8.5/10 (High)\n")
	}
}

func demoNetworkAnalysis(ctx context.Context, analyzer *usecase.NetworkAnalyzerUseCase, userID uuid.UUID) {
	targets := []string{
		"192.168.1.0/24",
		"10.0.0.1",
		"172.16.0.0/16",
	}

	for i, target := range targets {
		fmt.Printf("  %d. Analyzing network %s...\n", i+1, target)
		
		config := domain.NetworkScanConfig{
			Timeout:   5,
			Threads:   10,
			PortRange: "1-1000",
			ScanTCP:   true,
			ScanUDP:   false,
		}

		scan, err := analyzer.StartScan(ctx, userID, target, domain.NetworkScanTypePortScan, config)
		if err != nil {
			fmt.Printf("     ❌ Error: %v\n", err)
			continue
		}

		fmt.Printf("     ✅ Network scan started (ID: %s)\n", scan.ID.String()[:8])
		fmt.Printf("     📊 Status: %s, Progress: %d%%\n", scan.Status, scan.Progress)
		
		// Simulate scan results
		time.Sleep(1 * time.Second)
		fmt.Printf("     🖥️  AI Detection: 5 hosts discovered\n")
		fmt.Printf("     🔓 Open Ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)\n")
		fmt.Printf("     🤖 OS Detection: Linux (Ubuntu 20.04)\n")
		fmt.Printf("     ⚠️  Attack Surface Score: 6.5/10\n")
	}
}

func demoThreatIntelligence(ctx context.Context, threatIntel *usecase.ThreatIntelligenceUseCase) {
	targets := []string{
		"192.168.1.100",
		"malicious-site.com",
		"https://phishing-example.com",
		"d41d8cd98f00b204e9800998ecf8427e", // MD5 hash
	}

	for i, target := range targets {
		fmt.Printf("  %d. Analyzing threat intelligence for %s...\n", i+1, target)
		
		report, err := threatIntel.AnalyzeThreat(ctx, target)
		if err != nil {
			fmt.Printf("     ❌ Error: %v\n", err)
			continue
		}

		fmt.Printf("     ✅ Analysis completed (ID: %s)\n", report.ID.String()[:8])
		fmt.Printf("     🎯 Target: %s\n", report.Target)
		fmt.Printf("     📊 Risk Score: %.1f/10\n", report.RiskScore)
		fmt.Printf("     🔍 Confidence: %.0f%%\n", report.Confidence*100)
		fmt.Printf("     📝 Summary: %s\n", report.Summary)
		
		if len(report.Indicators) > 0 {
			fmt.Printf("     🚨 Threat Indicators:\n")
			for _, indicator := range report.Indicators {
				fmt.Printf("       - %s: %s (Confidence: %.0f%%)\n", 
					indicator.Type, indicator.Description, indicator.Confidence*100)
			}
		}
		
		if len(report.Recommendations) > 0 {
			fmt.Printf("     💡 Recommendations:\n")
			for _, rec := range report.Recommendations {
				fmt.Printf("       - %s\n", rec)
			}
		}
		
		time.Sleep(500 * time.Millisecond)
	}
}

func demoLogAnalysis(ctx context.Context, logAnalyzer *usecase.LogAnalyzerUseCase) {
	// Sample log entries for analysis
	sampleLogs := []string{
		`2024-01-15 10:30:15 [ERROR] Failed login attempt for user 'admin' from IP 192.168.1.100`,
		`2024-01-15 10:30:16 [ERROR] Failed login attempt for user 'admin' from IP 192.168.1.100`,
		`2024-01-15 10:30:17 [ERROR] Failed login attempt for user 'root' from IP 192.168.1.100`,
		`2024-01-15 10:30:18 [ERROR] Failed login attempt for user 'administrator' from IP 192.168.1.100`,
		`2024-01-15 10:30:19 [ERROR] Failed login attempt for user 'admin' from IP 192.168.1.100`,
		`2024-01-15 10:31:00 [INFO] GET /search?q=<script>alert('xss')</script> HTTP/1.1 200`,
		`2024-01-15 10:31:05 [INFO] POST /login.php?id=1' OR '1'='1 HTTP/1.1 500`,
		`2024-01-15 10:31:10 [WARN] Unusual traffic spike detected: 1000 requests/minute`,
		`2024-01-15 10:32:00 [ERROR] Database connection failed: Access denied for user 'webapp'`,
		`2024-01-15 10:32:30 [INFO] User 'john.doe' logged in successfully from IP 10.0.0.5`,
	}

	fmt.Printf("  📋 Analyzing %d log entries...\n", len(sampleLogs))
	
	timeRange := usecase.TimeRange{
		Start: time.Now().Add(-1 * time.Hour),
		End:   time.Now(),
	}

	report, err := logAnalyzer.AnalyzeLogs(ctx, sampleLogs, timeRange)
	if err != nil {
		fmt.Printf("     ❌ Error: %v\n", err)
		return
	}

	fmt.Printf("     ✅ Analysis completed (ID: %s)\n", report.ID.String()[:8])
	fmt.Printf("     📊 Total Logs: %d\n", report.TotalLogs)
	fmt.Printf("     🚨 Security Events: %d\n", len(report.SecurityEvents))
	fmt.Printf("     📈 Anomalies: %d\n", len(report.Anomalies))
	fmt.Printf("     ⚠️  Risk Score: %.1f/10\n", report.ThreatSummary.RiskScore)

	if len(report.SecurityEvents) > 0 {
		fmt.Printf("     🔍 Detected Security Events:\n")
		for _, event := range report.SecurityEvents {
			fmt.Printf("       - %s: %s (Severity: %s, Confidence: %.0f%%)\n",
				event.Type, event.Description, event.Severity, event.Confidence*100)
		}
	}

	if len(report.Anomalies) > 0 {
		fmt.Printf("     📊 Detected Anomalies:\n")
		for _, anomaly := range report.Anomalies {
			fmt.Printf("       - %s: %.1fx baseline (Confidence: %.0f%%)\n",
				anomaly.Type, anomaly.Deviation, anomaly.Confidence*100)
		}
	}

	if len(report.Recommendations) > 0 {
		fmt.Printf("     💡 AI Recommendations:\n")
		for _, rec := range report.Recommendations {
			fmt.Printf("       - %s\n", rec)
		}
	}
}

func demoComprehensiveAIAnalysis(ctx context.Context, aiService *usecase.AIModelService, userID uuid.UUID) {
	targets := []string{
		"https://example.com",
		"192.168.1.100",
		"test-domain.com",
	}

	fmt.Printf("  🎯 Performing comprehensive AI analysis on %d targets...\n", len(targets))

	request := &usecase.AIAnalysisRequest{
		ID:       uuid.New(),
		UserID:   userID,
		Type:     "comprehensive",
		Targets:  targets,
		Priority: "high",
		Config:   map[string]interface{}{
			"deep_analysis": true,
			"correlation":   true,
		},
	}

	result, err := aiService.PerformComprehensiveAnalysis(ctx, request)
	if err != nil {
		fmt.Printf("     ❌ Error: %v\n", err)
		return
	}

	fmt.Printf("     ✅ Comprehensive analysis completed (ID: %s)\n", result.ID.String()[:8])
	fmt.Printf("     ⏱️  Execution Time: %v\n", result.ExecutionTime)
	fmt.Printf("     📊 Overall Risk Score: %.1f/10\n", result.OverallRiskScore)
	fmt.Printf("     🎯 Threat Level: %s\n", result.ThreatLevel)
	fmt.Printf("     🔍 Confidence: %.0f%%\n", result.OverallConfidence*100)

	fmt.Printf("     📋 Analysis Results:\n")
	fmt.Printf("       - Vulnerability Results: %d\n", len(result.VulnerabilityResults))
	fmt.Printf("       - Network Results: %d\n", len(result.NetworkResults))
	fmt.Printf("       - Threat Intel Results: %d\n", len(result.ThreatIntelResults))

	if len(result.CorrelatedFindings) > 0 {
		fmt.Printf("     🔗 Correlated Findings:\n")
		for _, finding := range result.CorrelatedFindings {
			fmt.Printf("       - %s: %s (Confidence: %.0f%%)\n",
				finding.Type, finding.Description, finding.Confidence*100)
		}
	}

	if len(result.AIInsights) > 0 {
		fmt.Printf("     🧠 AI Insights:\n")
		for _, insight := range result.AIInsights {
			fmt.Printf("       - %s: %s (Confidence: %.0f%%)\n",
				insight.Type, insight.Title, insight.Confidence*100)
			if insight.Prediction != nil {
				fmt.Printf("         Prediction: %s (%.0f%% probability in %s)\n",
					insight.Prediction.Event, insight.Prediction.Probability*100, insight.Prediction.Timeframe)
			}
		}
	}

	if len(result.Recommendations) > 0 {
		fmt.Printf("     💡 AI Recommendations:\n")
		for _, rec := range result.Recommendations {
			fmt.Printf("       - [%s] %s\n", rec.Priority, rec.Title)
			fmt.Printf("         Timeline: %s, Impact: %s\n", rec.Timeline, rec.Impact)
		}
	}

	// Pretty print the full result as JSON (truncated for demo)
	fmt.Printf("     📄 Full Analysis Report:\n")
	jsonData, _ := json.MarshalIndent(map[string]interface{}{
		"id":                result.ID,
		"overall_risk_score": result.OverallRiskScore,
		"threat_level":      result.ThreatLevel,
		"execution_time":    result.ExecutionTime.String(),
		"findings_count":    len(result.CorrelatedFindings),
		"insights_count":    len(result.AIInsights),
		"recommendations_count": len(result.Recommendations),
	}, "       ", "  ")
	fmt.Printf("       %s\n", string(jsonData))
}
