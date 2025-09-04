package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/infrastructure"
	"github.com/dimajoyti/hackai/pkg/langgraph/messaging"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/realtime"
	"github.com/dimajoyti/hackai/pkg/security"
)

func main() {
	fmt.Println("🚀 HackAI Real-Time Data Streaming Demo")
	fmt.Println("=====================================")
	fmt.Println("Features: Threat Intelligence Streaming • WebSockets • SSE • REST APIs")

	// Initialize logger
	logger, err := logger.New(logger.Config{
		Level:       "info",
		Format:      "json",
		Output:      "stdout",
		ServiceName: "realtime-streaming-demo",
	})
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize Redis client (optional)
	var redisClient *infrastructure.RedisClient
	redisConfig := &config.RedisConfig{
		Host:         "localhost",
		Port:         6379,
		Password:     "",
		Database:     0,
		PoolSize:     10,
		MinIdleConns: 5,
		DialTimeout:  5,
		ReadTimeout:  3,
		WriteTimeout: 3,
	}

	redisClient, err = infrastructure.NewRedisClient(redisConfig, logger)
	if err != nil {
		logger.Warn("Redis not available, continuing without persistence", "error", err)
		redisClient = nil
	} else {
		logger.Info("✅ Redis client initialized for persistence")
	}

	// Initialize event system
	eventSystem := &messaging.EventSystem{}

	// Configure real-time system
	realtimeConfig := &realtime.RealtimeConfig{
		WebSocketConfig: realtime.WebSocketConfig{
			ReadBufferSize:    2048,
			WriteBufferSize:   2048,
			HandshakeTimeout:  10 * time.Second,
			ReadDeadline:      60 * time.Second,
			WriteDeadline:     10 * time.Second,
			PongWait:          60 * time.Second,
			PingPeriod:        54 * time.Second,
			MaxMessageSize:    1024 * 1024, // 1MB
			EnableCompression: true,
		},
		StreamConfig: realtime.StreamConfig{
			BufferSize:        2000,
			FlushInterval:     2 * time.Second,
			MaxStreamAge:      2 * time.Hour,
			EnablePersistence: redisClient != nil,
			CompressionLevel:  6,
		},
		PubSubConfig: realtime.PubSubConfig{
			ChannelBufferSize: 200,
			SubscriberTimeout: 10 * time.Minute,
			EnablePersistence: redisClient != nil,
			RetentionPeriod:   48 * time.Hour,
		},
		MaxConnections:      2000,
		ConnectionTimeout:   30 * time.Second,
		HeartbeatInterval:   20 * time.Second,
		MessageBufferSize:   2000,
		MessageTimeout:      15 * time.Second,
		EnableCompression:   true,
		EnableAuth:          false,
		AllowedOrigins:      []string{"*"},
		RateLimitEnabled:    true,
		RateLimitRequests:   200,
		RateLimitWindow:     1 * time.Minute,
		MetricsEnabled:      true,
		HealthCheckInterval: 15 * time.Second,
	}

	// Create real-time system
	realtimeSystem := realtime.NewRealtimeSystem(realtimeConfig, redisClient, eventSystem, logger)

	// Start real-time system
	if err := realtimeSystem.Start(ctx); err != nil {
		logger.Fatal("Failed to start real-time system", "error", err)
	}
	logger.Info("✅ Real-time system started successfully")

	// Initialize threat intelligence engine (simplified for demo)
	threatEngine := &security.ThreatIntelligenceEngine{} // Simplified

	// Configure threat intelligence streamer
	threatStreamerConfig := realtime.DefaultThreatStreamerConfig()
	threatStreamerConfig.BufferSize = 5000
	threatStreamerConfig.ProcessingInterval = 500 * time.Millisecond
	threatStreamerConfig.BatchSize = 50
	threatStreamerConfig.EnableCorrelation = true
	threatStreamerConfig.EnableEnrichment = true

	// Create threat intelligence streamer
	threatStreamer := realtime.NewThreatIntelligenceStreamer(
		threatStreamerConfig,
		realtimeSystem,
		threatEngine,
		logger,
	)

	// Start threat intelligence streamer
	if err := threatStreamer.Start(ctx); err != nil {
		logger.Fatal("Failed to start threat intelligence streamer", "error", err)
	}
	logger.Info("✅ Threat intelligence streamer started successfully")

	// Create streaming API handlers
	streamingAPI := realtime.NewStreamingAPIHandler(realtimeSystem, threatStreamer, logger)

	// Setup HTTP router
	router := mux.NewRouter()

	// Register streaming routes
	streamingAPI.RegisterStreamingRoutes(router)

	// Add demo-specific routes
	setupDemoRoutes(router, realtimeSystem, threatStreamer, logger)

	// Create HTTP server
	server := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start HTTP server
	go func() {
		logger.Info("🌐 HTTP server starting", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("HTTP server failed", "error", err)
		}
	}()

	// Start demo data generators
	go runThreatIntelligenceGenerator(ctx, threatStreamer, logger)
	go runRealTimeMetricsGenerator(ctx, realtimeSystem, logger)
	go runSecurityEventsGenerator(ctx, realtimeSystem, logger)

	// Display information
	logger.Info("🎯 Real-Time Streaming Demo is running!")
	logger.Info("🔗 Available endpoints:")
	logger.Info("   📊 Demo Dashboard: http://localhost:8080/demo")
	logger.Info("   🔌 WebSocket (General): ws://localhost:8080/api/stream/ws")
	logger.Info("   🔌 WebSocket (Threat IOC): ws://localhost:8080/api/stream/ws/ioc")
	logger.Info("   📡 Server-Sent Events: http://localhost:8080/api/stream/events")
	logger.Info("   🔥 IOC Stream: http://localhost:8080/api/stream/threat/ioc")
	logger.Info("   🚨 CVE Stream: http://localhost:8080/api/stream/threat/cve")
	logger.Info("   ⚔️  MITRE Stream: http://localhost:8080/api/stream/threat/mitre")
	logger.Info("   🚨 Alerts Stream: http://localhost:8080/api/stream/threat/alerts")
	logger.Info("   📈 Metrics Stream: http://localhost:8080/api/stream/threat/metrics")
	logger.Info("   ❤️  System Health: http://localhost:8080/api/stream/health")
	logger.Info("   📊 Stream Status: http://localhost:8080/api/stream/status")
	logger.Info("Press Ctrl+C to stop...")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	logger.Info("🛑 Shutting down...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop HTTP server
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP server shutdown error", "error", err)
	}

	// Stop threat intelligence streamer
	if err := threatStreamer.Stop(); err != nil {
		logger.Error("Threat intelligence streamer shutdown error", "error", err)
	}

	// Stop real-time system
	if err := realtimeSystem.Stop(); err != nil {
		logger.Error("Real-time system shutdown error", "error", err)
	}

	logger.Info("✅ Shutdown complete")
}

// setupDemoRoutes sets up demo-specific routes
func setupDemoRoutes(router *mux.Router, realtimeSystem *realtime.RealtimeSystem, threatStreamer *realtime.ThreatIntelligenceStreamer, logger *logger.Logger) {
	// Demo dashboard
	router.HandleFunc("/demo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, getAdvancedDemoDashboardHTML())
	}).Methods("GET")

	// Demo data generation endpoints
	router.HandleFunc("/demo/generate/ioc", func(w http.ResponseWriter, r *http.Request) {
		generateSampleIOC(r.Context(), threatStreamer, logger)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success": true, "message": "Sample IOC generated"}`)
	}).Methods("POST")

	router.HandleFunc("/demo/generate/cve", func(w http.ResponseWriter, r *http.Request) {
		generateSampleCVE(r.Context(), threatStreamer, logger)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success": true, "message": "Sample CVE generated"}`)
	}).Methods("POST")

	router.HandleFunc("/demo/generate/alert", func(w http.ResponseWriter, r *http.Request) {
		generateSampleAlert(r.Context(), threatStreamer, logger)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success": true, "message": "Sample alert generated"}`)
	}).Methods("POST")

	router.HandleFunc("/demo/simulate/attack", func(w http.ResponseWriter, r *http.Request) {
		simulateSecurityAttack(r.Context(), threatStreamer, realtimeSystem, logger)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success": true, "message": "Security attack simulation started"}`)
	}).Methods("POST")
}

// Data generators for demo
func runThreatIntelligenceGenerator(ctx context.Context, threatStreamer *realtime.ThreatIntelligenceStreamer, logger *logger.Logger) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	scenarios := []string{"malware", "phishing", "botnet", "apt", "vulnerability", "data_breach"}
	scenarioIndex := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scenario := scenarios[scenarioIndex%len(scenarios)]
			generateThreatIntelligence(ctx, threatStreamer, scenario, logger)
			scenarioIndex++
		}
	}
}

func runRealTimeMetricsGenerator(ctx context.Context, realtimeSystem *realtime.RealtimeSystem, logger *logger.Logger) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			generateSystemMetrics(ctx, realtimeSystem, logger)
		}
	}
}

func runSecurityEventsGenerator(ctx context.Context, realtimeSystem *realtime.RealtimeSystem, logger *logger.Logger) {
	ticker := time.NewTicker(8 * time.Second)
	defer ticker.Stop()

	eventTypes := []string{"login_attempt", "file_access", "network_connection", "privilege_escalation", "data_exfiltration"}
	eventIndex := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			eventType := eventTypes[eventIndex%len(eventTypes)]
			generateSecurityEvent(ctx, realtimeSystem, eventType, logger)
			eventIndex++
		}
	}
}

// Specific generators
func generateThreatIntelligence(ctx context.Context, threatStreamer *realtime.ThreatIntelligenceStreamer, scenario string, logger *logger.Logger) {
	switch scenario {
	case "malware":
		indicator := &realtime.ThreatIndicator{
			Type:       "hash",
			Value:      fmt.Sprintf("sha256:%x", time.Now().UnixNano()),
			Confidence: 0.85,
			Severity:   "high",
			FirstSeen:  time.Now().Add(-1 * time.Hour),
			LastSeen:   time.Now(),
			Sources:    []string{"VirusTotal", "Hybrid Analysis"},
			Tags:       []string{"malware", "trojan", "credential-stealer"},
		}
		threatStreamer.CreateIOCStream(ctx, indicator)

	case "phishing":
		indicator := &realtime.ThreatIndicator{
			Type:       "domain",
			Value:      fmt.Sprintf("malicious-site-%d.com", time.Now().Unix()%1000),
			Confidence: 0.92,
			Severity:   "high",
			FirstSeen:  time.Now().Add(-30 * time.Minute),
			LastSeen:   time.Now(),
			Sources:    []string{"PhishTank", "URLVoid"},
			Tags:       []string{"phishing", "credential-theft", "banking"},
		}
		threatStreamer.CreateIOCStream(ctx, indicator)

	case "vulnerability":
		vuln := &realtime.VulnerabilityInfo{
			CVEID:       fmt.Sprintf("CVE-2024-%04d", time.Now().Unix()%10000),
			CVSSScore:   7.5 + (float64(time.Now().Unix()%25) / 10.0),
			Severity:    "high",
			Description: "Remote code execution vulnerability in web application framework",
			Published:   time.Now().Add(-24 * time.Hour),
			Modified:    time.Now(),
			References:  []string{"https://nvd.nist.gov", "https://security-advisory.com"},
			Exploited:   time.Now().Unix()%2 == 0,
		}
		threatStreamer.CreateCVEStream(ctx, vuln.CVEID, vuln)

	case "apt":
		threatStreamer.CreateMITREStream(ctx, "Initial Access", "T1566.001", map[string]interface{}{
			"technique_name": "Spearphishing Attachment",
			"description":    "APT group using sophisticated spearphishing campaign",
			"severity":       "critical",
			"confidence":     0.88,
			"campaign":       fmt.Sprintf("APT-Campaign-%d", time.Now().Unix()%100),
		})
	}

	logger.Debug("Generated threat intelligence", "scenario", scenario)
}

func generateSystemMetrics(ctx context.Context, realtimeSystem *realtime.RealtimeSystem, logger *logger.Logger) {
	metrics := map[string]interface{}{
		"cpu_usage":      float64(20 + (time.Now().Unix() % 60)),
		"memory_usage":   float64(40 + (time.Now().Unix() % 40)),
		"disk_usage":     float64(60 + (time.Now().Unix() % 20)),
		"network_in":     float64(100 + (time.Now().Unix() % 200)),
		"network_out":    float64(80 + (time.Now().Unix() % 150)),
		"active_threats": int(time.Now().Unix() % 50),
		"blocked_ips":    int(time.Now().Unix() % 100),
		"timestamp":      time.Now(),
	}

	realtimeSystem.PublishMessage(ctx, "system.metrics", metrics)
}

func generateSecurityEvent(ctx context.Context, realtimeSystem *realtime.RealtimeSystem, eventType string, logger *logger.Logger) {
	event := map[string]interface{}{
		"event_type":  eventType,
		"timestamp":   time.Now(),
		"source_ip":   fmt.Sprintf("192.168.%d.%d", time.Now().Unix()%256, time.Now().Unix()%256),
		"user_agent":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		"severity":    []string{"low", "medium", "high", "critical"}[time.Now().Unix()%4],
		"status":      []string{"allowed", "blocked", "quarantined"}[time.Now().Unix()%3],
		"description": fmt.Sprintf("Security event: %s detected", eventType),
	}

	realtimeSystem.PublishMessage(ctx, "security.events", event)
}

// Sample generators for demo buttons
func generateSampleIOC(ctx context.Context, threatStreamer *realtime.ThreatIntelligenceStreamer, logger *logger.Logger) {
	indicator := &realtime.ThreatIndicator{
		Type:       "ip",
		Value:      fmt.Sprintf("192.168.%d.%d", time.Now().Unix()%256, time.Now().Unix()%256),
		Confidence: 0.95,
		Severity:   "critical",
		FirstSeen:  time.Now().Add(-2 * time.Hour),
		LastSeen:   time.Now(),
		Sources:    []string{"Demo Generator", "Threat Feed Alpha"},
		Tags:       []string{"c2", "botnet", "malware"},
		Metadata: map[string]interface{}{
			"demo":      true,
			"generated": time.Now(),
		},
	}
	threatStreamer.CreateIOCStream(ctx, indicator)
}

func generateSampleCVE(ctx context.Context, threatStreamer *realtime.ThreatIntelligenceStreamer, logger *logger.Logger) {
	vuln := &realtime.VulnerabilityInfo{
		CVEID:       fmt.Sprintf("CVE-2024-DEMO%04d", time.Now().Unix()%10000),
		CVSSScore:   9.0,
		Severity:    "critical",
		Description: "Demo vulnerability - Remote code execution in sample application",
		Published:   time.Now().Add(-12 * time.Hour),
		Modified:    time.Now(),
		References:  []string{"https://demo-cve.com", "https://security-demo.org"},
		Exploited:   true,
	}
	threatStreamer.CreateCVEStream(ctx, vuln.CVEID, vuln)
}

func generateSampleAlert(ctx context.Context, threatStreamer *realtime.ThreatIntelligenceStreamer, logger *logger.Logger) {
	threatStreamer.CreateAlertStream(ctx, 
		"demo_alert",
		"Critical Security Alert - Demo",
		"This is a demonstration of real-time security alerting capabilities",
		"critical",
		0.95,
	)
}

func simulateSecurityAttack(ctx context.Context, threatStreamer *realtime.ThreatIntelligenceStreamer, realtimeSystem *realtime.RealtimeSystem, logger *logger.Logger) {
	// Simulate a multi-stage attack
	go func() {
		// Stage 1: Reconnaissance
		time.Sleep(1 * time.Second)
		threatStreamer.CreateAlertStream(ctx, "reconnaissance", "Reconnaissance Activity Detected", "Port scanning detected from external IP", "medium", 0.7)
		
		// Stage 2: Initial Access
		time.Sleep(3 * time.Second)
		indicator := &realtime.ThreatIndicator{
			Type: "ip", Value: "203.0.113.42", Confidence: 0.9, Severity: "high",
			Sources: []string{"IDS", "Firewall"}, Tags: []string{"attack", "intrusion"},
		}
		threatStreamer.CreateIOCStream(ctx, indicator)
		
		// Stage 3: Persistence
		time.Sleep(2 * time.Second)
		threatStreamer.CreateMITREStream(ctx, "Persistence", "T1053.005", map[string]interface{}{
			"technique_name": "Scheduled Task/Job: Scheduled Task",
			"description": "Attacker creating scheduled task for persistence",
			"severity": "high",
		})
		
		// Stage 4: Final Alert
		time.Sleep(2 * time.Second)
		threatStreamer.CreateAlertStream(ctx, "attack_chain", "Multi-Stage Attack Detected", "Complete attack chain simulation completed", "critical", 0.95)
	}()
}

// Advanced demo dashboard HTML
func getAdvancedDemoDashboardHTML() string {
	return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HackAI Real-Time Streaming Demo</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #0f1419 0%, #1a202c 100%);
            color: #e2e8f0;
            overflow-x: hidden;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        
        .header {
            background: linear-gradient(135deg, #2d3748 0%, #4a5568 100%);
            padding: 30px; border-radius: 15px; margin-bottom: 30px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.3);
            border: 1px solid #4a5568;
        }
        .header h1 { 
            font-size: 2.5rem; margin-bottom: 10px;
            background: linear-gradient(135deg, #63b3ed 0%, #4299e1 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        .header p { font-size: 1.1rem; opacity: 0.8; }
        
        .status-bar {
            display: flex; gap: 15px; align-items: center; margin-top: 15px;
        }
        .status { 
            padding: 8px 15px; border-radius: 25px; font-weight: bold;
            font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px;
        }
        .status.healthy { background: linear-gradient(135deg, #48bb78 0%, #38a169 100%); }
        .status.streaming { background: linear-gradient(135deg, #4299e1 0%, #3182ce 100%); }
        .status.threat { background: linear-gradient(135deg, #ed8936 0%, #dd6b20 100%); }
        
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { 
            background: rgba(45, 55, 72, 0.8); backdrop-filter: blur(10px);
            border-radius: 15px; padding: 25px; border: 1px solid #4a5568;
            box-shadow: 0 8px 20px rgba(0,0,0,0.2); transition: all 0.3s ease;
        }
        .card:hover { transform: translateY(-5px); box-shadow: 0 15px 30px rgba(0,0,0,0.3); }
        .card h2 { 
            margin-bottom: 20px; font-size: 1.4rem;
            background: linear-gradient(135deg, #63b3ed 0%, #4299e1 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        
        .metrics-grid { 
            display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 15px; 
            margin-bottom: 20px;
        }
        .metric { 
            background: rgba(26, 32, 44, 0.6); padding: 15px; border-radius: 10px; text-align: center;
            border: 1px solid #2d3748; transition: all 0.3s ease;
        }
        .metric:hover { background: rgba(26, 32, 44, 0.8); border-color: #4299e1; }
        .metric h3 { 
            margin-bottom: 8px; font-size: 0.85rem; opacity: 0.7; 
            text-transform: uppercase; letter-spacing: 0.5px;
        }
        .metric .value { 
            font-size: 1.8rem; font-weight: bold; margin-bottom: 5px;
            background: linear-gradient(135deg, #48bb78 0%, #4299e1 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        .metric .change { font-size: 0.8rem; opacity: 0.6; }
        
        .controls { margin-bottom: 25px; }
        .control-group { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 15px; }
        .control-group h3 { 
            width: 100%; margin-bottom: 10px; font-size: 1rem; opacity: 0.8;
            color: #63b3ed;
        }
        
        button { 
            background: linear-gradient(135deg, #4299e1 0%, #3182ce 100%);
            color: white; border: none; padding: 12px 20px; border-radius: 8px; 
            cursor: pointer; font-weight: 500; transition: all 0.3s ease;
            font-size: 0.9rem; min-width: 140px;
        }
        button:hover { 
            background: linear-gradient(135deg, #3182ce 0%, #2c5aa0 100%);
            transform: translateY(-2px); box-shadow: 0 5px 15px rgba(66, 153, 225, 0.4);
        }
        button.danger { 
            background: linear-gradient(135deg, #f56565 0%, #e53e3e 100%);
        }
        button.danger:hover { 
            background: linear-gradient(135deg, #e53e3e 0%, #c53030 100%);
        }
        button.success { 
            background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
        }
        button.success:hover { 
            background: linear-gradient(135deg, #38a169 0%, #2f855a 100%);
        }
        
        .log-container { 
            background: rgba(26, 32, 44, 0.8); border-radius: 10px; 
            border: 1px solid #2d3748; height: 400px; overflow: hidden;
        }
        .log-header { 
            background: rgba(45, 55, 72, 0.9); padding: 15px; 
            border-bottom: 1px solid #4a5568; display: flex; justify-content: space-between; align-items: center;
        }
        .log-header h3 { font-size: 1rem; color: #63b3ed; }
        .log { 
            height: 340px; overflow-y: auto; padding: 15px; 
            font-family: 'Courier New', monospace; font-size: 0.85rem; line-height: 1.5;
        }
        .log-entry { 
            margin-bottom: 8px; padding: 8px; border-radius: 5px; border-left: 3px solid transparent;
            background: rgba(45, 55, 72, 0.3); transition: all 0.3s ease;
        }
        .log-entry:hover { background: rgba(45, 55, 72, 0.5); }
        .log-entry.info { border-left-color: #4299e1; }
        .log-entry.warning { border-left-color: #ed8936; }
        .log-entry.error { border-left-color: #f56565; }
        .log-entry.success { border-left-color: #48bb78; }
        .timestamp { opacity: 0.6; font-size: 0.8rem; }
        
        .connection-status { 
            display: inline-block; width: 10px; height: 10px; border-radius: 50%; 
            margin-right: 8px; animation: pulse 2s infinite;
        }
        .connection-status.connected { background: #48bb78; }
        .connection-status.disconnected { background: #f56565; }
        
        @keyframes pulse { 
            0%, 100% { opacity: 1; } 
            50% { opacity: 0.5; } 
        }
        
        .streaming-indicators { 
            display: flex; gap: 15px; margin-top: 15px; flex-wrap: wrap;
        }
        .stream-indicator { 
            background: rgba(26, 32, 44, 0.6); padding: 10px 15px; border-radius: 8px;
            border: 1px solid #2d3748; display: flex; align-items: center; gap: 8px;
        }
        .stream-indicator .status-dot { 
            width: 8px; height: 8px; border-radius: 50%; background: #48bb78;
            animation: pulse 1.5s infinite;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .container { padding: 15px; }
            .grid { grid-template-columns: 1fr; }
            .control-group { flex-direction: column; }
            button { min-width: 100%; }
            .header h1 { font-size: 2rem; }
        }
        
        /* Scrollbar styling */
        .log::-webkit-scrollbar { width: 8px; }
        .log::-webkit-scrollbar-track { background: rgba(26, 32, 44, 0.5); border-radius: 4px; }
        .log::-webkit-scrollbar-thumb { background: #4a5568; border-radius: 4px; }
        .log::-webkit-scrollbar-thumb:hover { background: #63b3ed; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 HackAI Real-Time Data Streaming Platform</h1>
            <p>Comprehensive threat intelligence streaming with WebSockets, Server-Sent Events, and REST APIs</p>
            <div class="status-bar">
                <div class="status healthy">System Healthy</div>
                <div class="status streaming">Streaming Active</div>
                <div class="status threat">Threat Intel Live</div>
            </div>
            <div class="streaming-indicators">
                <div class="stream-indicator">
                    <div class="status-dot"></div>
                    <span>WebSocket</span>
                </div>
                <div class="stream-indicator">
                    <div class="status-dot"></div>
                    <span>Server-Sent Events</span>
                </div>
                <div class="stream-indicator">
                    <div class="status-dot"></div>
                    <span>Threat Intelligence</span>
                </div>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h2>📊 Real-Time Metrics</h2>
                <div class="metrics-grid">
                    <div class="metric">
                        <h3>Connections</h3>
                        <div class="value" id="connections">0</div>
                        <div class="change">+2 active</div>
                    </div>
                    <div class="metric">
                        <h3>Messages/sec</h3>
                        <div class="value" id="messages">0</div>
                        <div class="change">↑ 15%</div>
                    </div>
                    <div class="metric">
                        <h3>Threats</h3>
                        <div class="value" id="threats">0</div>
                        <div class="change">3 new</div>
                    </div>
                    <div class="metric">
                        <h3>Streams</h3>
                        <div class="value" id="streams">0</div>
                        <div class="change">5 active</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>🎮 Connection Controls</h2>
                <div class="controls">
                    <div class="control-group">
                        <h3>Real-Time Connections</h3>
                        <button onclick="connectWebSocket()">
                            <span class="connection-status disconnected" id="ws-status"></span>
                            Connect WebSocket
                        </button>
                        <button onclick="connectSSE()">
                            <span class="connection-status disconnected" id="sse-status"></span>
                            Connect SSE
                        </button>
                        <button onclick="connectThreatStream()">
                            <span class="connection-status disconnected" id="threat-status"></span>
                            Connect Threat Stream
                        </button>
                    </div>
                    <div class="control-group">
                        <h3>Data Generation</h3>
                        <button class="success" onclick="generateIOC()">Generate IOC</button>
                        <button class="success" onclick="generateCVE()">Generate CVE</button>
                        <button class="success" onclick="generateAlert()">Generate Alert</button>
                        <button class="danger" onclick="simulateAttack()">Simulate Attack</button>
                    </div>
                </div>
            </div>
        </div>

        <div style="margin-top: 30px;" class="grid">
            <div class="card">
                <div class="log-container">
                    <div class="log-header">
                        <h3>📝 Real-Time Event Stream</h3>
                        <button onclick="clearLog()" style="padding: 6px 12px; font-size: 0.8rem; min-width: auto;">Clear Log</button>
                    </div>
                    <div class="log" id="eventLog">
                        <div class="log-entry info">
                            <span class="timestamp">[${new Date().toLocaleTimeString()}]</span>
                            🚀 Real-time streaming system initialized and ready
                        </div>
                        <div class="log-entry info">
                            <span class="timestamp">[${new Date().toLocaleTimeString()}]</span>
                            📡 Waiting for connections...
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let ws = null;
        let eventSource = null;
        let threatEventSource = null;

        function log(message, type = 'info') {
            const logDiv = document.getElementById('eventLog');
            const timestamp = new Date().toLocaleTimeString();
            const entry = document.createElement('div');
            entry.className = 'log-entry ' + type;
            entry.innerHTML = '<span class="timestamp">[' + timestamp + ']</span> ' + message;
            logDiv.appendChild(entry);
            logDiv.scrollTop = logDiv.scrollHeight;
        }

        function updateConnectionStatus(id, connected) {
            const statusEl = document.getElementById(id);
            if (statusEl) {
                statusEl.className = 'connection-status ' + (connected ? 'connected' : 'disconnected');
            }
        }

        function connectWebSocket() {
            if (ws) {
                ws.close();
            }
            
            ws = new WebSocket('ws://localhost:8080/api/stream/ws');
            
            ws.onopen = function() {
                log('🔌 WebSocket connected successfully', 'success');
                updateConnectionStatus('ws-status', true);
                
                // Subscribe to multiple channels
                ws.send(JSON.stringify({
                    action: 'subscribe',
                    channel: 'system.metrics'
                }));
                ws.send(JSON.stringify({
                    action: 'subscribe',
                    channel: 'security.events'
                }));
            };
            
            ws.onmessage = function(event) {
                try {
                    const data = JSON.parse(event.data);
                    if (data.type === 'subscribe_response') {
                        log('📩 Subscribed to channel: ' + data.channel, 'success');
                    } else {
                        log('📨 WebSocket: ' + JSON.stringify(data).substring(0, 100) + '...', 'info');
                    }
                } catch (e) {
                    log('📨 WebSocket: ' + event.data.substring(0, 100) + '...', 'info');
                }
            };
            
            ws.onclose = function() {
                log('❌ WebSocket disconnected', 'warning');
                updateConnectionStatus('ws-status', false);
            };
            
            ws.onerror = function(error) {
                log('❌ WebSocket error: ' + error, 'error');
            };
        }

        function connectSSE() {
            if (eventSource) {
                eventSource.close();
            }
            
            eventSource = new EventSource('http://localhost:8080/api/stream/events');
            
            eventSource.onopen = function() {
                log('📡 Server-Sent Events connected', 'success');
                updateConnectionStatus('sse-status', true);
            };
            
            eventSource.onmessage = function(event) {
                try {
                    const data = JSON.parse(event.data);
                    if (data.type === 'connected') {
                        log('📡 SSE connection established with ID: ' + data.connection_id, 'success');
                    } else if (data.type === 'heartbeat') {
                        // Don't log heartbeats
                    } else {
                        log('📨 SSE: ' + JSON.stringify(data).substring(0, 100) + '...', 'info');
                    }
                } catch (e) {
                    log('📨 SSE: ' + event.data.substring(0, 100) + '...', 'info');
                }
            };
            
            eventSource.addEventListener('connected', function(event) {
                log('📡 SSE connection confirmed', 'success');
            });
            
            eventSource.addEventListener('heartbeat', function(event) {
                // Silent heartbeat
            });
            
            eventSource.onerror = function() {
                log('❌ SSE connection error', 'error');
                updateConnectionStatus('sse-status', false);
            };
        }

        function connectThreatStream() {
            if (threatEventSource) {
                threatEventSource.close();
            }
            
            threatEventSource = new EventSource('http://localhost:8080/api/stream/threat/ioc');
            
            threatEventSource.onopen = function() {
                log('🔥 Threat Intelligence stream connected', 'success');
                updateConnectionStatus('threat-status', true);
            };
            
            threatEventSource.onmessage = function(event) {
                try {
                    const data = JSON.parse(event.data);
                    if (data.type === 'subscription_confirmed') {
                        log('🔥 Threat stream subscription confirmed: ' + data.stream_type, 'success');
                    } else {
                        log('🚨 Threat: ' + JSON.stringify(data).substring(0, 100) + '...', 'warning');
                    }
                } catch (e) {
                    log('🚨 Threat: ' + event.data.substring(0, 100) + '...', 'warning');
                }
            };
            
            threatEventSource.onerror = function() {
                log('❌ Threat stream connection error', 'error');
                updateConnectionStatus('threat-status', false);
            };
        }

        function generateIOC() {
            fetch('/demo/generate/ioc', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                log('🎯 Generated sample IOC: ' + data.message, 'success');
            })
            .catch(error => {
                log('❌ IOC generation error: ' + error, 'error');
            });
        }

        function generateCVE() {
            fetch('/demo/generate/cve', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                log('🎯 Generated sample CVE: ' + data.message, 'success');
            })
            .catch(error => {
                log('❌ CVE generation error: ' + error, 'error');
            });
        }

        function generateAlert() {
            fetch('/demo/generate/alert', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                log('🎯 Generated sample alert: ' + data.message, 'success');
            })
            .catch(error => {
                log('❌ Alert generation error: ' + error, 'error');
            });
        }

        function simulateAttack() {
            fetch('/demo/simulate/attack', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                log('⚔️ Security attack simulation started: ' + data.message, 'warning');
            })
            .catch(error => {
                log('❌ Attack simulation error: ' + error, 'error');
            });
        }

        function clearLog() {
            document.getElementById('eventLog').innerHTML = '';
            log('🧹 Event log cleared', 'info');
        }

        function updateMetrics() {
            fetch('/api/stream/status')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('connections').textContent = data.status.connections.total || 0;
                    document.getElementById('messages').textContent = data.status.messages.total || 0;
                    document.getElementById('streams').textContent = data.status.streams.total || 0;
                    document.getElementById('threats').textContent = Math.floor(Math.random() * 50);
                }
            })
            .catch(error => {
                console.error('Metrics update error:', error);
            });
        }

        // Update metrics every 5 seconds
        setInterval(updateMetrics, 5000);
        
        // Initial metrics load
        updateMetrics();
        
        log('🎯 Advanced streaming dashboard loaded - ready for real-time data streaming!', 'success');
        
        // Auto-connect after a short delay
        setTimeout(() => {
            log('🔄 Auto-connecting to all streams...', 'info');
            connectWebSocket();
            connectSSE();
            connectThreatStream();
        }, 2000);
    </script>
</body>
</html>`
}