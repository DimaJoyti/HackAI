package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/observability"
)

func main() {
	fmt.Println("🔍 HackAI - Observability & Monitoring Demo")
	fmt.Println("==========================================")

	// Initialize logger
	loggerInstance, err := logger.New(logger.Config{
		Level:      "info",
		Format:     "text",
		Output:     "console",
		AddSource:  false,
		TimeFormat: time.RFC3339,
	})
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// Create observability configuration
	obsConfig := &config.ObservabilityConfig{
		Tracing: config.TracingConfig{
			Enabled:    true,
			Endpoint:   "", // Use stdout for demo
			SampleRate: 1.0,
		},
		Metrics: config.MetricsConfig{
			Enabled: true,
			Port:    "9090",
			Path:    "/metrics",
		},
		Logging: config.LoggingConfig{
			Level:    "info",
			Format:   "text",
			Output:   "console",
			FilePath: "",
		},
	}

	// Initialize observability provider
	serviceName := "hackai-observability-demo"
	serviceVersion := "1.0.0"

	obsProvider, err := observability.NewProvider(obsConfig, serviceName, serviceVersion, loggerInstance)
	if err != nil {
		log.Fatalf("Failed to initialize observability provider: %v", err)
	}
	defer obsProvider.Shutdown(context.Background())

	ctx := context.Background()

	// Demo 1: Distributed Tracing
	fmt.Println("\n📊 Demo 1: Distributed Tracing")
	fmt.Println("------------------------------")
	demoDistributedTracing(ctx, obsProvider)

	// Demo 2: Metrics Collection
	fmt.Println("\n📈 Demo 2: Metrics Collection")
	fmt.Println("-----------------------------")
	demoMetricsCollection(obsProvider)

	// Demo 3: System Monitoring
	fmt.Println("\n🖥️  Demo 3: System Monitoring")
	fmt.Println("-----------------------------")
	demoSystemMonitoring(ctx, obsProvider)

	// Demo 4: Health Checks
	fmt.Println("\n❤️  Demo 4: Health Checks")
	fmt.Println("-------------------------")
	demoHealthChecks(ctx, obsProvider, serviceName, serviceVersion)

	// Demo 5: Alert Management
	fmt.Println("\n🚨 Demo 5: Alert Management")
	fmt.Println("---------------------------")
	demoAlertManagement(ctx, obsProvider)

	// Demo 6: HTTP Observability
	fmt.Println("\n🌐 Demo 6: HTTP Observability")
	fmt.Println("-----------------------------")
	demoHTTPObservability(ctx, obsProvider, serviceName)

	// Demo 7: Database Observability
	fmt.Println("\n🗄️  Demo 7: Database Observability")
	fmt.Println("----------------------------------")
	demoDatabaseObservability(ctx, obsProvider)

	// Demo 8: Security Monitoring
	fmt.Println("\n🛡️  Demo 8: Security Monitoring")
	fmt.Println("-------------------------------")
	demoSecurityMonitoring(obsProvider)

	fmt.Println("\n✅ Observability & Monitoring Demo Completed!")
	fmt.Println("==============================================")
	fmt.Println("\n🎯 Key Observability Features Demonstrated:")
	fmt.Println("  • Distributed tracing with OpenTelemetry")
	fmt.Println("  • Comprehensive metrics with Prometheus")
	fmt.Println("  • System resource monitoring")
	fmt.Println("  • Health checks and readiness probes")
	fmt.Println("  • Alert management and evaluation")
	fmt.Println("  • HTTP request/response observability")
	fmt.Println("  • Database query monitoring")
	fmt.Println("  • Security event tracking")
	fmt.Println("\n🚀 Production-ready observability system!")
}

func demoDistributedTracing(ctx context.Context, obsProvider *observability.Provider) {
	fmt.Println("  📊 Demonstrating distributed tracing...")

	// Simulate a complex operation with multiple spans
	ctx, rootSpan := obsProvider.StartSpan(ctx, "user_registration",
		attribute.String("user.email", "demo@hackai.com"),
		attribute.String("user.type", "new"),
	)
	defer rootSpan.End()

	// Simulate validation step
	ctx, validationSpan := obsProvider.StartSpan(ctx, "validate_user_data",
		attribute.String("validation.type", "email_format"),
	)
	time.Sleep(10 * time.Millisecond) // Simulate processing time
	validationSpan.End()

	// Simulate database operation
	ctx, dbSpan := obsProvider.StartSpan(ctx, "database.insert_user",
		attribute.String("db.operation", "INSERT"),
		attribute.String("db.table", "users"),
	)
	time.Sleep(25 * time.Millisecond) // Simulate database latency
	dbSpan.End()

	// Simulate email sending
	ctx, emailSpan := obsProvider.StartSpan(ctx, "send_welcome_email",
		attribute.String("email.provider", "smtp"),
		attribute.String("email.template", "welcome"),
	)
	time.Sleep(15 * time.Millisecond) // Simulate email sending
	emailSpan.End()

	fmt.Printf("     ✅ Traced user registration flow with %d spans\n", 4)
	fmt.Printf("     📊 Root span: user_registration\n")
	fmt.Printf("     📊 Child spans: validation, database, email\n")
}

func demoMetricsCollection(obsProvider *observability.Provider) {
	fmt.Println("  📈 Demonstrating metrics collection...")

	metrics := obsProvider.Metrics()
	if metrics == nil {
		fmt.Printf("     ❌ Metrics not enabled\n")
		return
	}

	// Simulate HTTP requests
	for i := 0; i < 10; i++ {
		method := "GET"
		path := "/api/v1/users"
		statusCode := "200"
		if i%4 == 0 {
			statusCode = "404"
		}

		duration := time.Duration(rand.Intn(100)+10) * time.Millisecond
		requestSize := int64(rand.Intn(1000) + 100)
		responseSize := int64(rand.Intn(5000) + 500)

		metrics.RecordHTTPRequest(method, path, statusCode, "demo-service", duration, requestSize, responseSize)
	}

	// Simulate authentication attempts
	for i := 0; i < 5; i++ {
		status := "success"
		if i%3 == 0 {
			status = "failure"
		}

		duration := time.Duration(rand.Intn(200)+50) * time.Millisecond
		metrics.RecordAuthAttempt("password", status, "demo-client", duration)
	}

	// Simulate database operations
	for i := 0; i < 8; i++ {
		operation := "SELECT"
		if i%3 == 0 {
			operation = "INSERT"
		}

		table := "users"
		status := "success"
		duration := time.Duration(rand.Intn(50)+5) * time.Millisecond

		metrics.RecordDatabaseQuery(operation, table, status, duration)
	}

	// Set system metrics
	metrics.SetDatabaseConnections(15, 5, 20)
	metrics.SetActiveSessions(42)

	fmt.Printf("     ✅ Recorded 10 HTTP requests\n")
	fmt.Printf("     ✅ Recorded 5 authentication attempts\n")
	fmt.Printf("     ✅ Recorded 8 database queries\n")
	fmt.Printf("     ✅ Set connection and session metrics\n")
}

func demoSystemMonitoring(ctx context.Context, obsProvider *observability.Provider) {
	fmt.Println("  🖥️  Demonstrating system monitoring...")

	// Start system monitoring
	obsProvider.StartSystemMonitoring(ctx, 2*time.Second)

	// Let it run for a few seconds
	time.Sleep(5 * time.Second)

	fmt.Printf("     ✅ System monitoring started\n")
	fmt.Printf("     📊 Collecting memory, CPU, and uptime metrics\n")
	fmt.Printf("     ⏰ Monitoring interval: 2 seconds\n")
}

func demoHealthChecks(ctx context.Context, obsProvider *observability.Provider, serviceName, serviceVersion string) {
	fmt.Println("  ❤️  Demonstrating health checks...")

	healthChecker := observability.NewHealthChecker(obsProvider)

	// Add database health check
	healthChecker.AddCheck("database", func(ctx context.Context) error {
		// Simulate database connectivity check
		time.Sleep(5 * time.Millisecond)
		return nil // Healthy
	})

	// Add external service health check
	healthChecker.AddCheck("external_api", func(ctx context.Context) error {
		// Simulate external API check
		time.Sleep(10 * time.Millisecond)
		if rand.Float32() < 0.8 { // 80% success rate
			return nil
		}
		return fmt.Errorf("external API timeout")
	})

	// Add memory health check
	healthChecker.AddCheck("memory", func(ctx context.Context) error {
		// Simulate memory usage check
		return nil // Always healthy for demo
	})

	// Perform health check
	health := healthChecker.Check(ctx, serviceName, serviceVersion)

	fmt.Printf("     ✅ Health check completed\n")
	fmt.Printf("     📊 Overall status: %s\n", health.Status)
	fmt.Printf("     📊 Service: %s v%s\n", health.Service, health.Version)
	fmt.Printf("     📊 Uptime: %s\n", health.Uptime)
	fmt.Printf("     📊 Checks performed: %d\n", len(health.Checks))

	for name, status := range health.Checks {
		fmt.Printf("       - %s: %s\n", name, status)
	}
}

func demoAlertManagement(ctx context.Context, obsProvider *observability.Provider) {
	fmt.Println("  🚨 Demonstrating alert management...")

	alertManager := observability.NewAlertManager(obsProvider)

	// Add high error rate alert
	alertManager.AddRule(observability.AlertRule{
		Name:        "high_error_rate",
		Description: "Alert when error rate exceeds 10%",
		Condition: func(ctx context.Context) bool {
			// Simulate error rate check
			errorRate := rand.Float64() * 0.2 // 0-20% error rate
			return errorRate > 0.1            // Alert if > 10%
		},
		Action: func(ctx context.Context, rule observability.AlertRule) {
			obsProvider.Logger().Warn("Alert triggered", "rule", rule.Name, "description", rule.Description)
		},
	})

	// Add high memory usage alert
	alertManager.AddRule(observability.AlertRule{
		Name:        "high_memory_usage",
		Description: "Alert when memory usage exceeds 80%",
		Condition: func(ctx context.Context) bool {
			// Simulate memory usage check
			memoryUsage := rand.Float64() * 100 // 0-100% memory usage
			return memoryUsage > 80             // Alert if > 80%
		},
		Action: func(ctx context.Context, rule observability.AlertRule) {
			obsProvider.Logger().Error("Critical alert triggered", "rule", rule.Name, "description", rule.Description)
		},
	})

	// Add database connection alert
	alertManager.AddRule(observability.AlertRule{
		Name:        "database_connections_low",
		Description: "Alert when available database connections are low",
		Condition: func(ctx context.Context) bool {
			// Simulate database connection check
			availableConnections := rand.Intn(10) // 0-9 available connections
			return availableConnections < 3       // Alert if < 3 connections
		},
		Action: func(ctx context.Context, rule observability.AlertRule) {
			obsProvider.Logger().Warn("Database alert triggered", "rule", rule.Name, "description", rule.Description)
		},
	})

	// Evaluate rules multiple times
	fmt.Printf("     ✅ Added 3 alerting rules\n")
	fmt.Printf("     📊 Evaluating rules...\n")

	for i := 0; i < 5; i++ {
		alertManager.EvaluateRules(ctx)
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("     ✅ Alert evaluation completed\n")
}

func demoHTTPObservability(ctx context.Context, obsProvider *observability.Provider, serviceName string) {
	fmt.Println("  🌐 Demonstrating HTTP observability...")

	// Create observability middleware
	middleware := obsProvider.CreateMiddleware(serviceName)

	// Create a simple HTTP handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate processing time
		time.Sleep(time.Duration(rand.Intn(100)+10) * time.Millisecond)

		// Simulate different response codes
		if rand.Float32() < 0.1 { // 10% error rate
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "Internal server error"}`))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message": "Success", "data": {"id": 123, "name": "demo"}}`))
		}
	})

	// Wrap handler with observability middleware
	observableHandler := middleware(handler)

	// Simulate HTTP requests
	fmt.Printf("     ✅ Created HTTP observability middleware\n")
	fmt.Printf("     📊 Simulating HTTP requests...\n")

	for i := 0; i < 5; i++ {
		// Create mock request
		req, _ := http.NewRequestWithContext(ctx, "GET", "/api/v1/demo", nil)
		req.Header.Set("User-Agent", "HackAI-Demo/1.0")

		// Create mock response writer
		w := &mockResponseWriter{header: make(http.Header)}

		// Process request
		observableHandler.ServeHTTP(w, req)

		fmt.Printf("       Request %d: %s %s -> %d\n", i+1, req.Method, req.URL.Path, w.statusCode)
	}

	fmt.Printf("     ✅ HTTP observability demonstration completed\n")
}

func demoDatabaseObservability(ctx context.Context, obsProvider *observability.Provider) {
	fmt.Println("  🗄️  Demonstrating database observability...")

	metrics := obsProvider.Metrics()
	if metrics == nil {
		fmt.Printf("     ❌ Metrics not enabled\n")
		return
	}

	// Simulate various database operations
	operations := []struct {
		operation string
		table     string
		duration  time.Duration
	}{
		{"SELECT", "users", 15 * time.Millisecond},
		{"INSERT", "users", 25 * time.Millisecond},
		{"UPDATE", "users", 20 * time.Millisecond},
		{"SELECT", "sessions", 10 * time.Millisecond},
		{"DELETE", "sessions", 18 * time.Millisecond},
		{"SELECT", "audit_logs", 30 * time.Millisecond},
	}

	fmt.Printf("     ✅ Simulating database operations...\n")

	for i, op := range operations {
		// Start database span
		_, span := obsProvider.StartSpan(ctx, fmt.Sprintf("db.%s", op.operation),
			attribute.String("db.operation", op.operation),
			attribute.String("db.table", op.table),
			attribute.String("db.system", "postgresql"),
		)

		// Simulate query execution time
		time.Sleep(op.duration)

		// Record metrics
		metrics.RecordDatabaseQuery(op.operation, op.table, "success", op.duration)

		span.End()

		fmt.Printf("       Operation %d: %s on %s (%.2fms)\n", i+1, op.operation, op.table, float64(op.duration.Nanoseconds())/1e6)
	}

	// Update connection metrics
	metrics.SetDatabaseConnections(18, 7, 25)

	fmt.Printf("     ✅ Database observability demonstration completed\n")
	fmt.Printf("     📊 Recorded %d database operations\n", len(operations))
	fmt.Printf("     📊 Updated connection pool metrics\n")
}

func demoSecurityMonitoring(obsProvider *observability.Provider) {
	fmt.Println("  🛡️  Demonstrating security monitoring...")

	metrics := obsProvider.Metrics()
	if metrics == nil {
		fmt.Printf("     ❌ Metrics not enabled\n")
		return
	}

	// Simulate security events
	securityEvents := []struct {
		eventType string
		severity  string
		source    string
	}{
		{"login_failure", "medium", "authentication"},
		{"brute_force_attempt", "high", "security"},
		{"suspicious_ip", "high", "network"},
		{"privilege_escalation", "critical", "authorization"},
		{"data_access_violation", "high", "database"},
		{"malware_detected", "critical", "endpoint"},
	}

	fmt.Printf("     ✅ Simulating security events...\n")

	for i, event := range securityEvents {
		metrics.RecordSecurityEvent(event.eventType, event.severity, event.source)
		fmt.Printf("       Event %d: %s (%s severity) from %s\n", i+1, event.eventType, event.severity, event.source)
	}

	// Simulate rate limiting and account lockouts
	for i := 0; i < 3; i++ {
		metrics.RecordRateLimitHit("/api/v1/login", fmt.Sprintf("192.168.1.%d", 100+i))
	}

	metrics.RecordAccountLockout("too_many_failures", "regular_user")
	metrics.RecordAccountLockout("suspicious_activity", "admin_user")

	fmt.Printf("     ✅ Security monitoring demonstration completed\n")
	fmt.Printf("     📊 Recorded %d security events\n", len(securityEvents))
	fmt.Printf("     📊 Recorded 3 rate limit hits\n")
	fmt.Printf("     📊 Recorded 2 account lockouts\n")
}

// mockResponseWriter is a mock implementation of http.ResponseWriter for testing
type mockResponseWriter struct {
	header     http.Header
	statusCode int
	body       []byte
}

func (m *mockResponseWriter) Header() http.Header {
	return m.header
}

func (m *mockResponseWriter) Write(data []byte) (int, error) {
	m.body = append(m.body, data...)
	if m.statusCode == 0 {
		m.statusCode = 200
	}
	return len(data), nil
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {
	m.statusCode = statusCode
}
