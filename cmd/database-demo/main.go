package main

import (
	"context"
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
	fmt.Println("🗄️  HackAI - Database & Storage Layer Demo")
	fmt.Println("==========================================")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

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

	// Initialize database
	db, err := database.New(&cfg.Database, loggerInstance)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Initialize storage manager
	storageManager := database.NewStorageManager(db, loggerInstance)

	// Initialize repositories
	auditRepo := repository.NewAuditRepository(db.DB, loggerInstance)

	// Initialize use cases
	dbManager := usecase.NewDatabaseManagerUseCase(db, storageManager, auditRepo, loggerInstance)

	ctx := context.Background()
	userID := uuid.New()

	// Demo 1: Database Health and Statistics
	fmt.Println("\n📊 Demo 1: Database Health & Statistics")
	fmt.Println("--------------------------------------")
	demoDatabaseHealth(ctx, dbManager)

	// Demo 2: Audit Logging System
	fmt.Println("\n📝 Demo 2: Comprehensive Audit Logging")
	fmt.Println("-------------------------------------")
	demoAuditLogging(ctx, auditRepo, userID)

	// Demo 3: Security Event Management
	fmt.Println("\n🚨 Demo 3: Security Event Management")
	fmt.Println("-----------------------------------")
	demoSecurityEvents(ctx, dbManager, auditRepo)

	// Demo 4: Threat Intelligence Storage
	fmt.Println("\n🛡️  Demo 4: Threat Intelligence Storage")
	fmt.Println("--------------------------------------")
	demoThreatIntelligence(ctx, auditRepo)

	// Demo 5: Data Retention & Archival
	fmt.Println("\n🗂️  Demo 5: Data Retention & Archival")
	fmt.Println("------------------------------------")
	demoDataRetention(ctx, dbManager, userID)

	// Demo 6: Backup Management
	fmt.Println("\n💾 Demo 6: Backup Management")
	fmt.Println("---------------------------")
	demoBackupManagement(ctx, dbManager, userID)

	// Demo 7: System Metrics Collection
	fmt.Println("\n📈 Demo 7: System Metrics Collection")
	fmt.Println("-----------------------------------")
	demoSystemMetrics(ctx, dbManager)

	// Demo 8: Storage Optimization
	fmt.Println("\n⚡ Demo 8: Storage Optimization")
	fmt.Println("------------------------------")
	demoStorageOptimization(ctx, storageManager)

	fmt.Println("\n✅ Database & Storage Layer Demo Completed!")
	fmt.Println("===========================================")
	fmt.Println("\n🎯 Key Features Demonstrated:")
	fmt.Println("  • Comprehensive audit logging with full traceability")
	fmt.Println("  • Advanced security event management and correlation")
	fmt.Println("  • Intelligent threat intelligence storage and retrieval")
	fmt.Println("  • Automated data retention and archival policies")
	fmt.Println("  • Enterprise-grade backup and recovery systems")
	fmt.Println("  • Real-time system metrics collection and analysis")
	fmt.Println("  • Database optimization and performance monitoring")
	fmt.Println("  • Scalable storage management with automated cleanup")
	fmt.Println("\n🚀 Production-ready database layer with enterprise features!")
}

func demoDatabaseHealth(ctx context.Context, dbManager *usecase.DatabaseManagerUseCase) {
	fmt.Println("  🔍 Checking database health and performance...")

	health, err := dbManager.GetDatabaseHealth(ctx)
	if err != nil {
		fmt.Printf("     ❌ Error: %v\n", err)
		return
	}

	fmt.Printf("     ✅ Database Status: %s\n", health["status"])

	if connStats, ok := health["connection_stats"]; ok {
		fmt.Printf("     📊 Connection Statistics:\n")
		if stats, ok := connStats.(map[string]interface{}); ok {
			for key, value := range stats {
				fmt.Printf("       - %s: %v\n", key, value)
			}
		}
	}

	if storageStats, ok := health["storage_stats"]; ok {
		fmt.Printf("     💾 Storage Statistics:\n")
		if stats, ok := storageStats.(map[string]interface{}); ok {
			if dbSize, ok := stats["database_size"]; ok {
				fmt.Printf("       - Database Size: %s\n", dbSize)
			}
			if tableSizes, ok := stats["table_sizes"].(map[string]interface{}); ok {
				fmt.Printf("       - Table Count: %d\n", len(tableSizes))
			}
		}
	}

	if performance, ok := health["performance"]; ok {
		fmt.Printf("     ⚡ Performance Metrics:\n")
		if perf, ok := performance.(map[string]interface{}); ok {
			if cacheHit, ok := perf["cache_hit_ratio"]; ok {
				fmt.Printf("       - Cache Hit Ratio: %.2f%%\n", cacheHit)
			}
		}
	}
}

func demoAuditLogging(ctx context.Context, auditRepo domain.AuditRepository, userID uuid.UUID) {
	fmt.Println("  📝 Creating comprehensive audit logs...")

	// Create various types of audit logs
	auditLogs := []struct {
		action   string
		resource string
		risk     domain.RiskLevel
		details  map[string]interface{}
	}{
		{"user_login", "authentication", domain.RiskLevelLow, map[string]interface{}{"ip": "192.168.1.100", "success": true}},
		{"admin_access", "admin_panel", domain.RiskLevelHigh, map[string]interface{}{"action": "user_management", "target": "user_123"}},
		{"data_export", "user_data", domain.RiskLevelMedium, map[string]interface{}{"records": 1000, "format": "csv"}},
		{"security_scan", "vulnerability_scanner", domain.RiskLevelLow, map[string]interface{}{"target": "https://example.com", "findings": 5}},
		{"failed_login", "authentication", domain.RiskLevelMedium, map[string]interface{}{"ip": "10.0.0.1", "attempts": 3}},
	}

	for i, logData := range auditLogs {
		if err := auditRepo.LogSecurityAction(&userID, logData.action, logData.resource, logData.risk, logData.details); err != nil {
			fmt.Printf("     ❌ Failed to create audit log %d: %v\n", i+1, err)
			continue
		}
		fmt.Printf("     ✅ Created audit log: %s on %s (Risk: %s)\n", logData.action, logData.resource, logData.risk)
	}

	// Search audit logs
	fmt.Println("  🔍 Searching audit logs...")
	logs, err := auditRepo.SearchAuditLogs("login", map[string]interface{}{
		"risk_level": domain.RiskLevelMedium,
	}, 10, 0)
	if err != nil {
		fmt.Printf("     ❌ Failed to search audit logs: %v\n", err)
	} else {
		fmt.Printf("     📊 Found %d audit logs matching search criteria\n", len(logs))
	}
}

func demoSecurityEvents(ctx context.Context, dbManager *usecase.DatabaseManagerUseCase, auditRepo domain.AuditRepository) {
	fmt.Println("  🚨 Creating and managing security events...")

	// Create security events
	events := []*domain.SecurityEvent{
		{
			Type:        "brute_force_attack",
			Category:    "authentication",
			Title:       "Brute Force Attack Detected",
			Description: "Multiple failed login attempts from single IP",
			Severity:    domain.SeverityHigh,
			Status:      domain.EventStatusOpen,
			SourceIP:    "192.168.1.100",
			TargetIP:    "10.0.0.1",
			DetectedBy:  "AI Security System",
			Confidence:  0.95,
		},
		{
			Type:        "sql_injection",
			Category:    "web_attack",
			Title:       "SQL Injection Attempt",
			Description: "Malicious SQL injection detected in web request",
			Severity:    domain.SeverityCritical,
			Status:      domain.EventStatusOpen,
			SourceIP:    "203.0.113.1",
			TargetIP:    "10.0.0.2",
			DetectedBy:  "Web Application Firewall",
			Confidence:  0.88,
		},
		{
			Type:        "malware_detection",
			Category:    "malware",
			Title:       "Malware Detected",
			Description: "Suspicious file behavior detected",
			Severity:    domain.SeverityMedium,
			Status:      domain.EventStatusInProgress,
			DetectedBy:  "Endpoint Protection",
			Confidence:  0.75,
		},
	}

	for i, event := range events {
		if err := dbManager.CreateSecurityEvent(ctx, event); err != nil {
			fmt.Printf("     ❌ Failed to create security event %d: %v\n", i+1, err)
			continue
		}
		fmt.Printf("     ✅ Created security event: %s (Severity: %s, Confidence: %.0f%%)\n",
			event.Type, event.Severity, event.Confidence*100)
	}

	// List security events
	fmt.Println("  📊 Retrieving security events...")
	retrievedEvents, err := dbManager.GetSecurityEvents(ctx, map[string]interface{}{
		"severity": domain.SeverityHigh,
	}, 10, 0)
	if err != nil {
		fmt.Printf("     ❌ Failed to retrieve security events: %v\n", err)
	} else {
		fmt.Printf("     📈 Found %d high-severity security events\n", len(retrievedEvents))
	}
}

func demoThreatIntelligence(ctx context.Context, auditRepo domain.AuditRepository) {
	fmt.Println("  🛡️  Storing and managing threat intelligence...")

	// Create threat intelligence records
	threats := []*domain.ThreatIntelligence{
		{
			Type:        "ip",
			Value:       "192.168.1.100",
			Source:      "Internal Analysis",
			Confidence:  0.9,
			Severity:    domain.SeverityHigh,
			ThreatType:  "botnet",
			Description: "Known botnet command and control server",
			Tags:        []string{"botnet", "c2", "malware"},
			FirstSeen:   time.Now().Add(-24 * time.Hour),
			LastSeen:    time.Now(),
		},
		{
			Type:        "domain",
			Value:       "malicious-site.com",
			Source:      "Threat Feed",
			Confidence:  0.85,
			Severity:    domain.SeverityCritical,
			ThreatType:  "phishing",
			Description: "Phishing domain targeting financial institutions",
			Tags:        []string{"phishing", "financial", "credential_theft"},
			FirstSeen:   time.Now().Add(-48 * time.Hour),
			LastSeen:    time.Now().Add(-6 * time.Hour),
		},
		{
			Type:        "hash",
			Value:       "d41d8cd98f00b204e9800998ecf8427e",
			Source:      "Malware Analysis",
			Confidence:  0.95,
			Severity:    domain.SeverityMedium,
			ThreatType:  "trojan",
			Description: "Banking trojan with keylogging capabilities",
			Tags:        []string{"trojan", "banking", "keylogger"},
			FirstSeen:   time.Now().Add(-72 * time.Hour),
			LastSeen:    time.Now().Add(-12 * time.Hour),
		},
	}

	for i, threat := range threats {
		if err := auditRepo.CreateThreatIntelligence(threat); err != nil {
			fmt.Printf("     ❌ Failed to create threat intelligence %d: %v\n", i+1, err)
			continue
		}
		fmt.Printf("     ✅ Stored threat intel: %s (%s) - %s (Confidence: %.0f%%)\n",
			threat.Type, threat.Value, threat.ThreatType, threat.Confidence*100)
	}

	// Search threat intelligence
	fmt.Println("  🔍 Searching threat intelligence...")
	intel, err := auditRepo.ListThreatIntelligence(map[string]interface{}{
		"threat_type": "phishing",
		"active_only": true,
	}, 10, 0)
	if err != nil {
		fmt.Printf("     ❌ Failed to search threat intelligence: %v\n", err)
	} else {
		fmt.Printf("     📊 Found %d active phishing threats\n", len(intel))
	}
}

func demoDataRetention(ctx context.Context, dbManager *usecase.DatabaseManagerUseCase, userID uuid.UUID) {
	fmt.Println("  🗂️  Managing data retention policies...")

	// Create retention policies
	policies := []*domain.DataRetentionPolicy{
		{
			Name:          "Audit Log Retention",
			Description:   "Retain audit logs for 90 days",
			DataType:      "audit_logs",
			RetentionDays: 90,
			ArchiveDays:   30,
			Enabled:       true,
		},
		{
			Name:          "Security Event Retention",
			Description:   "Retain security events for 365 days",
			DataType:      "security_events",
			RetentionDays: 365,
			ArchiveDays:   90,
			Enabled:       true,
		},
		{
			Name:          "System Metrics Retention",
			Description:   "Retain system metrics for 30 days",
			DataType:      "system_metrics",
			RetentionDays: 30,
			ArchiveDays:   7,
			Enabled:       true,
		},
	}

	for i, policy := range policies {
		if err := dbManager.CreateRetentionPolicy(ctx, userID, policy); err != nil {
			fmt.Printf("     ❌ Failed to create retention policy %d: %v\n", i+1, err)
			continue
		}
		fmt.Printf("     ✅ Created retention policy: %s (%d days)\n", policy.Name, policy.RetentionDays)
	}

	// List retention policies
	fmt.Println("  📊 Listing retention policies...")
	retrievedPolicies, err := dbManager.ListRetentionPolicies(ctx, 10, 0)
	if err != nil {
		fmt.Printf("     ❌ Failed to list retention policies: %v\n", err)
	} else {
		fmt.Printf("     📈 Found %d retention policies\n", len(retrievedPolicies))
	}

	// Trigger data archival
	fmt.Println("  🗄️  Triggering data archival...")
	if err := dbManager.ArchiveOldData(ctx, userID); err != nil {
		fmt.Printf("     ❌ Failed to archive data: %v\n", err)
	} else {
		fmt.Printf("     ✅ Data archival completed successfully\n")
	}
}

func demoBackupManagement(ctx context.Context, dbManager *usecase.DatabaseManagerUseCase, userID uuid.UUID) {
	fmt.Println("  💾 Creating and managing database backups...")

	// Create different types of backups
	backupTypes := []string{"full", "incremental", "differential"}

	for _, backupType := range backupTypes {
		backup, err := dbManager.CreateBackup(ctx, backupType, userID)
		if err != nil {
			fmt.Printf("     ❌ Failed to create %s backup: %v\n", backupType, err)
			continue
		}
		fmt.Printf("     ✅ Created %s backup (ID: %s)\n", backupType, backup.ID.String()[:8])
	}

	// Wait a moment for backups to process
	time.Sleep(2 * time.Second)

	// List backups
	fmt.Println("  📊 Listing database backups...")
	backups, err := dbManager.ListBackups(ctx, 10, 0)
	if err != nil {
		fmt.Printf("     ❌ Failed to list backups: %v\n", err)
	} else {
		fmt.Printf("     📈 Found %d database backups\n", len(backups))
		for _, backup := range backups {
			status := "In Progress"
			if backup.IsCompleted() {
				status = "Completed"
			}
			fmt.Printf("       - %s backup: %s (Status: %s)\n", backup.Type, backup.ID.String()[:8], status)
		}
	}
}

func demoSystemMetrics(ctx context.Context, dbManager *usecase.DatabaseManagerUseCase) {
	fmt.Println("  📈 Collecting and storing system metrics...")

	// Create sample system metrics
	metrics := []*domain.SystemMetrics{
		{
			MetricType:  "database",
			MetricName:  "connections_active",
			Value:       15.0,
			Unit:        "count",
			Service:     "database-service",
			Instance:    "db-01",
			Environment: "production",
			Timestamp:   time.Now(),
		},
		{
			MetricType:  "database",
			MetricName:  "query_duration_avg",
			Value:       32.5,
			Unit:        "milliseconds",
			Service:     "database-service",
			Instance:    "db-01",
			Environment: "production",
			Timestamp:   time.Now(),
		},
		{
			MetricType:  "system",
			MetricName:  "memory_usage",
			Value:       68.7,
			Unit:        "percent",
			Service:     "database-service",
			Instance:    "db-01",
			Environment: "production",
			Timestamp:   time.Now(),
		},
		{
			MetricType:  "system",
			MetricName:  "disk_usage",
			Value:       45.2,
			Unit:        "percent",
			Service:     "database-service",
			Instance:    "db-01",
			Environment: "production",
			Timestamp:   time.Now(),
		},
	}

	if err := dbManager.RecordSystemMetrics(ctx, metrics); err != nil {
		fmt.Printf("     ❌ Failed to record system metrics: %v\n", err)
	} else {
		fmt.Printf("     ✅ Recorded %d system metrics\n", len(metrics))
	}

	// Retrieve metrics
	fmt.Println("  📊 Retrieving system metrics...")
	from := time.Now().Add(-1 * time.Hour)
	to := time.Now()

	retrievedMetrics, err := dbManager.GetSystemMetrics(ctx, map[string]interface{}{
		"service": "database-service",
	}, from, to)
	if err != nil {
		fmt.Printf("     ❌ Failed to retrieve system metrics: %v\n", err)
	} else {
		fmt.Printf("     📈 Retrieved %d system metrics from last hour\n", len(retrievedMetrics))
		for _, metric := range retrievedMetrics {
			fmt.Printf("       - %s.%s: %.1f %s\n", metric.MetricType, metric.MetricName, metric.Value, metric.Unit)
		}
	}
}

func demoStorageOptimization(ctx context.Context, storageManager *database.StorageManager) {
	fmt.Println("  ⚡ Performing storage optimization...")

	// Get storage statistics before optimization
	fmt.Println("  📊 Getting storage statistics...")
	stats, err := storageManager.GetStorageStatistics(ctx)
	if err != nil {
		fmt.Printf("     ❌ Failed to get storage statistics: %v\n", err)
	} else {
		if dbSize, ok := stats["database_size"]; ok {
			fmt.Printf("     💾 Current database size: %s\n", dbSize)
		}
		if tableSizes, ok := stats["table_sizes"].(map[string]interface{}); ok {
			fmt.Printf("     📊 Number of tables: %d\n", len(tableSizes))
		}
	}

	// Perform database optimization
	fmt.Println("  🔧 Running database optimization...")
	if err := storageManager.OptimizeDatabase(ctx); err != nil {
		fmt.Printf("     ❌ Failed to optimize database: %v\n", err)
	} else {
		fmt.Printf("     ✅ Database optimization completed\n")
	}

	// Perform maintenance tasks
	fmt.Println("  🧹 Running maintenance tasks...")
	if err := storageManager.PerformMaintenance(ctx); err != nil {
		fmt.Printf("     ❌ Failed to perform maintenance: %v\n", err)
	} else {
		fmt.Printf("     ✅ Maintenance tasks completed\n")
	}
}
