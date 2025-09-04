package database

import (
	"context"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/config"
	pkglogger "github.com/dimajoyti/hackai/pkg/logger"
)

// DB wraps gorm.DB with additional functionality
type DB struct {
	*gorm.DB
	config *config.DatabaseConfig
	logger *pkglogger.Logger
}

// New creates a new database connection
func New(cfg *config.DatabaseConfig, log *pkglogger.Logger) (*DB, error) {
	// Configure GORM logger
	gormLogger := logger.New(
		&gormLogWriter{logger: log},
		logger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  false,
		},
	)

	// Open database connection
	db, err := gorm.Open(postgres.Open(cfg.GetDSN()), &gorm.Config{
		Logger:                 gormLogger,
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Get underlying sql.DB
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	// Configure connection pool
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Info("Database connection established successfully")

	return &DB{
		DB:     db,
		config: cfg,
		logger: log,
	}, nil
}

// Migrate runs database migrations using the new migration system
func (db *DB) Migrate() error {
	db.logger.Info("Running database migrations...")

	// Create migration manager
	migrationManager := NewMigrationManager(db.DB, db.logger)

	// Run all pending migrations
	if err := migrationManager.RunMigrations(); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	// Auto-migrate domain models for any new fields (GORM will only add, not remove)
	err := db.AutoMigrate(
		// User management
		&domain.User{},
		&domain.UserSession{},
		&domain.UserPermission{},
		&domain.UserActivity{},

		// Security scanning
		&domain.VulnerabilityScan{},
		&domain.Vulnerability{},
		&domain.NetworkScan{},
		&domain.NetworkHost{},
		&domain.NetworkPort{},

		// Audit and monitoring
		&domain.AuditLog{},
		&domain.SecurityEvent{},
		&domain.ThreatIntelligence{},
		&domain.SystemMetrics{},
		&domain.DataRetentionPolicy{},
		&domain.BackupRecord{},

		// LLM Security
		&domain.LLMRequestLog{},
		&domain.LLMProvider{},
		&domain.LLMModel{},
		&domain.LLMUsageQuota{},

		// Security Policies
		&domain.SecurityPolicy{},
		&domain.PolicyViolation{},
		&domain.PolicyRule{},
		&domain.PolicyTemplate{},
		&domain.PolicyExecution{},

		// Migration tracking
		&Migration{},
	)
	if err != nil {
		return fmt.Errorf("failed to auto-migrate domain models: %w", err)
	}

	db.logger.Info("Database migrations completed successfully")
	return nil
}

// MigrateToVersion migrates to a specific version
func (db *DB) MigrateToVersion(version string) error {
	migrationManager := NewMigrationManager(db.DB, db.logger)
	return migrationManager.RollbackToVersion(version)
}

// GetMigrationStatus returns the current migration status
func (db *DB) GetMigrationStatus() (map[string]interface{}, error) {
	migrationManager := NewMigrationManager(db.DB, db.logger)
	return migrationManager.GetMigrationStatus()
}

// createIndexes creates additional database indexes
func (db *DB) createIndexes() error {
	indexes := []string{
		// User management indexes
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email_active ON users(email) WHERE deleted_at IS NULL",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_username_active ON users(username) WHERE deleted_at IS NULL",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_token_active ON user_sessions(token) WHERE expires_at > NOW()",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_activities_user_created ON user_activities(user_id, created_at DESC)",

		// Security scanning indexes
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerability_scans_user_created ON vulnerability_scans(user_id, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerabilities_scan_severity ON vulnerabilities(scan_id, severity)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_scans_user_created ON network_scans(user_id, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_hosts_scan_ip ON network_hosts(scan_id, ip_address)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_ports_host_port ON network_ports(host_id, port, protocol)",

		// Audit and monitoring indexes
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_user_created ON audit_logs(user_id, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_action_resource ON audit_logs(action, resource)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_ip_created ON audit_logs(ip_address, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_risk_severity ON audit_logs(risk_level, severity)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_tags ON audit_logs USING GIN(tags)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_type_severity ON security_events(type, severity)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_status_created ON security_events(status, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_source_ip ON security_events(source_ip)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_intelligence_value ON threat_intelligence(value)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_intelligence_type_source ON threat_intelligence(type, source)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_intelligence_active ON threat_intelligence(expires_at) WHERE expires_at IS NULL OR expires_at > NOW()",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_system_metrics_timestamp ON system_metrics(timestamp DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_system_metrics_service_metric ON system_metrics(service, metric_name, timestamp DESC)",
	}

	for _, index := range indexes {
		if err := db.Exec(index).Error; err != nil {
			db.logger.Warnf("Failed to create index: %s, error: %v", index, err)
			// Continue with other indexes even if one fails
		}
	}

	return nil
}

// createConstraints creates additional database constraints
func (db *DB) createConstraints() error {
	constraints := []string{
		// User management constraints
		"ALTER TABLE users ADD CONSTRAINT IF NOT EXISTS chk_users_email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$')",
		"ALTER TABLE users ADD CONSTRAINT IF NOT EXISTS chk_users_role CHECK (role IN ('admin', 'moderator', 'user', 'guest'))",
		"ALTER TABLE users ADD CONSTRAINT IF NOT EXISTS chk_users_status CHECK (status IN ('active', 'inactive', 'suspended', 'pending'))",

		// Security scanning constraints
		"ALTER TABLE vulnerability_scans ADD CONSTRAINT IF NOT EXISTS chk_vuln_scans_progress CHECK (progress >= 0 AND progress <= 100)",
		"ALTER TABLE vulnerabilities ADD CONSTRAINT IF NOT EXISTS chk_vulnerabilities_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'))",
		"ALTER TABLE vulnerabilities ADD CONSTRAINT IF NOT EXISTS chk_vulnerabilities_status CHECK (status IN ('open', 'fixed', 'verified', 'ignored', 'false_positive'))",
		"ALTER TABLE network_scans ADD CONSTRAINT IF NOT EXISTS chk_network_scans_progress CHECK (progress >= 0 AND progress <= 100)",
		"ALTER TABLE network_ports ADD CONSTRAINT IF NOT EXISTS chk_network_ports_port CHECK (port >= 1 AND port <= 65535)",
		"ALTER TABLE network_ports ADD CONSTRAINT IF NOT EXISTS chk_network_ports_protocol CHECK (protocol IN ('tcp', 'udp'))",
		"ALTER TABLE network_ports ADD CONSTRAINT IF NOT EXISTS chk_network_ports_state CHECK (state IN ('open', 'closed', 'filtered'))",

		// Audit and monitoring constraints
		"ALTER TABLE audit_logs ADD CONSTRAINT IF NOT EXISTS chk_audit_logs_status CHECK (status IN ('success', 'failure', 'error', 'warning'))",
		"ALTER TABLE audit_logs ADD CONSTRAINT IF NOT EXISTS chk_audit_logs_risk_level CHECK (risk_level IN ('critical', 'high', 'medium', 'low', 'info'))",
		"ALTER TABLE audit_logs ADD CONSTRAINT IF NOT EXISTS chk_audit_logs_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'))",
		"ALTER TABLE security_events ADD CONSTRAINT IF NOT EXISTS chk_security_events_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'))",
		"ALTER TABLE security_events ADD CONSTRAINT IF NOT EXISTS chk_security_events_status CHECK (status IN ('open', 'in_progress', 'resolved', 'closed', 'ignored'))",
		"ALTER TABLE security_events ADD CONSTRAINT IF NOT EXISTS chk_security_events_confidence CHECK (confidence >= 0 AND confidence <= 1)",
		"ALTER TABLE threat_intelligence ADD CONSTRAINT IF NOT EXISTS chk_threat_intel_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'))",
		"ALTER TABLE threat_intelligence ADD CONSTRAINT IF NOT EXISTS chk_threat_intel_confidence CHECK (confidence >= 0 AND confidence <= 1)",
		"ALTER TABLE backup_records ADD CONSTRAINT IF NOT EXISTS chk_backup_records_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled'))",
		"ALTER TABLE backup_records ADD CONSTRAINT IF NOT EXISTS chk_backup_records_type CHECK (type IN ('full', 'incremental', 'differential'))",
		"ALTER TABLE data_retention_policies ADD CONSTRAINT IF NOT EXISTS chk_retention_policies_days CHECK (retention_days > 0)",
	}

	for _, constraint := range constraints {
		if err := db.Exec(constraint).Error; err != nil {
			db.logger.Warnf("Failed to create constraint: %s, error: %v", constraint, err)
			// Continue with other constraints even if one fails
		}
	}

	return nil
}

// Close closes the database connection
func (db *DB) Close() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Health checks database health
func (db *DB) Health(ctx context.Context) error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

// WithContext returns a new DB instance with context
func (db *DB) WithContext(ctx context.Context) *DB {
	return &DB{
		DB:     db.DB.WithContext(ctx),
		config: db.config,
		logger: db.logger.WithContext(ctx),
	}
}

// Transaction executes a function within a database transaction
func (db *DB) Transaction(ctx context.Context, fn func(*DB) error) error {
	return db.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txDB := &DB{
			DB:     tx,
			config: db.config,
			logger: db.logger.WithContext(ctx),
		}
		return fn(txDB)
	})
}

// Stats returns database statistics
func (db *DB) Stats() (map[string]interface{}, error) {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return nil, err
	}

	stats := sqlDB.Stats()
	return map[string]interface{}{
		"max_open_connections": stats.MaxOpenConnections,
		"open_connections":     stats.OpenConnections,
		"in_use":               stats.InUse,
		"idle":                 stats.Idle,
		"wait_count":           stats.WaitCount,
		"wait_duration":        stats.WaitDuration.String(),
		"max_idle_closed":      stats.MaxIdleClosed,
		"max_idle_time_closed": stats.MaxIdleTimeClosed,
		"max_lifetime_closed":  stats.MaxLifetimeClosed,
	}, nil
}

// Seed creates initial data for development/testing
func (db *DB) Seed() error {
	db.logger.Info("Seeding database with initial data...")

	// Create admin user
	adminUser := &domain.User{
		Email:     "admin@hackai.dev",
		Username:  "admin",
		Password:  "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj8xLRw5RQjC", // password: admin123
		FirstName: "Admin",
		LastName:  "User",
		Role:      domain.UserRoleAdmin,
		Status:    domain.UserStatusActive,
	}

	// Check if admin user already exists
	var existingUser domain.User
	if err := db.Where("email = ?", adminUser.Email).First(&existingUser).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			if err := db.Create(adminUser).Error; err != nil {
				return fmt.Errorf("failed to create admin user: %w", err)
			}
			db.logger.Info("Admin user created successfully")
		} else {
			return fmt.Errorf("failed to check for existing admin user: %w", err)
		}
	} else {
		db.logger.Info("Admin user already exists")
	}

	// Create demo user
	demoUser := &domain.User{
		Email:     "demo@hackai.dev",
		Username:  "demo",
		Password:  "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj8xLRw5RQjC", // password: demo123
		FirstName: "Demo",
		LastName:  "User",
		Role:      domain.UserRoleUser,
		Status:    domain.UserStatusActive,
	}

	// Check if demo user already exists
	if err := db.Where("email = ?", demoUser.Email).First(&existingUser).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			if err := db.Create(demoUser).Error; err != nil {
				return fmt.Errorf("failed to create demo user: %w", err)
			}
			db.logger.Info("Demo user created successfully")
		} else {
			return fmt.Errorf("failed to check for existing demo user: %w", err)
		}
	} else {
		db.logger.Info("Demo user already exists")
	}

	db.logger.Info("Database seeding completed successfully")
	return nil
}

// gormLogWriter implements GORM's logger interface
type gormLogWriter struct {
	logger *pkglogger.Logger
}

func (w *gormLogWriter) Printf(format string, args ...interface{}) {
	w.logger.Infof(format, args...)
}
