package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/quantum/assessment"
	"github.com/dimajoyti/hackai/pkg/quantum/cryptography"
	"github.com/dimajoyti/hackai/pkg/quantum/engine"
	"github.com/dimajoyti/hackai/pkg/quantum/integration"
	"github.com/dimajoyti/hackai/pkg/quantum/visualization"
)

// Config holds the application configuration
type Config struct {
	LogLevel        string `json:"log_level"`
	DashboardPort   int    `json:"dashboard_port"`
	DashboardHost   string `json:"dashboard_host"`
	EnableDashboard bool   `json:"enable_dashboard"`
	EnableTLS       bool   `json:"enable_tls"`
	CertFile        string `json:"cert_file"`
	KeyFile         string `json:"key_file"`
	MaxQubits       int    `json:"max_qubits"`
	EnableRealTime  bool   `json:"enable_real_time"`
	ConfigFile      string `json:"config_file"`
}

// QuantumSecuritySystem represents the main quantum security system
type QuantumSecuritySystem struct {
	logger               *logger.Logger
	config               *Config
	quantumSimulator     *engine.QuantumSimulatorImpl
	threatIntel          *assessment.QuantumThreatIntelligence
	vulnerabilityScanner *assessment.QuantumVulnerabilityScanner
	migrationPlanner     *cryptography.QuantumSafeMigrationPlanner
	postQuantumAnalyzer  *cryptography.PostQuantumAnalyzer
	dashboard            *visualization.QuantumDashboard
	langGraphNodes       *integration.QuantumLangGraphNodes
}

func main() {
	// Parse command line flags
	config := parseFlags()

	// Initialize logger
	loggerInstance, err := logger.New(logger.Config{
		Level:  logger.LogLevel(config.LogLevel),
		Format: "json",
	})
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	loggerInstance.Info("Starting Quantum Security System", map[string]interface{}{
		"version":    "1.0.0",
		"log_level":  config.LogLevel,
		"max_qubits": config.MaxQubits,
	})

	// Create the quantum security system
	system, err := NewQuantumSecuritySystem(loggerInstance, config)
	if err != nil {
		loggerInstance.Fatal("Failed to create quantum security system", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the system
	if err := system.Start(ctx); err != nil {
		loggerInstance.Fatal("Failed to start quantum security system", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	loggerInstance.Info("Quantum Security System started successfully", map[string]interface{}{
		"dashboard_enabled": config.EnableDashboard,
		"dashboard_port":    config.DashboardPort,
		"real_time":         config.EnableRealTime,
	})

	// Wait for shutdown signal
	<-sigChan
	loggerInstance.Info("Shutdown signal received, stopping system...", nil)

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := system.Stop(shutdownCtx); err != nil {
		loggerInstance.Error("Error during shutdown", map[string]interface{}{
			"error": err.Error(),
		})
	}

	loggerInstance.Info("Quantum Security System stopped", nil)
}

// parseFlags parses command line flags
func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	flag.IntVar(&config.DashboardPort, "dashboard-port", 8080, "Dashboard port")
	flag.StringVar(&config.DashboardHost, "dashboard-host", "localhost", "Dashboard host")
	flag.BoolVar(&config.EnableDashboard, "enable-dashboard", true, "Enable web dashboard")
	flag.BoolVar(&config.EnableTLS, "enable-tls", false, "Enable TLS for dashboard")
	flag.StringVar(&config.CertFile, "cert-file", "", "TLS certificate file")
	flag.StringVar(&config.KeyFile, "key-file", "", "TLS key file")
	flag.IntVar(&config.MaxQubits, "max-qubits", 20, "Maximum number of qubits for simulation")
	flag.BoolVar(&config.EnableRealTime, "enable-real-time", true, "Enable real-time updates")
	flag.StringVar(&config.ConfigFile, "config", "", "Configuration file path")

	flag.Parse()

	return config
}

// NewQuantumSecuritySystem creates a new quantum security system
func NewQuantumSecuritySystem(logger *logger.Logger, config *Config) (*QuantumSecuritySystem, error) {
	// Initialize quantum simulator
	simulatorConfig := &engine.SimulatorConfig{
		MaxQubits:     config.MaxQubits,
		EnableLogging: true,
		Precision:     1e-10,
	}
	quantumSimulator := engine.NewQuantumSimulator(simulatorConfig, logger)

	// Initialize threat intelligence
	threatIntelConfig := &assessment.ThreatIntelConfig{
		UpdateInterval:  1 * time.Hour,
		CacheExpiry:     24 * time.Hour,
		MaxCacheSize:    1000,
		EnableRealTime:  config.EnableRealTime,
		ThreatThreshold: 0.7,
		AlertingEnabled: true,
	}
	threatIntel := assessment.NewQuantumThreatIntelligence(logger, threatIntelConfig)

	// Initialize vulnerability scanner
	scannerConfig := &assessment.ScannerConfig{
		MaxConcurrentScans: 10,
		ScanTimeout:        30 * time.Minute,
		EnableDeepScan:     true,
		ScanInterval:       24 * time.Hour,
		ReportFormat:       "json",
		IncludeRemediation: true,
	}
	vulnerabilityScanner := assessment.NewQuantumVulnerabilityScanner(logger, scannerConfig)

	// Initialize post-quantum analyzer
	postQuantumConfig := &cryptography.PostQuantumConfig{
		SecurityLevels: map[string]int{
			"NIST_1": 128,
			"NIST_2": 192,
			"NIST_3": 256,
			"NIST_4": 384,
			"NIST_5": 512,
		},
		ThreatHorizon: 20 * 365 * 24 * time.Hour,
		QuantumAdvantage: map[string]float64{
			"LATTICE":      1.0,
			"HASH":         0.5,
			"CODE":         1.0,
			"MULTIVARIATE": 1.0,
		},
		NISTCompliance: true,
	}
	postQuantumAnalyzer := cryptography.NewPostQuantumAnalyzer(logger, postQuantumConfig)

	// Initialize migration planner
	migrationConfig := &cryptography.MigrationConfig{
		ThreatHorizon: 10 * 365 * 24 * time.Hour,
		RiskTolerance: "medium",
		ComplianceRequirements: []string{"NIST", "FIPS"},
		PerformanceRequirements: &cryptography.PerformanceRequirements{
			MaxKeyGenTime:    1 * time.Second,
			MaxSignTime:      100 * time.Millisecond,
			MaxVerifyTime:    50 * time.Millisecond,
			MaxEncryptTime:   100 * time.Millisecond,
			MaxDecryptTime:   100 * time.Millisecond,
			MinThroughput:    1000,
			MaxMemoryUsage:   10 * 1024 * 1024,
			MaxKeySize:       8192,
			MaxSignatureSize: 10240,
		},
	}
	migrationPlanner := cryptography.NewQuantumSafeMigrationPlanner(logger, migrationConfig, postQuantumAnalyzer)

	// Initialize dashboard if enabled
	var dashboard *visualization.QuantumDashboard
	if config.EnableDashboard {
		dashboardConfig := &visualization.DashboardConfig{
			Port:                config.DashboardPort,
			Host:                config.DashboardHost,
			EnableTLS:           config.EnableTLS,
			CertFile:            config.CertFile,
			KeyFile:             config.KeyFile,
			UpdateInterval:      30 * time.Second,
			MaxClients:          100,
			EnableAuthentication: false,
			Theme:               "cyberpunk",
			EnableRealTime:      config.EnableRealTime,
		}
		dashboard = visualization.NewQuantumDashboard(
			logger,
			dashboardConfig,
			threatIntel,
			vulnerabilityScanner,
			migrationPlanner,
		)
	}

	// Initialize LangGraph integration nodes
	langGraphNodes := integration.NewQuantumLangGraphNodes(
		logger,
		quantumSimulator,
		threatIntel,
		vulnerabilityScanner,
		migrationPlanner,
		postQuantumAnalyzer,
	)

	return &QuantumSecuritySystem{
		logger:               logger,
		config:               config,
		quantumSimulator:     quantumSimulator,
		threatIntel:          threatIntel,
		vulnerabilityScanner: vulnerabilityScanner,
		migrationPlanner:     migrationPlanner,
		postQuantumAnalyzer:  postQuantumAnalyzer,
		dashboard:            dashboard,
		langGraphNodes:       langGraphNodes,
	}, nil
}

// Start starts the quantum security system
func (qss *QuantumSecuritySystem) Start(ctx context.Context) error {
	qss.logger.Info("Starting quantum security system components", nil)

	// Start threat intelligence
	if err := qss.threatIntel.Start(ctx); err != nil {
		return fmt.Errorf("failed to start threat intelligence: %w", err)
	}

	// Start dashboard if enabled
	if qss.config.EnableDashboard && qss.dashboard != nil {
		if err := qss.dashboard.Start(ctx); err != nil {
			return fmt.Errorf("failed to start dashboard: %w", err)
		}
	}

	qss.logger.Info("All quantum security system components started successfully", nil)
	return nil
}

// Stop stops the quantum security system
func (qss *QuantumSecuritySystem) Stop(ctx context.Context) error {
	qss.logger.Info("Stopping quantum security system components", nil)

	// Stop threat intelligence
	if err := qss.threatIntel.Stop(); err != nil {
		qss.logger.Error("Failed to stop threat intelligence", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Stop dashboard if enabled
	if qss.config.EnableDashboard && qss.dashboard != nil {
		if err := qss.dashboard.Stop(ctx); err != nil {
			qss.logger.Error("Failed to stop dashboard", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	qss.logger.Info("All quantum security system components stopped", nil)
	return nil
}
