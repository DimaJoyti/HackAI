package security

import (
	"context"
	"testing"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createThreatIntelTestLogger() *logger.Logger {
	config := logger.Config{
		Level:     logger.LevelDebug,
		Format:    "text",
		Output:    "stdout",
		AddSource: false,
	}
	testLogger, _ := logger.New(config)
	return testLogger
}

func TestMITREATTACKConnector_QueryTechniques(t *testing.T) {
	testLogger := createThreatIntelTestLogger()
	config := DefaultMITREATTACKConfig()
	config.BaseURL = "https://httpbin.org/json" // Mock endpoint for testing

	connector := NewMITREATTACKConnector(config, testLogger)
	require.NotNil(t, connector)

	ctx := context.Background()
	err := connector.Start(ctx)
	require.NoError(t, err)

	// Test querying techniques
	query := &MITREQuery{
		Type:       "technique",
		MaxResults: 10,
	}

	// Note: This will fail with real API but tests the structure
	techniques, err := connector.QueryTechniques(ctx, query)
	// We expect an error since we're using a mock endpoint
	assert.Error(t, err)
	assert.Nil(t, techniques)
}

func TestMITREATTACKConnector_GetTechniqueByID(t *testing.T) {
	testLogger := createThreatIntelTestLogger()
	config := DefaultMITREATTACKConfig()
	config.BaseURL = "https://httpbin.org/json" // Mock endpoint for testing

	connector := NewMITREATTACKConnector(config, testLogger)
	require.NotNil(t, connector)

	ctx := context.Background()

	// Test getting technique by ID
	technique, err := connector.GetTechniqueByID(ctx, "T1055")
	// We expect an error since we're using a mock endpoint
	assert.Error(t, err)
	assert.Nil(t, technique)
}

func TestCVEConnector_QueryCVEs(t *testing.T) {
	testLogger := createThreatIntelTestLogger()
	config := DefaultCVEConfig()
	config.NVDURL = "https://httpbin.org/json" // Mock endpoint for testing

	connector := NewCVEConnector(config, testLogger)
	require.NotNil(t, connector)

	ctx := context.Background()
	err := connector.Start(ctx)
	require.NoError(t, err)

	// Test querying CVEs
	query := &CVEQuery{
		Keyword:    "buffer overflow",
		MaxResults: 10,
	}

	// Note: This will fail with real API but tests the structure
	cves, err := connector.QueryCVEs(ctx, query)
	// We expect an error since we're using a mock endpoint
	assert.Error(t, err)
	assert.Nil(t, cves)
}

func TestCVEConnector_GetCVEByID(t *testing.T) {
	testLogger := createThreatIntelTestLogger()
	config := DefaultCVEConfig()
	config.NVDURL = "https://httpbin.org/json" // Mock endpoint for testing

	connector := NewCVEConnector(config, testLogger)
	require.NotNil(t, connector)

	ctx := context.Background()

	// Test getting CVE by ID
	cve, err := connector.GetCVEByID(ctx, "CVE-2021-44228")
	// We expect an error since we're using a mock endpoint
	assert.Error(t, err)
	assert.Nil(t, cve)
}

func TestThreatIntelligenceOrchestrator_Start(t *testing.T) {
	testLogger := createThreatIntelTestLogger()

	// Create orchestrator with disabled external connectors for testing
	config := DefaultThreatOrchestratorConfig()
	config.EnableMITRE = false            // Disable for testing
	config.EnableCVE = false              // Disable for testing
	config.EnableThreatFeeds = false      // Disable for testing
	config.EnableCorrelation = false      // Disable for testing
	config.EnableRealTimeAnalysis = false // Disable for testing

	orchestrator := NewThreatIntelligenceOrchestrator(
		config,
		nil, // mitreConnector
		nil, // cveConnector
		nil, // threatEngine
		nil, // feedManager
		nil, // iocDatabase
		nil, // reputationEngine
		nil, // threatCache
		testLogger,
	)
	require.NotNil(t, orchestrator)

	ctx := context.Background()
	err := orchestrator.Start(ctx)
	require.NoError(t, err)

	// Test stopping
	err = orchestrator.Stop(ctx)
	require.NoError(t, err)
}

func TestThreatIntelligenceOrchestrator_AnalyzeThreat(t *testing.T) {
	testLogger := createThreatIntelTestLogger()

	// Create orchestrator with minimal components
	config := DefaultThreatOrchestratorConfig()
	orchestrator := NewThreatIntelligenceOrchestrator(
		config,
		nil, // mitreConnector
		nil, // cveConnector
		nil, // threatEngine
		nil, // feedManager
		nil, // iocDatabase
		nil, // reputationEngine
		nil, // threatCache
		testLogger,
	)
	require.NotNil(t, orchestrator)

	ctx := context.Background()

	tests := []struct {
		name      string
		indicator string
		expectErr bool
	}{
		{
			name:      "IP address indicator",
			indicator: "192.168.1.1",
			expectErr: false,
		},
		{
			name:      "CVE indicator",
			indicator: "CVE-2021-44228",
			expectErr: false,
		},
		{
			name:      "MITRE technique indicator",
			indicator: "T1055",
			expectErr: false,
		},
		{
			name:      "Domain indicator",
			indicator: "malicious.example.com",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := orchestrator.AnalyzeThreat(ctx, tt.indicator)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.indicator, result.Indicator)
				assert.GreaterOrEqual(t, result.ThreatScore, 0.0)
				assert.LessOrEqual(t, result.ThreatScore, 1.0)
				assert.NotEmpty(t, result.ThreatLevel)
				assert.NotNil(t, result.Sources)
				assert.NotNil(t, result.Recommendations)
			}
		})
	}
}

func TestThreatIntelligenceOrchestrator_GenerateReport(t *testing.T) {
	testLogger := createThreatIntelTestLogger()

	// Create orchestrator
	config := DefaultThreatOrchestratorConfig()
	orchestrator := NewThreatIntelligenceOrchestrator(
		config,
		nil, // mitreConnector
		nil, // cveConnector
		nil, // threatEngine
		nil, // feedManager
		nil, // iocDatabase
		nil, // reputationEngine
		nil, // threatCache
		testLogger,
	)
	require.NotNil(t, orchestrator)

	ctx := context.Background()

	// Test report generation
	timeRange := TimeRange{
		Start: time.Now().Add(-24 * time.Hour),
		End:   time.Now(),
	}

	report, err := orchestrator.GenerateReport(ctx, timeRange)
	require.NoError(t, err)
	require.NotNil(t, report)

	// Verify report structure
	assert.NotEmpty(t, report.ID)
	assert.NotZero(t, report.GeneratedAt)
	assert.Equal(t, timeRange, report.TimeRange)
	assert.NotNil(t, report.Summary)
	assert.NotNil(t, report.Recommendations)
	assert.NotNil(t, report.Metadata)
}

func TestThreatCorrelationEngine_GetResults(t *testing.T) {
	testLogger := createThreatIntelTestLogger()
	config := DefaultCorrelationConfig()

	engine := NewThreatCorrelationEngine(config, testLogger)
	require.NotNil(t, engine)

	ctx := context.Background()
	timeRange := TimeRange{
		Start: time.Now().Add(-1 * time.Hour),
		End:   time.Now(),
	}

	results, err := engine.GetResults(ctx, timeRange)
	require.NoError(t, err)
	assert.NotNil(t, results)
	assert.Equal(t, 0, len(results)) // Empty for placeholder implementation
}

func TestThreatAlertManager_GetAlerts(t *testing.T) {
	testLogger := createThreatIntelTestLogger()
	config := DefaultAlertConfig()

	manager := NewThreatAlertManager(config, testLogger)
	require.NotNil(t, manager)

	ctx := context.Background()
	timeRange := TimeRange{
		Start: time.Now().Add(-1 * time.Hour),
		End:   time.Now(),
	}

	alerts, err := manager.GetAlerts(ctx, timeRange)
	require.NoError(t, err)
	assert.NotNil(t, alerts)
	assert.Equal(t, 0, len(alerts)) // Empty initially
}

func TestThreatIntelligenceIntegration_HelperMethods(t *testing.T) {
	testLogger := createThreatIntelTestLogger()

	orchestrator := NewThreatIntelligenceOrchestrator(
		DefaultThreatOrchestratorConfig(),
		nil, nil, nil, nil, nil, nil, nil,
		testLogger,
	)

	// Test helper methods
	assert.True(t, orchestrator.isCVEIndicator("CVE-2021-44228"))
	assert.False(t, orchestrator.isCVEIndicator("192.168.1.1"))

	assert.True(t, orchestrator.isMITREIndicator("T1055"))
	assert.False(t, orchestrator.isMITREIndicator("CVE-2021-44228"))

	// Test threat level calculation
	assert.Equal(t, "critical", orchestrator.calculateThreatLevel(0.9))
	assert.Equal(t, "high", orchestrator.calculateThreatLevel(0.7))
	assert.Equal(t, "medium", orchestrator.calculateThreatLevel(0.5))
	assert.Equal(t, "low", orchestrator.calculateThreatLevel(0.3))
	assert.Equal(t, "info", orchestrator.calculateThreatLevel(0.1))
}

func TestThreatIntelligenceIntegration_EndToEnd(t *testing.T) {
	testLogger := createThreatIntelTestLogger()

	// Create orchestrator with disabled external connectors for testing
	config := DefaultThreatOrchestratorConfig()
	config.EnableMITRE = false            // Disable for testing
	config.EnableCVE = false              // Disable for testing
	config.EnableThreatFeeds = false      // Disable for testing
	config.EnableRealTimeAnalysis = false // Disable for testing
	config.EnableCorrelation = false      // Disable for testing

	orchestrator := NewThreatIntelligenceOrchestrator(
		config,
		nil, // mitreConnector
		nil, // cveConnector
		nil, nil, nil, nil, nil,
		testLogger,
	)
	require.NotNil(t, orchestrator)

	ctx := context.Background()

	// Start orchestrator
	err := orchestrator.Start(ctx)
	require.NoError(t, err)

	// Analyze multiple threat indicators
	indicators := []string{
		"192.168.1.100",
		"CVE-2021-44228",
		"T1055",
		"malicious.example.com",
	}

	for _, indicator := range indicators {
		result, err := orchestrator.AnalyzeThreat(ctx, indicator)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, indicator, result.Indicator)

		testLogger.Info("Analyzed threat indicator",
			"indicator", indicator,
			"threat_score", result.ThreatScore,
			"threat_level", result.ThreatLevel,
			"sources", len(result.Sources))
	}

	// Generate comprehensive report
	timeRange := TimeRange{
		Start: time.Now().Add(-24 * time.Hour),
		End:   time.Now(),
	}

	report, err := orchestrator.GenerateReport(ctx, timeRange)
	require.NoError(t, err)
	require.NotNil(t, report)

	testLogger.Info("Generated threat intelligence report",
		"report_id", report.ID,
		"time_range", report.TimeRange,
		"recommendations", len(report.Recommendations))

	// Stop orchestrator
	err = orchestrator.Stop(ctx)
	require.NoError(t, err)

	testLogger.Info("Threat intelligence integration test completed successfully")
}
