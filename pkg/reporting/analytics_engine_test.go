package reporting

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestAnalyticsLogger() *logger.Logger {
	config := logger.Config{
		Level:     logger.LevelDebug,
		Format:    "text",
		Output:    "stdout",
		AddSource: false,
	}
	testLogger, _ := logger.New(config)
	return testLogger
}

func TestAnalyticsEngine_Start_Stop(t *testing.T) {
	logger := createTestAnalyticsLogger()
	config := DefaultAnalyticsConfig()
	config.EnableScheduling = false       // Disable for testing
	config.EnableRealTimeAnalysis = false // Disable for testing
	ae := NewAnalyticsEngine(config, logger)

	ctx := context.Background()

	// Test start
	err := ae.Start(ctx)
	require.NoError(t, err)

	// Test double start (should fail)
	err = ae.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")

	// Test stop
	err = ae.Stop(ctx)
	require.NoError(t, err)

	// Test double stop (should not fail)
	err = ae.Stop(ctx)
	require.NoError(t, err)
}

func TestAnalyticsEngine_GenerateReport(t *testing.T) {
	logger := createTestAnalyticsLogger()
	config := DefaultAnalyticsConfig()
	config.EnableScheduling = false
	config.EnableRealTimeAnalysis = false
	ae := NewAnalyticsEngine(config, logger)

	ctx := context.Background()
	err := ae.Start(ctx)
	require.NoError(t, err)

	// Register mock data collector
	mockCollector := &MockDataCollector{}
	ae.RegisterDataCollector("test-collector", mockCollector)

	// Generate report using security template
	params := map[string]interface{}{
		"time_range":          "7d",
		"include_predictions": true,
	}

	report, err := ae.GenerateReport(ctx, "security-analytics", params)
	require.NoError(t, err)
	assert.NotNil(t, report)
	assert.Equal(t, "security-analytics", report.TemplateID)
	assert.Equal(t, "completed", report.Status)
	assert.NotNil(t, report.CompletedAt)
	assert.NotNil(t, report.Data)
	assert.NotNil(t, report.Data.Summary)
}

func TestAnalyticsEngine_RegisterDataCollector(t *testing.T) {
	logger := createTestAnalyticsLogger()
	config := DefaultAnalyticsConfig()
	ae := NewAnalyticsEngine(config, logger)

	mockCollector := &MockDataCollector{}
	ae.RegisterDataCollector("test-collector", mockCollector)

	// Verify collector was registered
	assert.Contains(t, ae.dataCollectors, "test-collector")
	assert.Equal(t, mockCollector, ae.dataCollectors["test-collector"])
}

func TestAnalyticsEngine_RegisterDataProcessor(t *testing.T) {
	logger := createTestAnalyticsLogger()
	config := DefaultAnalyticsConfig()
	ae := NewAnalyticsEngine(config, logger)

	mockProcessor := &MockDataProcessor{}
	ae.RegisterDataProcessor("test-processor", mockProcessor)

	// Verify processor was registered
	assert.Contains(t, ae.processors, "test-processor")
	assert.Equal(t, mockProcessor, ae.processors["test-processor"])
}

func TestAnalyticsEngine_RegisterReportExporter(t *testing.T) {
	logger := createTestAnalyticsLogger()
	config := DefaultAnalyticsConfig()
	ae := NewAnalyticsEngine(config, logger)

	mockExporter := &MockReportExporter{}
	ae.RegisterReportExporter("test-exporter", mockExporter)

	// Verify exporter was registered
	assert.Contains(t, ae.exporters, "test-exporter")
	assert.Equal(t, mockExporter, ae.exporters["test-exporter"])
}

func TestAnalyticsEngine_ExportReport(t *testing.T) {
	logger := createTestAnalyticsLogger()
	config := DefaultAnalyticsConfig()
	config.EnableScheduling = false
	config.EnableRealTimeAnalysis = false
	ae := NewAnalyticsEngine(config, logger)

	ctx := context.Background()
	err := ae.Start(ctx)
	require.NoError(t, err)

	// Register mock components
	mockCollector := &MockDataCollector{}
	mockExporter := &MockReportExporter{}
	ae.RegisterDataCollector("test-collector", mockCollector)
	ae.RegisterReportExporter("test-exporter", mockExporter)

	// Generate report
	params := map[string]interface{}{
		"time_range": "24h",
	}

	report, err := ae.GenerateReport(ctx, "performance-analytics", params)
	require.NoError(t, err)

	// Export report
	data, err := ae.ExportReport(ctx, report.ID, "json")
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "mock export")
}

func TestReportManager_CreateTemplate(t *testing.T) {
	logger := createTestAnalyticsLogger()
	config := DefaultReportConfig()
	rm := NewReportManager(config, logger)

	template := &ReportTemplate{
		ID:          "test-template",
		Name:        "Test Template",
		Description: "A test report template",
		Type:        "test",
		Category:    "testing",
		Sections: []*TemplateSection{
			{
				ID:         "section-1",
				Title:      "Test Section",
				Type:       "analysis",
				Order:      1,
				Required:   true,
				DataSource: "test-source",
			},
		},
		Parameters: []*TemplateParameter{
			{
				Name:         "test_param",
				Type:         "string",
				Required:     true,
				DefaultValue: "default",
				Description:  "A test parameter",
			},
		},
		Format:   "json",
		IsActive: true,
	}

	err := rm.CreateTemplate(template)
	require.NoError(t, err)
	assert.NotZero(t, template.CreatedAt)
	assert.NotZero(t, template.UpdatedAt)
	assert.Equal(t, 1, template.Version)

	// Verify template was created
	retrieved, err := rm.GetTemplate("test-template")
	require.NoError(t, err)
	assert.Equal(t, "Test Template", retrieved.Name)
	assert.Len(t, retrieved.Sections, 1)
	assert.Len(t, retrieved.Parameters, 1)
}

func TestReportManager_StoreReport(t *testing.T) {
	logger := createTestAnalyticsLogger()
	config := DefaultReportConfig()
	rm := NewReportManager(config, logger)

	report := &Report{
		ID:          "test-report-1",
		Name:        "Test Report",
		Type:        "test",
		Description: "A test report",
		TemplateID:  "test-template",
		Status:      "completed",
		CreatedBy:   "test-user",
		Format:      "json",
		Version:     1,
		Data: &ReportData{
			Summary: &ReportSummary{
				Title:            "Test Summary",
				ExecutiveSummary: "This is a test summary",
				KeyFindings:      []string{"Finding 1", "Finding 2"},
				KeyMetrics:       map[string]interface{}{"metric1": 100},
			},
			Sections:        []*ReportSection{},
			Charts:          []*ReportChart{},
			Tables:          []*ReportTable{},
			Insights:        []*ReportInsight{},
			Recommendations: []*ReportRecommendation{},
			Appendices:      []*ReportAppendix{},
			RawData:         map[string]interface{}{"raw": "data"},
		},
		Config: map[string]interface{}{"test": true},
	}

	err := rm.StoreReport(report)
	require.NoError(t, err)

	// Verify report was stored
	retrieved, err := rm.GetReport("test-report-1")
	require.NoError(t, err)
	assert.Equal(t, "Test Report", retrieved.Name)
	assert.Equal(t, "completed", retrieved.Status)
	assert.NotNil(t, retrieved.Data)
	assert.Equal(t, "Test Summary", retrieved.Data.Summary.Title)
}

func TestReportScheduler_ScheduleReport(t *testing.T) {
	logger := createTestAnalyticsLogger()
	config := DefaultSchedulerConfig()
	config.EnableScheduling = false // Disable worker for testing
	rs := NewReportScheduler(config, logger)

	schedule := &ScheduleConfig{
		ID:         "test-schedule",
		Name:       "Test Schedule",
		TemplateID: "test-template",
		Enabled:    true,
		CronExpr:   "0 2 * * *", // Daily at 2 AM
		Timezone:   "UTC",
		Parameters: map[string]interface{}{"param1": "value1"},
		Recipients: []string{"admin@example.com"},
		Format:     "json",
		Metadata:   map[string]interface{}{"test": true},
	}

	err := rs.ScheduleReport(schedule)
	require.NoError(t, err)
	assert.NotZero(t, schedule.CreatedAt)
	assert.NotZero(t, schedule.UpdatedAt)

	// Verify schedule was created
	retrieved, err := rs.GetSchedule("test-schedule")
	require.NoError(t, err)
	assert.Equal(t, "Test Schedule", retrieved.Name)
	assert.Equal(t, "test-template", retrieved.TemplateID)
	assert.True(t, retrieved.Enabled)
}

// Mock implementations for testing

type MockDataCollector struct{}

func (m *MockDataCollector) CollectData(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"metrics": map[string]float64{
			"cpu_usage":    75.5,
			"memory_usage": 60.2,
			"disk_usage":   45.8,
		},
		"events": []map[string]interface{}{
			{"type": "security", "count": 10},
			{"type": "performance", "count": 25},
		},
		"timestamp": time.Now(),
	}, nil
}

func (m *MockDataCollector) GetDataSources() []string {
	return []string{"metrics", "events", "logs"}
}

func (m *MockDataCollector) ValidateParams(params map[string]interface{}) error {
	return nil
}

type MockDataProcessor struct{}

func (m *MockDataProcessor) ProcessData(ctx context.Context, data interface{}) (interface{}, error) {
	return map[string]interface{}{
		"processed": true,
		"original":  data,
		"summary": map[string]interface{}{
			"total_events": 35,
			"avg_cpu":      75.5,
		},
	}, nil
}

func (m *MockDataProcessor) GetProcessorType() string {
	return "mock-processor"
}

func (m *MockDataProcessor) GetCapabilities() []string {
	return []string{"aggregation", "filtering", "transformation"}
}

type MockReportExporter struct{}

func (m *MockReportExporter) ExportReport(ctx context.Context, report *Report, format string) ([]byte, error) {
	return []byte(`{"mock export": "data", "format": "` + format + `", "report_id": "` + report.ID + `"}`), nil
}

func (m *MockReportExporter) GetSupportedFormats() []string {
	return []string{"json", "csv", "pdf"}
}

func (m *MockReportExporter) ValidateFormat(format string) error {
	supportedFormats := m.GetSupportedFormats()
	for _, supported := range supportedFormats {
		if format == supported {
			return nil
		}
	}
	return fmt.Errorf("unsupported format: %s", format)
}
