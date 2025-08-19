package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/dimajoyti/hackai/pkg/logger"
)

func createTestLogger() *logger.Logger {
	config := logger.Config{
		Level:     logger.LevelDebug,
		Format:    "text",
		Output:    "stdout",
		AddSource: false,
	}
	testLogger, _ := logger.New(config)
	return testLogger
}

func TestDashboardManager_CreateDashboard(t *testing.T) {
	logger := createTestLogger()
	config := DefaultDashboardConfig()
	dm := NewDashboardManager(config, logger)

	dashboard := &Dashboard{
		ID:          "test-dashboard-1",
		Name:        "Test Dashboard",
		Description: "A test dashboard",
		Category:    "test",
		Widgets:     []*Widget{},
		Layout:      &DashboardLayout{Columns: 12, Rows: 8},
		Permissions: []string{"read", "write"},
		CreatedBy:   "test-user",
		IsPublic:    true,
		Tags:        []string{"test", "monitoring"},
		Metadata:    make(map[string]interface{}),
	}

	err := dm.CreateDashboard(dashboard)
	require.NoError(t, err)

	// Verify dashboard was created
	retrieved, err := dm.GetDashboard("test-dashboard-1")
	require.NoError(t, err)
	assert.Equal(t, "Test Dashboard", retrieved.Name)
	assert.Equal(t, "test", retrieved.Category)
	assert.True(t, retrieved.IsPublic)
	assert.Contains(t, retrieved.Tags, "test")
}

func TestDashboardManager_AddWidget(t *testing.T) {
	logger := createTestLogger()
	config := DefaultDashboardConfig()
	dm := NewDashboardManager(config, logger)

	// Create dashboard first
	dashboard := &Dashboard{
		ID:          "test-dashboard-2",
		Name:        "Test Dashboard 2",
		Description: "A test dashboard for widgets",
		Category:    "test",
		Widgets:     []*Widget{},
		Layout:      &DashboardLayout{Columns: 12, Rows: 8},
		Permissions: []string{"read", "write"},
		CreatedBy:   "test-user",
		IsPublic:    true,
		Tags:        []string{"test"},
		Metadata:    make(map[string]interface{}),
	}

	err := dm.CreateDashboard(dashboard)
	require.NoError(t, err)

	// Add widget
	widget := &Widget{
		ID:          "test-widget-1",
		Type:        "chart",
		Title:       "Test Chart",
		Description: "A test chart widget",
		DataSource:  "test-source",
		Query:       "SELECT * FROM test",
		Config: &WidgetConfig{
			ChartType:     "line",
			Colors:        []string{"#FF0000", "#00FF00"},
			Thresholds:    map[string]float64{"warning": 80, "critical": 90},
			DisplayFormat: "percentage",
			Aggregation:   "avg",
			TimeRange:     "1h",
			AutoRefresh:   true,
			ShowLegend:    true,
			ShowGrid:      true,
			Options:       make(map[string]interface{}),
		},
		Position: &WidgetPosition{
			X:      0,
			Y:      0,
			Width:  6,
			Height: 4,
		},
		RefreshRate: 30 * time.Second,
		Alerts:      []*WidgetAlert{},
		Metadata:    make(map[string]interface{}),
	}

	err = dm.AddWidget("test-dashboard-2", widget)
	require.NoError(t, err)

	// Verify widget was added
	retrieved, err := dm.GetDashboard("test-dashboard-2")
	require.NoError(t, err)
	assert.Len(t, retrieved.Widgets, 1)
	assert.Equal(t, "Test Chart", retrieved.Widgets[0].Title)
	assert.Equal(t, "chart", retrieved.Widgets[0].Type)
}

func TestDashboardManager_UpdateWidget(t *testing.T) {
	logger := createTestLogger()
	config := DefaultDashboardConfig()
	dm := NewDashboardManager(config, logger)

	// Create dashboard and widget
	dashboard := &Dashboard{
		ID:          "test-dashboard-3",
		Name:        "Test Dashboard 3",
		Description: "A test dashboard for widget updates",
		Category:    "test",
		Widgets:     []*Widget{},
		Layout:      &DashboardLayout{Columns: 12, Rows: 8},
		Permissions: []string{"read", "write"},
		CreatedBy:   "test-user",
		IsPublic:    true,
		Tags:        []string{"test"},
		Metadata:    make(map[string]interface{}),
	}

	err := dm.CreateDashboard(dashboard)
	require.NoError(t, err)

	widget := &Widget{
		ID:          "test-widget-2",
		Type:        "table",
		Title:       "Original Title",
		Description: "Original description",
		DataSource:  "test-source",
		Query:       "SELECT * FROM test",
		Config: &WidgetConfig{
			ChartType:     "table",
			Colors:        []string{},
			Thresholds:    make(map[string]float64),
			DisplayFormat: "table",
			Aggregation:   "none",
			TimeRange:     "1h",
			AutoRefresh:   false,
			ShowLegend:    false,
			ShowGrid:      true,
			Options:       make(map[string]interface{}),
		},
		Position: &WidgetPosition{
			X:      6,
			Y:      0,
			Width:  6,
			Height: 4,
		},
		RefreshRate: 60 * time.Second,
		Alerts:      []*WidgetAlert{},
		Metadata:    make(map[string]interface{}),
	}

	err = dm.AddWidget("test-dashboard-3", widget)
	require.NoError(t, err)

	// Update widget
	widget.Title = "Updated Title"
	widget.Description = "Updated description"
	widget.Config.AutoRefresh = true

	err = dm.UpdateWidget(widget)
	require.NoError(t, err)

	// Verify widget was updated
	retrieved, err := dm.GetDashboard("test-dashboard-3")
	require.NoError(t, err)
	assert.Len(t, retrieved.Widgets, 1)
	assert.Equal(t, "Updated Title", retrieved.Widgets[0].Title)
	assert.Equal(t, "Updated description", retrieved.Widgets[0].Description)
	assert.True(t, retrieved.Widgets[0].Config.AutoRefresh)
}

func TestDashboardManager_RegisterDataProvider(t *testing.T) {
	logger := createTestLogger()
	config := DefaultDashboardConfig()
	dm := NewDashboardManager(config, logger)

	// Create mock data provider
	mockProvider := &MockDataProvider{}

	// Register data provider
	dm.RegisterDataProvider("test-provider", mockProvider)

	// Verify provider was registered
	assert.Contains(t, dm.dataProviders, "test-provider")
	assert.Equal(t, mockProvider, dm.dataProviders["test-provider"])
}

func TestDashboardManager_ExportDashboard(t *testing.T) {
	logger := createTestLogger()
	config := DefaultDashboardConfig()
	config.EnableExport = true
	dm := NewDashboardManager(config, logger)

	// Create dashboard
	dashboard := &Dashboard{
		ID:          "test-dashboard-4",
		Name:        "Export Test Dashboard",
		Description: "A dashboard for export testing",
		Category:    "test",
		Widgets:     []*Widget{},
		Layout:      &DashboardLayout{Columns: 12, Rows: 8},
		Permissions: []string{"read"},
		CreatedBy:   "test-user",
		IsPublic:    false,
		Tags:        []string{"export", "test"},
		Metadata:    make(map[string]interface{}),
	}

	err := dm.CreateDashboard(dashboard)
	require.NoError(t, err)

	// Export dashboard
	data, err := dm.ExportDashboard("test-dashboard-4", "json")
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Verify JSON format
	assert.Contains(t, string(data), "Export Test Dashboard")
	assert.Contains(t, string(data), "export")
}

func TestDashboardManager_Start_Stop(t *testing.T) {
	logger := createTestLogger()
	config := DefaultDashboardConfig()
	config.EnableRealTime = false // Disable for testing
	config.EnableAlerts = false   // Disable for testing
	dm := NewDashboardManager(config, logger)

	ctx := context.Background()

	// Test start
	err := dm.Start(ctx)
	require.NoError(t, err)

	// Test double start (should fail)
	err = dm.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")

	// Test stop
	err = dm.Stop(ctx)
	require.NoError(t, err)

	// Test double stop (should not fail)
	err = dm.Stop(ctx)
	require.NoError(t, err)
}

func TestDashboardManager_ListDashboards(t *testing.T) {
	logger := createTestLogger()
	config := DefaultDashboardConfig()
	dm := NewDashboardManager(config, logger)

	// Create multiple dashboards
	dashboards := []*Dashboard{
		{
			ID:          "dashboard-1",
			Name:        "Dashboard 1",
			Description: "First dashboard",
			Category:    "test",
			Widgets:     []*Widget{},
			Layout:      &DashboardLayout{Columns: 12, Rows: 8},
			Permissions: []string{"read"},
			CreatedBy:   "user-1",
			IsPublic:    true,
			Tags:        []string{"test"},
			Metadata:    make(map[string]interface{}),
		},
		{
			ID:          "dashboard-2",
			Name:        "Dashboard 2",
			Description: "Second dashboard",
			Category:    "production",
			Widgets:     []*Widget{},
			Layout:      &DashboardLayout{Columns: 12, Rows: 8},
			Permissions: []string{"read", "write"},
			CreatedBy:   "user-2",
			IsPublic:    false,
			Tags:        []string{"production"},
			Metadata:    make(map[string]interface{}),
		},
	}

	for _, dashboard := range dashboards {
		err := dm.CreateDashboard(dashboard)
		require.NoError(t, err)
	}

	// List all dashboards
	allDashboards := dm.ListDashboards()
	assert.Len(t, allDashboards, 2)

	// Verify dashboard names
	names := make([]string, len(allDashboards))
	for i, d := range allDashboards {
		names[i] = d.Name
	}
	assert.Contains(t, names, "Dashboard 1")
	assert.Contains(t, names, "Dashboard 2")
}

// Mock data provider for testing
type MockDataProvider struct{}

func (m *MockDataProvider) GetData(ctx context.Context, query string, timeRange string) (interface{}, error) {
	return map[string]interface{}{
		"data":   []float64{1.0, 2.0, 3.0, 4.0, 5.0},
		"labels": []string{"A", "B", "C", "D", "E"},
	}, nil
}

func (m *MockDataProvider) GetMetrics(ctx context.Context, metrics []string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	for _, metric := range metrics {
		result[metric] = 42.0
	}
	return result, nil
}

func (m *MockDataProvider) GetHealthStatus(ctx context.Context) (*HealthStatus, error) {
	return &HealthStatus{
		Status:      "healthy",
		Services:    map[string]string{"test": "healthy"},
		Metrics:     map[string]float64{"uptime": 100.0},
		Alerts:      []string{},
		LastChecked: time.Now(),
		Metadata:    make(map[string]interface{}),
	}, nil
}

func (m *MockDataProvider) ValidateQuery(query string) error {
	return nil
}
