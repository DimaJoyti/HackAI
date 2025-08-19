package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// DashboardManager manages comprehensive monitoring dashboards
type DashboardManager struct {
	logger        *logger.Logger
	config        *DashboardConfig
	dashboards    map[string]*Dashboard
	widgets       map[string]*Widget
	dataProviders map[string]DataProvider
	alertManager  *AlertManager
	mu            sync.RWMutex
	isRunning     bool
}

// DashboardConfig configuration for dashboard manager
type DashboardConfig struct {
	RefreshInterval time.Duration `json:"refresh_interval"`
	MaxDashboards   int           `json:"max_dashboards"`
	MaxWidgets      int           `json:"max_widgets"`
	EnableRealTime  bool          `json:"enable_real_time"`
	EnableAlerts    bool          `json:"enable_alerts"`
	DataRetention   time.Duration `json:"data_retention"`
	CacheTimeout    time.Duration `json:"cache_timeout"`
	EnableExport    bool          `json:"enable_export"`
	ExportFormats   []string      `json:"export_formats"`
}

// Dashboard represents a monitoring dashboard
type Dashboard struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Widgets     []*Widget              `json:"widgets"`
	Layout      *DashboardLayout       `json:"layout"`
	Permissions []string               `json:"permissions"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	CreatedBy   string                 `json:"created_by"`
	IsPublic    bool                   `json:"is_public"`
	Tags        []string               `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Widget represents a dashboard widget
type Widget struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	DataSource  string                 `json:"data_source"`
	Query       string                 `json:"query"`
	Config      *WidgetConfig          `json:"config"`
	Position    *WidgetPosition        `json:"position"`
	Data        interface{}            `json:"data"`
	LastUpdated time.Time              `json:"last_updated"`
	RefreshRate time.Duration          `json:"refresh_rate"`
	Alerts      []*WidgetAlert         `json:"alerts"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// DashboardLayout defines dashboard layout
type DashboardLayout struct {
	Columns int                    `json:"columns"`
	Rows    int                    `json:"rows"`
	Grid    map[string]interface{} `json:"grid"`
}

// WidgetConfig configuration for widgets
type WidgetConfig struct {
	ChartType     string                 `json:"chart_type"`
	Colors        []string               `json:"colors"`
	Thresholds    map[string]float64     `json:"thresholds"`
	DisplayFormat string                 `json:"display_format"`
	Aggregation   string                 `json:"aggregation"`
	TimeRange     string                 `json:"time_range"`
	AutoRefresh   bool                   `json:"auto_refresh"`
	ShowLegend    bool                   `json:"show_legend"`
	ShowGrid      bool                   `json:"show_grid"`
	Options       map[string]interface{} `json:"options"`
}

// WidgetPosition defines widget position
type WidgetPosition struct {
	X      int `json:"x"`
	Y      int `json:"y"`
	Width  int `json:"width"`
	Height int `json:"height"`
}

// WidgetAlert defines widget alerts
type WidgetAlert struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Condition string                 `json:"condition"`
	Threshold float64                `json:"threshold"`
	Severity  string                 `json:"severity"`
	Enabled   bool                   `json:"enabled"`
	Actions   []string               `json:"actions"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// DataProvider interface for data providers
type DataProvider interface {
	GetData(ctx context.Context, query string, timeRange string) (interface{}, error)
	GetMetrics(ctx context.Context, metrics []string) (map[string]interface{}, error)
	GetHealthStatus(ctx context.Context) (*HealthStatus, error)
	ValidateQuery(query string) error
}

// HealthStatus represents system health status
type HealthStatus struct {
	Status      string                 `json:"status"`
	Services    map[string]string      `json:"services"`
	Metrics     map[string]float64     `json:"metrics"`
	Alerts      []string               `json:"alerts"`
	LastChecked time.Time              `json:"last_checked"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AlertManager manages dashboard alerts
type AlertManager struct {
	logger       *logger.Logger
	config       *AlertConfig
	rules        map[string]*AlertRule
	activeAlerts map[string]*Alert
	handlers     []AlertHandler
	mu           sync.RWMutex
}

// AlertConfig configuration for alerts
type AlertConfig struct {
	EnableAlerts         bool          `json:"enable_alerts"`
	CheckInterval        time.Duration `json:"check_interval"`
	MaxAlerts            int           `json:"max_alerts"`
	AlertRetention       time.Duration `json:"alert_retention"`
	EnableNotifications  bool          `json:"enable_notifications"`
	NotificationChannels []string      `json:"notification_channels"`
}

// AlertRule defines alert rules
type AlertRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Query       string                 `json:"query"`
	Condition   string                 `json:"condition"`
	Threshold   float64                `json:"threshold"`
	Severity    string                 `json:"severity"`
	Enabled     bool                   `json:"enabled"`
	Actions     []AlertAction          `json:"actions"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Alert represents an active alert
type Alert struct {
	ID          string                 `json:"id"`
	RuleID      string                 `json:"rule_id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Status      string                 `json:"status"`
	Value       float64                `json:"value"`
	Threshold   float64                `json:"threshold"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AlertAction defines alert actions
type AlertAction struct {
	Type       string                 `json:"type"`
	Target     string                 `json:"target"`
	Parameters map[string]interface{} `json:"parameters"`
}

// AlertHandler interface for alert handlers
type AlertHandler interface {
	HandleAlert(ctx context.Context, alert *Alert) error
	GetType() string
}

// NewDashboardManager creates a new dashboard manager
func NewDashboardManager(config *DashboardConfig, logger *logger.Logger) *DashboardManager {
	if config == nil {
		config = DefaultDashboardConfig()
	}

	alertManager := NewAlertManager(DefaultAlertConfig(), logger)

	return &DashboardManager{
		logger:        logger,
		config:        config,
		dashboards:    make(map[string]*Dashboard),
		widgets:       make(map[string]*Widget),
		dataProviders: make(map[string]DataProvider),
		alertManager:  alertManager,
	}
}

// DefaultDashboardConfig returns default configuration
func DefaultDashboardConfig() *DashboardConfig {
	return &DashboardConfig{
		RefreshInterval: 30 * time.Second,
		MaxDashboards:   100,
		MaxWidgets:      1000,
		EnableRealTime:  true,
		EnableAlerts:    true,
		DataRetention:   7 * 24 * time.Hour,
		CacheTimeout:    5 * time.Minute,
		EnableExport:    true,
		ExportFormats:   []string{"json", "csv", "pdf"},
	}
}

// Start starts the dashboard manager
func (dm *DashboardManager) Start(ctx context.Context) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if dm.isRunning {
		return fmt.Errorf("dashboard manager is already running")
	}

	dm.logger.Info("Starting dashboard manager")

	// Start alert manager
	if dm.config.EnableAlerts {
		if err := dm.alertManager.Start(ctx); err != nil {
			return fmt.Errorf("failed to start alert manager: %w", err)
		}
	}

	// Start real-time updates if enabled
	if dm.config.EnableRealTime {
		go dm.realTimeUpdateWorker(ctx)
	}

	// Start data refresh worker
	go dm.dataRefreshWorker(ctx)

	dm.isRunning = true
	dm.logger.Info("Dashboard manager started successfully")
	return nil
}

// Stop stops the dashboard manager
func (dm *DashboardManager) Stop(ctx context.Context) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if !dm.isRunning {
		return nil
	}

	dm.logger.Info("Stopping dashboard manager")
	dm.isRunning = false
	dm.logger.Info("Dashboard manager stopped")
	return nil
}

// CreateDashboard creates a new dashboard
func (dm *DashboardManager) CreateDashboard(dashboard *Dashboard) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if len(dm.dashboards) >= dm.config.MaxDashboards {
		return fmt.Errorf("maximum number of dashboards reached: %d", dm.config.MaxDashboards)
	}

	dashboard.CreatedAt = time.Now()
	dashboard.UpdatedAt = time.Now()

	dm.dashboards[dashboard.ID] = dashboard
	dm.logger.Info("Dashboard created", "id", dashboard.ID, "name", dashboard.Name)
	return nil
}

// GetDashboard gets a dashboard by ID
func (dm *DashboardManager) GetDashboard(id string) (*Dashboard, error) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	dashboard, exists := dm.dashboards[id]
	if !exists {
		return nil, fmt.Errorf("dashboard not found: %s", id)
	}

	return dashboard, nil
}

// UpdateDashboard updates a dashboard
func (dm *DashboardManager) UpdateDashboard(dashboard *Dashboard) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	existing, exists := dm.dashboards[dashboard.ID]
	if !exists {
		return fmt.Errorf("dashboard not found: %s", dashboard.ID)
	}

	dashboard.CreatedAt = existing.CreatedAt
	dashboard.UpdatedAt = time.Now()

	dm.dashboards[dashboard.ID] = dashboard
	dm.logger.Info("Dashboard updated", "id", dashboard.ID, "name", dashboard.Name)
	return nil
}

// DeleteDashboard deletes a dashboard
func (dm *DashboardManager) DeleteDashboard(id string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if _, exists := dm.dashboards[id]; !exists {
		return fmt.Errorf("dashboard not found: %s", id)
	}

	delete(dm.dashboards, id)
	dm.logger.Info("Dashboard deleted", "id", id)
	return nil
}

// ListDashboards lists all dashboards
func (dm *DashboardManager) ListDashboards() []*Dashboard {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	dashboards := make([]*Dashboard, 0, len(dm.dashboards))
	for _, dashboard := range dm.dashboards {
		dashboards = append(dashboards, dashboard)
	}

	return dashboards
}

// AddWidget adds a widget to a dashboard
func (dm *DashboardManager) AddWidget(dashboardID string, widget *Widget) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dashboard, exists := dm.dashboards[dashboardID]
	if !exists {
		return fmt.Errorf("dashboard not found: %s", dashboardID)
	}

	if len(dm.widgets) >= dm.config.MaxWidgets {
		return fmt.Errorf("maximum number of widgets reached: %d", dm.config.MaxWidgets)
	}

	widget.LastUpdated = time.Now()
	dashboard.Widgets = append(dashboard.Widgets, widget)
	dm.widgets[widget.ID] = widget

	dm.logger.Info("Widget added to dashboard",
		"widget_id", widget.ID,
		"dashboard_id", dashboardID,
		"widget_type", widget.Type)
	return nil
}

// UpdateWidget updates a widget
func (dm *DashboardManager) UpdateWidget(widget *Widget) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	existing, exists := dm.widgets[widget.ID]
	if !exists {
		return fmt.Errorf("widget not found: %s", widget.ID)
	}

	widget.LastUpdated = time.Now()
	dm.widgets[widget.ID] = widget

	// Update widget in dashboard
	for _, dashboard := range dm.dashboards {
		for i, w := range dashboard.Widgets {
			if w.ID == widget.ID {
				dashboard.Widgets[i] = widget
				break
			}
		}
	}

	dm.logger.Debug("Widget updated", "widget_id", widget.ID, "type", existing.Type)
	return nil
}

// RefreshWidget refreshes widget data
func (dm *DashboardManager) RefreshWidget(ctx context.Context, widgetID string) error {
	dm.mu.RLock()
	widget, exists := dm.widgets[widgetID]
	dm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("widget not found: %s", widgetID)
	}

	provider, exists := dm.dataProviders[widget.DataSource]
	if !exists {
		return fmt.Errorf("data provider not found: %s", widget.DataSource)
	}

	data, err := provider.GetData(ctx, widget.Query, widget.Config.TimeRange)
	if err != nil {
		return fmt.Errorf("failed to get widget data: %w", err)
	}

	dm.mu.Lock()
	widget.Data = data
	widget.LastUpdated = time.Now()
	dm.mu.Unlock()

	dm.logger.Debug("Widget data refreshed", "widget_id", widgetID)
	return nil
}

// RegisterDataProvider registers a data provider
func (dm *DashboardManager) RegisterDataProvider(name string, provider DataProvider) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dm.dataProviders[name] = provider
	dm.logger.Info("Data provider registered", "name", name)
}

// GetSystemHealth gets overall system health
func (dm *DashboardManager) GetSystemHealth(ctx context.Context) (*HealthStatus, error) {
	health := &HealthStatus{
		Status:      "healthy",
		Services:    make(map[string]string),
		Metrics:     make(map[string]float64),
		Alerts:      []string{},
		LastChecked: time.Now(),
		Metadata:    make(map[string]interface{}),
	}

	// Check all data providers
	for name, provider := range dm.dataProviders {
		providerHealth, err := provider.GetHealthStatus(ctx)
		if err != nil {
			health.Services[name] = "unhealthy"
			health.Status = "degraded"
			dm.logger.Error("Data provider health check failed", "provider", name, "error", err)
		} else {
			health.Services[name] = providerHealth.Status
			if providerHealth.Status != "healthy" {
				health.Status = "degraded"
			}
		}
	}

	// Get active alerts
	if dm.config.EnableAlerts {
		activeAlerts := dm.alertManager.GetActiveAlerts()
		for _, alert := range activeAlerts {
			health.Alerts = append(health.Alerts, alert.Name)
			if alert.Severity == "critical" {
				health.Status = "critical"
			}
		}
	}

	return health, nil
}

// ExportDashboard exports a dashboard
func (dm *DashboardManager) ExportDashboard(dashboardID, format string) ([]byte, error) {
	if !dm.config.EnableExport {
		return nil, fmt.Errorf("export is disabled")
	}

	dashboard, err := dm.GetDashboard(dashboardID)
	if err != nil {
		return nil, err
	}

	switch format {
	case "json":
		return json.MarshalIndent(dashboard, "", "  ")
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// Worker methods
func (dm *DashboardManager) realTimeUpdateWorker(ctx context.Context) {
	ticker := time.NewTicker(dm.config.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dm.updateRealTimeData(ctx)
		}
	}
}

func (dm *DashboardManager) dataRefreshWorker(ctx context.Context) {
	ticker := time.NewTicker(dm.config.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dm.refreshAllWidgets(ctx)
		}
	}
}

func (dm *DashboardManager) updateRealTimeData(ctx context.Context) {
	dm.mu.RLock()
	widgets := make([]*Widget, 0, len(dm.widgets))
	for _, widget := range dm.widgets {
		if widget.Config.AutoRefresh {
			widgets = append(widgets, widget)
		}
	}
	dm.mu.RUnlock()

	for _, widget := range widgets {
		if err := dm.RefreshWidget(ctx, widget.ID); err != nil {
			dm.logger.Error("Failed to refresh widget", "widget_id", widget.ID, "error", err)
		}
	}
}

func (dm *DashboardManager) refreshAllWidgets(ctx context.Context) {
	dm.mu.RLock()
	widgets := make([]*Widget, 0, len(dm.widgets))
	for _, widget := range dm.widgets {
		widgets = append(widgets, widget)
	}
	dm.mu.RUnlock()

	for _, widget := range widgets {
		if time.Since(widget.LastUpdated) > widget.RefreshRate {
			if err := dm.RefreshWidget(ctx, widget.ID); err != nil {
				dm.logger.Error("Failed to refresh widget", "widget_id", widget.ID, "error", err)
			}
		}
	}
}

// NewAlertManager creates a new alert manager
func NewAlertManager(config *AlertConfig, logger *logger.Logger) *AlertManager {
	return &AlertManager{
		logger:       logger,
		config:       config,
		rules:        make(map[string]*AlertRule),
		activeAlerts: make(map[string]*Alert),
		handlers:     []AlertHandler{},
	}
}

// DefaultAlertConfig returns default alert configuration
func DefaultAlertConfig() *AlertConfig {
	return &AlertConfig{
		EnableAlerts:         true,
		CheckInterval:        1 * time.Minute,
		MaxAlerts:            1000,
		AlertRetention:       24 * time.Hour,
		EnableNotifications:  true,
		NotificationChannels: []string{"email", "slack"},
	}
}

// Start starts the alert manager
func (am *AlertManager) Start(ctx context.Context) error {
	am.logger.Info("Starting alert manager")

	if am.config.EnableAlerts {
		go am.alertCheckWorker(ctx)
	}

	return nil
}

// GetActiveAlerts gets all active alerts
func (am *AlertManager) GetActiveAlerts() []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	alerts := make([]*Alert, 0, len(am.activeAlerts))
	for _, alert := range am.activeAlerts {
		alerts = append(alerts, alert)
	}

	return alerts
}

func (am *AlertManager) alertCheckWorker(ctx context.Context) {
	ticker := time.NewTicker(am.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			am.checkAlerts(ctx)
		}
	}
}

func (am *AlertManager) checkAlerts(ctx context.Context) {
	// Placeholder for alert checking logic
	am.logger.Debug("Checking alerts")
}
