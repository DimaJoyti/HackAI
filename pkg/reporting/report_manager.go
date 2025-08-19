package reporting

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// Additional types needed for analytics engine

// TemplateSection represents a section in a report template
type TemplateSection struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Type        string                 `json:"type"`
	Order       int                    `json:"order"`
	Required    bool                   `json:"required"`
	DataSource  string                 `json:"data_source"`
	Query       string                 `json:"query"`
	Config      map[string]interface{} `json:"config"`
}

// TemplateParameter represents a parameter in a report template
type TemplateParameter struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Required     bool        `json:"required"`
	DefaultValue interface{} `json:"default_value"`
	Description  string      `json:"description"`
	Validation   string      `json:"validation"`
}

// ScheduleConfig represents scheduling configuration
type ScheduleConfig struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	TemplateID  string                 `json:"template_id"`
	Enabled     bool                   `json:"enabled"`
	CronExpr    string                 `json:"cron_expr"`
	Timezone    string                 `json:"timezone"`
	Parameters  map[string]interface{} `json:"parameters"`
	Recipients  []string               `json:"recipients"`
	Format      string                 `json:"format"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	LastRun     *time.Time             `json:"last_run,omitempty"`
	NextRun     *time.Time             `json:"next_run,omitempty"`
	RunCount    int                    `json:"run_count"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ChartConfig represents chart configuration
type ChartConfig struct {
	Type        string                 `json:"type"`
	Colors      []string               `json:"colors"`
	Width       int                    `json:"width"`
	Height      int                    `json:"height"`
	ShowLegend  bool                   `json:"show_legend"`
	ShowGrid    bool                   `json:"show_grid"`
	Responsive  bool                   `json:"responsive"`
	Animation   bool                   `json:"animation"`
	Options     map[string]interface{} `json:"options"`
}

// TableConfig represents table configuration
type TableConfig struct {
	Sortable    bool                   `json:"sortable"`
	Filterable  bool                   `json:"filterable"`
	Paginated   bool                   `json:"paginated"`
	PageSize    int                    `json:"page_size"`
	Striped     bool                   `json:"striped"`
	Bordered    bool                   `json:"bordered"`
	Responsive  bool                   `json:"responsive"`
	Options     map[string]interface{} `json:"options"`
}

// ReportScheduler manages scheduled report generation
type ReportScheduler struct {
	logger    *logger.Logger
	config    *SchedulerConfig
	schedules map[string]*ScheduleConfig
	mu        sync.RWMutex
	isRunning bool
}

// SchedulerConfig configuration for scheduler
type SchedulerConfig struct {
	EnableScheduling bool          `json:"enable_scheduling"`
	CheckInterval    time.Duration `json:"check_interval"`
	MaxConcurrent    int           `json:"max_concurrent"`
	RetryAttempts    int           `json:"retry_attempts"`
	RetryDelay       time.Duration `json:"retry_delay"`
}

// NewReportManager creates a new report manager
func NewReportManager(config *ReportConfig, logger *logger.Logger) *ReportManager {
	if config == nil {
		config = DefaultReportConfig()
	}

	return &ReportManager{
		logger:    logger,
		config:    config,
		reports:   make(map[string]*Report),
		templates: make(map[string]*ReportTemplate),
	}
}

// DefaultReportConfig returns default report configuration
func DefaultReportConfig() *ReportConfig {
	return &ReportConfig{
		MaxReports:        10000,
		DefaultFormat:     "json",
		RetentionPeriod:   30 * 24 * time.Hour,
		EnableVersioning:  true,
		EnableCompression: true,
	}
}

// Start starts the report manager
func (rm *ReportManager) Start(ctx context.Context) error {
	rm.logger.Info("Starting report manager")
	
	// Initialize default templates
	rm.initializeDefaultTemplates()
	
	return nil
}

// StoreReport stores a report
func (rm *ReportManager) StoreReport(report *Report) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if len(rm.reports) >= rm.config.MaxReports {
		return fmt.Errorf("maximum number of reports reached: %d", rm.config.MaxReports)
	}

	rm.reports[report.ID] = report
	rm.logger.Info("Report stored", "report_id", report.ID, "type", report.Type)
	return nil
}

// GetReport gets a report by ID
func (rm *ReportManager) GetReport(reportID string) (*Report, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	report, exists := rm.reports[reportID]
	if !exists {
		return nil, fmt.Errorf("report not found: %s", reportID)
	}

	return report, nil
}

// ListReports lists all reports
func (rm *ReportManager) ListReports() []*Report {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	reports := make([]*Report, 0, len(rm.reports))
	for _, report := range rm.reports {
		reports = append(reports, report)
	}

	return reports
}

// GetTemplate gets a template by ID
func (rm *ReportManager) GetTemplate(templateID string) (*ReportTemplate, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	template, exists := rm.templates[templateID]
	if !exists {
		return nil, fmt.Errorf("template not found: %s", templateID)
	}

	return template, nil
}

// CreateTemplate creates a new report template
func (rm *ReportManager) CreateTemplate(template *ReportTemplate) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	template.CreatedAt = time.Now()
	template.UpdatedAt = time.Now()
	template.Version = 1

	rm.templates[template.ID] = template
	rm.logger.Info("Report template created", "template_id", template.ID, "name", template.Name)
	return nil
}

// ListTemplates lists all templates
func (rm *ReportManager) ListTemplates() []*ReportTemplate {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	templates := make([]*ReportTemplate, 0, len(rm.templates))
	for _, template := range rm.templates {
		templates = append(templates, template)
	}

	return templates
}

// initializeDefaultTemplates creates default report templates
func (rm *ReportManager) initializeDefaultTemplates() {
	// Security Analytics Template
	securityTemplate := &ReportTemplate{
		ID:          "security-analytics",
		Name:        "Security Analytics Report",
		Description: "Comprehensive security analytics and threat intelligence report",
		Type:        "security",
		Category:    "analytics",
		Sections: []*TemplateSection{
			{
				ID:         "executive-summary",
				Title:      "Executive Summary",
				Type:       "summary",
				Order:      1,
				Required:   true,
				DataSource: "security",
			},
			{
				ID:         "threat-landscape",
				Title:      "Threat Landscape",
				Type:       "analysis",
				Order:      2,
				Required:   true,
				DataSource: "threat-intelligence",
			},
			{
				ID:         "security-metrics",
				Title:      "Security Metrics",
				Type:       "metrics",
				Order:      3,
				Required:   true,
				DataSource: "metrics",
			},
		},
		Parameters: []*TemplateParameter{
			{
				Name:         "time_range",
				Type:         "string",
				Required:     true,
				DefaultValue: "7d",
				Description:  "Time range for the report (e.g., 7d, 30d, 90d)",
			},
			{
				Name:         "include_predictions",
				Type:         "boolean",
				Required:     false,
				DefaultValue: true,
				Description:  "Include predictive analytics in the report",
			},
		},
		Format:    "json",
		IsActive:  true,
	}

	// Performance Analytics Template
	performanceTemplate := &ReportTemplate{
		ID:          "performance-analytics",
		Name:        "Performance Analytics Report",
		Description: "System performance and operational metrics report",
		Type:        "performance",
		Category:    "analytics",
		Sections: []*TemplateSection{
			{
				ID:         "system-overview",
				Title:      "System Overview",
				Type:       "overview",
				Order:      1,
				Required:   true,
				DataSource: "system",
			},
			{
				ID:         "performance-metrics",
				Title:      "Performance Metrics",
				Type:       "metrics",
				Order:      2,
				Required:   true,
				DataSource: "performance",
			},
		},
		Parameters: []*TemplateParameter{
			{
				Name:         "time_range",
				Type:         "string",
				Required:     true,
				DefaultValue: "24h",
				Description:  "Time range for the report",
			},
		},
		Format:   "json",
		IsActive: true,
	}

	rm.templates[securityTemplate.ID] = securityTemplate
	rm.templates[performanceTemplate.ID] = performanceTemplate

	rm.logger.Info("Default report templates initialized", "count", len(rm.templates))
}

// GenerateReport generates a report based on template and parameters
func (rm *ReportManager) GenerateReport(ctx context.Context, templateID string, params map[string]interface{}) (*Report, error) {
	rm.mu.RLock()
	_, exists := rm.templates[templateID]
	rm.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("template not found: %s", templateID)
	}
	
	// Create a new report
	report := &Report{
		ID:         fmt.Sprintf("report_%d", time.Now().Unix()),
		TemplateID: templateID,
		Status:     "completed",
		CreatedAt:  time.Now(),
		CompletedAt: func() *time.Time { t := time.Now(); return &t }(),
		Data: &ReportData{
			Summary: &ReportSummary{
				Title:           "Generated Report",
				ExecutiveSummary: "This is a generated report",
				KeyFindings:     []string{"Finding 1", "Finding 2"},
				KeyMetrics:      map[string]interface{}{"total": 100, "success": 95},
				Recommendations: []string{"Recommendation 1"},
				NextSteps:       []string{"Step 1"},
			},
		},
		Metadata: &ReportMetadata{
			GenerationTime: time.Second,
			DataSources:    []string{"system"},
			Filters:        map[string]interface{}{},
			Parameters:     params,
		},
	}
	
	// Store the report
	rm.mu.Lock()
	rm.reports[report.ID] = report
	rm.mu.Unlock()
	
	rm.logger.Info("Report generated", "report_id", report.ID, "template_id", templateID)
	return report, nil
}

// NewReportScheduler creates a new report scheduler
func NewReportScheduler(config *SchedulerConfig, logger *logger.Logger) *ReportScheduler {
	if config == nil {
		config = DefaultSchedulerConfig()
	}

	return &ReportScheduler{
		logger:    logger,
		config:    config,
		schedules: make(map[string]*ScheduleConfig),
	}
}

// DefaultSchedulerConfig returns default scheduler configuration
func DefaultSchedulerConfig() *SchedulerConfig {
	return &SchedulerConfig{
		EnableScheduling: true,
		CheckInterval:    1 * time.Minute,
		MaxConcurrent:    5,
		RetryAttempts:    3,
		RetryDelay:       5 * time.Minute,
	}
}

// Start starts the report scheduler
func (rs *ReportScheduler) Start(ctx context.Context) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.isRunning {
		return fmt.Errorf("scheduler is already running")
	}

	rs.logger.Info("Starting report scheduler")

	if rs.config.EnableScheduling {
		go rs.schedulerWorker(ctx)
	}

	rs.isRunning = true
	return nil
}

// ScheduleReport schedules a report for automatic generation
func (rs *ReportScheduler) ScheduleReport(schedule *ScheduleConfig) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	schedule.CreatedAt = time.Now()
	schedule.UpdatedAt = time.Now()

	rs.schedules[schedule.ID] = schedule
	rs.logger.Info("Report scheduled", "schedule_id", schedule.ID, "template_id", schedule.TemplateID)
	return nil
}

// GetSchedule gets a schedule by ID
func (rs *ReportScheduler) GetSchedule(scheduleID string) (*ScheduleConfig, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	schedule, exists := rs.schedules[scheduleID]
	if !exists {
		return nil, fmt.Errorf("schedule not found: %s", scheduleID)
	}

	return schedule, nil
}

// ListSchedules lists all schedules
func (rs *ReportScheduler) ListSchedules() []*ScheduleConfig {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	schedules := make([]*ScheduleConfig, 0, len(rs.schedules))
	for _, schedule := range rs.schedules {
		schedules = append(schedules, schedule)
	}

	return schedules
}

// schedulerWorker runs the scheduler worker
func (rs *ReportScheduler) schedulerWorker(ctx context.Context) {
	ticker := time.NewTicker(rs.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rs.checkSchedules(ctx)
		}
	}
}

// checkSchedules checks for schedules that need to run
func (rs *ReportScheduler) checkSchedules(ctx context.Context) {
	rs.mu.RLock()
	schedules := make([]*ScheduleConfig, 0, len(rs.schedules))
	for _, schedule := range rs.schedules {
		if schedule.Enabled {
			schedules = append(schedules, schedule)
		}
	}
	rs.mu.RUnlock()

	for _, schedule := range schedules {
		if rs.shouldRunSchedule(schedule) {
			go rs.runScheduledReport(ctx, schedule)
		}
	}
}

// shouldRunSchedule checks if a schedule should run
func (rs *ReportScheduler) shouldRunSchedule(schedule *ScheduleConfig) bool {
	// Simplified check - in production, use proper cron parsing
	if schedule.NextRun == nil {
		return true
	}
	return time.Now().After(*schedule.NextRun)
}

// runScheduledReport runs a scheduled report
func (rs *ReportScheduler) runScheduledReport(ctx context.Context, schedule *ScheduleConfig) {
	rs.logger.Info("Running scheduled report", "schedule_id", schedule.ID, "template_id", schedule.TemplateID)
	
	// Update schedule
	rs.mu.Lock()
	now := time.Now()
	schedule.LastRun = &now
	schedule.RunCount++
	// Calculate next run time (simplified)
	nextRun := now.Add(24 * time.Hour) // Daily for now
	schedule.NextRun = &nextRun
	rs.mu.Unlock()

	// In a real implementation, this would trigger report generation
	rs.logger.Debug("Scheduled report completed", "schedule_id", schedule.ID)
}
