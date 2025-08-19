package reporting

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// AnalyticsEngine provides automated reporting and analytics
type AnalyticsEngine struct {
	logger         *logger.Logger
	config         *AnalyticsConfig
	reportManager  *ReportManager
	scheduler      *ReportScheduler
	dataCollectors map[string]DataCollector
	processors     map[string]DataProcessor
	exporters      map[string]ReportExporter
	mu             sync.RWMutex
	isRunning      bool
}

// AnalyticsConfig configuration for analytics engine
type AnalyticsConfig struct {
	EnableScheduling     bool          `json:"enable_scheduling"`
	DefaultRetention     time.Duration `json:"default_retention"`
	MaxReports           int           `json:"max_reports"`
	MaxDataPoints        int           `json:"max_data_points"`
	EnableRealTimeAnalysis bool        `json:"enable_real_time_analysis"`
	AnalysisInterval     time.Duration `json:"analysis_interval"`
	EnablePredictive     bool          `json:"enable_predictive"`
	EnableAnomalyDetection bool        `json:"enable_anomaly_detection"`
	ExportFormats        []string      `json:"export_formats"`
	NotificationChannels []string      `json:"notification_channels"`
}

// ReportManager manages report generation and storage
type ReportManager struct {
	logger    *logger.Logger
	config    *ReportConfig
	reports   map[string]*Report
	templates map[string]*ReportTemplate
	mu        sync.RWMutex
}

// ReportConfig configuration for report manager
type ReportConfig struct {
	MaxReports       int           `json:"max_reports"`
	DefaultFormat    string        `json:"default_format"`
	RetentionPeriod  time.Duration `json:"retention_period"`
	EnableVersioning bool          `json:"enable_versioning"`
	EnableCompression bool         `json:"enable_compression"`
}

// Report represents a generated report
type Report struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	TemplateID  string                 `json:"template_id"`
	Data        *ReportData            `json:"data"`
	Metadata    *ReportMetadata        `json:"metadata"`
	Status      string                 `json:"status"`
	CreatedAt   time.Time              `json:"created_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	CreatedBy   string                 `json:"created_by"`
	Tags        []string               `json:"tags"`
	Format      string                 `json:"format"`
	Size        int64                  `json:"size"`
	Version     int                    `json:"version"`
	Config      map[string]interface{} `json:"config"`
}

// ReportData contains the actual report data
type ReportData struct {
	Summary     *ReportSummary         `json:"summary"`
	Sections    []*ReportSection       `json:"sections"`
	Charts      []*ReportChart         `json:"charts"`
	Tables      []*ReportTable         `json:"tables"`
	Insights    []*ReportInsight       `json:"insights"`
	Recommendations []*ReportRecommendation `json:"recommendations"`
	Appendices  []*ReportAppendix      `json:"appendices"`
	RawData     map[string]interface{} `json:"raw_data"`
}

// ReportMetadata contains report metadata
type ReportMetadata struct {
	GenerationTime  time.Duration          `json:"generation_time"`
	DataSources     []string               `json:"data_sources"`
	TimeRange       *TimeRange             `json:"time_range"`
	Filters         map[string]interface{} `json:"filters"`
	Parameters      map[string]interface{} `json:"parameters"`
	Quality         *DataQuality           `json:"quality"`
	Compliance      *ComplianceInfo        `json:"compliance"`
	Security        *SecurityInfo          `json:"security"`
}

// ReportTemplate defines report structure
type ReportTemplate struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Category    string                 `json:"category"`
	Sections    []*TemplateSection     `json:"sections"`
	Parameters  []*TemplateParameter   `json:"parameters"`
	Schedule    *ScheduleConfig        `json:"schedule"`
	Recipients  []string               `json:"recipients"`
	Format      string                 `json:"format"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	CreatedBy   string                 `json:"created_by"`
	IsActive    bool                   `json:"is_active"`
	Version     int                    `json:"version"`
	Config      map[string]interface{} `json:"config"`
}

// ReportSummary provides executive summary
type ReportSummary struct {
	Title           string                 `json:"title"`
	ExecutiveSummary string                `json:"executive_summary"`
	KeyFindings     []string               `json:"key_findings"`
	KeyMetrics      map[string]interface{} `json:"key_metrics"`
	TrendAnalysis   *TrendAnalysis         `json:"trend_analysis"`
	RiskAssessment  *RiskAssessment        `json:"risk_assessment"`
	Recommendations []string               `json:"recommendations"`
	NextSteps       []string               `json:"next_steps"`
}

// ReportSection represents a report section
type ReportSection struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Content     string                 `json:"content"`
	Type        string                 `json:"type"`
	Order       int                    `json:"order"`
	Data        interface{}            `json:"data"`
	Charts      []*ReportChart         `json:"charts"`
	Tables      []*ReportTable         `json:"tables"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ReportChart represents a chart in the report
type ReportChart struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Type        string                 `json:"type"`
	Data        interface{}            `json:"data"`
	Config      *ChartConfig           `json:"config"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ReportTable represents a table in the report
type ReportTable struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Headers     []string               `json:"headers"`
	Rows        [][]interface{}        `json:"rows"`
	Config      *TableConfig           `json:"config"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ReportInsight represents an analytical insight
type ReportInsight struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Confidence  float64                `json:"confidence"`
	Impact      string                 `json:"impact"`
	Evidence    []string               `json:"evidence"`
	Actions     []string               `json:"actions"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ReportRecommendation represents a recommendation
type ReportRecommendation struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Priority    string                 `json:"priority"`
	Category    string                 `json:"category"`
	Impact      string                 `json:"impact"`
	Effort      string                 `json:"effort"`
	Timeline    string                 `json:"timeline"`
	Resources   []string               `json:"resources"`
	Dependencies []string              `json:"dependencies"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ReportAppendix represents an appendix
type ReportAppendix struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Content     string                 `json:"content"`
	Type        string                 `json:"type"`
	Data        interface{}            `json:"data"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// TimeRange represents a time range
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// DataQuality represents data quality metrics
type DataQuality struct {
	Completeness float64 `json:"completeness"`
	Accuracy     float64 `json:"accuracy"`
	Consistency  float64 `json:"consistency"`
	Timeliness   float64 `json:"timeliness"`
	Validity     float64 `json:"validity"`
	Overall      float64 `json:"overall"`
}

// ComplianceInfo represents compliance information
type ComplianceInfo struct {
	Standards   []string               `json:"standards"`
	Status      string                 `json:"status"`
	Violations  []string               `json:"violations"`
	Remediation []string               `json:"remediation"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// SecurityInfo represents security information
type SecurityInfo struct {
	Classification string                 `json:"classification"`
	AccessLevel    string                 `json:"access_level"`
	Encryption     bool                   `json:"encryption"`
	Retention      time.Duration          `json:"retention"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// TrendAnalysis represents trend analysis
type TrendAnalysis struct {
	Period      string             `json:"period"`
	Trends      []*Trend           `json:"trends"`
	Predictions []*Prediction      `json:"predictions"`
	Seasonality *SeasonalityInfo   `json:"seasonality"`
	Anomalies   []*AnomalyInfo     `json:"anomalies"`
}

// Trend represents a trend
type Trend struct {
	Metric    string  `json:"metric"`
	Direction string  `json:"direction"`
	Change    float64 `json:"change"`
	Period    string  `json:"period"`
	Confidence float64 `json:"confidence"`
}

// Prediction represents a prediction
type Prediction struct {
	Metric     string    `json:"metric"`
	Value      float64   `json:"value"`
	Confidence float64   `json:"confidence"`
	Timeframe  string    `json:"timeframe"`
	Factors    []string  `json:"factors"`
	ValidUntil time.Time `json:"valid_until"`
}

// SeasonalityInfo represents seasonality information
type SeasonalityInfo struct {
	HasSeasonality bool                   `json:"has_seasonality"`
	Patterns       []string               `json:"patterns"`
	Strength       float64                `json:"strength"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// AnomalyInfo represents anomaly information
type AnomalyInfo struct {
	Timestamp   time.Time              `json:"timestamp"`
	Metric      string                 `json:"metric"`
	Value       float64                `json:"value"`
	Expected    float64                `json:"expected"`
	Deviation   float64                `json:"deviation"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// RiskAssessment represents risk assessment
type RiskAssessment struct {
	OverallRisk string                 `json:"overall_risk"`
	RiskFactors []*RiskFactor          `json:"risk_factors"`
	Mitigation  []*MitigationStrategy  `json:"mitigation"`
	Timeline    string                 `json:"timeline"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// RiskFactor represents a risk factor
type RiskFactor struct {
	Name        string  `json:"name"`
	Probability float64 `json:"probability"`
	Impact      string  `json:"impact"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
}

// MitigationStrategy represents a mitigation strategy
type MitigationStrategy struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Priority    string   `json:"priority"`
	Timeline    string   `json:"timeline"`
	Resources   []string `json:"resources"`
	Effectiveness float64 `json:"effectiveness"`
}

// Interfaces
type DataCollector interface {
	CollectData(ctx context.Context, params map[string]interface{}) (interface{}, error)
	GetDataSources() []string
	ValidateParams(params map[string]interface{}) error
}

type DataProcessor interface {
	ProcessData(ctx context.Context, data interface{}) (interface{}, error)
	GetProcessorType() string
	GetCapabilities() []string
}

type ReportExporter interface {
	ExportReport(ctx context.Context, report *Report, format string) ([]byte, error)
	GetSupportedFormats() []string
	ValidateFormat(format string) error
}

// NewAnalyticsEngine creates a new analytics engine
func NewAnalyticsEngine(config *AnalyticsConfig, logger *logger.Logger) *AnalyticsEngine {
	if config == nil {
		config = DefaultAnalyticsConfig()
	}

	reportManager := NewReportManager(DefaultReportConfig(), logger)
	scheduler := NewReportScheduler(DefaultSchedulerConfig(), logger)

	return &AnalyticsEngine{
		logger:         logger,
		config:         config,
		reportManager:  reportManager,
		scheduler:      scheduler,
		dataCollectors: make(map[string]DataCollector),
		processors:     make(map[string]DataProcessor),
		exporters:      make(map[string]ReportExporter),
	}
}

// DefaultAnalyticsConfig returns default configuration
func DefaultAnalyticsConfig() *AnalyticsConfig {
	return &AnalyticsConfig{
		EnableScheduling:       true,
		DefaultRetention:       30 * 24 * time.Hour,
		MaxReports:             10000,
		MaxDataPoints:          1000000,
		EnableRealTimeAnalysis: true,
		AnalysisInterval:       15 * time.Minute,
		EnablePredictive:       true,
		EnableAnomalyDetection: true,
		ExportFormats:          []string{"json", "csv", "pdf", "html"},
		NotificationChannels:   []string{"email", "slack", "webhook"},
	}
}

// Start starts the analytics engine
func (ae *AnalyticsEngine) Start(ctx context.Context) error {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	
	if ae.isRunning {
		return fmt.Errorf("analytics engine is already running")
	}
	
	// Start the report manager
	if err := ae.reportManager.Start(ctx); err != nil {
		return fmt.Errorf("failed to start report manager: %w", err)
	}
	
	ae.isRunning = true
	ae.logger.Info("Analytics engine started")
	return nil
}

// Stop stops the analytics engine
func (ae *AnalyticsEngine) Stop(ctx context.Context) error {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	
	if !ae.isRunning {
		// Already stopped, no error
		return nil
	}
	
	ae.isRunning = false
	ae.logger.Info("Analytics engine stopped")
	return nil
}

// RegisterDataCollector registers a data collector
func (ae *AnalyticsEngine) RegisterDataCollector(name string, collector DataCollector) {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	
	ae.dataCollectors[name] = collector
	ae.logger.Info("Registered data collector", "name", name)
}

// GenerateReport generates a report
func (ae *AnalyticsEngine) GenerateReport(ctx context.Context, templateID string, params map[string]interface{}) (*Report, error) {
	ae.mu.RLock()
	defer ae.mu.RUnlock()
	
	if !ae.isRunning {
		return nil, fmt.Errorf("analytics engine is not running")
	}
	
	return ae.reportManager.GenerateReport(ctx, templateID, params)
}

// RegisterDataProcessor registers a data processor
func (ae *AnalyticsEngine) RegisterDataProcessor(name string, processor DataProcessor) {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	
	ae.processors[name] = processor
	ae.logger.Info("Registered data processor", "name", name)
}

// RegisterReportExporter registers a report exporter
func (ae *AnalyticsEngine) RegisterReportExporter(name string, exporter ReportExporter) {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	
	ae.exporters[name] = exporter
	ae.logger.Info("Registered report exporter", "name", name)
}

// ExportReport exports a report in the specified format
func (ae *AnalyticsEngine) ExportReport(ctx context.Context, reportID string, format string) ([]byte, error) {
	ae.mu.RLock()
	defer ae.mu.RUnlock()
	
	if !ae.isRunning {
		return nil, fmt.Errorf("analytics engine is not running")
	}
	
	report, err := ae.reportManager.GetReport(reportID)
	if err != nil {
		return nil, fmt.Errorf("failed to get report: %w", err)
	}
	
	// Try to use registered exporters first
	for _, exporter := range ae.exporters {
		formats := exporter.GetSupportedFormats()
		for _, supportedFormat := range formats {
			if supportedFormat == format {
				return exporter.ExportReport(ctx, report, format)
			}
		}
	}
	
	// Fallback to simple JSON export
	if format == "json" {
		return []byte(fmt.Sprintf(`{"id":"%s","status":"%s","template_id":"%s"}`, 
			report.ID, report.Status, report.TemplateID)), nil
	}
	
	return nil, fmt.Errorf("unsupported format: %s", format)
}
