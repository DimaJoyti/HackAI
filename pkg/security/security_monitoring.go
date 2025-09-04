package security

import (
	"time"
)

// MonitoringConfig configuration for security monitoring
type MonitoringConfig struct {
	Enabled          bool          `json:"enabled"`
	DashboardEnabled bool          `json:"dashboard_enabled"`
	RealTimeUpdates  bool          `json:"real_time_updates"`
	UpdateInterval   time.Duration `json:"update_interval"`
	RetentionPeriod  time.Duration `json:"retention_period"`
}

// Various monitoring data structures (simplified versions)
type DashboardData struct {
	Overview        *SecurityOverview             `json:"overview"`
	ThreatAnalysis  *ThreatAnalysis              `json:"threat_analysis"`
	ComponentStatus *MonitoringComponentStatus   `json:"component_status"`
	PerformanceData *PerformanceData             `json:"performance_data"`
	RecentEvents    []*SecurityEvent             `json:"recent_events"`
	AlertSummary    *MonitoringAlertSummary      `json:"alert_summary"`
	TrendData       *TrendData                   `json:"trend_data"`
}

type SecurityOverview struct {
	SystemHealth  string              `json:"system_health"`
	TotalThreats  int                 `json:"total_threats"`
	ActiveAlerts  int                 `json:"active_alerts"`
	SystemUptime  string              `json:"system_uptime"`
	LastScanTime  time.Time           `json:"last_scan_time"`
	TopThreats    []*ThreatSummary    `json:"top_threats"`
}

type ThreatAnalysis struct {
	TotalThreats     int                        `json:"total_threats"`
	HighSeverity     int                        `json:"high_severity"`
	MediumSeverity   int                        `json:"medium_severity"`
	LowSeverity      int                        `json:"low_severity"`
	ThreatTrends     []*MonitoringThreatTrend   `json:"threat_trends"`
	TopAttackVectors []string                   `json:"top_attack_vectors"`
	Mitigated        int                        `json:"mitigated"`
	InProgress       int                        `json:"in_progress"`
}

type MonitoringComponentStatus struct {
	TotalComponents    int                            `json:"total_components"`
	HealthyComponents  int                            `json:"healthy_components"`
	UnhealthyComponents int                           `json:"unhealthy_components"`
	Components         map[string]*ComponentMetrics   `json:"components"`
	LastUpdateTime     time.Time                      `json:"last_update_time"`
}

// Note: ComponentMetrics is defined in security_metrics.go

type PerformanceData struct {
	RequestsPerSecond   float64   `json:"requests_per_second"`
	ErrorRate           float64   `json:"error_rate"`
	AverageResponseTime float64   `json:"average_response_time"`
	TotalRequests       int64     `json:"total_requests"`
	TotalErrors         int64     `json:"total_errors"`
	Uptime              string    `json:"uptime"`
	LastUpdateTime      time.Time `json:"last_update_time"`
}

type MonitoringAlertSummary struct {
	TotalAlerts    int    `json:"total_alerts"`
	CriticalAlerts int    `json:"critical_alerts"`
	HighAlerts     int    `json:"high_alerts"`
	MediumAlerts   int    `json:"medium_alerts"`
	LowAlerts      int    `json:"low_alerts"`
	ResolvedAlerts int    `json:"resolved_alerts"`
	LastAlertTime  string `json:"last_alert_time"`
}

type TrendData struct {
	ThreatTrends      []*MonitoringThreatTrend `json:"threat_trends"`
	PerformanceTrends []*PerformanceTrend      `json:"performance_trends"`
	AlertTrends       []*AlertTrend            `json:"alert_trends"`
	TimeRange         string                   `json:"time_range"`
}

type ThreatSummary struct {
	Type        string  `json:"type"`
	Count       int     `json:"count"`
	Severity    string  `json:"severity"`
	TrendChange float64 `json:"trend_change"`
	LastSeen    string  `json:"last_seen"`
}

type MonitoringThreatTrend struct {
	ThreatType string       `json:"threat_type"`
	Data       []*DataPoint `json:"data"`
	Trend      string       `json:"trend"`
}

type PerformanceTrend struct {
	Metric string       `json:"metric"`
	Data   []*DataPoint `json:"data"`
	Unit   string       `json:"unit"`
}

type AlertTrend struct {
	Severity string       `json:"severity"`
	Data     []*DataPoint `json:"data"`
}

type DataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
	Label     string    `json:"label,omitempty"`
}

// Note: Most SecurityMonitor methods have been removed due to incompatibility with current struct definition
// The SecurityMonitor type itself is defined in advanced_security_components.go