package health

import (
	"sort"
	"sync"
	"time"
)

// HealthHistory tracks health check results over time
type HealthHistory struct {
	records    map[string][]*HistoryRecord
	maxRecords int
	mutex      sync.RWMutex
}

// HistoryRecord represents a single health check record
type HistoryRecord struct {
	Timestamp time.Time              `json:"timestamp"`
	Status    Status                 `json:"status"`
	Duration  time.Duration          `json:"duration"`
	Message   string                 `json:"message"`
	Error     string                 `json:"error,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// HealthTrends provides trend analysis for health checks
type HealthTrends struct {
	history *HealthHistory
}

// TrendAnalysis represents trend analysis results
type TrendAnalysis struct {
	CheckName          string              `json:"check_name"`
	TimeWindow         time.Duration       `json:"time_window"`
	TotalChecks        int                 `json:"total_checks"`
	SuccessRate        float64             `json:"success_rate"`
	AverageLatency     time.Duration       `json:"average_latency"`
	P95Latency         time.Duration       `json:"p95_latency"`
	P99Latency         time.Duration       `json:"p99_latency"`
	StatusDistribution map[Status]int      `json:"status_distribution"`
	Trend              TrendDirection      `json:"trend"`
	RecentIncidents    []IncidentSummary   `json:"recent_incidents"`
	Availability       AvailabilityMetrics `json:"availability"`
}

// TrendDirection indicates the trend direction
type TrendDirection string

const (
	TrendImproving TrendDirection = "improving"
	TrendStable    TrendDirection = "stable"
	TrendDegrading TrendDirection = "degrading"
)

// IncidentSummary summarizes a health incident
type IncidentSummary struct {
	StartTime      time.Time     `json:"start_time"`
	EndTime        *time.Time    `json:"end_time,omitempty"`
	Duration       time.Duration `json:"duration"`
	Status         Status        `json:"status"`
	Resolved       bool          `json:"resolved"`
	AffectedChecks int           `json:"affected_checks"`
}

// AvailabilityMetrics provides availability statistics
type AvailabilityMetrics struct {
	Uptime        time.Duration `json:"uptime"`
	Downtime      time.Duration `json:"downtime"`
	MTBF          time.Duration `json:"mtbf"` // Mean Time Between Failures
	MTTR          time.Duration `json:"mttr"` // Mean Time To Recovery
	IncidentCount int           `json:"incident_count"`
}

// NewHealthHistory creates a new health history tracker
func NewHealthHistory(maxRecords int) *HealthHistory {
	if maxRecords == 0 {
		maxRecords = 10000 // Default to 10k records per checker
	}

	return &HealthHistory{
		records:    make(map[string][]*HistoryRecord),
		maxRecords: maxRecords,
	}
}

// AddRecord adds a health check record to history
func (hh *HealthHistory) AddRecord(checkName string, result CheckResult) {
	hh.mutex.Lock()
	defer hh.mutex.Unlock()

	record := &HistoryRecord{
		Timestamp: result.Timestamp,
		Status:    result.Status,
		Duration:  result.Duration,
		Message:   result.Message,
		Error:     result.Error,
		Metadata:  result.Metadata,
	}

	records := hh.records[checkName]
	records = append(records, record)

	// Trim records if exceeding max
	if len(records) > hh.maxRecords {
		records = records[len(records)-hh.maxRecords:]
	}

	hh.records[checkName] = records
}

// GetRecords returns health check records for a specific checker within a time window
func (hh *HealthHistory) GetRecords(checkName string, since time.Time) []*HistoryRecord {
	hh.mutex.RLock()
	defer hh.mutex.RUnlock()

	records := hh.records[checkName]
	if records == nil {
		return []*HistoryRecord{}
	}

	// Filter records by time
	filtered := make([]*HistoryRecord, 0)
	for _, record := range records {
		if record.Timestamp.After(since) {
			filtered = append(filtered, record)
		}
	}

	return filtered
}

// GetAllRecords returns all records for a checker
func (hh *HealthHistory) GetAllRecords(checkName string) []*HistoryRecord {
	hh.mutex.RLock()
	defer hh.mutex.RUnlock()

	records := hh.records[checkName]
	if records == nil {
		return []*HistoryRecord{}
	}

	// Return a copy
	result := make([]*HistoryRecord, len(records))
	copy(result, records)
	return result
}

// GetCheckerNames returns all checker names with history
func (hh *HealthHistory) GetCheckerNames() []string {
	hh.mutex.RLock()
	defer hh.mutex.RUnlock()

	names := make([]string, 0, len(hh.records))
	for name := range hh.records {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

// GetStats returns history statistics
func (hh *HealthHistory) GetStats() map[string]interface{} {
	hh.mutex.RLock()
	defer hh.mutex.RUnlock()

	totalRecords := 0
	for _, records := range hh.records {
		totalRecords += len(records)
	}

	return map[string]interface{}{
		"total_checkers": len(hh.records),
		"total_records":  totalRecords,
		"max_records":    hh.maxRecords,
	}
}

// Cleanup removes old records beyond the retention period
func (hh *HealthHistory) Cleanup(retentionPeriod time.Duration) {
	hh.mutex.Lock()
	defer hh.mutex.Unlock()

	cutoff := time.Now().Add(-retentionPeriod)

	for checkName, records := range hh.records {
		filtered := make([]*HistoryRecord, 0)
		for _, record := range records {
			if record.Timestamp.After(cutoff) {
				filtered = append(filtered, record)
			}
		}
		hh.records[checkName] = filtered
	}
}

// NewHealthTrends creates a new health trends analyzer
func NewHealthTrends(history *HealthHistory) *HealthTrends {
	return &HealthTrends{
		history: history,
	}
}

// AnalyzeTrends analyzes trends for a specific checker
func (ht *HealthTrends) AnalyzeTrends(checkName string, timeWindow time.Duration) *TrendAnalysis {
	since := time.Now().Add(-timeWindow)
	records := ht.history.GetRecords(checkName, since)

	if len(records) == 0 {
		return &TrendAnalysis{
			CheckName:          checkName,
			TimeWindow:         timeWindow,
			StatusDistribution: make(map[Status]int),
			RecentIncidents:    []IncidentSummary{},
		}
	}

	analysis := &TrendAnalysis{
		CheckName:          checkName,
		TimeWindow:         timeWindow,
		TotalChecks:        len(records),
		StatusDistribution: make(map[Status]int),
		RecentIncidents:    []IncidentSummary{},
	}

	// Calculate basic metrics
	var totalDuration time.Duration
	durations := make([]time.Duration, 0, len(records))
	successCount := 0

	for _, record := range records {
		analysis.StatusDistribution[record.Status]++
		totalDuration += record.Duration
		durations = append(durations, record.Duration)

		if record.Status == StatusHealthy {
			successCount++
		}
	}

	analysis.SuccessRate = float64(successCount) / float64(len(records))
	analysis.AverageLatency = totalDuration / time.Duration(len(records))

	// Calculate percentiles
	sort.Slice(durations, func(i, j int) bool {
		return durations[i] < durations[j]
	})

	if len(durations) > 0 {
		p95Index := int(float64(len(durations)) * 0.95)
		p99Index := int(float64(len(durations)) * 0.99)

		if p95Index >= len(durations) {
			p95Index = len(durations) - 1
		}
		if p99Index >= len(durations) {
			p99Index = len(durations) - 1
		}

		analysis.P95Latency = durations[p95Index]
		analysis.P99Latency = durations[p99Index]
	}

	// Analyze trend direction
	analysis.Trend = ht.calculateTrendDirection(records)

	// Find recent incidents
	analysis.RecentIncidents = ht.findIncidents(records)

	// Calculate availability metrics
	analysis.Availability = ht.calculateAvailability(records, timeWindow)

	return analysis
}

// calculateTrendDirection determines if the trend is improving, stable, or degrading
func (ht *HealthTrends) calculateTrendDirection(records []*HistoryRecord) TrendDirection {
	if len(records) < 10 {
		return TrendStable // Not enough data
	}

	// Split records into two halves and compare success rates
	mid := len(records) / 2
	firstHalf := records[:mid]
	secondHalf := records[mid:]

	firstSuccess := 0
	secondSuccess := 0

	for _, record := range firstHalf {
		if record.Status == StatusHealthy {
			firstSuccess++
		}
	}

	for _, record := range secondHalf {
		if record.Status == StatusHealthy {
			secondSuccess++
		}
	}

	firstRate := float64(firstSuccess) / float64(len(firstHalf))
	secondRate := float64(secondSuccess) / float64(len(secondHalf))

	diff := secondRate - firstRate

	if diff > 0.1 { // 10% improvement
		return TrendImproving
	} else if diff < -0.1 { // 10% degradation
		return TrendDegrading
	}

	return TrendStable
}

// findIncidents identifies incidents (periods of unhealthy status)
func (ht *HealthTrends) findIncidents(records []*HistoryRecord) []IncidentSummary {
	incidents := make([]IncidentSummary, 0)

	var currentIncident *IncidentSummary

	for _, record := range records {
		if record.Status == StatusUnhealthy {
			if currentIncident == nil {
				// Start new incident
				currentIncident = &IncidentSummary{
					StartTime:      record.Timestamp,
					Status:         record.Status,
					Resolved:       false,
					AffectedChecks: 1,
				}
			}
		} else if currentIncident != nil {
			// End current incident
			currentIncident.EndTime = &record.Timestamp
			currentIncident.Duration = record.Timestamp.Sub(currentIncident.StartTime)
			currentIncident.Resolved = true

			incidents = append(incidents, *currentIncident)
			currentIncident = nil
		}
	}

	// Handle ongoing incident
	if currentIncident != nil {
		now := time.Now()
		currentIncident.EndTime = &now
		currentIncident.Duration = now.Sub(currentIncident.StartTime)
		incidents = append(incidents, *currentIncident)
	}

	return incidents
}

// calculateAvailability calculates availability metrics
func (ht *HealthTrends) calculateAvailability(records []*HistoryRecord, timeWindow time.Duration) AvailabilityMetrics {
	if len(records) == 0 {
		return AvailabilityMetrics{}
	}

	var uptime, downtime time.Duration
	var incidentCount int
	var totalIncidentDuration time.Duration

	incidents := ht.findIncidents(records)
	incidentCount = len(incidents)

	for _, incident := range incidents {
		totalIncidentDuration += incident.Duration
	}

	downtime = totalIncidentDuration
	uptime = timeWindow - downtime

	var mtbf, mttr time.Duration
	if incidentCount > 0 {
		mttr = totalIncidentDuration / time.Duration(incidentCount)
		if incidentCount > 1 {
			mtbf = uptime / time.Duration(incidentCount-1)
		}
	}

	return AvailabilityMetrics{
		Uptime:        uptime,
		Downtime:      downtime,
		MTBF:          mtbf,
		MTTR:          mttr,
		IncidentCount: incidentCount,
	}
}

// GetOverallTrends returns trend analysis for all checkers
func (ht *HealthTrends) GetOverallTrends(timeWindow time.Duration) map[string]*TrendAnalysis {
	checkerNames := ht.history.GetCheckerNames()
	trends := make(map[string]*TrendAnalysis)

	for _, name := range checkerNames {
		trends[name] = ht.AnalyzeTrends(name, timeWindow)
	}

	return trends
}

// GetSystemHealth returns overall system health based on all checkers
func (ht *HealthTrends) GetSystemHealth(timeWindow time.Duration) map[string]interface{} {
	trends := ht.GetOverallTrends(timeWindow)

	totalCheckers := len(trends)
	healthyCheckers := 0
	degradedCheckers := 0
	unhealthyCheckers := 0

	var totalSuccessRate float64
	var totalAvailability float64
	var totalIncidents int

	for _, trend := range trends {
		totalSuccessRate += trend.SuccessRate
		totalIncidents += trend.Availability.IncidentCount

		availability := float64(trend.Availability.Uptime) / float64(trend.TimeWindow)
		totalAvailability += availability

		if trend.SuccessRate >= 0.95 {
			healthyCheckers++
		} else if trend.SuccessRate >= 0.8 {
			degradedCheckers++
		} else {
			unhealthyCheckers++
		}
	}

	var avgSuccessRate, avgAvailability float64
	if totalCheckers > 0 {
		avgSuccessRate = totalSuccessRate / float64(totalCheckers)
		avgAvailability = totalAvailability / float64(totalCheckers)
	}

	return map[string]interface{}{
		"total_checkers":     totalCheckers,
		"healthy_checkers":   healthyCheckers,
		"degraded_checkers":  degradedCheckers,
		"unhealthy_checkers": unhealthyCheckers,
		"avg_success_rate":   avgSuccessRate,
		"avg_availability":   avgAvailability,
		"total_incidents":    totalIncidents,
		"time_window":        timeWindow.String(),
	}
}
