package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// LogAnalyzerUseCase implements AI-powered log analysis
type LogAnalyzerUseCase struct {
	repo   domain.SecurityRepository
	logger *logger.Logger
}

// LogEntry represents a structured log entry
type LogEntry struct {
	ID        uuid.UUID              `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Source    string                 `json:"source"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields"`
	Raw       string                 `json:"raw"`
}

// SecurityEvent represents a detected security event
type SecurityEvent struct {
	ID          uuid.UUID   `json:"id"`
	Type        string      `json:"type"`        // attack_type, anomaly, etc.
	Severity    string      `json:"severity"`    // critical, high, medium, low
	Confidence  float64     `json:"confidence"`  // 0.0 to 1.0
	Description string      `json:"description"`
	Source      string      `json:"source"`
	Timestamp   time.Time   `json:"timestamp"`
	Evidence    []LogEntry  `json:"evidence"`
	Indicators  []string    `json:"indicators"`
	Remediation []string    `json:"remediation"`
}

// AnomalyPattern represents detected anomalous patterns
type AnomalyPattern struct {
	Type        string    `json:"type"`
	Pattern     string    `json:"pattern"`
	Frequency   int       `json:"frequency"`
	Baseline    float64   `json:"baseline"`
	Current     float64   `json:"current"`
	Deviation   float64   `json:"deviation"`
	Confidence  float64   `json:"confidence"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// LogAnalysisReport represents comprehensive log analysis results
type LogAnalysisReport struct {
	ID               uuid.UUID         `json:"id"`
	TimeRange        TimeRange         `json:"time_range"`
	TotalLogs        int               `json:"total_logs"`
	SecurityEvents   []SecurityEvent   `json:"security_events"`
	Anomalies        []AnomalyPattern  `json:"anomalies"`
	TopSources       []SourceStats     `json:"top_sources"`
	TopErrors        []ErrorStats      `json:"top_errors"`
	ThreatSummary    ThreatSummary     `json:"threat_summary"`
	Recommendations  []string          `json:"recommendations"`
	GeneratedAt      time.Time         `json:"generated_at"`
}

type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type SourceStats struct {
	Source string `json:"source"`
	Count  int    `json:"count"`
}

type ErrorStats struct {
	Error string `json:"error"`
	Count int    `json:"count"`
}

type ThreatSummary struct {
	CriticalEvents int     `json:"critical_events"`
	HighEvents     int     `json:"high_events"`
	MediumEvents   int     `json:"medium_events"`
	LowEvents      int     `json:"low_events"`
	RiskScore      float64 `json:"risk_score"`
}

// NewLogAnalyzerUseCase creates a new log analyzer use case
func NewLogAnalyzerUseCase(repo domain.SecurityRepository, log *logger.Logger) *LogAnalyzerUseCase {
	return &LogAnalyzerUseCase{
		repo:   repo,
		logger: log,
	}
}

// AnalyzeLogs performs comprehensive AI-powered log analysis
func (l *LogAnalyzerUseCase) AnalyzeLogs(ctx context.Context, logs []string, timeRange TimeRange) (*LogAnalysisReport, error) {
	report := &LogAnalysisReport{
		ID:          uuid.New(),
		TimeRange:   timeRange,
		TotalLogs:   len(logs),
		GeneratedAt: time.Now(),
	}

	// Parse and structure log entries
	logEntries, err := l.parseLogEntries(logs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse log entries: %w", err)
	}

	// Detect security events using AI patterns
	securityEvents := l.detectSecurityEvents(logEntries)
	report.SecurityEvents = securityEvents

	// Detect anomalies using statistical analysis
	anomalies := l.detectAnomalies(logEntries)
	report.Anomalies = anomalies

	// Generate statistics
	report.TopSources = l.generateSourceStats(logEntries)
	report.TopErrors = l.generateErrorStats(logEntries)
	report.ThreatSummary = l.generateThreatSummary(securityEvents)

	// Generate recommendations
	report.Recommendations = l.generateRecommendations(securityEvents, anomalies)

	l.logger.WithContext(ctx).WithFields(logger.Fields{
		"total_logs":       len(logs),
		"security_events":  len(securityEvents),
		"anomalies":        len(anomalies),
		"risk_score":       report.ThreatSummary.RiskScore,
	}).Info("Log analysis completed")

	return report, nil
}

// parseLogEntries parses raw log strings into structured entries
func (l *LogAnalyzerUseCase) parseLogEntries(logs []string) ([]LogEntry, error) {
	var entries []LogEntry

	for _, logLine := range logs {
		entry, err := l.parseLogEntry(logLine)
		if err != nil {
			l.logger.WithError(err).Warn("Failed to parse log entry")
			continue
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// parseLogEntry parses a single log line into a structured entry
func (l *LogAnalyzerUseCase) parseLogEntry(logLine string) (LogEntry, error) {
	entry := LogEntry{
		ID:     uuid.New(),
		Raw:    logLine,
		Fields: make(map[string]interface{}),
	}

	// Try to parse as JSON first
	if strings.HasPrefix(logLine, "{") {
		var jsonLog map[string]interface{}
		if err := json.Unmarshal([]byte(logLine), &jsonLog); err == nil {
			return l.parseJSONLog(jsonLog, logLine)
		}
	}

	// Parse common log formats
	if parsed := l.parseCommonLogFormat(logLine); parsed != nil {
		return *parsed, nil
	}

	// Parse syslog format
	if parsed := l.parseSyslogFormat(logLine); parsed != nil {
		return *parsed, nil
	}

	// Parse Apache/Nginx access logs
	if parsed := l.parseAccessLogFormat(logLine); parsed != nil {
		return *parsed, nil
	}

	// Default parsing - extract basic information
	entry.Message = logLine
	entry.Timestamp = time.Now()
	entry.Level = l.extractLogLevel(logLine)
	entry.Source = l.extractSource(logLine)

	return entry, nil
}

// detectSecurityEvents uses AI patterns to detect security events
func (l *LogAnalyzerUseCase) detectSecurityEvents(entries []LogEntry) []SecurityEvent {
	var events []SecurityEvent

	// Group entries by time windows for pattern analysis
	timeWindows := l.groupByTimeWindows(entries, 5*time.Minute)

	for _, window := range timeWindows {
		// Detect various attack patterns
		events = append(events, l.detectBruteForceAttacks(window)...)
		events = append(events, l.detectSQLInjectionAttempts(window)...)
		events = append(events, l.detectXSSAttempts(window)...)
		events = append(events, l.detectDirectoryTraversalAttempts(window)...)
		events = append(events, l.detectDDoSAttempts(window)...)
		events = append(events, l.detectPrivilegeEscalation(window)...)
		events = append(events, l.detectDataExfiltration(window)...)
		events = append(events, l.detectMalwareActivity(window)...)
	}

	return events
}

// detectBruteForceAttacks detects brute force authentication attempts
func (l *LogAnalyzerUseCase) detectBruteForceAttacks(entries []LogEntry) []SecurityEvent {
	var events []SecurityEvent

	// Count failed login attempts by IP
	failedLogins := make(map[string][]LogEntry)
	
	for _, entry := range entries {
		if l.isFailedLoginAttempt(entry) {
			ip := l.extractIPAddress(entry)
			if ip != "" {
				failedLogins[ip] = append(failedLogins[ip], entry)
			}
		}
	}

	// Detect brute force patterns
	for ip, attempts := range failedLogins {
		if len(attempts) >= 10 { // Threshold for brute force
			event := SecurityEvent{
				ID:          uuid.New(),
				Type:        "brute_force_attack",
				Severity:    l.calculateBruteForceSeverity(len(attempts)),
				Confidence:  l.calculateBruteForceConfidence(attempts),
				Description: fmt.Sprintf("Brute force attack detected from IP %s with %d failed login attempts", ip, len(attempts)),
				Source:      ip,
				Timestamp:   attempts[0].Timestamp,
				Evidence:    attempts,
				Indicators:  []string{fmt.Sprintf("failed_logins:%d", len(attempts)), fmt.Sprintf("source_ip:%s", ip)},
				Remediation: []string{
					fmt.Sprintf("Block IP address %s", ip),
					"Implement account lockout policies",
					"Enable multi-factor authentication",
					"Monitor for additional suspicious activity",
				},
			}
			events = append(events, event)
		}
	}

	return events
}

// detectSQLInjectionAttempts detects SQL injection attack patterns
func (l *LogAnalyzerUseCase) detectSQLInjectionAttempts(entries []LogEntry) []SecurityEvent {
	var events []SecurityEvent

	sqlInjectionPatterns := []string{
		`(?i)union\s+select`,
		`(?i)or\s+1\s*=\s*1`,
		`(?i)and\s+1\s*=\s*1`,
		`(?i)drop\s+table`,
		`(?i)insert\s+into`,
		`(?i)delete\s+from`,
		`(?i)update\s+.*\s+set`,
		`(?i)exec\s*\(`,
		`(?i)script\s*>`,
		`(?i)javascript:`,
		`'.*or.*'.*'`,
		`".*or.*".*"`,
	}

	for _, entry := range entries {
		for _, pattern := range sqlInjectionPatterns {
			if matched, _ := regexp.MatchString(pattern, entry.Message); matched {
				event := SecurityEvent{
					ID:          uuid.New(),
					Type:        "sql_injection_attempt",
					Severity:    "high",
					Confidence:  0.8,
					Description: "SQL injection attempt detected in request",
					Source:      l.extractIPAddress(entry),
					Timestamp:   entry.Timestamp,
					Evidence:    []LogEntry{entry},
					Indicators:  []string{fmt.Sprintf("pattern:%s", pattern)},
					Remediation: []string{
						"Implement parameterized queries",
						"Validate and sanitize input",
						"Use web application firewall",
						"Review application code for vulnerabilities",
					},
				}
				events = append(events, event)
				break
			}
		}
	}

	return events
}

// detectXSSAttempts detects cross-site scripting attack patterns
func (l *LogAnalyzerUseCase) detectXSSAttempts(entries []LogEntry) []SecurityEvent {
	var events []SecurityEvent

	xssPatterns := []string{
		`<script[^>]*>.*?</script>`,
		`javascript:`,
		`on\w+\s*=`,
		`<iframe[^>]*>`,
		`<object[^>]*>`,
		`<embed[^>]*>`,
		`<link[^>]*>`,
		`<meta[^>]*>`,
		`<img[^>]*onerror`,
		`<svg[^>]*onload`,
	}

	for _, entry := range entries {
		for _, pattern := range xssPatterns {
			if matched, _ := regexp.MatchString(pattern, entry.Message); matched {
				event := SecurityEvent{
					ID:          uuid.New(),
					Type:        "xss_attempt",
					Severity:    "medium",
					Confidence:  0.7,
					Description: "Cross-site scripting (XSS) attempt detected",
					Source:      l.extractIPAddress(entry),
					Timestamp:   entry.Timestamp,
					Evidence:    []LogEntry{entry},
					Indicators:  []string{fmt.Sprintf("pattern:%s", pattern)},
					Remediation: []string{
						"Implement output encoding",
						"Use Content Security Policy (CSP)",
						"Validate and sanitize input",
						"Use web application firewall",
					},
				}
				events = append(events, event)
				break
			}
		}
	}

	return events
}

// detectAnomalies uses statistical analysis to detect anomalous patterns
func (l *LogAnalyzerUseCase) detectAnomalies(entries []LogEntry) []AnomalyPattern {
	var anomalies []AnomalyPattern

	// Analyze request frequency anomalies
	anomalies = append(anomalies, l.detectFrequencyAnomalies(entries)...)

	// Analyze error rate anomalies
	anomalies = append(anomalies, l.detectErrorRateAnomalies(entries)...)

	// Analyze response time anomalies
	anomalies = append(anomalies, l.detectResponseTimeAnomalies(entries)...)

	// Analyze user behavior anomalies
	anomalies = append(anomalies, l.detectUserBehaviorAnomalies(entries)...)

	return anomalies
}

// detectFrequencyAnomalies detects unusual request frequency patterns
func (l *LogAnalyzerUseCase) detectFrequencyAnomalies(entries []LogEntry) []AnomalyPattern {
	var anomalies []AnomalyPattern

	// Group entries by hour
	hourlyCount := make(map[int]int)
	for _, entry := range entries {
		hour := entry.Timestamp.Hour()
		hourlyCount[hour]++
	}

	// Calculate baseline (average)
	total := 0
	for _, count := range hourlyCount {
		total += count
	}
	baseline := float64(total) / 24.0

	// Detect anomalies (requests significantly above baseline)
	for hour, count := range hourlyCount {
		if float64(count) > baseline*2.0 { // 2x baseline threshold
			deviation := (float64(count) - baseline) / baseline
			anomaly := AnomalyPattern{
				Type:       "request_frequency",
				Pattern:    fmt.Sprintf("hour_%d", hour),
				Frequency:  count,
				Baseline:   baseline,
				Current:    float64(count),
				Deviation:  deviation,
				Confidence: l.calculateAnomalyConfidence(deviation),
				FirstSeen:  time.Now().Add(-time.Duration(24-hour) * time.Hour),
				LastSeen:   time.Now().Add(-time.Duration(24-hour) * time.Hour),
			}
			anomalies = append(anomalies, anomaly)
		}
	}

	return anomalies
}

// Helper methods

func (l *LogAnalyzerUseCase) parseJSONLog(jsonLog map[string]interface{}, raw string) (LogEntry, error) {
	entry := LogEntry{
		ID:     uuid.New(),
		Raw:    raw,
		Fields: jsonLog,
	}

	// Extract common fields
	if timestamp, ok := jsonLog["timestamp"].(string); ok {
		if t, err := time.Parse(time.RFC3339, timestamp); err == nil {
			entry.Timestamp = t
		}
	}

	if level, ok := jsonLog["level"].(string); ok {
		entry.Level = level
	}

	if message, ok := jsonLog["message"].(string); ok {
		entry.Message = message
	}

	if source, ok := jsonLog["source"].(string); ok {
		entry.Source = source
	}

	return entry, nil
}

func (l *LogAnalyzerUseCase) parseCommonLogFormat(logLine string) *LogEntry {
	// Parse Common Log Format: IP - - [timestamp] "method path protocol" status size
	pattern := `^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d+) (\S+)`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(logLine)

	if len(matches) >= 6 {
		entry := LogEntry{
			ID:      uuid.New(),
			Raw:     logLine,
			Message: logLine,
			Fields:  make(map[string]interface{}),
		}

		entry.Fields["ip"] = matches[1]
		entry.Fields["request"] = matches[3]
		entry.Fields["status"] = matches[4]
		entry.Fields["size"] = matches[5]

		// Parse timestamp
		if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[2]); err == nil {
			entry.Timestamp = t
		}

		return &entry
	}

	return nil
}

func (l *LogAnalyzerUseCase) parseSyslogFormat(logLine string) *LogEntry {
	// Parse syslog format: timestamp hostname service: message
	pattern := `^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:]+):\s*(.*)$`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(logLine)

	if len(matches) >= 5 {
		entry := LogEntry{
			ID:      uuid.New(),
			Raw:     logLine,
			Message: matches[4],
			Source:  matches[3],
			Fields:  make(map[string]interface{}),
		}

		entry.Fields["hostname"] = matches[2]

		// Parse timestamp (simplified)
		if t, err := time.Parse("Jan 2 15:04:05", matches[1]); err == nil {
			// Add current year
			entry.Timestamp = t.AddDate(time.Now().Year(), 0, 0)
		}

		return &entry
	}

	return nil
}

func (l *LogAnalyzerUseCase) parseAccessLogFormat(logLine string) *LogEntry {
	// Similar to common log format but with more fields
	return l.parseCommonLogFormat(logLine)
}

func (l *LogAnalyzerUseCase) extractLogLevel(logLine string) string {
	levels := []string{"FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"}
	logUpper := strings.ToUpper(logLine)
	
	for _, level := range levels {
		if strings.Contains(logUpper, level) {
			return level
		}
	}
	
	return "INFO"
}

func (l *LogAnalyzerUseCase) extractSource(logLine string) string {
	// Try to extract source from common patterns
	patterns := []string{
		`\[([^\]]+)\]`,
		`(\w+):\s`,
		`^(\w+)\s`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(logLine)
		if len(matches) >= 2 {
			return matches[1]
		}
	}

	return "unknown"
}

func (l *LogAnalyzerUseCase) extractIPAddress(entry LogEntry) string {
	// Try to extract IP from various fields
	if ip, ok := entry.Fields["ip"].(string); ok {
		return ip
	}

	// Extract from message using regex
	ipPattern := `\b(?:\d{1,3}\.){3}\d{1,3}\b`
	re := regexp.MustCompile(ipPattern)
	matches := re.FindStringSubmatch(entry.Message)
	if len(matches) > 0 {
		return matches[0]
	}

	return ""
}

func (l *LogAnalyzerUseCase) isFailedLoginAttempt(entry LogEntry) bool {
	message := strings.ToLower(entry.Message)
	failurePatterns := []string{
		"failed login",
		"authentication failed",
		"invalid credentials",
		"login failed",
		"access denied",
		"unauthorized",
		"401",
		"403",
	}

	for _, pattern := range failurePatterns {
		if strings.Contains(message, pattern) {
			return true
		}
	}

	return false
}

func (l *LogAnalyzerUseCase) groupByTimeWindows(entries []LogEntry, windowSize time.Duration) [][]LogEntry {
	if len(entries) == 0 {
		return nil
	}

	// Sort entries by timestamp
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})

	var windows [][]LogEntry
	var currentWindow []LogEntry
	windowStart := entries[0].Timestamp

	for _, entry := range entries {
		if entry.Timestamp.Sub(windowStart) > windowSize {
			if len(currentWindow) > 0 {
				windows = append(windows, currentWindow)
			}
			currentWindow = []LogEntry{entry}
			windowStart = entry.Timestamp
		} else {
			currentWindow = append(currentWindow, entry)
		}
	}

	if len(currentWindow) > 0 {
		windows = append(windows, currentWindow)
	}

	return windows
}

func (l *LogAnalyzerUseCase) calculateBruteForceSeverity(attemptCount int) string {
	if attemptCount >= 100 {
		return "critical"
	} else if attemptCount >= 50 {
		return "high"
	} else if attemptCount >= 20 {
		return "medium"
	}
	return "low"
}

func (l *LogAnalyzerUseCase) calculateBruteForceConfidence(attempts []LogEntry) float64 {
	// Higher confidence with more attempts and shorter time span
	if len(attempts) >= 50 {
		return 0.95
	} else if len(attempts) >= 20 {
		return 0.85
	} else if len(attempts) >= 10 {
		return 0.75
	}
	return 0.6
}

func (l *LogAnalyzerUseCase) calculateAnomalyConfidence(deviation float64) float64 {
	// Higher confidence with larger deviations
	if deviation >= 5.0 {
		return 0.95
	} else if deviation >= 3.0 {
		return 0.85
	} else if deviation >= 2.0 {
		return 0.75
	}
	return 0.6
}

func (l *LogAnalyzerUseCase) generateSourceStats(entries []LogEntry) []SourceStats {
	sourceCount := make(map[string]int)
	for _, entry := range entries {
		sourceCount[entry.Source]++
	}

	var stats []SourceStats
	for source, count := range sourceCount {
		stats = append(stats, SourceStats{Source: source, Count: count})
	}

	// Sort by count descending
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Count > stats[j].Count
	})

	// Return top 10
	if len(stats) > 10 {
		stats = stats[:10]
	}

	return stats
}

func (l *LogAnalyzerUseCase) generateErrorStats(entries []LogEntry) []ErrorStats {
	errorCount := make(map[string]int)
	for _, entry := range entries {
		if entry.Level == "ERROR" || entry.Level == "FATAL" {
			errorCount[entry.Message]++
		}
	}

	var stats []ErrorStats
	for error, count := range errorCount {
		stats = append(stats, ErrorStats{Error: error, Count: count})
	}

	// Sort by count descending
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Count > stats[j].Count
	})

	// Return top 10
	if len(stats) > 10 {
		stats = stats[:10]
	}

	return stats
}

func (l *LogAnalyzerUseCase) generateThreatSummary(events []SecurityEvent) ThreatSummary {
	summary := ThreatSummary{}

	for _, event := range events {
		switch event.Severity {
		case "critical":
			summary.CriticalEvents++
		case "high":
			summary.HighEvents++
		case "medium":
			summary.MediumEvents++
		case "low":
			summary.LowEvents++
		}
	}

	// Calculate risk score (0-10)
	summary.RiskScore = float64(summary.CriticalEvents*4 + summary.HighEvents*3 + summary.MediumEvents*2 + summary.LowEvents*1)
	if summary.RiskScore > 10 {
		summary.RiskScore = 10
	}

	return summary
}

func (l *LogAnalyzerUseCase) generateRecommendations(events []SecurityEvent, anomalies []AnomalyPattern) []string {
	var recommendations []string

	if len(events) == 0 && len(anomalies) == 0 {
		return []string{"No security issues detected. Continue monitoring."}
	}

	// Event-based recommendations
	hasBruteForce := false
	hasSQLInjection := false
	hasXSS := false

	for _, event := range events {
		switch event.Type {
		case "brute_force_attack":
			hasBruteForce = true
		case "sql_injection_attempt":
			hasSQLInjection = true
		case "xss_attempt":
			hasXSS = true
		}
	}

	if hasBruteForce {
		recommendations = append(recommendations, "Implement account lockout policies and rate limiting")
		recommendations = append(recommendations, "Enable multi-factor authentication")
	}

	if hasSQLInjection {
		recommendations = append(recommendations, "Review and implement parameterized queries")
		recommendations = append(recommendations, "Deploy web application firewall")
	}

	if hasXSS {
		recommendations = append(recommendations, "Implement Content Security Policy (CSP)")
		recommendations = append(recommendations, "Review input validation and output encoding")
	}

	// Anomaly-based recommendations
	if len(anomalies) > 0 {
		recommendations = append(recommendations, "Investigate unusual traffic patterns")
		recommendations = append(recommendations, "Review system capacity and scaling")
	}

	// General recommendations
	recommendations = append(recommendations, "Increase log monitoring frequency")
	recommendations = append(recommendations, "Review and update security policies")

	return recommendations
}

// Placeholder methods for additional detection capabilities
func (l *LogAnalyzerUseCase) detectDirectoryTraversalAttempts(entries []LogEntry) []SecurityEvent {
	return []SecurityEvent{}
}

func (l *LogAnalyzerUseCase) detectDDoSAttempts(entries []LogEntry) []SecurityEvent {
	return []SecurityEvent{}
}

func (l *LogAnalyzerUseCase) detectPrivilegeEscalation(entries []LogEntry) []SecurityEvent {
	return []SecurityEvent{}
}

func (l *LogAnalyzerUseCase) detectDataExfiltration(entries []LogEntry) []SecurityEvent {
	return []SecurityEvent{}
}

func (l *LogAnalyzerUseCase) detectMalwareActivity(entries []LogEntry) []SecurityEvent {
	return []SecurityEvent{}
}

func (l *LogAnalyzerUseCase) detectErrorRateAnomalies(entries []LogEntry) []AnomalyPattern {
	return []AnomalyPattern{}
}

func (l *LogAnalyzerUseCase) detectResponseTimeAnomalies(entries []LogEntry) []AnomalyPattern {
	return []AnomalyPattern{}
}

func (l *LogAnalyzerUseCase) detectUserBehaviorAnomalies(entries []LogEntry) []AnomalyPattern {
	return []AnomalyPattern{}
}
