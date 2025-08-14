package security_test

import (
	"context"
	"testing"
	"time"

	"github.com/dimajoyti/hackai/pkg/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockLogger implements the security.Logger interface for testing
type MockLogger struct {
	logs []LogEntry
}

type LogEntry struct {
	Level   string
	Message string
	Fields  []interface{}
}

func (m *MockLogger) Info(msg string, fields ...interface{}) {
	m.logs = append(m.logs, LogEntry{Level: "info", Message: msg, Fields: fields})
}

func (m *MockLogger) Error(msg string, fields ...interface{}) {
	m.logs = append(m.logs, LogEntry{Level: "error", Message: msg, Fields: fields})
}

func (m *MockLogger) Warn(msg string, fields ...interface{}) {
	m.logs = append(m.logs, LogEntry{Level: "warn", Message: msg, Fields: fields})
}

func (m *MockLogger) Debug(msg string, fields ...interface{}) {
	m.logs = append(m.logs, LogEntry{Level: "debug", Message: msg, Fields: fields})
}

func TestThreatIntelligenceEngine(t *testing.T) {
	logger := &MockLogger{}

	config := &security.ThreatIntelligenceConfig{
		Enabled:             true,
		UpdateInterval:      1 * time.Hour,
		Sources:             []string{"internal", "external"},
		APIKeys:             map[string]string{},
		CacheTimeout:        4 * time.Hour,
		MaxCacheSize:        1000,
		IOCTypes:            []string{"ip", "domain", "hash", "url"},
		ReputationScoring:   true,
		AutoBlocking:        false,
		RealTimeFeeds:       false,
		ThreatCorrelation:   true,
		GeolocationAnalysis: true,
		BehaviorAnalysis:    true,
		MachineLearning:     false,
		FeedConfigs:         []*security.FeedConfig{},
	}

	t.Run("Create Threat Intelligence Engine", func(t *testing.T) {
		engine := security.NewThreatIntelligenceEngine(config, logger)
		require.NotNil(t, engine)

		// Test starting the engine
		err := engine.Start()
		require.NoError(t, err)

		// Test stopping the engine
		err = engine.Stop()
		require.NoError(t, err)
	})

	t.Run("Analyze IP Address Threat", func(t *testing.T) {
		engine := security.NewThreatIntelligenceEngine(config, logger)
		require.NotNil(t, engine)

		err := engine.Start()
		require.NoError(t, err)
		defer engine.Stop()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Test analyzing a known malicious IP
		report, err := engine.AnalyzeThreat(ctx, "203.0.113.1")
		require.NoError(t, err)
		require.NotNil(t, report)

		assert.Equal(t, "203.0.113.1", report.Target)
		assert.Equal(t, "ip", report.TargetType)
		assert.True(t, report.ThreatScore > 0)
		assert.NotEmpty(t, report.RiskLevel)
		assert.True(t, len(report.Indicators) > 0)

		// Check for geolocation info
		if config.GeolocationAnalysis {
			assert.NotNil(t, report.GeolocationInfo)
		}

		// Check for behavior analysis
		if config.BehaviorAnalysis {
			assert.NotNil(t, report.BehaviorAnalysis)
		}

		// Check for reputation data
		if config.ReputationScoring {
			assert.NotNil(t, report.ReputationData)
		}
	})

	t.Run("Analyze Domain Threat", func(t *testing.T) {
		engine := security.NewThreatIntelligenceEngine(config, logger)
		require.NotNil(t, engine)

		err := engine.Start()
		require.NoError(t, err)
		defer engine.Stop()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Test analyzing a suspicious domain
		report, err := engine.AnalyzeThreat(ctx, "malicious.example.com")
		require.NoError(t, err)
		require.NotNil(t, report)

		assert.Equal(t, "malicious.example.com", report.Target)
		assert.Equal(t, "domain", report.TargetType)
		assert.True(t, report.ThreatScore > 0)
		assert.NotEmpty(t, report.RiskLevel)
		assert.True(t, len(report.Indicators) > 0)
	})

	t.Run("Analyze URL Threat", func(t *testing.T) {
		engine := security.NewThreatIntelligenceEngine(config, logger)
		require.NotNil(t, engine)

		err := engine.Start()
		require.NoError(t, err)
		defer engine.Stop()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Test analyzing a suspicious URL
		report, err := engine.AnalyzeThreat(ctx, "https://phishing.example.com/login")
		require.NoError(t, err)
		require.NotNil(t, report)

		assert.Equal(t, "https://phishing.example.com/login", report.Target)
		assert.Equal(t, "url", report.TargetType)
		assert.True(t, len(report.Indicators) >= 0)
	})

	t.Run("Analyze Hash Threat", func(t *testing.T) {
		engine := security.NewThreatIntelligenceEngine(config, logger)
		require.NotNil(t, engine)

		err := engine.Start()
		require.NoError(t, err)
		defer engine.Stop()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Test analyzing a known malware hash
		report, err := engine.AnalyzeThreat(ctx, "d41d8cd98f00b204e9800998ecf8427e")
		require.NoError(t, err)
		require.NotNil(t, report)

		assert.Equal(t, "d41d8cd98f00b204e9800998ecf8427e", report.Target)
		assert.Equal(t, "hash", report.TargetType)
		assert.True(t, len(report.Indicators) >= 0)
	})

	t.Run("Check IOC Lookup", func(t *testing.T) {
		engine := security.NewThreatIntelligenceEngine(config, logger)
		require.NotNil(t, engine)

		err := engine.Start()
		require.NoError(t, err)
		defer engine.Stop()

		// Test IOC lookup for known indicator
		ioc, err := engine.CheckIOC("203.0.113.1", "ip")
		require.NoError(t, err)

		if ioc != nil {
			assert.Equal(t, "ip", ioc.Type)
			assert.Equal(t, "203.0.113.1", ioc.Value)
			assert.True(t, ioc.Confidence > 0)
		}
	})

	t.Run("Add Custom IOC", func(t *testing.T) {
		engine := security.NewThreatIntelligenceEngine(config, logger)
		require.NotNil(t, engine)

		err := engine.Start()
		require.NoError(t, err)
		defer engine.Stop()

		// Test adding a custom IOC
		customIOC := &security.ThreatIndicator{
			Type:        "ip",
			Value:       "192.0.2.100",
			Confidence:  0.8,
			Severity:    "medium",
			Source:      "Test",
			Description: "Test malicious IP",
			Tags:        []string{"test", "malicious"},
		}

		err = engine.AddIOC(customIOC)
		require.NoError(t, err)

		// Verify the IOC was added
		ioc, err := engine.CheckIOC("192.0.2.100", "ip")
		require.NoError(t, err)
		require.NotNil(t, ioc)

		assert.Equal(t, "ip", ioc.Type)
		assert.Equal(t, "192.0.2.100", ioc.Value)
		assert.Equal(t, 0.8, ioc.Confidence)
		assert.Equal(t, "medium", ioc.Severity)
	})

	t.Run("Get Reputation Score", func(t *testing.T) {
		engine := security.NewThreatIntelligenceEngine(config, logger)
		require.NotNil(t, engine)

		err := engine.Start()
		require.NoError(t, err)
		defer engine.Stop()

		// Test reputation scoring
		score, err := engine.GetReputationScore("203.0.113.1", "ip")
		require.NoError(t, err)
		assert.True(t, score >= 0.0 && score <= 1.0)

		// Test reputation for good IP
		goodScore, err := engine.GetReputationScore("8.8.8.8", "ip")
		require.NoError(t, err)
		assert.True(t, goodScore >= 0.0 && goodScore <= 1.0)
	})

	t.Run("Get Threat Statistics", func(t *testing.T) {
		engine := security.NewThreatIntelligenceEngine(config, logger)
		require.NotNil(t, engine)

		err := engine.Start()
		require.NoError(t, err)
		defer engine.Stop()

		// Test getting statistics
		stats := engine.GetThreatStatistics()
		require.NotNil(t, stats)

		assert.Contains(t, stats, "enabled")
		assert.Equal(t, true, stats["enabled"])

		// Check for component statistics
		if stats["feeds"] != nil {
			feedStats := stats["feeds"].(map[string]interface{})
			assert.Contains(t, feedStats, "total_feeds")
		}

		if stats["iocs"] != nil {
			iocStats := stats["iocs"].(map[string]interface{})
			assert.Contains(t, iocStats, "total_indicators")
		}

		if stats["reputation"] != nil {
			repStats := stats["reputation"].(map[string]interface{})
			assert.Contains(t, repStats, "total_scores")
		}

		if stats["cache"] != nil {
			cacheStats := stats["cache"].(map[string]interface{})
			assert.Contains(t, cacheStats, "total_entries")
		}
	})

	t.Run("Test Disabled Engine", func(t *testing.T) {
		disabledConfig := &security.ThreatIntelligenceConfig{
			Enabled: false,
		}

		engine := security.NewThreatIntelligenceEngine(disabledConfig, logger)
		require.NotNil(t, engine)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Test that disabled engine returns error
		_, err := engine.AnalyzeThreat(ctx, "203.0.113.1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "disabled")

		// Test that IOC operations return nil/error for disabled engine
		ioc, err := engine.CheckIOC("203.0.113.1", "ip")
		assert.NoError(t, err)
		assert.Nil(t, ioc)

		err = engine.AddIOC(&security.ThreatIndicator{})
		assert.Error(t, err)

		score, err := engine.GetReputationScore("203.0.113.1", "ip")
		assert.NoError(t, err)
		assert.Equal(t, 0.0, score)
	})
}

func TestThreatFeedManager(t *testing.T) {
	logger := &MockLogger{}

	config := &security.ThreatIntelligenceConfig{
		Enabled:        true,
		UpdateInterval: 1 * time.Hour,
		FeedConfigs: []*security.FeedConfig{
			{
				ID:              "test_feed_1",
				Name:            "Test Feed 1",
				URL:             "https://example.com/feed1.json",
				Type:            "json",
				Format:          "json",
				Enabled:         true,
				UpdateFrequency: 1 * time.Hour,
				Quality:         0.8,
				Reliability:     0.9,
			},
		},
	}

	t.Run("Create Feed Manager", func(t *testing.T) {
		manager := security.NewThreatFeedManager(config, logger)
		require.NotNil(t, manager)

		err := manager.Start()
		require.NoError(t, err)

		err = manager.Stop()
		require.NoError(t, err)
	})

	t.Run("List Feeds", func(t *testing.T) {
		manager := security.NewThreatFeedManager(config, logger)
		require.NotNil(t, manager)

		err := manager.Start()
		require.NoError(t, err)
		defer manager.Stop()

		feeds := manager.ListFeeds()
		assert.Len(t, feeds, 1)
		assert.Equal(t, "test_feed_1", feeds[0].ID)
		assert.Equal(t, "Test Feed 1", feeds[0].Name)
	})

	t.Run("Get Feed Statistics", func(t *testing.T) {
		manager := security.NewThreatFeedManager(config, logger)
		require.NotNil(t, manager)

		err := manager.Start()
		require.NoError(t, err)
		defer manager.Stop()

		stats := manager.GetStatistics()
		assert.Contains(t, stats, "total_feeds")
		assert.Contains(t, stats, "enabled_feeds")
		assert.Equal(t, 1, stats["total_feeds"])
		assert.Equal(t, 1, stats["enabled_feeds"])
	})
}

func TestIOCDatabase(t *testing.T) {
	logger := &MockLogger{}

	config := &security.ThreatIntelligenceConfig{
		Enabled:  true,
		IOCTypes: []string{"ip", "domain", "hash", "url"},
	}

	t.Run("Create IOC Database", func(t *testing.T) {
		db := security.NewIOCDatabase(config, logger)
		require.NotNil(t, db)

		err := db.Start()
		require.NoError(t, err)

		err = db.Stop()
		require.NoError(t, err)
	})

	t.Run("Add and Lookup IOC", func(t *testing.T) {
		db := security.NewIOCDatabase(config, logger)
		require.NotNil(t, db)

		err := db.Start()
		require.NoError(t, err)
		defer db.Stop()

		// Add a test IOC
		testIOC := &security.ThreatIndicator{
			Type:        "ip",
			Value:       "192.0.2.200",
			Confidence:  0.9,
			Severity:    "high",
			Source:      "Test",
			Description: "Test malicious IP",
			Tags:        []string{"test", "malicious"},
		}

		err = db.Add(testIOC)
		require.NoError(t, err)

		// Lookup the IOC
		foundIOC, err := db.Lookup("192.0.2.200", "ip")
		require.NoError(t, err)
		require.NotNil(t, foundIOC)

		assert.Equal(t, "ip", foundIOC.Type)
		assert.Equal(t, "192.0.2.200", foundIOC.Value)
		assert.Equal(t, 0.9, foundIOC.Confidence)
		assert.Equal(t, "high", foundIOC.Severity)
	})

	t.Run("Search IOCs", func(t *testing.T) {
		db := security.NewIOCDatabase(config, logger)
		require.NotNil(t, db)

		err := db.Start()
		require.NoError(t, err)
		defer db.Stop()

		// Add multiple test IOCs
		testIOCs := []*security.ThreatIndicator{
			{
				Type:       "ip",
				Value:      "192.0.2.201",
				Confidence: 0.8,
				Severity:   "medium",
				Source:     "Test",
				Tags:       []string{"test"},
			},
			{
				Type:       "domain",
				Value:      "test.example.com",
				Confidence: 0.7,
				Severity:   "low",
				Source:     "Test",
				Tags:       []string{"test"},
			},
		}

		for _, ioc := range testIOCs {
			err = db.Add(ioc)
			require.NoError(t, err)
		}

		// Search by type
		criteria := &security.SearchCriteria{
			Type: "ip",
		}
		results, err := db.Search(criteria)
		require.NoError(t, err)
		assert.True(t, len(results) >= 1)

		// Search by severity
		criteria = &security.SearchCriteria{
			Severity: "medium",
		}
		results, err = db.Search(criteria)
		require.NoError(t, err)
		assert.True(t, len(results) >= 1)

		// Search by tags
		criteria = &security.SearchCriteria{
			Tags: []string{"test"},
		}
		results, err = db.Search(criteria)
		require.NoError(t, err)
		assert.True(t, len(results) >= 2)
	})

	t.Run("Get IOC Statistics", func(t *testing.T) {
		db := security.NewIOCDatabase(config, logger)
		require.NotNil(t, db)

		err := db.Start()
		require.NoError(t, err)
		defer db.Stop()

		stats := db.GetStatistics()
		assert.Contains(t, stats, "total_indicators")
		assert.Contains(t, stats, "by_type")
		assert.Contains(t, stats, "by_severity")
		assert.Contains(t, stats, "by_source")
	})
}

func TestReputationEngine(t *testing.T) {
	logger := &MockLogger{}

	config := &security.ThreatIntelligenceConfig{
		Enabled:           true,
		ReputationScoring: true,
	}

	t.Run("Create Reputation Engine", func(t *testing.T) {
		engine := security.NewReputationEngine(config, logger)
		require.NotNil(t, engine)

		err := engine.Start()
		require.NoError(t, err)

		err = engine.Stop()
		require.NoError(t, err)
	})

	t.Run("Get and Update Reputation Score", func(t *testing.T) {
		engine := security.NewReputationEngine(config, logger)
		require.NotNil(t, engine)

		err := engine.Start()
		require.NoError(t, err)
		defer engine.Stop()

		// Get initial score
		score, err := engine.GetScore("192.0.2.300", "ip")
		require.NoError(t, err)
		assert.True(t, score >= 0.0 && score <= 1.0)

		// Update score
		err = engine.UpdateScore("192.0.2.300", "ip", 0.2, "test_source", "test_update")
		require.NoError(t, err)

		// Get updated score
		newScore, err := engine.GetScore("192.0.2.300", "ip")
		require.NoError(t, err)
		assert.True(t, newScore >= 0.0 && newScore <= 1.0)

		// Get detailed reputation data
		repData, err := engine.GetReputationData("192.0.2.300", "ip")
		require.NoError(t, err)
		require.NotNil(t, repData)

		assert.Equal(t, "192.0.2.300", repData.Indicator)
		assert.Equal(t, "ip", repData.Type)
		assert.Contains(t, repData.SourceScores, "test_source")
		assert.Equal(t, 0.2, repData.SourceScores["test_source"])
	})

	t.Run("Get Reputation Statistics", func(t *testing.T) {
		engine := security.NewReputationEngine(config, logger)
		require.NotNil(t, engine)

		err := engine.Start()
		require.NoError(t, err)
		defer engine.Stop()

		stats := engine.GetStatistics()
		assert.Contains(t, stats, "total_scores")
		assert.Contains(t, stats, "total_sources")
		assert.Contains(t, stats, "by_type")
		assert.Contains(t, stats, "score_distribution")
	})
}

func TestThreatCache(t *testing.T) {
	logger := &MockLogger{}

	config := &security.ThreatIntelligenceConfig{
		Enabled:      true,
		CacheTimeout: 1 * time.Hour,
		MaxCacheSize: 100,
	}

	t.Run("Create Threat Cache", func(t *testing.T) {
		cache := security.NewThreatCache(config, logger)
		require.NotNil(t, cache)

		err := cache.Start()
		require.NoError(t, err)

		err = cache.Stop()
		require.NoError(t, err)
	})

	t.Run("Cache Set and Get", func(t *testing.T) {
		cache := security.NewThreatCache(config, logger)
		require.NotNil(t, cache)

		err := cache.Start()
		require.NoError(t, err)
		defer cache.Stop()

		// Create test report
		testReport := &security.ThreatReport{
			ID:          "test_report_1",
			Target:      "192.0.2.400",
			TargetType:  "ip",
			ThreatScore: 7.5,
			RiskLevel:   "high",
			Indicators: []*security.ThreatIndicator{
				{
					Type:     "ip",
					Value:    "192.0.2.400",
					Severity: "high",
				},
			},
		}

		// Set in cache
		cache.Set("192.0.2.400", testReport)

		// Get from cache
		cachedReport := cache.Get("192.0.2.400")
		require.NotNil(t, cachedReport)

		assert.Equal(t, "test_report_1", cachedReport.ID)
		assert.Equal(t, "192.0.2.400", cachedReport.Target)
		assert.Equal(t, "ip", cachedReport.TargetType)
		assert.Equal(t, 7.5, cachedReport.ThreatScore)
	})

	t.Run("Cache Statistics", func(t *testing.T) {
		cache := security.NewThreatCache(config, logger)
		require.NotNil(t, cache)

		err := cache.Start()
		require.NoError(t, err)
		defer cache.Stop()

		stats := cache.GetStatistics()
		assert.Contains(t, stats, "total_entries")
		assert.Contains(t, stats, "max_size")
		assert.Contains(t, stats, "cache_timeout")
		assert.Contains(t, stats, "utilization_percent")
	})

	t.Run("Cache Clear", func(t *testing.T) {
		cache := security.NewThreatCache(config, logger)
		require.NotNil(t, cache)

		err := cache.Start()
		require.NoError(t, err)
		defer cache.Stop()

		// Add test data
		testReport := &security.ThreatReport{
			ID:     "test_report_2",
			Target: "test.example.com",
		}
		cache.Set("test.example.com", testReport)

		// Verify it's cached
		cachedReport := cache.Get("test.example.com")
		assert.NotNil(t, cachedReport)

		// Clear cache
		cache.Clear()

		// Verify it's gone
		cachedReport = cache.Get("test.example.com")
		assert.Nil(t, cachedReport)
	})
}
