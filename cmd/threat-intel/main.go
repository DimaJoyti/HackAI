package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/security"
)

// SimpleLogger implements the security.Logger interface
type SimpleLogger struct{}

func (l *SimpleLogger) Info(msg string, fields ...interface{}) {
	fmt.Printf("[INFO] %s", msg)
	if len(fields) > 0 {
		fmt.Printf(" %v", fields)
	}
	fmt.Println()
}

func (l *SimpleLogger) Error(msg string, fields ...interface{}) {
	fmt.Printf("[ERROR] %s", msg)
	if len(fields) > 0 {
		fmt.Printf(" %v", fields)
	}
	fmt.Println()
}

func (l *SimpleLogger) Warn(msg string, fields ...interface{}) {
	fmt.Printf("[WARN] %s", msg)
	if len(fields) > 0 {
		fmt.Printf(" %v", fields)
	}
	fmt.Println()
}

func (l *SimpleLogger) Debug(msg string, fields ...interface{}) {
	fmt.Printf("[DEBUG] %s", msg)
	if len(fields) > 0 {
		fmt.Printf(" %v", fields)
	}
	fmt.Println()
}

func main() {
	var (
		command    = flag.String("command", "analyze", "Command to execute (analyze, lookup, add, stats, feeds)")
		target     = flag.String("target", "", "Target to analyze (IP, domain, URL, hash)")
		iocType    = flag.String("type", "", "IOC type (ip, domain, url, hash)")
		iocValue   = flag.String("value", "", "IOC value")
		severity   = flag.String("severity", "medium", "IOC severity (low, medium, high, critical)")
		source     = flag.String("source", "Manual", "IOC source")
		confidence = flag.Float64("confidence", 0.7, "IOC confidence (0.0-1.0)")
		format     = flag.String("format", "json", "Output format (json, table)")
		timeout    = flag.Duration("timeout", 30*time.Second, "Analysis timeout")
		help       = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help {
		showHelp()
		return
	}

	logger := &SimpleLogger{}

	switch *command {
	case "analyze":
		if *target == "" {
			fmt.Println("Error: target is required for analysis")
			showHelp()
			os.Exit(1)
		}
		analyzeThreat(logger, *target, *timeout, *format)
	case "lookup":
		if *iocValue == "" || *iocType == "" {
			fmt.Println("Error: value and type are required for lookup")
			showHelp()
			os.Exit(1)
		}
		lookupIOC(logger, *iocValue, *iocType, *format)
	case "add":
		if *iocValue == "" || *iocType == "" {
			fmt.Println("Error: value and type are required for adding IOC")
			showHelp()
			os.Exit(1)
		}
		addIOC(logger, *iocValue, *iocType, *severity, *source, *confidence, *format)
	case "stats":
		showStatistics(logger, *format)
	case "feeds":
		showFeeds(logger, *format)
	default:
		fmt.Printf("Unknown command: %s\n", *command)
		showHelp()
		os.Exit(1)
	}
}

func showHelp() {
	fmt.Println("Threat Intelligence CLI Tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  threat-intel [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  analyze   Analyze a target for threats")
	fmt.Println("  lookup    Lookup an IOC in the database")
	fmt.Println("  add       Add a new IOC to the database")
	fmt.Println("  stats     Show threat intelligence statistics")
	fmt.Println("  feeds     Show threat feed information")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -command     Command to execute (default: analyze)")
	fmt.Println("  -target      Target to analyze (IP, domain, URL, hash)")
	fmt.Println("  -type        IOC type (ip, domain, url, hash)")
	fmt.Println("  -value       IOC value")
	fmt.Println("  -severity    IOC severity: low, medium, high, critical (default: medium)")
	fmt.Println("  -source      IOC source (default: Manual)")
	fmt.Println("  -confidence  IOC confidence 0.0-1.0 (default: 0.7)")
	fmt.Println("  -format      Output format: json, table (default: json)")
	fmt.Println("  -timeout     Analysis timeout (default: 30s)")
	fmt.Println("  -help        Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  threat-intel -command=analyze -target=203.0.113.1")
	fmt.Println("  threat-intel -command=analyze -target=malicious.example.com -format=table")
	fmt.Println("  threat-intel -command=lookup -type=ip -value=203.0.113.1")
	fmt.Println("  threat-intel -command=add -type=ip -value=192.0.2.100 -severity=high")
	fmt.Println("  threat-intel -command=stats -format=table")
	fmt.Println("  threat-intel -command=feeds")
}

func analyzeThreat(logger security.Logger, target string, timeout time.Duration, format string) {
	fmt.Printf("[INFO] Analyzing threat: %s\n", target)

	// Create threat intelligence engine
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

	engine := security.NewThreatIntelligenceEngine(config, logger)

	if err := engine.Start(); err != nil {
		fmt.Printf("[ERROR] Failed to start threat intelligence engine: %v\n", err)
		os.Exit(1)
	}
	defer engine.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Analyze the threat
	report, err := engine.AnalyzeThreat(ctx, target)
	if err != nil {
		fmt.Printf("[ERROR] Failed to analyze threat: %v\n", err)
		os.Exit(1)
	}

	// Output results
	if format == "json" {
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("Threat Analysis Report\n")
		fmt.Printf("======================\n")
		fmt.Printf("Target: %s\n", report.Target)
		fmt.Printf("Type: %s\n", report.TargetType)
		fmt.Printf("Threat Score: %.2f\n", report.ThreatScore)
		fmt.Printf("Risk Level: %s\n", report.RiskLevel)
		fmt.Printf("Confidence: %.2f\n", report.Confidence)
		fmt.Printf("Indicators: %d\n", len(report.Indicators))

		if len(report.Indicators) > 0 {
			fmt.Printf("\nThreat Indicators:\n")
			for i, indicator := range report.Indicators {
				fmt.Printf("  %d. [%s] %s - %s (Confidence: %.2f)\n",
					i+1, strings.ToUpper(indicator.Severity), indicator.Type, indicator.Value, indicator.Confidence)
				if indicator.Description != "" {
					fmt.Printf("     Description: %s\n", indicator.Description)
				}
				if len(indicator.Tags) > 0 {
					fmt.Printf("     Tags: %s\n", strings.Join(indicator.Tags, ", "))
				}
			}
		}

		if report.GeolocationInfo != nil {
			fmt.Printf("\nGeolocation:\n")
			fmt.Printf("  Country: %s (%s)\n", report.GeolocationInfo.Country, report.GeolocationInfo.CountryCode)
			fmt.Printf("  Region: %s\n", report.GeolocationInfo.Region)
			fmt.Printf("  City: %s\n", report.GeolocationInfo.City)
			fmt.Printf("  Risk Level: %s\n", report.GeolocationInfo.RiskLevel)
		}

		if len(report.Recommendations) > 0 {
			fmt.Printf("\nRecommendations:\n")
			for i, rec := range report.Recommendations {
				fmt.Printf("  %d. %s\n", i+1, rec)
			}
		}

		if len(report.Actions) > 0 {
			fmt.Printf("\nSuggested Actions:\n")
			for i, action := range report.Actions {
				fmt.Printf("  %d. %s\n", i+1, action)
			}
		}
	}
}

func lookupIOC(logger security.Logger, value, iocType, format string) {
	fmt.Printf("[INFO] Looking up IOC: %s (%s)\n", value, iocType)

	config := &security.ThreatIntelligenceConfig{
		Enabled:        true,
		UpdateInterval: 1 * time.Hour,
		IOCTypes:       []string{"ip", "domain", "hash", "url"},
		CacheTimeout:   4 * time.Hour,
		MaxCacheSize:   1000,
	}

	engine := security.NewThreatIntelligenceEngine(config, logger)

	if err := engine.Start(); err != nil {
		fmt.Printf("[ERROR] Failed to start threat intelligence engine: %v\n", err)
		os.Exit(1)
	}
	defer engine.Stop()

	// Lookup IOC
	ioc, err := engine.CheckIOC(value, iocType)
	if err != nil {
		fmt.Printf("[ERROR] Failed to lookup IOC: %v\n", err)
		os.Exit(1)
	}

	if ioc == nil {
		fmt.Printf("[INFO] IOC not found in database\n")
		return
	}

	// Output results
	if format == "json" {
		data, _ := json.MarshalIndent(ioc, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("IOC Found\n")
		fmt.Printf("=========\n")
		fmt.Printf("ID: %s\n", ioc.ID)
		fmt.Printf("Type: %s\n", ioc.Type)
		fmt.Printf("Value: %s\n", ioc.Value)
		fmt.Printf("Severity: %s\n", ioc.Severity)
		fmt.Printf("Confidence: %.2f\n", ioc.Confidence)
		fmt.Printf("Source: %s\n", ioc.Source)
		fmt.Printf("First Seen: %s\n", ioc.FirstSeen.Format(time.RFC3339))
		fmt.Printf("Last Seen: %s\n", ioc.LastSeen.Format(time.RFC3339))

		if ioc.Description != "" {
			fmt.Printf("Description: %s\n", ioc.Description)
		}

		if len(ioc.Tags) > 0 {
			fmt.Printf("Tags: %s\n", strings.Join(ioc.Tags, ", "))
		}
	}
}

func addIOC(logger security.Logger, value, iocType, severity, source string, confidence float64, format string) {
	fmt.Printf("[INFO] Adding IOC: %s (%s)\n", value, iocType)

	config := &security.ThreatIntelligenceConfig{
		Enabled:        true,
		UpdateInterval: 1 * time.Hour,
		IOCTypes:       []string{"ip", "domain", "hash", "url"},
		CacheTimeout:   4 * time.Hour,
		MaxCacheSize:   1000,
	}

	engine := security.NewThreatIntelligenceEngine(config, logger)

	if err := engine.Start(); err != nil {
		fmt.Printf("[ERROR] Failed to start threat intelligence engine: %v\n", err)
		os.Exit(1)
	}
	defer engine.Stop()

	// Create IOC
	ioc := &security.ThreatIndicator{
		Type:        iocType,
		Value:       value,
		Severity:    severity,
		Source:      source,
		Confidence:  confidence,
		Description: fmt.Sprintf("Manually added %s indicator", iocType),
		Tags:        []string{"manual", "user_added"},
	}

	// Add IOC
	err := engine.AddIOC(ioc)
	if err != nil {
		fmt.Printf("[ERROR] Failed to add IOC: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[INFO] IOC added successfully\n")

	// Verify by looking it up
	addedIOC, err := engine.CheckIOC(value, iocType)
	if err != nil {
		fmt.Printf("[ERROR] Failed to verify IOC: %v\n", err)
		return
	}

	if addedIOC != nil {
		if format == "json" {
			data, _ := json.MarshalIndent(addedIOC, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Added IOC Details:\n")
			fmt.Printf("  ID: %s\n", addedIOC.ID)
			fmt.Printf("  Type: %s\n", addedIOC.Type)
			fmt.Printf("  Value: %s\n", addedIOC.Value)
			fmt.Printf("  Severity: %s\n", addedIOC.Severity)
			fmt.Printf("  Confidence: %.2f\n", addedIOC.Confidence)
			fmt.Printf("  Source: %s\n", addedIOC.Source)
		}
	}
}

func showStatistics(logger security.Logger, format string) {
	fmt.Printf("[INFO] Getting threat intelligence statistics\n")

	config := &security.ThreatIntelligenceConfig{
		Enabled:           true,
		UpdateInterval:    1 * time.Hour,
		ReputationScoring: true,
		IOCTypes:          []string{"ip", "domain", "hash", "url"},
		CacheTimeout:      4 * time.Hour,
		MaxCacheSize:      1000,
	}

	engine := security.NewThreatIntelligenceEngine(config, logger)

	if err := engine.Start(); err != nil {
		fmt.Printf("[ERROR] Failed to start threat intelligence engine: %v\n", err)
		os.Exit(1)
	}
	defer engine.Stop()

	// Get statistics
	stats := engine.GetThreatStatistics()

	if format == "json" {
		data, _ := json.MarshalIndent(stats, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("Threat Intelligence Statistics\n")
		fmt.Printf("==============================\n")
		fmt.Printf("Engine Enabled: %v\n", stats["enabled"])

		if feedStats, ok := stats["feeds"].(map[string]interface{}); ok {
			fmt.Printf("\nThreat Feeds:\n")
			fmt.Printf("  Total Feeds: %v\n", feedStats["total_feeds"])
			fmt.Printf("  Enabled Feeds: %v\n", feedStats["enabled_feeds"])
			fmt.Printf("  Total Indicators: %v\n", feedStats["total_indicators"])
		}

		if iocStats, ok := stats["iocs"].(map[string]interface{}); ok {
			fmt.Printf("\nIOC Database:\n")
			fmt.Printf("  Total Indicators: %v\n", iocStats["total_indicators"])

			if byType, ok := iocStats["by_type"].(map[string]interface{}); ok {
				fmt.Printf("  By Type:\n")
				for iocType, count := range byType {
					fmt.Printf("    %s: %v\n", iocType, count)
				}
			}

			if bySeverity, ok := iocStats["by_severity"].(map[string]interface{}); ok {
				fmt.Printf("  By Severity:\n")
				for severity, count := range bySeverity {
					fmt.Printf("    %s: %v\n", severity, count)
				}
			}
		}

		if repStats, ok := stats["reputation"].(map[string]interface{}); ok {
			fmt.Printf("\nReputation Engine:\n")
			fmt.Printf("  Total Scores: %v\n", repStats["total_scores"])
			fmt.Printf("  Total Sources: %v\n", repStats["total_sources"])
		}

		if cacheStats, ok := stats["cache"].(map[string]interface{}); ok {
			fmt.Printf("\nThreat Cache:\n")
			fmt.Printf("  Total Entries: %v\n", cacheStats["total_entries"])
			fmt.Printf("  Max Size: %v\n", cacheStats["max_size"])
			fmt.Printf("  Utilization: %.1f%%\n", cacheStats["utilization_percent"])
		}
	}
}

func showFeeds(logger security.Logger, format string) {
	fmt.Printf("[INFO] Getting threat feed information\n")

	config := &security.ThreatIntelligenceConfig{
		Enabled: true,
		FeedConfigs: []*security.FeedConfig{
			{
				ID:              "sample_feed_1",
				Name:            "Sample Malware Feed",
				URL:             "https://example.com/malware.json",
				Type:            "malware",
				Format:          "json",
				Enabled:         true,
				UpdateFrequency: 1 * time.Hour,
				Quality:         0.8,
				Reliability:     0.9,
			},
			{
				ID:              "sample_feed_2",
				Name:            "Sample IP Reputation Feed",
				URL:             "https://example.com/ip-reputation.csv",
				Type:            "reputation",
				Format:          "csv",
				Enabled:         true,
				UpdateFrequency: 30 * time.Minute,
				Quality:         0.7,
				Reliability:     0.8,
			},
		},
	}

	engine := security.NewThreatIntelligenceEngine(config, logger)

	if err := engine.Start(); err != nil {
		fmt.Printf("[ERROR] Failed to start threat intelligence engine: %v\n", err)
		os.Exit(1)
	}
	defer engine.Stop()

	// Get feed manager and list feeds
	stats := engine.GetThreatStatistics()

	if format == "json" {
		data, _ := json.MarshalIndent(stats["feeds"], "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("Threat Intelligence Feeds\n")
		fmt.Printf("=========================\n")

		if feedStats, ok := stats["feeds"].(map[string]interface{}); ok {
			fmt.Printf("Total Feeds: %v\n", feedStats["total_feeds"])
			fmt.Printf("Enabled Feeds: %v\n", feedStats["enabled_feeds"])
			fmt.Printf("Total Indicators: %v\n", feedStats["total_indicators"])
		}

		fmt.Printf("\nConfigured Feeds:\n")
		for i, feedConfig := range config.FeedConfigs {
			fmt.Printf("  %d. %s\n", i+1, feedConfig.Name)
			fmt.Printf("     ID: %s\n", feedConfig.ID)
			fmt.Printf("     URL: %s\n", feedConfig.URL)
			fmt.Printf("     Type: %s\n", feedConfig.Type)
			fmt.Printf("     Format: %s\n", feedConfig.Format)
			fmt.Printf("     Enabled: %v\n", feedConfig.Enabled)
			fmt.Printf("     Update Frequency: %v\n", feedConfig.UpdateFrequency)
			fmt.Printf("     Quality: %.1f\n", feedConfig.Quality)
			fmt.Printf("     Reliability: %.1f\n", feedConfig.Reliability)
			fmt.Println()
		}
	}
}
