# Threat Intelligence Integration

The Threat Intelligence Integration provides comprehensive threat intelligence capabilities for the HackAI platform. It includes real-time threat analysis, IOC management, reputation scoring, threat correlation, and automated threat detection with detailed reporting and analysis.

## Features

### 🔍 **Comprehensive Threat Analysis**
- **Multi-Target Analysis** - IP addresses, domains, URLs, and file hashes
- **Real-time Threat Detection** - Automated threat identification and classification
- **Geolocation Analysis** - Geographic threat intelligence and risk assessment
- **Behavior Analysis** - Behavioral pattern detection and anomaly identification
- **Threat Correlation** - Intelligent correlation of related threats and indicators
- **Risk Scoring** - Automated risk assessment with CVSS-style scoring

### 📊 **Advanced IOC Management**
- **IOC Database** - Centralized indicator of compromise storage and management
- **Multi-Type Support** - IP addresses, domains, URLs, hashes, and custom indicators
- **Automated Enrichment** - Automatic IOC enrichment with threat intelligence
- **Expiration Management** - Automatic cleanup of expired indicators
- **Search and Filtering** - Advanced search capabilities with multiple criteria
- **Bulk Operations** - Batch import/export and bulk management operations

### 🌐 **Threat Feed Integration**
- **Multiple Feed Formats** - JSON, CSV, STIX, MISP, and custom formats
- **Real-time Updates** - Continuous feed monitoring and automatic updates
- **Feed Quality Assessment** - Automatic quality and reliability scoring
- **Authentication Support** - API keys, OAuth, and custom authentication
- **Feed Correlation** - Cross-feed correlation and deduplication
- **Performance Optimization** - Efficient feed processing and caching

### 📈 **Reputation Scoring Engine**
- **Multi-Source Scoring** - Aggregated reputation from multiple sources
- **Dynamic Scoring** - Real-time reputation updates and recalculation
- **Confidence Metrics** - Statistical confidence in reputation scores
- **Historical Tracking** - Reputation score history and trend analysis
- **Source Weighting** - Configurable source reliability and weighting
- **Custom Scoring** - Extensible scoring algorithms and criteria

### 🚨 **Intelligent Threat Correlation**
- **Pattern Recognition** - Automated detection of threat patterns
- **Campaign Tracking** - Attribution and tracking of threat campaigns
- **Malware Family Detection** - Identification of malware families and variants
- **TTP Mapping** - Tactics, techniques, and procedures correlation
- **Timeline Analysis** - Temporal correlation of threat activities
- **Relationship Mapping** - Visual representation of threat relationships

### ⚡ **High-Performance Caching**
- **Intelligent Caching** - LRU-based caching with automatic optimization
- **Cache Warming** - Proactive caching of frequently accessed data
- **Performance Metrics** - Cache hit rates and performance monitoring
- **Memory Management** - Automatic memory optimization and cleanup
- **Distributed Caching** - Support for distributed cache architectures
- **Cache Invalidation** - Smart cache invalidation strategies

## Quick Start

### Installation

```bash
# Build the threat intelligence CLI tool
go build -o threat-intel cmd/threat-intel/main.go
```

### Basic Usage

```bash
# Analyze a threat target
./threat-intel -command=analyze -target=203.0.113.1 -format=table

# Lookup an IOC
./threat-intel -command=lookup -type=ip -value=203.0.113.1

# Add a new IOC
./threat-intel -command=add -type=ip -value=192.0.2.100 -severity=high

# Show statistics
./threat-intel -command=stats -format=table

# Show threat feeds
./threat-intel -command=feeds
```

### Target Types

- **IP Addresses** - IPv4 and IPv6 addresses with geolocation analysis
- **Domains** - Domain names with DNS and SSL certificate analysis
- **URLs** - Full URLs with pattern analysis and reputation checking
- **Hashes** - MD5, SHA1, SHA256 file hashes with malware detection
- **Custom** - Extensible support for custom indicator types

## Architecture

### Core Components

#### ThreatIntelligenceEngine
- **Purpose**: Main orchestrator for all threat intelligence operations
- **Features**: Multi-target analysis, correlation, caching, real-time processing
- **Capabilities**: Geolocation analysis, behavior detection, reputation scoring

#### ThreatFeedManager
- **Purpose**: Management of external threat intelligence feeds
- **Features**: Multi-format parsing, authentication, quality assessment
- **Capabilities**: Real-time updates, feed correlation, performance optimization

#### IOCDatabase
- **Purpose**: Centralized storage and management of indicators of compromise
- **Features**: Multi-type support, search/filtering, expiration management
- **Capabilities**: Bulk operations, automated enrichment, relationship tracking

#### ReputationEngine
- **Purpose**: Multi-source reputation scoring and analysis
- **Features**: Dynamic scoring, confidence metrics, historical tracking
- **Capabilities**: Source weighting, custom algorithms, trend analysis

#### ThreatCache
- **Purpose**: High-performance caching for threat intelligence data
- **Features**: LRU caching, automatic optimization, performance monitoring
- **Capabilities**: Cache warming, distributed support, smart invalidation

### Data Flow

```
External Feeds → ThreatFeedManager → IOCDatabase → ThreatIntelligenceEngine
                                                          ↓
Target Analysis → GeolocationAnalysis → BehaviorAnalysis → ReputationEngine
                                                          ↓
                 ThreatCache ← ThreatCorrelation ← ThreatReport
```

## Configuration

### Engine Configuration

```go
config := &security.ThreatIntelligenceConfig{
    Enabled:              true,
    UpdateInterval:       1 * time.Hour,
    Sources:              []string{"internal", "external"},
    APIKeys:              map[string]string{
        "virustotal": "your-api-key",
        "alienvault": "your-api-key",
    },
    CacheTimeout:         4 * time.Hour,
    MaxCacheSize:         10000,
    IOCTypes:             []string{"ip", "domain", "hash", "url"},
    ReputationScoring:    true,
    AutoBlocking:         false,
    RealTimeFeeds:        true,
    ThreatCorrelation:    true,
    GeolocationAnalysis:  true,
    BehaviorAnalysis:     true,
    MachineLearning:      true,
    
    FeedConfigs: []*security.FeedConfig{
        {
            ID:              "malware_feed",
            Name:            "Malware Intelligence Feed",
            URL:             "https://feeds.example.com/malware.json",
            Type:            "malware",
            Format:          "json",
            Enabled:         true,
            UpdateFrequency: 30 * time.Minute,
            Quality:         0.9,
            Reliability:     0.95,
            Authentication: &security.FeedAuthentication{
                Type:   "api_key",
                APIKey: "your-feed-api-key",
            },
        },
    },
}
```

### Feed Configuration

```go
feedConfig := &security.FeedConfig{
    ID:              "custom_feed",
    Name:            "Custom Threat Feed",
    URL:             "https://your-feed.com/threats.csv",
    Type:            "mixed",
    Format:          "csv",
    Enabled:         true,
    UpdateFrequency: 1 * time.Hour,
    Quality:         0.8,
    Reliability:     0.85,
    Authentication: &security.FeedAuthentication{
        Type:     "bearer",
        Token:    "your-bearer-token",
        Headers:  map[string]string{
            "X-Custom-Header": "custom-value",
        },
    },
    Tags: []string{"custom", "high_quality"},
}
```

## Programmatic Usage

### Basic Threat Analysis

```go
package main

import (
    "context"
    "fmt"
    "time"
    "github.com/dimajoyti/hackai/pkg/security"
)

func main() {
    // Create logger
    logger := &SimpleLogger{}
    
    // Create threat intelligence engine
    config := &security.ThreatIntelligenceConfig{
        Enabled:              true,
        UpdateInterval:       1 * time.Hour,
        CacheTimeout:         4 * time.Hour,
        MaxCacheSize:         1000,
        IOCTypes:             []string{"ip", "domain", "hash", "url"},
        ReputationScoring:    true,
        ThreatCorrelation:    true,
        GeolocationAnalysis:  true,
        BehaviorAnalysis:     true,
    }
    
    engine := security.NewThreatIntelligenceEngine(config, logger)
    
    // Start the engine
    if err := engine.Start(); err != nil {
        panic(err)
    }
    defer engine.Stop()
    
    // Analyze a threat
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    report, err := engine.AnalyzeThreat(ctx, "203.0.113.1")
    if err != nil {
        panic(err)
    }
    
    // Process results
    fmt.Printf("Threat Score: %.2f\n", report.ThreatScore)
    fmt.Printf("Risk Level: %s\n", report.RiskLevel)
    fmt.Printf("Indicators: %d\n", len(report.Indicators))
    
    for _, indicator := range report.Indicators {
        fmt.Printf("  [%s] %s - %s (Confidence: %.2f)\n",
            indicator.Severity, indicator.Type, indicator.Value, indicator.Confidence)
    }
}
```

### Advanced IOC Management

```go
// Create IOC database
iocDB := security.NewIOCDatabase(config, logger)
iocDB.Start()
defer iocDB.Stop()

// Add custom IOC
customIOC := &security.ThreatIndicator{
    Type:        "ip",
    Value:       "192.0.2.100",
    Confidence:  0.9,
    Severity:    "high",
    Source:      "Internal Analysis",
    Description: "Malicious IP detected in network logs",
    Tags:        []string{"malware", "botnet", "internal"},
}

err := iocDB.Add(customIOC)
if err != nil {
    panic(err)
}

// Search IOCs
criteria := &security.SearchCriteria{
    Type:          "ip",
    Severity:      "high",
    MinConfidence: 0.8,
    Tags:          []string{"malware"},
    Since:         &[]time.Time{time.Now().Add(-24 * time.Hour)}[0],
}

results, err := iocDB.Search(criteria)
if err != nil {
    panic(err)
}

fmt.Printf("Found %d high-confidence malware IPs\n", len(results))
```

### Reputation Scoring

```go
// Create reputation engine
repEngine := security.NewReputationEngine(config, logger)
repEngine.Start()
defer repEngine.Stop()

// Get reputation score
score, err := repEngine.GetScore("203.0.113.1", "ip")
if err != nil {
    panic(err)
}

fmt.Printf("Reputation Score: %.2f\n", score)

// Update reputation from multiple sources
repEngine.UpdateScore("203.0.113.1", "ip", 0.1, "virustotal", "detected_malware")
repEngine.UpdateScore("203.0.113.1", "ip", 0.2, "alienvault", "suspicious_activity")
repEngine.UpdateScore("203.0.113.1", "ip", 0.05, "internal", "blocked_connection")

// Get detailed reputation data
repData, err := repEngine.GetReputationData("203.0.113.1", "ip")
if err != nil {
    panic(err)
}

fmt.Printf("Overall Score: %.2f\n", repData.OverallScore)
fmt.Printf("Confidence: %.2f\n", repData.Confidence)
fmt.Printf("Sources: %v\n", repData.SourceScores)
```

### Feed Management

```go
// Create feed manager
feedManager := security.NewThreatFeedManager(config, logger)
feedManager.Start()
defer feedManager.Stop()

// List all feeds
feeds := feedManager.ListFeeds()
for _, feed := range feeds {
    fmt.Printf("Feed: %s (%s) - Enabled: %v\n", 
        feed.Name, feed.Type, feed.Enabled)
}

// Manually update a specific feed
err := feedManager.UpdateFeed("malware_feed")
if err != nil {
    fmt.Printf("Failed to update feed: %v\n", err)
}

// Get feed statistics
stats := feedManager.GetStatistics()
fmt.Printf("Total Feeds: %v\n", stats["total_feeds"])
fmt.Printf("Enabled Feeds: %v\n", stats["enabled_feeds"])
```

## Analysis Types Reference

### IP Address Analysis

#### Geolocation Intelligence
- **Country Risk Assessment** - High-risk country identification
- **ASN Analysis** - Autonomous system number reputation
- **ISP Reputation** - Internet service provider analysis
- **Geographic Anomalies** - Unusual geographic patterns
- **VPN/Proxy Detection** - Anonymous proxy identification

#### Behavior Analysis
- **Traffic Patterns** - Unusual traffic behavior detection
- **Port Scanning** - Network reconnaissance detection
- **Brute Force** - Authentication attack patterns
- **Botnet Activity** - Command and control communication
- **DDoS Participation** - Distributed attack involvement

#### Network Intelligence
- **Blacklist Checking** - Multiple blacklist verification
- **Reputation History** - Historical reputation tracking
- **Related Infrastructure** - Connected malicious infrastructure
- **Threat Campaigns** - Campaign attribution and tracking
- **Malware Communication** - C2 server identification

### Domain Analysis

#### DNS Intelligence
- **DNS Record Analysis** - A, AAAA, MX, TXT record examination
- **Subdomain Enumeration** - Malicious subdomain detection
- **DNS Tunneling** - Covert channel detection
- **Fast Flux Detection** - Rapid IP address changes
- **Domain Generation** - Algorithmic domain detection

#### Certificate Analysis
- **SSL Certificate Validation** - Certificate authority verification
- **Certificate Transparency** - CT log analysis
- **Certificate Anomalies** - Suspicious certificate patterns
- **Wildcard Certificates** - Overly broad certificate usage
- **Self-Signed Certificates** - Untrusted certificate detection

#### Domain Characteristics
- **Registration Analysis** - WHOIS data examination
- **Domain Age** - Recently registered domain detection
- **Registrar Reputation** - Registrar abuse patterns
- **Domain Similarity** - Typosquatting detection
- **Internationalized Domains** - IDN homograph attacks

### URL Analysis

#### Pattern Analysis
- **Suspicious Patterns** - Malicious URL pattern detection
- **Phishing Indicators** - Social engineering URL patterns
- **Malware Distribution** - Malware hosting URL detection
- **Redirect Chains** - Malicious redirect analysis
- **URL Shorteners** - Shortened URL expansion and analysis

#### Content Analysis
- **Landing Page Analysis** - Destination content examination
- **JavaScript Analysis** - Malicious script detection
- **Download Analysis** - Malware payload detection
- **Form Analysis** - Credential harvesting detection
- **Social Engineering** - Deceptive content identification

### Hash Analysis

#### Malware Detection
- **Signature Matching** - Known malware signature detection
- **Family Classification** - Malware family identification
- **Variant Analysis** - Malware variant detection
- **Packer Detection** - Packed malware identification
- **Behavioral Signatures** - Dynamic behavior analysis

#### File Intelligence
- **File Type Analysis** - File format verification
- **Metadata Extraction** - File metadata examination
- **Digital Signatures** - Code signing verification
- **Entropy Analysis** - File randomness assessment
- **String Analysis** - Embedded string extraction

## CLI Reference

### Commands

```bash
# Threat analysis
threat-intel -command=analyze -target=TARGET [options]

# IOC lookup
threat-intel -command=lookup -type=TYPE -value=VALUE [options]

# IOC management
threat-intel -command=add -type=TYPE -value=VALUE [options]

# Statistics
threat-intel -command=stats [options]

# Feed management
threat-intel -command=feeds [options]
```

### Options

- `-command`: Command to execute (analyze, lookup, add, stats, feeds)
- `-target`: Target to analyze (IP, domain, URL, hash)
- `-type`: IOC type (ip, domain, url, hash)
- `-value`: IOC value
- `-severity`: IOC severity (low, medium, high, critical)
- `-source`: IOC source
- `-confidence`: IOC confidence (0.0-1.0)
- `-format`: Output format (json, table)
- `-timeout`: Analysis timeout
- `-help`: Show help message

### Examples

```bash
# Comprehensive threat analysis
threat-intel -command=analyze -target=203.0.113.1 -format=table

# Domain analysis with JSON output
threat-intel -command=analyze -target=malicious.example.com -format=json

# URL analysis with custom timeout
threat-intel -command=analyze -target=https://phishing.example.com -timeout=60s

# Hash analysis
threat-intel -command=analyze -target=d41d8cd98f00b204e9800998ecf8427e

# IOC lookup
threat-intel -command=lookup -type=ip -value=203.0.113.1 -format=table

# Add high-severity IOC
threat-intel -command=add -type=ip -value=192.0.2.100 -severity=high -confidence=0.9

# Add custom IOC with source
threat-intel -command=add -type=domain -value=bad.example.com -source="Internal Analysis"

# Show detailed statistics
threat-intel -command=stats -format=table

# Show feed information
threat-intel -command=feeds -format=json
```

## Integration Examples

### SIEM Integration

```go
// SIEM event processor
func processSIEMEvent(event *SIEMEvent, engine *security.ThreatIntelligenceEngine) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    // Analyze source IP
    if event.SourceIP != "" {
        report, err := engine.AnalyzeThreat(ctx, event.SourceIP)
        if err == nil && report.ThreatScore > 7.0 {
            // High threat score - trigger alert
            triggerSecurityAlert(event, report)
        }
    }
    
    // Check destination domain
    if event.DestinationDomain != "" {
        ioc, err := engine.CheckIOC(event.DestinationDomain, "domain")
        if err == nil && ioc != nil && ioc.Severity == "high" {
            // Known malicious domain - block and alert
            blockDomain(event.DestinationDomain)
            triggerSecurityAlert(event, nil)
        }
    }
}
```

### Firewall Integration

```go
// Firewall rule generator
func generateFirewallRules(engine *security.ThreatIntelligenceEngine) []FirewallRule {
    var rules []FirewallRule
    
    // Get high-severity IP indicators
    criteria := &security.SearchCriteria{
        Type:          "ip",
        Severity:      "high",
        MinConfidence: 0.8,
    }
    
    indicators, err := engine.IOCDatabase.Search(criteria)
    if err != nil {
        return rules
    }
    
    for _, indicator := range indicators {
        rule := FirewallRule{
            Action:      "DENY",
            Source:      indicator.Value,
            Destination: "ANY",
            Protocol:    "ANY",
            Description: fmt.Sprintf("Block malicious IP: %s", indicator.Description),
        }
        rules = append(rules, rule)
    }
    
    return rules
}
```

### Incident Response Integration

```go
// Incident enrichment
func enrichIncident(incident *Incident, engine *security.ThreatIntelligenceEngine) {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    // Analyze all IOCs in the incident
    for _, ioc := range incident.IOCs {
        report, err := engine.AnalyzeThreat(ctx, ioc.Value)
        if err != nil {
            continue
        }
        
        // Add threat intelligence to incident
        incident.ThreatIntelligence = append(incident.ThreatIntelligence, &ThreatIntelligence{
            IOC:           ioc.Value,
            ThreatScore:   report.ThreatScore,
            RiskLevel:     report.RiskLevel,
            Indicators:    report.Indicators,
            Geolocation:   report.GeolocationInfo,
            Correlations:  report.RelatedThreats,
        })
        
        // Update incident severity based on threat score
        if report.ThreatScore > 8.0 && incident.Severity < "critical" {
            incident.Severity = "critical"
        }
    }
}
```

## Best Practices

### Feed Management
1. **Quality Assessment** - Regularly evaluate feed quality and reliability
2. **Source Diversity** - Use multiple diverse threat intelligence sources
3. **Update Frequency** - Balance freshness with performance requirements
4. **Authentication Security** - Securely manage feed API keys and credentials

### IOC Management
1. **Data Hygiene** - Regularly clean up expired and low-quality IOCs
2. **Source Attribution** - Always track IOC sources for verification
3. **Confidence Scoring** - Use confidence scores to prioritize actions
4. **Lifecycle Management** - Implement proper IOC lifecycle management

### Performance Optimization
1. **Caching Strategy** - Implement intelligent caching for frequently accessed data
2. **Batch Processing** - Use batch operations for bulk IOC management
3. **Resource Monitoring** - Monitor memory and CPU usage for optimization
4. **Scaling Considerations** - Plan for horizontal scaling requirements

### Security Considerations
1. **Access Control** - Implement proper access controls for threat intelligence data
2. **Data Encryption** - Encrypt sensitive threat intelligence data at rest and in transit
3. **Audit Logging** - Maintain comprehensive audit logs for all operations
4. **Privacy Protection** - Ensure compliance with data privacy regulations

The Threat Intelligence Integration provides comprehensive threat intelligence capabilities that enable organizations to proactively identify threats, correlate indicators, and maintain situational awareness through automated threat analysis and real-time intelligence feeds.
