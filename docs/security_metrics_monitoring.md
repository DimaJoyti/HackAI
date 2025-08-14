# Security Metrics and Monitoring System

The Security Metrics and Monitoring System provides comprehensive real-time monitoring, alerting, and dashboard capabilities for all security components in the HackAI platform. It includes metrics collection, threat analysis, component health monitoring, and automated alerting.

## Features

### 🔍 **Comprehensive Metrics Collection**
- **Real-time Security Metrics** - Continuous collection of security events and performance data
- **Component Health Monitoring** - Health status tracking for all security components
- **Threat Intelligence Metrics** - Detailed threat analysis and correlation
- **Performance Monitoring** - Processing times, resource utilization, and throughput metrics
- **Prometheus Integration** - Native Prometheus metrics export for external monitoring

### 📊 **Advanced Dashboard System**
- **Real-time Dashboard** - Live security overview with WebSocket updates
- **Interactive Visualizations** - Threat trends, component status, and performance charts
- **Customizable Views** - Component-specific and system-wide monitoring views
- **Historical Analysis** - Trend analysis and historical data visualization
- **Mobile-responsive UI** - Access monitoring data from any device

### 🚨 **Intelligent Alerting System**
- **Rule-based Alerting** - Configurable alert rules with thresholds and conditions
- **Multi-channel Notifications** - Slack, email, webhook, and log-based alerts
- **Alert Escalation** - Automatic escalation based on severity and time
- **Alert Suppression** - Temporary suppression during maintenance windows
- **Alert Correlation** - Intelligent grouping and deduplication of related alerts

### 📈 **Performance Analytics**
- **Processing Time Analysis** - Component-level performance monitoring
- **Throughput Metrics** - Request processing rates and queue depths
- **Resource Utilization** - CPU, memory, and network usage tracking
- **Bottleneck Detection** - Automatic identification of performance issues
- **Capacity Planning** - Historical trends for resource planning

## Quick Start

### Installation

```bash
# Build the security monitoring CLI tool
go build -o security-monitor cmd/security-monitor/main.go
```

### Basic Usage

```bash
# Show security metrics
./security-monitor -command=metrics -format=table

# Show component health status
./security-monitor -command=health -format=table

# Show active alerts
./security-monitor -command=alerts -format=table

# Run security event simulation
./security-monitor -command=simulate -duration=30s

# Start interactive dashboard
./security-monitor -command=dashboard -port=8080
```

### Dashboard Access

Once the dashboard is running, access it at:
- **Main Dashboard**: http://localhost:8080/api/v1/dashboard
- **Metrics API**: http://localhost:8080/api/v1/metrics
- **Health API**: http://localhost:8080/api/v1/health
- **Alerts API**: http://localhost:8080/api/v1/alerts
- **WebSocket**: ws://localhost:8080/ws

## Architecture

### Core Components

#### SecurityMetricsCollector
- **Purpose**: Collects and aggregates security metrics from all components
- **Features**: Real-time event processing, Prometheus integration, health monitoring
- **Metrics**: Threat detections, blocked requests, processing times, component health

#### SecurityMonitor
- **Purpose**: Provides dashboard and monitoring capabilities
- **Features**: Real-time updates, WebSocket support, trend analysis
- **Endpoints**: REST API for metrics, health, and dashboard data

#### SecurityAlertManager
- **Purpose**: Manages alerts, notifications, and escalations
- **Features**: Rule-based alerting, multi-channel notifications, escalation management
- **Channels**: Slack, email, webhook, log-based notifications

### Data Flow

```
Security Components → SecurityMetricsCollector → SecurityMonitor → Dashboard
                                ↓
                    SecurityAlertManager → Alert Channels
```

## Configuration

### Metrics Configuration

```go
metricsConfig := &security.MetricsConfig{
    Enabled:               true,
    CollectionInterval:    5 * time.Second,
    RetentionPeriod:       24 * time.Hour,
    PrometheusEnabled:     true,
    PrometheusNamespace:   "security",
    BufferSize:            1000,
    ExportInterval:        10 * time.Second,
    HealthCheckInterval:   30 * time.Second,
    EnableDetailedMetrics: true,
}
```

### Monitoring Configuration

```go
monitoringConfig := &security.MonitoringConfig{
    Enabled:          true,
    DashboardEnabled: true,
    RealTimeUpdates:  true,
    UpdateInterval:   2 * time.Second,
    RetentionPeriod:  24 * time.Hour,
    MaxConnections:   100,
    EnableWebSocket:  true,
    DashboardPort:    8080,
    MetricsEndpoint:  "/api/v1/metrics",
    HealthEndpoint:   "/api/v1/health",
    AlertsEndpoint:   "/api/v1/alerts",
}
```

### Alerting Configuration

```go
alertConfig := &security.AlertingConfig{
    Enabled:              true,
    MaxActiveAlerts:      1000,
    AlertRetentionPeriod: 7 * 24 * time.Hour,
    EvaluationInterval:   10 * time.Second,
    BufferSize:           500,
    Channels: []*security.ChannelConfig{
        {
            Type:          "slack",
            Name:          "security-alerts",
            Enabled:       true,
            Config: map[string]interface{}{
                "webhook_url": "https://hooks.slack.com/...",
            },
            Severities:    []string{"critical", "high"},
            RetryAttempts: 3,
            RetryDelay:    5 * time.Second,
        },
    },
    Rules: []*security.AlertRuleConfig{
        {
            ID:             "high_threat_score",
            Name:           "High Threat Score Detected",
            Enabled:        true,
            Condition:      "threat_score > threshold",
            Threshold:      0.8,
            Severity:       "critical",
            Description:    "Alert when threat score exceeds 0.8",
            Component:      "ai_firewall",
            MetricName:     "threat_score",
            Operator:       ">",
            TimeWindow:     5 * time.Minute,
            MinOccurrences: 1,
            Channels:       []string{"security-alerts"},
        },
    },
}
```

## Programmatic Usage

### Basic Metrics Collection

```go
package main

import (
    "time"
    "github.com/dimajoyti/hackai/pkg/security"
)

func main() {
    // Create logger
    logger := &SimpleLogger{}
    
    // Create metrics collector
    config := &security.MetricsConfig{
        Enabled:               true,
        CollectionInterval:    5 * time.Second,
        PrometheusEnabled:     true,
        BufferSize:            1000,
        HealthCheckInterval:   30 * time.Second,
        EnableDetailedMetrics: true,
    }
    
    collector := security.NewSecurityMetricsCollector(config, logger)
    
    // Start collection
    if err := collector.Start(); err != nil {
        panic(err)
    }
    defer collector.Stop()
    
    // Record security events
    collector.RecordThreatDetection("sql_injection", "critical", "ai_firewall", "192.168.1.100", 0.9)
    collector.RecordBlockedRequest("malicious_payload", "firewall", "192.168.1.100")
    collector.UpdateComponentHealth("ai_firewall", "healthy", true)
    
    // Get metrics
    metrics := collector.GetMetrics()
    fmt.Printf("Threats detected: %d\n", metrics.ThreatsDetected)
    fmt.Printf("Blocked requests: %d\n", metrics.BlockedRequests)
    
    // Get component metrics
    componentMetrics := collector.GetComponentMetrics("ai_firewall")
    if componentMetrics != nil {
        fmt.Printf("Component health: %s\n", componentMetrics.HealthStatus)
    }
}
```

### Dashboard Integration

```go
// Create monitoring system
metricsCollector := security.NewSecurityMetricsCollector(metricsConfig, logger)
alertManager := security.NewSecurityAlertManager(alertConfig, logger)
monitor := security.NewSecurityMonitor(metricsCollector, alertManager, monitoringConfig, logger)

// Start all components
metricsCollector.Start()
alertManager.Start()
monitor.Start()

// Dashboard is now available at http://localhost:8080
```

### Alert Management

```go
// Create alert manager
alertManager := security.NewSecurityAlertManager(alertConfig, logger)
alertManager.Start()

// Trigger alert
metadata := map[string]interface{}{
    "source":       "192.168.1.100",
    "component":    "ai_firewall",
    "threat_score": 0.9,
}
alertManager.TriggerAlert("high_threat", "threat_detection", "critical", 
    "High Threat Detected", "Threat score exceeded threshold", metadata)

// Get active alerts
activeAlerts := alertManager.GetActiveAlerts()
for _, alert := range activeAlerts {
    fmt.Printf("Alert: %s - %s\n", alert.Title, alert.Severity)
}

// Resolve alert
alertManager.ResolveAlert(alertID, "False positive")

// Suppress alerts
alertManager.SuppressAlert("high_threat", "Maintenance window", 1*time.Hour)
```

## Metrics Reference

### Core Security Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `total_requests` | Counter | Total number of requests processed |
| `blocked_requests` | Counter | Number of requests blocked |
| `threats_detected` | Counter | Number of threats detected |
| `threat_score` | Histogram | Distribution of threat scores |
| `processing_duration` | Histogram | Processing time for security checks |
| `component_health` | Gauge | Health status of security components |
| `alerts_triggered` | Counter | Number of alerts triggered |

### Component Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `requests_processed` | Counter | Requests processed by component |
| `threats_detected` | Counter | Threats detected by component |
| `actions_executed` | Counter | Actions executed by component |
| `average_processing_time` | Gauge | Average processing time |
| `error_count` | Counter | Number of errors encountered |
| `health_status` | Gauge | Component health status |

### Performance Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `cpu_usage` | Gauge | CPU utilization percentage |
| `memory_usage` | Gauge | Memory usage in bytes |
| `concurrent_requests` | Gauge | Number of concurrent requests |
| `queue_depth` | Gauge | Processing queue depth |
| `cache_hit_rate` | Gauge | Cache hit rate percentage |

## Alert Rules

### Pre-configured Alert Rules

#### High Threat Score
- **Condition**: `threat_score > 0.8`
- **Severity**: Critical
- **Description**: Triggers when threat score exceeds 0.8

#### Component Health Degradation
- **Condition**: `component_health < 1`
- **Severity**: High
- **Description**: Triggers when component health is not healthy

#### High Error Rate
- **Condition**: `error_rate > 0.1`
- **Severity**: Medium
- **Description**: Triggers when error rate exceeds 10%

#### Processing Time Spike
- **Condition**: `processing_time > 5s`
- **Severity**: Medium
- **Description**: Triggers when processing time exceeds 5 seconds

### Custom Alert Rules

```go
rule := &security.AlertRuleConfig{
    ID:             "custom_rule",
    Name:           "Custom Security Rule",
    Enabled:        true,
    Condition:      "metric_value > threshold",
    Threshold:      100,
    Severity:       "high",
    Description:    "Custom alert rule description",
    Component:      "custom_component",
    MetricName:     "custom_metric",
    Operator:       ">",
    TimeWindow:     10 * time.Minute,
    MinOccurrences: 3,
    Channels:       []string{"slack", "email"},
}
```

## Dashboard Features

### Security Overview
- **Total Requests**: Real-time request count
- **Threats Detected**: Number of threats identified
- **Blocked Requests**: Number of requests blocked
- **System Health**: Overall system health status
- **Average Risk Score**: Current average threat score

### Threat Analysis
- **Threats by Type**: Breakdown by threat category
- **Threats by Severity**: Distribution by severity level
- **Threat Trends**: Historical threat patterns
- **Top Threats**: Most frequent threat types
- **Risk Distribution**: Risk score distribution

### Component Status
- **Component Health**: Health status of all components
- **Performance Metrics**: Processing times and throughput
- **Error Rates**: Component-specific error rates
- **Resource Utilization**: CPU, memory, and network usage

### Real-time Updates
- **WebSocket Integration**: Live data updates
- **Auto-refresh**: Configurable refresh intervals
- **Event Streaming**: Real-time event notifications
- **Interactive Charts**: Clickable and zoomable visualizations

## CLI Reference

### Commands

```bash
# Show security metrics
security-monitor -command=metrics [-format=json|table] [-component=name]

# Show component health
security-monitor -command=health [-format=json|table]

# Show active alerts
security-monitor -command=alerts [-format=json|table]

# Run simulation
security-monitor -command=simulate [-duration=30s]

# Start dashboard
security-monitor -command=dashboard [-port=8080]
```

### Options

- `-command`: Command to execute (metrics, health, alerts, simulate, dashboard)
- `-format`: Output format (json, table)
- `-component`: Component name for filtering
- `-duration`: Duration for simulation
- `-port`: Port for dashboard server
- `-help`: Show help message

## Integration Examples

### Prometheus Integration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'security-metrics'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "Security Monitoring",
    "panels": [
      {
        "title": "Threat Detection Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(security_threat_detections_total[5m])"
          }
        ]
      }
    ]
  }
}
```

### Slack Integration

```go
channel := &security.ChannelConfig{
    Type:    "slack",
    Name:    "security-alerts",
    Enabled: true,
    Config: map[string]interface{}{
        "webhook_url": "https://hooks.slack.com/services/...",
        "channel":     "#security",
        "username":    "SecurityBot",
    },
    Severities: []string{"critical", "high"},
}
```

## Best Practices

### Metrics Collection
1. **Sampling Strategy** - Use appropriate sampling rates for high-volume metrics
2. **Buffer Management** - Configure buffer sizes based on expected load
3. **Resource Monitoring** - Monitor collector resource usage
4. **Data Retention** - Set appropriate retention periods for different metric types

### Dashboard Design
1. **Performance** - Optimize dashboard queries for fast loading
2. **User Experience** - Design intuitive and actionable dashboards
3. **Mobile Support** - Ensure dashboards work on mobile devices
4. **Accessibility** - Follow accessibility guidelines for inclusive design

### Alert Management
1. **Alert Fatigue** - Avoid excessive alerting with proper thresholds
2. **Escalation Paths** - Define clear escalation procedures
3. **Documentation** - Document alert meanings and response procedures
4. **Testing** - Regularly test alert channels and escalation paths

### Security Considerations
1. **Access Control** - Secure dashboard and API access
2. **Data Privacy** - Protect sensitive information in metrics
3. **Audit Logging** - Log access to monitoring systems
4. **Encryption** - Use HTTPS for all dashboard communications

The Security Metrics and Monitoring System provides comprehensive visibility into the security posture of the HackAI platform, enabling proactive threat detection, performance optimization, and incident response.
