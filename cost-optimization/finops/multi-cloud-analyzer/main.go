package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// MultiCloudCostAnalyzer provides comprehensive cost analysis across cloud providers
type MultiCloudCostAnalyzer struct {
	analysisConfig *AnalysisConfig
}

// AnalysisConfig contains configuration for cost analysis
type AnalysisConfig struct {
	TimeRange           string  `json:"time_range"`        // 7d, 30d, 90d
	CostThreshold       float64 `json:"cost_threshold"`    // Minimum cost to analyze
	SavingsThreshold    float64 `json:"savings_threshold"` // Minimum savings to recommend
	IncludeSpotAnalysis bool    `json:"include_spot_analysis"`
	IncludeRIAnalysis   bool    `json:"include_ri_analysis"`
	IncludeRightsizing  bool    `json:"include_rightsizing"`
}

// CostRecommendation represents a cost optimization recommendation
type CostRecommendation struct {
	ID                string                 `json:"id"`
	Type              string                 `json:"type"`
	CloudProvider     string                 `json:"cloud_provider"`
	Resource          string                 `json:"resource"`
	CurrentCost       float64                `json:"current_cost"`
	OptimizedCost     float64                `json:"optimized_cost"`
	PotentialSavings  float64                `json:"potential_savings"`
	SavingsPercentage float64                `json:"savings_percentage"`
	Priority          string                 `json:"priority"`
	Effort            string                 `json:"effort"`
	Risk              string                 `json:"risk"`
	Implementation    []string               `json:"implementation"`
	Details           map[string]interface{} `json:"details"`
	CreatedAt         time.Time              `json:"created_at"`
}

// CostAnalysisReport represents the complete cost analysis report
type CostAnalysisReport struct {
	GeneratedAt       time.Time               `json:"generated_at"`
	TimeRange         string                  `json:"time_range"`
	TotalCost         float64                 `json:"total_cost"`
	OptimizedCost     float64                 `json:"optimized_cost"`
	PotentialSavings  float64                 `json:"potential_savings"`
	SavingsPercentage float64                 `json:"savings_percentage"`
	CloudBreakdown    map[string]CloudCosts   `json:"cloud_breakdown"`
	ServiceBreakdown  map[string]float64      `json:"service_breakdown"`
	Recommendations   []CostRecommendation    `json:"recommendations"`
	Summary           CostOptimizationSummary `json:"summary"`
}

// CloudCosts represents costs for a specific cloud provider
type CloudCosts struct {
	Provider          string  `json:"provider"`
	CurrentCost       float64 `json:"current_cost"`
	OptimizedCost     float64 `json:"optimized_cost"`
	PotentialSavings  float64 `json:"potential_savings"`
	SavingsPercentage float64 `json:"savings_percentage"`
}

// CostOptimizationSummary provides a high-level summary
type CostOptimizationSummary struct {
	TotalRecommendations int     `json:"total_recommendations"`
	HighPriorityCount    int     `json:"high_priority_count"`
	MediumPriorityCount  int     `json:"medium_priority_count"`
	LowPriorityCount     int     `json:"low_priority_count"`
	QuickWinsCount       int     `json:"quick_wins_count"`
	EstimatedSavings     float64 `json:"estimated_savings"`
}

// NewMultiCloudCostAnalyzer creates a new cost analyzer instance
func NewMultiCloudCostAnalyzer(ctx context.Context) (*MultiCloudCostAnalyzer, error) {
	// Default analysis configuration
	analysisConfig := &AnalysisConfig{
		TimeRange:           "30d",
		CostThreshold:       10.0,
		SavingsThreshold:    5.0,
		IncludeSpotAnalysis: true,
		IncludeRIAnalysis:   true,
		IncludeRightsizing:  true,
	}

	return &MultiCloudCostAnalyzer{
		analysisConfig: analysisConfig,
	}, nil
}

// AnalyzeCosts performs comprehensive cost analysis across all cloud providers
func (mca *MultiCloudCostAnalyzer) AnalyzeCosts(ctx context.Context) (*CostAnalysisReport, error) {
	log.Println("Starting multi-cloud cost analysis...")

	report := &CostAnalysisReport{
		GeneratedAt:      time.Now(),
		TimeRange:        mca.analysisConfig.TimeRange,
		CloudBreakdown:   make(map[string]CloudCosts),
		ServiceBreakdown: make(map[string]float64),
	}

	// Simulate AWS costs
	awsCosts := CloudCosts{
		Provider:          "aws",
		CurrentCost:       1500.0,
		OptimizedCost:     1200.0,
		PotentialSavings:  300.0,
		SavingsPercentage: 20.0,
	}
	report.CloudBreakdown["aws"] = awsCosts

	// Simulate GCP costs
	gcpCosts := CloudCosts{
		Provider:          "gcp",
		CurrentCost:       800.0,
		OptimizedCost:     650.0,
		PotentialSavings:  150.0,
		SavingsPercentage: 18.75,
	}
	report.CloudBreakdown["gcp"] = gcpCosts

	// Add sample recommendations
	report.Recommendations = []CostRecommendation{
		{
			ID:                "aws-ec2-001",
			Type:              "rightsizing",
			CloudProvider:     "aws",
			Resource:          "ec2-instances",
			CurrentCost:       500.0,
			OptimizedCost:     350.0,
			PotentialSavings:  150.0,
			SavingsPercentage: 30.0,
			Priority:          "high",
			Effort:            "medium",
			Risk:              "low",
			Implementation: []string{
				"Analyze CPU and memory utilization",
				"Downsize underutilized instances",
				"Consider burstable instances for variable workloads",
			},
			Details: map[string]interface{}{
				"instance_types": []string{"t3.large", "t3.medium"},
				"utilization":    "25%",
			},
			CreatedAt: time.Now(),
		},
		{
			ID:                "gcp-compute-001",
			Type:              "preemptible",
			CloudProvider:     "gcp",
			Resource:          "compute-instances",
			CurrentCost:       300.0,
			OptimizedCost:     180.0,
			PotentialSavings:  120.0,
			SavingsPercentage: 40.0,
			Priority:          "medium",
			Effort:            "low",
			Risk:              "medium",
			Implementation: []string{
				"Migrate fault-tolerant workloads to preemptible instances",
				"Implement proper restart handling",
			},
			Details: map[string]interface{}{
				"workload_type":   "batch_processing",
				"fault_tolerance": true,
			},
			CreatedAt: time.Now(),
		},
	}

	// Calculate totals
	report.TotalCost = awsCosts.CurrentCost + gcpCosts.CurrentCost
	report.OptimizedCost = awsCosts.OptimizedCost + gcpCosts.OptimizedCost
	report.PotentialSavings = report.TotalCost - report.OptimizedCost
	if report.TotalCost > 0 {
		report.SavingsPercentage = (report.PotentialSavings / report.TotalCost) * 100
	}

	// Generate summary
	report.Summary = CostOptimizationSummary{
		TotalRecommendations: len(report.Recommendations),
		HighPriorityCount:    1,
		MediumPriorityCount:  1,
		LowPriorityCount:     0,
		QuickWinsCount:       1,
		EstimatedSavings:     report.PotentialSavings,
	}

	log.Printf("Analysis complete. Total potential savings: $%.2f (%.1f%%)",
		report.PotentialSavings, report.SavingsPercentage)

	return report, nil
}

// GenerateReport generates a formatted text report
func (mca *MultiCloudCostAnalyzer) GenerateReport(report *CostAnalysisReport) string {
	output := fmt.Sprintf(`
Multi-Cloud Cost Analysis Report
================================
Generated: %s
Time Range: %s

Cost Summary:
- Current Total Cost: $%.2f
- Optimized Cost: $%.2f
- Potential Savings: $%.2f (%.1f%%)

Cloud Provider Breakdown:
`,
		report.GeneratedAt.Format("2006-01-02 15:04:05"),
		report.TimeRange,
		report.TotalCost,
		report.OptimizedCost,
		report.PotentialSavings,
		report.SavingsPercentage,
	)

	for provider, costs := range report.CloudBreakdown {
		output += fmt.Sprintf("- %s: $%.2f → $%.2f (Save $%.2f)\n",
			provider, costs.CurrentCost, costs.OptimizedCost, costs.PotentialSavings)
	}

	output += fmt.Sprintf(`
Recommendations (%d total):
`, len(report.Recommendations))

	for i, rec := range report.Recommendations {
		output += fmt.Sprintf(`
%d. %s (%s)
   Provider: %s | Resource: %s
   Savings: $%.2f (%.1f%%) | Priority: %s
   Implementation: %s
`,
			i+1, rec.Type, rec.ID,
			rec.CloudProvider, rec.Resource,
			rec.PotentialSavings, rec.SavingsPercentage, rec.Priority,
			rec.Implementation[0],
		)
	}

	return output
}

// Main function for testing
func main() {
	ctx := context.Background()

	analyzer, err := NewMultiCloudCostAnalyzer(ctx)
	if err != nil {
		log.Fatalf("Failed to create cost analyzer: %v", err)
	}

	report, err := analyzer.AnalyzeCosts(ctx)
	if err != nil {
		log.Fatalf("Failed to analyze costs: %v", err)
	}

	// Output report as JSON
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal report: %v", err)
	}

	fmt.Println("=== JSON Report ===")
	fmt.Println(string(reportJSON))

	// Output formatted report
	fmt.Println("\n=== Formatted Report ===")
	fmt.Println(analyzer.GenerateReport(report))
}
