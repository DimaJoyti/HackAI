package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

// SimpleCostAnalyzer provides basic cost analysis functionality
type SimpleCostAnalyzer struct {
	awsConfig aws.Config
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

// CostAnalysisReport contains the complete cost analysis results
type CostAnalysisReport struct {
	GeneratedAt        time.Time               `json:"generated_at"`
	TimeRange          string                  `json:"time_range"`
	TotalCurrentCost   float64                 `json:"total_current_cost"`
	TotalOptimizedCost float64                 `json:"total_optimized_cost"`
	TotalSavings       float64                 `json:"total_savings"`
	SavingsPercentage  float64                 `json:"savings_percentage"`
	Recommendations    []CostRecommendation    `json:"recommendations"`
	CloudBreakdown     map[string]CloudCosts   `json:"cloud_breakdown"`
	ServiceBreakdown   map[string]float64      `json:"service_breakdown"`
	Summary            CostOptimizationSummary `json:"summary"`
}

// CloudCosts represents costs for a specific cloud provider
type CloudCosts struct {
	Provider          string  `json:"provider"`
	CurrentCost       float64 `json:"current_cost"`
	OptimizedCost     float64 `json:"optimized_cost"`
	PotentialSavings  float64 `json:"potential_savings"`
	SavingsPercentage float64 `json:"savings_percentage"`
}

// CostOptimizationSummary provides high-level summary
type CostOptimizationSummary struct {
	TotalRecommendations int     `json:"total_recommendations"`
	HighPriorityCount    int     `json:"high_priority_count"`
	MediumPriorityCount  int     `json:"medium_priority_count"`
	LowPriorityCount     int     `json:"low_priority_count"`
	QuickWins            int     `json:"quick_wins"`
	LongTermSavings      float64 `json:"long_term_savings"`
	AutomatableCount     int     `json:"automatable_count"`
}

// NewSimpleCostAnalyzer creates a new cost analyzer instance
func NewSimpleCostAnalyzer(ctx context.Context) (*SimpleCostAnalyzer, error) {
	// Initialize AWS config
	awsConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &SimpleCostAnalyzer{
		awsConfig: awsConfig,
	}, nil
}

// AnalyzeCosts performs basic cost analysis
func (sca *SimpleCostAnalyzer) AnalyzeCosts(ctx context.Context) (*CostAnalysisReport, error) {
	log.Println("Starting cost analysis...")

	report := &CostAnalysisReport{
		GeneratedAt:      time.Now(),
		TimeRange:        "30d",
		CloudBreakdown:   make(map[string]CloudCosts),
		ServiceBreakdown: make(map[string]float64),
	}

	// Generate sample recommendations for demonstration
	recommendations := []CostRecommendation{
		{
			ID:                "aws-spot-001",
			Type:              "spot_instances",
			CloudProvider:     "aws",
			Resource:          "ec2-instances",
			CurrentCost:       500.0,
			OptimizedCost:     150.0,
			PotentialSavings:  350.0,
			SavingsPercentage: 70.0,
			Priority:          "high",
			Effort:            "medium",
			Risk:              "medium",
			Implementation: []string{
				"Convert development instances to spot instances",
				"Implement graceful shutdown handling",
				"Use Auto Scaling with mixed instance types",
			},
			Details: map[string]interface{}{
				"instance_types":     []string{"t3.medium", "t3.large"},
				"interruption_rate":  "5%",
				"workload_tolerance": "fault-tolerant",
			},
			CreatedAt: time.Now(),
		},
		{
			ID:                "aws-rightsize-001",
			Type:              "rightsizing",
			CloudProvider:     "aws",
			Resource:          "ec2-instances",
			CurrentCost:       300.0,
			OptimizedCost:     180.0,
			PotentialSavings:  120.0,
			SavingsPercentage: 40.0,
			Priority:          "medium",
			Effort:            "low",
			Risk:              "low",
			Implementation: []string{
				"Analyze CPU and memory utilization",
				"Downsize underutilized instances",
				"Monitor performance after changes",
			},
			Details: map[string]interface{}{
				"current_utilization": "25%",
				"recommended_size":    "t3.small",
				"confidence_level":    "high",
			},
			CreatedAt: time.Now(),
		},
		{
			ID:                "aws-storage-001",
			Type:              "storage_optimization",
			CloudProvider:     "aws",
			Resource:          "ebs-volumes",
			CurrentCost:       200.0,
			OptimizedCost:     120.0,
			PotentialSavings:  80.0,
			SavingsPercentage: 40.0,
			Priority:          "medium",
			Effort:            "low",
			Risk:              "low",
			Implementation: []string{
				"Implement EBS volume lifecycle policies",
				"Convert to gp3 volumes for better price/performance",
				"Delete unused snapshots",
			},
			Details: map[string]interface{}{
				"volume_type":      "gp2",
				"recommended_type": "gp3",
				"unused_snapshots": 15,
			},
			CreatedAt: time.Now(),
		},
	}

	report.Recommendations = recommendations

	// Calculate cloud breakdown
	awsCosts := CloudCosts{
		Provider:          "aws",
		CurrentCost:       1000.0,
		OptimizedCost:     450.0,
		PotentialSavings:  550.0,
		SavingsPercentage: 55.0,
	}

	gcpCosts := CloudCosts{
		Provider:          "gcp",
		CurrentCost:       500.0,
		OptimizedCost:     350.0,
		PotentialSavings:  150.0,
		SavingsPercentage: 30.0,
	}

	azureCosts := CloudCosts{
		Provider:          "azure",
		CurrentCost:       300.0,
		OptimizedCost:     210.0,
		PotentialSavings:  90.0,
		SavingsPercentage: 30.0,
	}

	report.CloudBreakdown["aws"] = awsCosts
	report.CloudBreakdown["gcp"] = gcpCosts
	report.CloudBreakdown["azure"] = azureCosts

	// Calculate totals
	report.TotalCurrentCost = awsCosts.CurrentCost + gcpCosts.CurrentCost + azureCosts.CurrentCost
	report.TotalOptimizedCost = awsCosts.OptimizedCost + gcpCosts.OptimizedCost + azureCosts.OptimizedCost
	report.TotalSavings = report.TotalCurrentCost - report.TotalOptimizedCost
	if report.TotalCurrentCost > 0 {
		report.SavingsPercentage = (report.TotalSavings / report.TotalCurrentCost) * 100
	}

	// Generate summary
	report.Summary = CostOptimizationSummary{
		TotalRecommendations: len(recommendations),
		HighPriorityCount:    1,
		MediumPriorityCount:  2,
		LowPriorityCount:     0,
		QuickWins:            2,
		LongTermSavings:      report.TotalSavings * 12, // Annual savings
		AutomatableCount:     3,
	}

	// Service breakdown
	report.ServiceBreakdown["EC2"] = 600.0
	report.ServiceBreakdown["RDS"] = 300.0
	report.ServiceBreakdown["S3"] = 200.0
	report.ServiceBreakdown["CloudWatch"] = 50.0
	report.ServiceBreakdown["Other"] = 650.0

	log.Printf("Cost analysis completed. Total potential savings: $%.2f", report.TotalSavings)
	return report, nil
}

// GenerateReport generates a formatted cost analysis report
func (sca *SimpleCostAnalyzer) GenerateReport(report *CostAnalysisReport) string {
	output := fmt.Sprintf(`
=== HackAI Multi-Cloud Cost Analysis Report ===
Generated: %s
Time Range: %s

=== Summary ===
Total Current Cost: $%.2f
Total Optimized Cost: $%.2f
Total Potential Savings: $%.2f (%.1f%%)

=== Recommendations ===
Total Recommendations: %d
- High Priority: %d
- Medium Priority: %d
- Low Priority: %d
- Quick Wins: %d
- Automatable: %d

Annual Savings Potential: $%.2f

=== Cloud Provider Breakdown ===
`,
		report.GeneratedAt.Format("2006-01-02 15:04:05"),
		report.TimeRange,
		report.TotalCurrentCost,
		report.TotalOptimizedCost,
		report.TotalSavings,
		report.SavingsPercentage,
		report.Summary.TotalRecommendations,
		report.Summary.HighPriorityCount,
		report.Summary.MediumPriorityCount,
		report.Summary.LowPriorityCount,
		report.Summary.QuickWins,
		report.Summary.AutomatableCount,
		report.Summary.LongTermSavings,
	)

	for provider, costs := range report.CloudBreakdown {
		output += fmt.Sprintf("- %s: $%.2f → $%.2f (Save $%.2f, %.1f%%)\n",
			provider, costs.CurrentCost, costs.OptimizedCost, costs.PotentialSavings, costs.SavingsPercentage)
	}

	output += "\n=== Top Recommendations ===\n"
	for i, rec := range report.Recommendations {
		if i >= 3 { // Show top 3 recommendations
			break
		}
		output += fmt.Sprintf("%d. %s (%s)\n", i+1, rec.Type, rec.CloudProvider)
		output += fmt.Sprintf("   Savings: $%.2f (%.1f%%) - Priority: %s\n",
			rec.PotentialSavings, rec.SavingsPercentage, rec.Priority)
		output += fmt.Sprintf("   Resource: %s\n", rec.Resource)
		output += fmt.Sprintf("   Implementation: %s\n\n", rec.Implementation[0])
	}

	return output
}

// Main function for testing
func main() {
	ctx := context.Background()

	analyzer, err := NewSimpleCostAnalyzer(ctx)
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
