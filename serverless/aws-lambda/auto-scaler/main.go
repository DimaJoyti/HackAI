package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
)

// AutoScalerEvent represents the event structure for auto-scaling
type AutoScalerEvent struct {
	Source      string                 `json:"source"`
	DetailType  string                 `json:"detail-type"`
	Detail      map[string]interface{} `json:"detail"`
	Function    string                 `json:"function"`
	CloudProvider string               `json:"cloud_provider"`
	ClusterName string                 `json:"cluster_name"`
	ServiceName string                 `json:"service_name"`
	MetricType  string                 `json:"metric_type"`
	Threshold   float64                `json:"threshold"`
	Action      string                 `json:"action"` // scale_up, scale_down, optimize
}

// AutoScalerResponse represents the response from auto-scaling operations
type AutoScalerResponse struct {
	Success     bool                   `json:"success"`
	Message     string                 `json:"message"`
	Action      string                 `json:"action"`
	Details     map[string]interface{} `json:"details"`
	Timestamp   time.Time              `json:"timestamp"`
	Cost        float64                `json:"estimated_cost_impact"`
}

// AutoScaler handles multi-cloud auto-scaling operations
type AutoScaler struct {
	cloudWatchClient    *cloudwatch.Client
	autoScalingClient   *applicationautoscaling.Client
	eksClient          *eks.Client
	ecsClient          *ecs.Client
	region             string
	environment        string
}

// NewAutoScaler creates a new AutoScaler instance
func NewAutoScaler(ctx context.Context) (*AutoScaler, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &AutoScaler{
		cloudWatchClient:  cloudwatch.NewFromConfig(cfg),
		autoScalingClient: applicationautoscaling.NewFromConfig(cfg),
		eksClient:        eks.NewFromConfig(cfg),
		ecsClient:        ecs.NewFromConfig(cfg),
		region:           os.Getenv("AWS_REGION"),
		environment:      os.Getenv("ENVIRONMENT"),
	}, nil
}

// HandleRequest processes auto-scaling events
func (as *AutoScaler) HandleRequest(ctx context.Context, event events.CloudWatchEvent) (AutoScalerResponse, error) {
	log.Printf("Processing auto-scaling event: %+v", event)

	var autoScalerEvent AutoScalerEvent
	if err := json.Unmarshal(event.Detail, &autoScalerEvent); err != nil {
		return AutoScalerResponse{
			Success:   false,
			Message:   fmt.Sprintf("Failed to parse event: %v", err),
			Timestamp: time.Now(),
		}, err
	}

	response := AutoScalerResponse{
		Timestamp: time.Now(),
		Action:    autoScalerEvent.Action,
	}

	switch autoScalerEvent.Action {
	case "scale_up":
		return as.scaleUp(ctx, autoScalerEvent)
	case "scale_down":
		return as.scaleDown(ctx, autoScalerEvent)
	case "optimize":
		return as.optimize(ctx, autoScalerEvent)
	default:
		response.Success = false
		response.Message = fmt.Sprintf("Unknown action: %s", autoScalerEvent.Action)
		return response, fmt.Errorf("unknown action: %s", autoScalerEvent.Action)
	}
}

// scaleUp handles scaling up resources
func (as *AutoScaler) scaleUp(ctx context.Context, event AutoScalerEvent) (AutoScalerResponse, error) {
	log.Printf("Scaling up %s in cluster %s", event.ServiceName, event.ClusterName)

	response := AutoScalerResponse{
		Action:    "scale_up",
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	// Get current metrics
	metrics, err := as.getCurrentMetrics(ctx, event.ClusterName, event.ServiceName)
	if err != nil {
		response.Success = false
		response.Message = fmt.Sprintf("Failed to get metrics: %v", err)
		return response, err
	}

	// Calculate optimal scaling
	currentReplicas := metrics["current_replicas"].(int)
	targetReplicas := as.calculateTargetReplicas(currentReplicas, event.Threshold, "up")

	// Apply scaling
	err = as.applyScaling(ctx, event.ClusterName, event.ServiceName, targetReplicas)
	if err != nil {
		response.Success = false
		response.Message = fmt.Sprintf("Failed to scale up: %v", err)
		return response, err
	}

	response.Success = true
	response.Message = fmt.Sprintf("Successfully scaled up %s from %d to %d replicas", 
		event.ServiceName, currentReplicas, targetReplicas)
	response.Details["previous_replicas"] = currentReplicas
	response.Details["new_replicas"] = targetReplicas
	response.Cost = as.calculateCostImpact(currentReplicas, targetReplicas)

	// Send metrics to CloudWatch
	as.sendMetrics(ctx, "AutoScaling", "ScaleUp", 1.0, event.ClusterName, event.ServiceName)

	return response, nil
}

// scaleDown handles scaling down resources
func (as *AutoScaler) scaleDown(ctx context.Context, event AutoScalerEvent) (AutoScalerResponse, error) {
	log.Printf("Scaling down %s in cluster %s", event.ServiceName, event.ClusterName)

	response := AutoScalerResponse{
		Action:    "scale_down",
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	// Get current metrics
	metrics, err := as.getCurrentMetrics(ctx, event.ClusterName, event.ServiceName)
	if err != nil {
		response.Success = false
		response.Message = fmt.Sprintf("Failed to get metrics: %v", err)
		return response, err
	}

	currentReplicas := metrics["current_replicas"].(int)
	
	// Ensure minimum replicas
	minReplicas := 1
	if env := os.Getenv("MIN_REPLICAS"); env != "" {
		if min, err := strconv.Atoi(env); err == nil {
			minReplicas = min
		}
	}

	if currentReplicas <= minReplicas {
		response.Success = false
		response.Message = fmt.Sprintf("Cannot scale down below minimum replicas (%d)", minReplicas)
		return response, fmt.Errorf("minimum replicas reached")
	}

	targetReplicas := as.calculateTargetReplicas(currentReplicas, event.Threshold, "down")
	if targetReplicas < minReplicas {
		targetReplicas = minReplicas
	}

	// Apply scaling
	err = as.applyScaling(ctx, event.ClusterName, event.ServiceName, targetReplicas)
	if err != nil {
		response.Success = false
		response.Message = fmt.Sprintf("Failed to scale down: %v", err)
		return response, err
	}

	response.Success = true
	response.Message = fmt.Sprintf("Successfully scaled down %s from %d to %d replicas", 
		event.ServiceName, currentReplicas, targetReplicas)
	response.Details["previous_replicas"] = currentReplicas
	response.Details["new_replicas"] = targetReplicas
	response.Cost = as.calculateCostImpact(currentReplicas, targetReplicas)

	// Send metrics to CloudWatch
	as.sendMetrics(ctx, "AutoScaling", "ScaleDown", 1.0, event.ClusterName, event.ServiceName)

	return response, nil
}

// optimize handles resource optimization
func (as *AutoScaler) optimize(ctx context.Context, event AutoScalerEvent) (AutoScalerResponse, error) {
	log.Printf("Optimizing resources for %s in cluster %s", event.ServiceName, event.ClusterName)

	response := AutoScalerResponse{
		Action:    "optimize",
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	// Get comprehensive metrics
	metrics, err := as.getComprehensiveMetrics(ctx, event.ClusterName, event.ServiceName)
	if err != nil {
		response.Success = false
		response.Message = fmt.Sprintf("Failed to get metrics: %v", err)
		return response, err
	}

	// Analyze and optimize
	optimizations := as.analyzeOptimizations(metrics)
	
	response.Success = true
	response.Message = "Resource optimization analysis completed"
	response.Details = optimizations
	response.Cost = optimizations["estimated_savings"].(float64)

	// Send optimization metrics
	as.sendMetrics(ctx, "AutoScaling", "Optimize", 1.0, event.ClusterName, event.ServiceName)

	return response, nil
}

// Helper methods

func (as *AutoScaler) getCurrentMetrics(ctx context.Context, clusterName, serviceName string) (map[string]interface{}, error) {
	// Implementation for getting current metrics from CloudWatch
	// This is a simplified version - in production, you'd query actual metrics
	return map[string]interface{}{
		"current_replicas": 3,
		"cpu_utilization": 75.0,
		"memory_utilization": 60.0,
		"request_rate": 100.0,
	}, nil
}

func (as *AutoScaler) getComprehensiveMetrics(ctx context.Context, clusterName, serviceName string) (map[string]interface{}, error) {
	// Implementation for getting comprehensive metrics
	return map[string]interface{}{
		"current_replicas": 3,
		"cpu_utilization": 75.0,
		"memory_utilization": 60.0,
		"request_rate": 100.0,
		"response_time": 200.0,
		"error_rate": 0.1,
		"cost_per_hour": 5.0,
	}, nil
}

func (as *AutoScaler) calculateTargetReplicas(current int, threshold float64, direction string) int {
	factor := 1.5 // Default scaling factor
	if direction == "up" {
		return int(float64(current) * factor)
	}
	return int(float64(current) / factor)
}

func (as *AutoScaler) applyScaling(ctx context.Context, clusterName, serviceName string, targetReplicas int) error {
	// Implementation for applying scaling to the actual service
	// This would interact with EKS, ECS, or other container orchestration services
	log.Printf("Applying scaling: cluster=%s, service=%s, replicas=%d", clusterName, serviceName, targetReplicas)
	return nil
}

func (as *AutoScaler) calculateCostImpact(currentReplicas, targetReplicas int) float64 {
	costPerReplica := 0.10 // $0.10 per hour per replica
	return float64(targetReplicas-currentReplicas) * costPerReplica
}

func (as *AutoScaler) analyzeOptimizations(metrics map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"cpu_optimization": "Consider using smaller instance types",
		"memory_optimization": "Memory usage is optimal",
		"cost_optimization": "Switch to spot instances for 60% savings",
		"estimated_savings": 50.0,
	}
}

func (as *AutoScaler) sendMetrics(ctx context.Context, namespace, metricName string, value float64, dimensions ...string) error {
	// Implementation for sending custom metrics to CloudWatch
	return nil
}

// Lambda handler
func handler(ctx context.Context, event events.CloudWatchEvent) (AutoScalerResponse, error) {
	autoScaler, err := NewAutoScaler(ctx)
	if err != nil {
		return AutoScalerResponse{
			Success:   false,
			Message:   fmt.Sprintf("Failed to initialize auto-scaler: %v", err),
			Timestamp: time.Now(),
		}, err
	}

	return autoScaler.HandleRequest(ctx, event)
}

func main() {
	lambda.Start(handler)
}
