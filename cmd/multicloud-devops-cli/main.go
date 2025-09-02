package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/agents/multiagent"
	"github.com/dimajoyti/hackai/pkg/ai"
	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/logger"
)

const (
	Version = "1.0.0"
	Banner  = `
🌥️  Multi-Cloud Multi-Agent DevOps CLI  🤖
===============================================
Version: %s
A comprehensive DevOps orchestration system combining
multi-cloud infrastructure with intelligent agent workflows
`
)

// Agent ID constants
const (
	InfraAWSAgentID          = "infra-aws"
	InfraGCPAgentID          = "infra-gcp"
	InfraAzureAgentID        = "infra-azure"
	SecurityScannerAgentID   = "security-scanner"
	SecurityComplianceAgentID = "security-compliance"
	MonitorHealthAgentID     = "monitor-health"
	MonitorAlertsAgentID     = "monitor-alerts"
	CostAnalyzerAgentID      = "cost-analyzer"
	CostRecommendationsAgentID = "cost-recommendations"
)

// CLI Commands
type Command struct {
	Name        string
	Description string
	Usage       string
	Handler     func(args []string) error
}

// Cloud Provider Types
type CloudProvider string

const (
	AWS   CloudProvider = "aws"
	GCP   CloudProvider = "gcp"
	Azure CloudProvider = "azure"
)

// DevOps Agent Types
type AgentType string

const (
	InfrastructureAgent AgentType = "infrastructure"
	SecurityAgent       AgentType = "security"
	MonitoringAgent     AgentType = "monitoring"
	DeploymentAgent     AgentType = "deployment"
	CostOptimizer       AgentType = "cost"
	ComplianceAgent     AgentType = "compliance"
)

// DevOps CLI System
type MultiCloudDevOpsCLI struct {
	orchestrator *multiagent.MultiAgentOrchestrator
	agents       map[string]ai.Agent
	logger       *logger.Logger
	config       *config.Config
}

func main() {
	fmt.Printf(Banner, Version)

	// Parse flags
	var (
		command     = flag.String("command", "", "Command to execute")
		cloud       = flag.String("cloud", "", "Cloud provider (aws,gcp,azure)")
		environment = flag.String("env", "development", "Environment (development,staging,production)")
		agents      = flag.String("agents", "", "Comma-separated list of agent types")
		verbose     = flag.Bool("verbose", false, "Enable verbose output")
		help        = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help || *command == "" {
		showHelp()
		return
	}

	// Initialize CLI system
	cli, err := NewMultiCloudDevOpsCLI(*environment, *verbose)
	if err != nil {
		log.Fatalf("Failed to initialize CLI: %v", err)
	}
	defer cli.Close()

	// Execute command
	args := []string{*cloud, *agents}
	if err := cli.ExecuteCommand(*command, args); err != nil {
		log.Fatalf("Command failed: %v", err)
	}
}

func showHelp() {
	fmt.Print(`
USAGE:
  multicloud-devops-cli -command <cmd> [options]

COMMANDS:
  deploy      Deploy infrastructure across multiple clouds
  scale       Auto-scale resources based on demand
  monitor     Monitor multi-cloud infrastructure health
  optimize    Optimize costs and performance
  secure      Run security assessments
  comply      Check compliance across environments
  backup      Backup and disaster recovery operations
  migrate     Migrate workloads between clouds
  analyze     Analyze infrastructure and performance
  orchestrate Execute custom multi-agent workflows

OPTIONS:
  -cloud <provider>     Target cloud provider(s): aws,gcp,azure
  -env <environment>    Environment: development,staging,production
  -agents <types>       Agent types: infrastructure,security,monitoring,deployment,cost,compliance
  -verbose              Enable detailed output
  -help                Show this help message

EXAMPLES:
  # Deploy to AWS with infrastructure and security agents
  multicloud-devops-cli -command deploy -cloud aws -agents infrastructure,security

  # Monitor all clouds with monitoring and security agents
  multicloud-devops-cli -command monitor -cloud aws,gcp,azure -agents monitoring,security

  # Cost optimization across all environments
  multicloud-devops-cli -command optimize -agents cost,monitoring -env production

  # Compliance check with multiple agents
  multicloud-devops-cli -command comply -agents compliance,security -verbose
`)
}

func NewMultiCloudDevOpsCLI(environment string, verbose bool) (*MultiCloudDevOpsCLI, error) {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Initialize logger
	logLevel := logger.LogLevel(cfg.Observability.Logging.Level)
	if verbose {
		logLevel = logger.LogLevel("debug")
	}

	logger, err := logger.New(logger.Config{
		Level:      logLevel,
		Format:     cfg.Observability.Logging.Format,
		Output:     cfg.Observability.Logging.Output,
		AddSource:  true,
		TimeFormat: time.RFC3339,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Initialize multi-agent orchestrator
	orchestratorConfig := &multiagent.OrchestratorConfig{
		MaxConcurrentTasks:     20,
		TaskTimeout:            30 * time.Minute,
		ConflictResolutionMode: "consensus",
		ConsensusThreshold:     0.75,
		EnableLoadBalancing:    true,
		EnableFailover:         true,
		HealthCheckInterval:    15 * time.Second,
		MetricsEnabled:         true,
	}

	orchestrator := multiagent.NewMultiAgentOrchestrator(orchestratorConfig, logger)

	cli := &MultiCloudDevOpsCLI{
		orchestrator: orchestrator,
		agents:       make(map[string]ai.Agent),
		logger:       logger,
		config:       cfg,
	}

	// Initialize and register default agents
	if err := cli.initializeAgents(); err != nil {
		return nil, fmt.Errorf("failed to initialize agents: %w", err)
	}

	return cli, nil
}

func (cli *MultiCloudDevOpsCLI) initializeAgents() error {
	// Create DevOps-specific agents
	agents := []struct {
		id          string
		name        string
		agentType   AgentType
		description string
	}{
		{InfraAWSAgentID, "AWS Infrastructure Agent", InfrastructureAgent, "Manages AWS infrastructure deployment and configuration"},
		{InfraGCPAgentID, "GCP Infrastructure Agent", InfrastructureAgent, "Manages GCP infrastructure deployment and configuration"},
		{InfraAzureAgentID, "Azure Infrastructure Agent", InfrastructureAgent, "Manages Azure infrastructure deployment and configuration"},
		{SecurityScannerAgentID, "Security Assessment Agent", SecurityAgent, "Performs security scans and vulnerability assessments"},
		{SecurityComplianceAgentID, "Compliance Validation Agent", ComplianceAgent, "Validates compliance with security standards"},
		{MonitorHealthAgentID, "Health Monitor Agent", MonitoringAgent, "Monitors system health and performance metrics"},
		{MonitorAlertsAgentID, "Alert Management Agent", MonitoringAgent, "Manages alerts and incident response"},
		{"deploy-kubernetes", "Kubernetes Deployment Agent", DeploymentAgent, "Manages Kubernetes deployments across clouds"},
		{"deploy-serverless", "Serverless Deployment Agent", DeploymentAgent, "Manages serverless function deployments"},
		{CostAnalyzerAgentID, "Cost Analysis Agent", CostOptimizer, "Analyzes and optimizes cloud costs"},
		{CostRecommendationsAgentID, "Cost Recommendation Agent", CostOptimizer, "Provides cost optimization recommendations"},
	}

	for _, agentInfo := range agents {
		agent := cli.createDevOpsAgent(agentInfo.id, agentInfo.name, agentInfo.agentType, agentInfo.description)
		cli.agents[agentInfo.id] = agent

		if err := cli.orchestrator.RegisterAgent(agent); err != nil {
			return fmt.Errorf("failed to register agent %s: %w", agentInfo.id, err)
		}
	}

	cli.logger.Info("Initialized DevOps agents", "count", len(agents))
	return nil
}

func (cli *MultiCloudDevOpsCLI) createDevOpsAgent(id, name string, agentType AgentType, description string) ai.Agent {
	return &DevOpsAgent{
		id:          id,
		name:        name,
		agentType:   agentType,
		description: description,
		logger:      cli.logger,
	}
}

func (cli *MultiCloudDevOpsCLI) ExecuteCommand(command string, args []string) error {
	ctx := context.Background()

	// Start orchestrator
	if err := cli.orchestrator.Start(ctx); err != nil {
		return fmt.Errorf("failed to start orchestrator: %w", err)
	}
	defer cli.orchestrator.Stop()

	commands := map[string]func([]string) error{
		"deploy":      cli.deployCommand,
		"scale":       cli.scaleCommand,
		"monitor":     cli.monitorCommand,
		"optimize":    cli.optimizeCommand,
		"secure":      cli.secureCommand,
		"comply":      cli.complyCommand,
		"backup":      cli.backupCommand,
		"migrate":     cli.migrateCommand,
		"analyze":     cli.analyzeCommand,
		"orchestrate": cli.orchestrateCommand,
	}

	handler, exists := commands[command]
	if !exists {
		return fmt.Errorf("unknown command: %s", command)
	}

	fmt.Printf("🚀 Executing command: %s\n", command)
	return handler(args)
}

func (cli *MultiCloudDevOpsCLI) deployCommand(args []string) error {
	clouds := cli.parseCloudProviders(args[0])
	agents := cli.parseAgentTypes(args[1])

	fmt.Printf("🏗️  Multi-Cloud Infrastructure Deployment\n")
	fmt.Printf("Target Clouds: %v\n", clouds)
	fmt.Printf("Active Agents: %v\n", agents)

	task := &multiagent.MultiAgentTask{
		ID:          fmt.Sprintf("deploy-%d", time.Now().Unix()),
		Type:        "security_analysis",
		Priority:    multiagent.TaskPriorityHigh,
		Description: "Deploy infrastructure across multiple cloud providers",
		RequiredAgents: cli.getAgentsByType(agents),
		Parameters: map[string]any{
			"clouds":      clouds,
			"environment": "production",
			"strategy":    "blue_green",
			"rollback_enabled": true,
		},
		CollaborationMode: "parallel",
		CreatedAt:         time.Now(),
	}

	result, err := cli.orchestrator.ExecuteTask(context.Background(), task)
	if err != nil {
		return fmt.Errorf("deployment failed: %w", err)
	}

	cli.printTaskResult("Deployment", result)
	return nil
}

func (cli *MultiCloudDevOpsCLI) scaleCommand(args []string) error {
	fmt.Printf("📈 Auto-Scaling Infrastructure\n")

	task := &multiagent.MultiAgentTask{
		ID:          fmt.Sprintf("scale-%d", time.Now().Unix()),
		Type:        "business_analysis",
		Priority:    multiagent.TaskPriorityMedium,
		Description: "Auto-scale resources based on demand patterns",
		RequiredAgents: []string{InfraAWSAgentID, InfraGCPAgentID, MonitorHealthAgentID},
		Parameters: map[string]any{
			"scaling_policy": "predictive",
			"min_instances":  2,
			"max_instances":  50,
			"target_cpu":     70,
		},
		CollaborationMode: "sequential",
		CreatedAt:         time.Now(),
	}

	result, err := cli.orchestrator.ExecuteTask(context.Background(), task)
	if err != nil {
		return fmt.Errorf("scaling failed: %w", err)
	}

	cli.printTaskResult("Auto-Scaling", result)
	return nil
}

func (cli *MultiCloudDevOpsCLI) monitorCommand(args []string) error {
	fmt.Printf("📊 Multi-Cloud Infrastructure Monitoring\n")

	task := &multiagent.MultiAgentTask{
		ID:          fmt.Sprintf("monitor-%d", time.Now().Unix()),
		Type:        "security_analysis",
		Priority:    multiagent.TaskPriorityMedium,
		Description: "Monitor infrastructure health across all clouds",
		RequiredAgents: []string{MonitorHealthAgentID, MonitorAlertsAgentID, SecurityScannerAgentID},
		Parameters: map[string]any{
			"metrics":          []string{"cpu", "memory", "disk", "network"},
			"alert_thresholds": map[string]float64{"cpu": 80, "memory": 85},
			"check_interval":   "5m",
		},
		CollaborationMode: "parallel",
		CreatedAt:         time.Now(),
	}

	result, err := cli.orchestrator.ExecuteTask(context.Background(), task)
	if err != nil {
		return fmt.Errorf("monitoring failed: %w", err)
	}

	cli.printTaskResult("Monitoring", result)
	return nil
}

func (cli *MultiCloudDevOpsCLI) optimizeCommand(args []string) error {
	fmt.Printf("💰 Cost and Performance Optimization\n")

	task := &multiagent.MultiAgentTask{
		ID:          fmt.Sprintf("optimize-%d", time.Now().Unix()),
		Type:        "business_analysis",
		Priority:    multiagent.TaskPriorityMedium,
		Description: "Optimize costs and performance across clouds",
		RequiredAgents: []string{CostAnalyzerAgentID, CostRecommendationsAgentID, MonitorHealthAgentID},
		Parameters: map[string]any{
			"optimization_target": "cost_performance",
			"budget_limit":        10000,
			"performance_sla":     0.99,
		},
		CollaborationMode: "sequential",
		CreatedAt:         time.Now(),
	}

	result, err := cli.orchestrator.ExecuteTask(context.Background(), task)
	if err != nil {
		return fmt.Errorf("optimization failed: %w", err)
	}

	cli.printTaskResult("Cost Optimization", result)
	return nil
}

func (cli *MultiCloudDevOpsCLI) secureCommand(args []string) error {
	fmt.Printf("🔒 Security Assessment and Hardening\n")

	task := &multiagent.MultiAgentTask{
		ID:          fmt.Sprintf("secure-%d", time.Now().Unix()),
		Type:        "security_analysis",
		Priority:    multiagent.TaskPriorityHigh,
		Description: "Comprehensive security assessment and hardening",
		RequiredAgents: []string{SecurityScannerAgentID, SecurityComplianceAgentID},
		Parameters: map[string]any{
			"scan_depth":      "comprehensive",
			"compliance_frameworks": []string{"SOC2", "ISO27001", "NIST"},
			"remediation_mode": "automatic",
		},
		CollaborationMode: "parallel",
		CreatedAt:         time.Now(),
	}

	result, err := cli.orchestrator.ExecuteTask(context.Background(), task)
	if err != nil {
		return fmt.Errorf("security assessment failed: %w", err)
	}

	cli.printTaskResult("Security Assessment", result)
	return nil
}

func (cli *MultiCloudDevOpsCLI) complyCommand(args []string) error {
	fmt.Printf("📋 Compliance Validation\n")

	task := &multiagent.MultiAgentTask{
		ID:          fmt.Sprintf("comply-%d", time.Now().Unix()),
		Type:        "security_analysis",
		Priority:    multiagent.TaskPriorityHigh,
		Description: "Validate compliance across all environments",
		RequiredAgents: []string{SecurityComplianceAgentID},
		Parameters: map[string]any{
			"frameworks": []string{"GDPR", "HIPAA", "PCI-DSS"},
			"generate_report": true,
			"audit_trail": true,
		},
		CollaborationMode: "sequential",
		CreatedAt:         time.Now(),
	}

	result, err := cli.orchestrator.ExecuteTask(context.Background(), task)
	if err != nil {
		return fmt.Errorf("compliance check failed: %w", err)
	}

	cli.printTaskResult("Compliance Check", result)
	return nil
}

func (cli *MultiCloudDevOpsCLI) backupCommand(args []string) error {
	fmt.Printf("💾 Backup and Disaster Recovery\n")

	task := &multiagent.MultiAgentTask{
		ID:          fmt.Sprintf("backup-%d", time.Now().Unix()),
		Type:        "business_analysis",
		Priority:    multiagent.TaskPriorityHigh,
		Description: "Execute backup and disaster recovery procedures",
		RequiredAgents: []string{InfraAWSAgentID, InfraGCPAgentID, InfraAzureAgentID},
		Parameters: map[string]any{
			"backup_type": "full",
			"retention_days": 30,
			"cross_region_backup": true,
		},
		CollaborationMode: "parallel",
		CreatedAt:         time.Now(),
	}

	result, err := cli.orchestrator.ExecuteTask(context.Background(), task)
	if err != nil {
		return fmt.Errorf("backup operation failed: %w", err)
	}

	cli.printTaskResult("Backup & Recovery", result)
	return nil
}

func (cli *MultiCloudDevOpsCLI) migrateCommand(args []string) error {
	fmt.Printf("🚚 Workload Migration\n")

	task := &multiagent.MultiAgentTask{
		ID:          fmt.Sprintf("migrate-%d", time.Now().Unix()),
		Type:        "business_analysis",
		Priority:    multiagent.TaskPriorityMedium,
		Description: "Migrate workloads between cloud providers",
		RequiredAgents: []string{InfraAWSAgentID, InfraGCPAgentID, "deploy-kubernetes"},
		Parameters: map[string]any{
			"source_cloud": "aws",
			"target_cloud": "gcp",
			"migration_strategy": "lift_and_shift",
			"downtime_window": "4h",
		},
		CollaborationMode: "sequential",
		CreatedAt:         time.Now(),
	}

	result, err := cli.orchestrator.ExecuteTask(context.Background(), task)
	if err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	cli.printTaskResult("Workload Migration", result)
	return nil
}

func (cli *MultiCloudDevOpsCLI) analyzeCommand(args []string) error {
	fmt.Printf("📊 Infrastructure Analysis\n")

	task := &multiagent.MultiAgentTask{
		ID:          fmt.Sprintf("analyze-%d", time.Now().Unix()),
		Type:        "business_analysis",
		Priority:    multiagent.TaskPriorityLow,
		Description: "Analyze infrastructure performance and usage patterns",
		RequiredAgents: []string{MonitorHealthAgentID, CostAnalyzerAgentID},
		Parameters: map[string]any{
			"analysis_period": "30d",
			"metrics": []string{"performance", "cost", "utilization"},
			"generate_recommendations": true,
		},
		CollaborationMode: "sequential",
		CreatedAt:         time.Now(),
	}

	result, err := cli.orchestrator.ExecuteTask(context.Background(), task)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	cli.printTaskResult("Infrastructure Analysis", result)
	return nil
}

func (cli *MultiCloudDevOpsCLI) orchestrateCommand(args []string) error {
	fmt.Printf("🎼 Custom Workflow Orchestration\n")

	task := &multiagent.MultiAgentTask{
		ID:          fmt.Sprintf("orchestrate-%d", time.Now().Unix()),
		Type:        "security_analysis",
		Priority:    multiagent.TaskPriorityMedium,
		Description: "Execute custom multi-agent DevOps workflow",
		RequiredAgents: cli.getAgentsByType(cli.parseAgentTypes(args[1])),
		Parameters: map[string]any{
			"workflow_type": "custom",
			"steps": []string{"analyze", "plan", "execute", "validate"},
		},
		CollaborationMode: "consensus",
		CreatedAt:         time.Now(),
	}

	result, err := cli.orchestrator.ExecuteTask(context.Background(), task)
	if err != nil {
		return fmt.Errorf("custom orchestration failed: %w", err)
	}

	cli.printTaskResult("Custom Orchestration", result)
	return nil
}

// Helper functions
func (cli *MultiCloudDevOpsCLI) parseCloudProviders(cloudStr string) []CloudProvider {
	if cloudStr == "" {
		return []CloudProvider{AWS, GCP, Azure}
	}

	var providers []CloudProvider
	for _, cloud := range strings.Split(cloudStr, ",") {
		cloud = strings.TrimSpace(cloud)
		switch cloud {
		case "aws":
			providers = append(providers, AWS)
		case "gcp":
			providers = append(providers, GCP)
		case "azure":
			providers = append(providers, Azure)
		}
	}
	return providers
}

func (cli *MultiCloudDevOpsCLI) parseAgentTypes(agentStr string) []AgentType {
	if agentStr == "" {
		return []AgentType{InfrastructureAgent, SecurityAgent, MonitoringAgent}
	}

	var types []AgentType
	for _, agent := range strings.Split(agentStr, ",") {
		agent = strings.TrimSpace(agent)
		switch agent {
		case "infrastructure":
			types = append(types, InfrastructureAgent)
		case "security":
			types = append(types, SecurityAgent)
		case "monitoring":
			types = append(types, MonitoringAgent)
		case "deployment":
			types = append(types, DeploymentAgent)
		case "cost":
			types = append(types, CostOptimizer)
		case "compliance":
			types = append(types, ComplianceAgent)
		}
	}
	return types
}

func (cli *MultiCloudDevOpsCLI) getAgentsByType(agentTypes []AgentType) []string {
	var agents []string
	for agentID, agent := range cli.agents {
		devopsAgent, ok := agent.(*DevOpsAgent)
		if !ok {
			continue
		}

		for _, agentType := range agentTypes {
			if devopsAgent.agentType == agentType {
				agents = append(agents, agentID)
				break
			}
		}
	}
	return agents
}

func (cli *MultiCloudDevOpsCLI) printTaskResult(operation string, result *multiagent.MultiAgentTaskResult) {
	fmt.Printf("\n📊 %s Results:\n", operation)
	fmt.Printf("   • Success: %v\n", result.Success)
	fmt.Printf("   • Execution Time: %v\n", result.ExecutionTime)
	fmt.Printf("   • Participants: %d agents\n", result.ParticipantCount)
	fmt.Printf("   • Conflicts Resolved: %d\n", result.ConflictsCount)
	fmt.Printf("   • Confidence Score: %.2f\n", result.Confidence)
	fmt.Printf("   • Consensus Score: %.2f\n", result.ConsensusScore)

	if result.Success {
		fmt.Printf("✅ %s completed successfully!\n", operation)
	} else {
		fmt.Printf("❌ %s failed.\n", operation)
	}
}

func (cli *MultiCloudDevOpsCLI) Close() error {
	if cli.orchestrator != nil {
		cli.orchestrator.Stop()
	}
	return nil
}

// DevOpsAgent implements ai.Agent interface for DevOps-specific operations
type DevOpsAgent struct {
	id          string
	name        string
	agentType   AgentType
	description string
	logger      *logger.Logger
}

func (d *DevOpsAgent) ID() string { return d.id }
func (d *DevOpsAgent) Name() string { return d.name }
func (d *DevOpsAgent) Description() string { return d.description }

func (d *DevOpsAgent) Execute(ctx context.Context, input ai.AgentInput) (ai.AgentOutput, error) {
	d.logger.Info("DevOps agent executing task", "agent", d.name, "type", d.agentType)

	// Simulate DevOps operation based on agent type
	executionTime := time.Duration(100+len(d.name)*10) * time.Millisecond
	time.Sleep(executionTime)

	var response string
	var confidence float64

	switch d.agentType {
	case InfrastructureAgent:
		response = fmt.Sprintf("Infrastructure deployment completed on %s", d.name)
		confidence = 0.92
	case SecurityAgent:
		response = fmt.Sprintf("Security scan completed - %d vulnerabilities found, %d remediated", 5, 3)
		confidence = 0.88
	case MonitoringAgent:
		response = fmt.Sprintf("Monitoring setup complete - %d metrics configured", 15)
		confidence = 0.95
	case DeploymentAgent:
		response = fmt.Sprintf("Deployment successful - %d services deployed", 8)
		confidence = 0.90
	case CostOptimizer:
		response = fmt.Sprintf("Cost optimization complete - Potential savings: $%.2f/month", 2500.50)
		confidence = 0.87
	case ComplianceAgent:
		response = fmt.Sprintf("Compliance check complete - %d/100 controls validated", 95)
		confidence = 0.93
	}

	return ai.AgentOutput{
		Response:   response,
		Confidence: confidence,
		Success:    true,
		Metadata: map[string]any{
			"agent_id":    d.id,
			"agent_type":  string(d.agentType),
			"cloud_ready": true,
		},
		Duration: executionTime,
	}, nil
}

func (d *DevOpsAgent) AddTool(tool ai.Tool) error                { return nil }
func (d *DevOpsAgent) RemoveTool(toolName string) error         { return nil }
func (d *DevOpsAgent) GetAvailableTools() []ai.Tool             { return []ai.Tool{} }
func (d *DevOpsAgent) SetDecisionEngine(engine ai.DecisionEngine) error { return nil }

func (d *DevOpsAgent) GetMetrics() ai.AgentMetrics {
	return ai.AgentMetrics{
		TotalExecutions:   150,
		SuccessfulRuns:    142,
		FailedRuns:        8,
		AverageLatency:    250 * time.Millisecond,
		LastExecutionTime: time.Now(),
	}
}

func (d *DevOpsAgent) Validate() error {
	if d.id == "" || d.name == "" {
		return fmt.Errorf("agent must have ID and name")
	}
	return nil
}