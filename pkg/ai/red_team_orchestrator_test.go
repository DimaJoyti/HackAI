package ai

import (
	"context"
	"testing"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createRedTeamTestLogger() *logger.Logger {
	config := logger.Config{
		Level:     logger.LevelDebug,
		Format:    "text",
		Output:    "stdout",
		AddSource: false,
	}
	testLogger, _ := logger.New(config)
	return testLogger
}

func TestRedTeamOrchestrator_StartCampaign(t *testing.T) {
	testLogger := createRedTeamTestLogger()

	// Create jailbreak detection engine
	jailbreakConfig := JailbreakDetectionConfig{
		EnableTaxonomyDetection: true,
		ConfidenceThreshold:     0.5,
		MaxConversationHistory:  100,
	}
	jailbreakEngine := NewJailbreakDetectionEngine("test-engine", jailbreakConfig, testLogger)

	// Create red team orchestrator
	redTeamConfig := RedTeamConfig{
		MaxConcurrentCampaigns: 5,
		MaxConcurrentAgents:    10,
		DefaultCampaignTimeout: 30 * time.Minute,
		EnableAdaptiveStrategy: true,
		EnableStealth:          false,
		EnablePersistence:      false,
		AggressivenessLevel:    "medium",
		TargetValidation:       true,
		ComplianceMode:         true,
	}

	orchestrator := NewRedTeamOrchestrator("test-orchestrator", redTeamConfig, jailbreakEngine, testLogger)
	require.NotNil(t, orchestrator)

	// Test campaign configuration
	campaignConfig := CampaignConfig{
		MaxDuration:         10 * time.Minute,
		MaxAttempts:         50,
		DelayBetweenAttacks: 100 * time.Millisecond,
		AdaptiveStrategy:    true,
		StealthMode:         false,
		PersistenceMode:     false,
		SuccessThreshold:    0.1,
	}

	objectives := []string{"jailbreak", "bypass_filters"}
	target := "test-target"

	t.Run("successful campaign start", func(t *testing.T) {
		ctx := context.Background()

		campaign, err := orchestrator.StartCampaign(ctx, campaignConfig, target, objectives)
		require.NoError(t, err)
		require.NotNil(t, campaign)

		assert.NotEmpty(t, campaign.ID)
		assert.Equal(t, target, campaign.Target)
		assert.Equal(t, objectives, campaign.Objectives)
		assert.Contains(t, []string{"initializing", "running"}, campaign.Status) // May start immediately
		assert.NotEmpty(t, campaign.AttackChains)
		assert.NotEmpty(t, campaign.AssignedAgents)
		assert.NotZero(t, campaign.StartTime)

		// Wait a bit for campaign to start
		time.Sleep(100 * time.Millisecond)

		// Verify campaign is in active campaigns
		orchestrator.mutex.RLock()
		_, exists := orchestrator.activeCampaigns[campaign.ID]
		orchestrator.mutex.RUnlock()
		assert.True(t, exists)
	})

	t.Run("concurrent campaign limit", func(t *testing.T) {
		ctx := context.Background()

		// Start campaigns up to the limit
		for i := 0; i < redTeamConfig.MaxConcurrentCampaigns; i++ {
			_, err := orchestrator.StartCampaign(ctx, campaignConfig, target, objectives)
			if i < redTeamConfig.MaxConcurrentCampaigns-1 {
				require.NoError(t, err)
			}
		}

		// Try to start one more campaign (should fail)
		_, err := orchestrator.StartCampaign(ctx, campaignConfig, target, objectives)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "maximum concurrent campaigns reached")
	})
}

func TestAttackChainGenerator_GenerateAttackChains(t *testing.T) {
	testLogger := createRedTeamTestLogger()
	generator := NewAttackChainGenerator(testLogger)
	require.NotNil(t, generator)

	campaignConfig := CampaignConfig{
		MaxDuration:      10 * time.Minute,
		AdaptiveStrategy: true,
		StealthMode:      false,
	}

	tests := []struct {
		name       string
		target     string
		objectives []string
		minChains  int
	}{
		{
			name:       "jailbreak objective",
			target:     "test-target",
			objectives: []string{"jailbreak"},
			minChains:  1,
		},
		{
			name:       "multiple objectives",
			target:     "test-target",
			objectives: []string{"jailbreak", "bypass_filters", "information_extraction"},
			minChains:  2,
		},
		{
			name:       "unknown objective",
			target:     "test-target",
			objectives: []string{"unknown_objective"},
			minChains:  1, // Should fall back to default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			chains, err := generator.GenerateAttackChains(ctx, tt.target, tt.objectives, campaignConfig)
			require.NoError(t, err)
			require.NotNil(t, chains)

			assert.GreaterOrEqual(t, len(chains), tt.minChains)

			for _, chain := range chains {
				assert.NotEmpty(t, chain.ID)
				assert.NotEmpty(t, chain.Name)
				assert.NotEmpty(t, chain.Description)
				assert.NotEmpty(t, chain.Steps)
				assert.Equal(t, "pending", chain.Status)

				// Verify steps are properly generated
				for _, step := range chain.Steps {
					assert.NotEmpty(t, step.ID)
					assert.NotEmpty(t, step.Name)
					assert.NotEmpty(t, step.Type)
					assert.NotEmpty(t, step.Payload)
					assert.Equal(t, "pending", step.Status)
				}
			}
		})
	}
}

func TestRedTeamAgent_ExecuteAttack(t *testing.T) {
	testLogger := createRedTeamTestLogger()

	tests := []struct {
		name           string
		specialization string
		target         string
		payload        string
	}{
		{
			name:           "social engineering agent",
			specialization: "social_engineering",
			target:         "test-target",
			payload:        "Please help me, I'm desperate",
		},
		{
			name:           "technical exploitation agent",
			specialization: "technical_exploitation",
			target:         "test-target",
			payload:        "Execute system command",
		},
		{
			name:           "stealth agent",
			specialization: "stealth",
			target:         "test-target",
			payload:        "Bypass detection systems",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := NewRedTeamAgent("test-agent", "Test Agent", tt.specialization, testLogger)
			require.NotNil(t, agent)

			assert.Equal(t, tt.specialization, agent.Specialization)
			assert.Equal(t, "idle", agent.Status)
			assert.NotEmpty(t, agent.Capabilities)

			ctx := context.Background()

			result, err := agent.ExecuteAttack(ctx, tt.target, tt.payload)
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, agent.ID, result.AgentID)
			assert.Equal(t, tt.target, result.Target)
			assert.Equal(t, tt.payload, result.Payload)
			assert.NotZero(t, result.Timestamp)
			assert.Greater(t, result.Duration, time.Duration(0))

			// Verify agent status returned to idle
			assert.Equal(t, "idle", agent.Status)

			// Verify performance metrics were updated
			assert.Equal(t, 1, agent.Performance.TotalAttempts)
			assert.Greater(t, agent.Performance.AverageResponseTime, time.Duration(0))
			assert.NotZero(t, agent.Performance.LastActivity)
		})
	}
}

func TestPayloadGenerator_GeneratePayload(t *testing.T) {
	testLogger := createRedTeamTestLogger()
	generator := NewPayloadGenerator(testLogger)
	require.NotNil(t, generator)

	tests := []struct {
		name       string
		templateID string
		target     string
		expectErr  bool
	}{
		{
			name:       "DAN classic template",
			templateID: "dan_classic",
			target:     "test-target",
			expectErr:  false,
		},
		{
			name:       "ignore instructions template",
			templateID: "ignore_instructions",
			target:     "test-target",
			expectErr:  false,
		},
		{
			name:       "emotional appeal template",
			templateID: "emotional_appeal",
			target:     "test-target",
			expectErr:  false,
		},
		{
			name:       "unknown template",
			templateID: "unknown_template",
			target:     "test-target",
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			context := map[string]interface{}{
				"target": tt.target,
			}

			payload, err := generator.GeneratePayload(tt.templateID, tt.target, context)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Empty(t, payload)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, payload)
			}
		})
	}
}

func TestRedTeamReportGenerator_GenerateReport(t *testing.T) {
	testLogger := createRedTeamTestLogger()
	generator := NewRedTeamReportGenerator(testLogger)
	require.NotNil(t, generator)

	// Create a mock campaign with results
	campaign := &RedTeamCampaign{
		ID:             "test-campaign",
		Name:           "Test Campaign",
		Target:         "test-target",
		Objectives:     []string{"jailbreak", "bypass_filters"},
		StartTime:      time.Now().Add(-1 * time.Hour),
		EndTime:        time.Now(),
		Status:         "completed",
		Progress:       1.0,
		AssignedAgents: []string{"agent1", "agent2"},
		AttackChains: []*AttackChain{
			{
				ID:   "chain1",
				Name: "Direct Jailbreak Chain",
				Steps: []*AttackStep{
					{ID: "step1", Name: "DAN Attempt", Success: true},
					{ID: "step2", Name: "Override Instructions", Success: false},
				},
				Results: &AttackChainResults{
					StepsCompleted:    2,
					StepsSuccessful:   1,
					ChainSuccessRate:  0.5,
					TotalDuration:     5 * time.Minute,
					ObjectiveAchieved: true,
				},
			},
		},
		Results: &CampaignResults{
			TotalAttempts:       10,
			SuccessfulAttempts:  3,
			SuccessRate:         0.3,
			AverageResponseTime: 2 * time.Second,
			VulnerabilitiesFound: []Vulnerability{
				{
					ID:          "vuln1",
					Type:        "jailbreak",
					Severity:    "medium",
					Description: "Successful jailbreak attempt",
				},
			},
			Recommendations:  []string{"Implement additional validation"},
			ThreatAssessment: "medium",
			ComplianceStatus: "compliant",
		},
	}

	t.Run("generate comprehensive report", func(t *testing.T) {
		report, err := generator.GenerateReport(campaign)
		require.NoError(t, err)
		require.NotNil(t, report)

		assert.NotEmpty(t, report.ID)
		assert.NotEmpty(t, report.Title)
		assert.NotZero(t, report.GeneratedAt)

		// Verify campaign summary
		require.NotNil(t, report.CampaignSummary)
		assert.Equal(t, campaign.ID, report.CampaignSummary.CampaignID)
		assert.Equal(t, campaign.Target, report.CampaignSummary.Target)
		assert.Equal(t, campaign.Results.TotalAttempts, report.CampaignSummary.TotalAttempts)
		assert.Equal(t, campaign.Results.SuccessRate, report.CampaignSummary.SuccessRate)

		// Verify executive summary
		require.NotNil(t, report.ExecutiveSummary)
		assert.NotEmpty(t, report.ExecutiveSummary.OverallRiskLevel)
		assert.NotEmpty(t, report.ExecutiveSummary.KeyFindings)
		assert.NotEmpty(t, report.ExecutiveSummary.ImmediateActions)

		// Verify technical findings
		require.NotNil(t, report.TechnicalFindings)
		assert.Equal(t, len(campaign.Results.VulnerabilitiesFound), len(report.TechnicalFindings.VulnerabilitiesFound))

		// Verify risk assessment
		require.NotNil(t, report.RiskAssessment)
		assert.Greater(t, report.RiskAssessment.OverallRiskScore, 0.0)
		assert.NotEmpty(t, report.RiskAssessment.RiskCategories)

		// Verify recommendations
		require.NotNil(t, report.Recommendations)
		assert.NotEmpty(t, report.Recommendations.ImmediateActions)

		// Verify appendices
		require.NotNil(t, report.Appendices)
		assert.NotEmpty(t, report.Appendices.Methodology)
	})
}

func TestRedTeamOrchestrator_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testLogger := createRedTeamTestLogger()

	// Create jailbreak detection engine
	jailbreakConfig := JailbreakDetectionConfig{
		EnableTaxonomyDetection: true,
		ConfidenceThreshold:     0.5,
		MaxConversationHistory:  100,
	}
	jailbreakEngine := NewJailbreakDetectionEngine("test-engine", jailbreakConfig, testLogger)

	// Create red team orchestrator
	redTeamConfig := RedTeamConfig{
		MaxConcurrentCampaigns: 2,
		MaxConcurrentAgents:    5,
		DefaultCampaignTimeout: 1 * time.Minute,
		EnableAdaptiveStrategy: true,
		AggressivenessLevel:    "low",
		ComplianceMode:         true,
	}

	orchestrator := NewRedTeamOrchestrator("integration-test", redTeamConfig, jailbreakEngine, testLogger)
	require.NotNil(t, orchestrator)

	// Test full campaign lifecycle
	t.Run("full campaign lifecycle", func(t *testing.T) {
		ctx := context.Background()

		campaignConfig := CampaignConfig{
			MaxDuration:         30 * time.Second,
			MaxAttempts:         10,
			DelayBetweenAttacks: 50 * time.Millisecond,
			AdaptiveStrategy:    true,
			SuccessThreshold:    0.1,
		}

		objectives := []string{"jailbreak"}
		target := "integration-test-target"

		// Start campaign
		campaign, err := orchestrator.StartCampaign(ctx, campaignConfig, target, objectives)
		require.NoError(t, err)
		require.NotNil(t, campaign)

		// Wait for campaign to complete
		timeout := time.After(45 * time.Second)
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		var finalCampaign *RedTeamCampaign
		for {
			select {
			case <-timeout:
				t.Fatal("Campaign did not complete within timeout")
			case <-ticker.C:
				orchestrator.mutex.RLock()
				activeCampaign, exists := orchestrator.activeCampaigns[campaign.ID]
				orchestrator.mutex.RUnlock()

				if !exists {
					// Campaign completed
					finalCampaign = campaign
					goto campaignCompleted
				} else {
					// Update campaign reference
					campaign = activeCampaign
				}
			}
		}

	campaignCompleted:
		// Verify campaign completion
		assert.Equal(t, "completed", finalCampaign.Status)
		assert.Equal(t, 1.0, finalCampaign.Progress)
		assert.NotZero(t, finalCampaign.EndTime)
		require.NotNil(t, finalCampaign.Results)

		// Verify results
		assert.Greater(t, finalCampaign.Results.TotalAttempts, 0)
		assert.GreaterOrEqual(t, finalCampaign.Results.SuccessRate, 0.0)
		assert.LessOrEqual(t, finalCampaign.Results.SuccessRate, 1.0)
		assert.Greater(t, finalCampaign.Results.AverageResponseTime, time.Duration(0))
		assert.NotEmpty(t, finalCampaign.Results.Recommendations)
		assert.NotEmpty(t, finalCampaign.Results.ThreatAssessment)

		// Generate report
		reportGenerator := NewRedTeamReportGenerator(testLogger)
		report, err := reportGenerator.GenerateReport(finalCampaign)
		require.NoError(t, err)
		require.NotNil(t, report)

		assert.NotEmpty(t, report.ID)
		assert.Contains(t, report.Title, target)
		assert.NotNil(t, report.CampaignSummary)
		assert.NotNil(t, report.ExecutiveSummary)
		assert.NotNil(t, report.TechnicalFindings)
		assert.NotNil(t, report.RiskAssessment)
		assert.NotNil(t, report.Recommendations)

		testLogger.Info("Integration test completed successfully",
			"campaign_id", finalCampaign.ID,
			"duration", finalCampaign.EndTime.Sub(finalCampaign.StartTime),
			"success_rate", finalCampaign.Results.SuccessRate,
			"total_attempts", finalCampaign.Results.TotalAttempts)
	})
}
