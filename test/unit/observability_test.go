package unit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/observability"
)

func TestTracingProvider_Initialization(t *testing.T) {
	log, err := logger.New(logger.Config{
		Level:  "error",
		Format: "text",
		Output: "console",
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		config  *config.TracingConfig
		wantErr bool
	}{
		{
			name: "disabled tracing",
			config: &config.TracingConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "enabled tracing with stdout",
			config: &config.TracingConfig{
				Enabled:    true,
				Endpoint:   "",
				SampleRate: 1.0,
			},
			wantErr: false,
		},
		{
			name: "enabled tracing with endpoint",
			config: &config.TracingConfig{
				Enabled:    true,
				Endpoint:   "http://localhost:14268/api/traces",
				SampleRate: 0.5,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := observability.NewTracingProvider(tt.config, "test-service", "1.0.0", log)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)

				// Test shutdown
				if provider != nil {
					err = provider.Shutdown(context.Background())
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestTracingProvider_SpanOperations(t *testing.T) {
	log, err := logger.New(logger.Config{
		Level:  "error",
		Format: "text",
		Output: "console",
	})
	require.NoError(t, err)

	config := &config.TracingConfig{
		Enabled:    true,
		Endpoint:   "",
		SampleRate: 1.0,
	}

	provider, err := observability.NewTracingProvider(config, "test-service", "1.0.0", log)
	require.NoError(t, err)
	defer provider.Shutdown(context.Background())

	ctx := context.Background()

	t.Run("basic span creation", func(t *testing.T) {
		_, span := provider.StartSpan(ctx, "test-operation")
		assert.NotNil(t, span)
		span.End()
	})

	t.Run("span with attributes", func(t *testing.T) {
		_, span := provider.StartSpan(ctx, "test-operation-with-attrs")
		assert.NotNil(t, span)
		span.End()
	})

	t.Run("HTTP span", func(t *testing.T) {
		_, span := provider.StartHTTPSpan(ctx, "GET", "/api/test",
			attribute.String("user.id", "123"),
		)
		assert.NotNil(t, span)
		span.End()
	})

	t.Run("database span", func(t *testing.T) {
		_, span := provider.StartDatabaseSpan(ctx, "SELECT", "users",
			attribute.String("db.query", "SELECT * FROM users"),
		)
		assert.NotNil(t, span)
		span.End()
	})

	t.Run("external service span", func(t *testing.T) {
		_, span := provider.StartExternalSpan(ctx, "payment-service", "process-payment",
			attribute.String("payment.id", "pay_123"),
		)
		assert.NotNil(t, span)
		span.End()
	})
}

func TestTracingProvider_SpanEvents(t *testing.T) {
	log, err := logger.New(logger.Config{
		Level:  "error",
		Format: "text",
		Output: "console",
	})
	require.NoError(t, err)

	config := &config.TracingConfig{
		Enabled:    true,
		Endpoint:   "",
		SampleRate: 1.0,
	}

	provider, err := observability.NewTracingProvider(config, "test-service", "1.0.0", log)
	require.NoError(t, err)
	defer provider.Shutdown(context.Background())

	ctx := context.Background()
	ctx, span := provider.StartSpan(ctx, "test-operation")
	defer span.End()

	t.Run("add span event", func(t *testing.T) {
		provider.AddSpanEvent(ctx, "test-event",
			attribute.String("event.type", "test"),
		)
	})

	t.Run("set span attributes", func(t *testing.T) {
		provider.SetSpanAttributes(ctx,
			attribute.String("operation.result", "success"),
			attribute.Int("items.processed", 10),
		)
	})

	t.Run("record error", func(t *testing.T) {
		testErr := assert.AnError
		provider.RecordError(ctx, testErr,
			attribute.String("error.context", "test"),
		)
	})
}

func TestMetricsProvider_Initialization(t *testing.T) {
	log, err := logger.New(logger.Config{
		Level:  "error",
		Format: "text",
		Output: "console",
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		config  *config.MetricsConfig
		wantErr bool
	}{
		{
			name: "disabled metrics",
			config: &config.MetricsConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "enabled metrics",
			config: &config.MetricsConfig{
				Enabled: true,
				Port:    "9090",
				Path:    "/metrics",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := observability.NewMetricsProvider(tt.config, "test-service", "1.0.0", log)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
			}
		})
	}
}

func TestMetricsProvider_HTTPMetrics(t *testing.T) {
	log, err := logger.New(logger.Config{
		Level:  "error",
		Format: "text",
		Output: "console",
	})
	require.NoError(t, err)

	config := &config.MetricsConfig{
		Enabled: true,
		Port:    "9090",
		Path:    "/metrics",
	}

	provider, err := observability.NewMetricsProvider(config, "test-service", "1.0.0", log)
	require.NoError(t, err)

	t.Run("record HTTP request", func(t *testing.T) {
		provider.RecordHTTPRequest(
			"GET", "/api/test", "200", "test-service",
			100*time.Millisecond, 1024, 2048,
		)
	})

	t.Run("record multiple HTTP requests", func(t *testing.T) {
		methods := []string{"GET", "POST", "PUT", "DELETE"}
		statusCodes := []string{"200", "201", "400", "500"}

		for _, method := range methods {
			for _, status := range statusCodes {
				provider.RecordHTTPRequest(
					method, "/api/test", status, "test-service",
					time.Duration(50+len(method))*time.Millisecond,
					int64(100+len(method)), int64(200+len(status)),
				)
			}
		}
	})
}

func TestMetricsProvider_DatabaseMetrics(t *testing.T) {
	log, err := logger.New(logger.Config{
		Level:  "error",
		Format: "text",
		Output: "console",
	})
	require.NoError(t, err)

	config := &config.MetricsConfig{
		Enabled: true,
		Port:    "9090",
		Path:    "/metrics",
	}

	provider, err := observability.NewMetricsProvider(config, "test-service", "1.0.0", log)
	require.NoError(t, err)

	t.Run("set database connections", func(t *testing.T) {
		provider.SetDatabaseConnections(10, 5, 15)
	})

	t.Run("record database query", func(t *testing.T) {
		provider.RecordDatabaseQuery("SELECT", "users", "success", 25*time.Millisecond)
		provider.RecordDatabaseQuery("INSERT", "users", "success", 50*time.Millisecond)
		provider.RecordDatabaseQuery("UPDATE", "users", "error", 100*time.Millisecond)
	})
}

func TestMetricsProvider_AuthenticationMetrics(t *testing.T) {
	log, err := logger.New(logger.Config{
		Level:  "error",
		Format: "text",
		Output: "console",
	})
	require.NoError(t, err)

	config := &config.MetricsConfig{
		Enabled: true,
		Port:    "9090",
		Path:    "/metrics",
	}

	provider, err := observability.NewMetricsProvider(config, "test-service", "1.0.0", log)
	require.NoError(t, err)

	t.Run("record auth attempt", func(t *testing.T) {
		provider.RecordAuthAttempt("password", "success", "test-agent", 150*time.Millisecond)
		provider.RecordAuthAttempt("password", "failure", "test-agent", 75*time.Millisecond)
		provider.RecordAuthAttempt("totp", "success", "mobile-app", 200*time.Millisecond)
	})

	t.Run("set active sessions", func(t *testing.T) {
		provider.SetActiveSessions(42)
		provider.SetActiveSessions(38)
		provider.SetActiveSessions(45)
	})
}

func TestMetricsProvider_SecurityMetrics(t *testing.T) {
	log, err := logger.New(logger.Config{
		Level:  "error",
		Format: "text",
		Output: "console",
	})
	require.NoError(t, err)

	config := &config.MetricsConfig{
		Enabled: true,
		Port:    "9090",
		Path:    "/metrics",
	}

	provider, err := observability.NewMetricsProvider(config, "test-service", "1.0.0", log)
	require.NoError(t, err)

	t.Run("record security events", func(t *testing.T) {
		provider.RecordSecurityEvent("login_failure", "medium", "authentication")
		provider.RecordSecurityEvent("brute_force", "high", "security")
		provider.RecordSecurityEvent("privilege_escalation", "critical", "authorization")
	})

	t.Run("record rate limit hits", func(t *testing.T) {
		provider.RecordRateLimitHit("/api/login", "192.168.1.100")
		provider.RecordRateLimitHit("/api/register", "192.168.1.101")
	})

	t.Run("record account lockouts", func(t *testing.T) {
		provider.RecordAccountLockout("too_many_failures", "regular_user")
		provider.RecordAccountLockout("suspicious_activity", "admin_user")
	})
}

func TestObservabilityProvider_Integration(t *testing.T) {
	log, err := logger.New(logger.Config{
		Level:  "error",
		Format: "text",
		Output: "console",
	})
	require.NoError(t, err)

	config := &config.ObservabilityConfig{
		Tracing: config.TracingConfig{
			Enabled:    true,
			Endpoint:   "",
			SampleRate: 1.0,
		},
		Metrics: config.MetricsConfig{
			Enabled: true,
			Port:    "9090",
			Path:    "/metrics",
		},
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "text",
			Output: "console",
		},
	}

	provider, err := observability.NewProvider(config, "test-service", "1.0.0", log)
	require.NoError(t, err)
	defer provider.Shutdown(context.Background())

	t.Run("tracing and metrics integration", func(t *testing.T) {
		ctx := context.Background()

		// Start a span
		ctx, span := provider.StartSpan(ctx, "integration-test",
			attribute.String("test.type", "integration"),
		)
		defer span.End()

		// Record metrics
		provider.Metrics().RecordHTTPRequest(
			"GET", "/api/integration", "200", "test-service",
			100*time.Millisecond, 512, 1024,
		)

		// Record database operation
		provider.Metrics().RecordDatabaseQuery(
			"SELECT", "test_table", "success", 25*time.Millisecond,
		)
	})

	t.Run("system monitoring", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Start system monitoring
		provider.StartSystemMonitoring(ctx, 500*time.Millisecond)

		// Let it run for a short time
		time.Sleep(1 * time.Second)
	})
}

func TestHealthChecker(t *testing.T) {
	log, err := logger.New(logger.Config{
		Level:  "error",
		Format: "text",
		Output: "console",
	})
	require.NoError(t, err)

	config := &config.ObservabilityConfig{
		Tracing: config.TracingConfig{Enabled: false},
		Metrics: config.MetricsConfig{Enabled: false},
		Logging: config.LoggingConfig{Level: "error", Format: "text", Output: "console"},
	}

	provider, err := observability.NewProvider(config, "test-service", "1.0.0", log)
	require.NoError(t, err)

	healthChecker := observability.NewHealthChecker(provider)

	t.Run("add health checks", func(t *testing.T) {
		healthChecker.AddCheck("database", func(ctx context.Context) error {
			return nil // Always healthy
		})

		healthChecker.AddCheck("cache", func(ctx context.Context) error {
			return assert.AnError // Always unhealthy
		})

		healthChecker.AddCheck("external_service", func(ctx context.Context) error {
			return nil // Always healthy
		})
	})

	t.Run("perform health check", func(t *testing.T) {
		ctx := context.Background()
		health := healthChecker.Check(ctx, "test-service", "1.0.0")

		assert.NotNil(t, health)
		assert.Equal(t, "test-service", health.Service)
		assert.Equal(t, "1.0.0", health.Version)
		assert.Equal(t, "unhealthy", health.Status) // Should be unhealthy due to cache check
		assert.Len(t, health.Checks, 3)
		assert.Equal(t, "healthy", health.Checks["database"])
		assert.Contains(t, health.Checks["cache"], "unhealthy")
		assert.Equal(t, "healthy", health.Checks["external_service"])
	})
}

func TestAlertManager(t *testing.T) {
	log, err := logger.New(logger.Config{
		Level:  "error",
		Format: "text",
		Output: "console",
	})
	require.NoError(t, err)

	config := &config.ObservabilityConfig{
		Tracing: config.TracingConfig{Enabled: false},
		Metrics: config.MetricsConfig{Enabled: false},
		Logging: config.LoggingConfig{Level: "error", Format: "text", Output: "console"},
	}

	provider, err := observability.NewProvider(config, "test-service", "1.0.0", log)
	require.NoError(t, err)

	alertManager := observability.NewAlertManager(provider)

	t.Run("add alert rules", func(t *testing.T) {
		alertTriggered := false

		alertManager.AddRule(observability.AlertRule{
			Name:        "test_alert",
			Description: "Test alert rule",
			Condition: func(ctx context.Context) bool {
				return true // Always trigger
			},
			Action: func(ctx context.Context, rule observability.AlertRule) {
				alertTriggered = true
			},
		})

		alertManager.AddRule(observability.AlertRule{
			Name:        "never_trigger",
			Description: "Alert that never triggers",
			Condition: func(ctx context.Context) bool {
				return false // Never trigger
			},
			Action: func(ctx context.Context, rule observability.AlertRule) {
				t.Error("This alert should never trigger")
			},
		})

		// Evaluate rules
		alertManager.EvaluateRules(context.Background())

		// Give some time for goroutines to execute
		time.Sleep(100 * time.Millisecond)

		assert.True(t, alertTriggered, "Alert should have been triggered")
	})
}
