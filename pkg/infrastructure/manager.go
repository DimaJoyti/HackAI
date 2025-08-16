package infrastructure

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/database"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var managerTracer = otel.Tracer("hackai/infrastructure/manager")

// InfrastructureManager manages all infrastructure components
type InfrastructureManager struct {
	// Configuration
	config    *config.Config
	llmConfig *LLMInfrastructureConfig
	logger    *logger.Logger

	// Core components
	database      *database.DB
	redis         *RedisClient
	healthManager *HealthManager

	// LLM-specific components
	llmCache          *LLMCache
	sessionManager    *SessionManager
	rateLimiter       RateLimiter
	securityValidator *SecurityValidator
	auditLogger       *AuditLogger

	// Middleware
	rateLimitMiddleware *RateLimitMiddleware
	securityMiddleware  *SecurityMiddleware

	// Lifecycle
	started   bool
	stopping  bool
	stopChan  chan struct{}
	waitGroup sync.WaitGroup
	mutex     sync.RWMutex
}

// NewInfrastructureManager creates a new infrastructure manager
func NewInfrastructureManager(cfg *config.Config, logger *logger.Logger) (*InfrastructureManager, error) {
	// Load LLM infrastructure configuration
	llmConfig, err := LoadLLMInfrastructureConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load LLM infrastructure config: %w", err)
	}

	return &InfrastructureManager{
		config:    cfg,
		llmConfig: llmConfig,
		logger:    logger,
		stopChan:  make(chan struct{}),
	}, nil
}

// Initialize initializes all infrastructure components
func (im *InfrastructureManager) Initialize(ctx context.Context) error {
	ctx, span := managerTracer.Start(ctx, "infrastructure_manager.initialize")
	defer span.End()

	im.logger.Info("Initializing infrastructure components...")

	// Initialize database
	if err := im.initializeDatabase(ctx); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize Redis
	if err := im.initializeRedis(ctx); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to initialize Redis: %w", err)
	}

	// Initialize security components
	if err := im.initializeSecurity(ctx); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to initialize security: %w", err)
	}

	// Initialize rate limiting
	if err := im.initializeRateLimit(ctx); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to initialize rate limiting: %w", err)
	}

	// Initialize LLM-specific components
	if err := im.initializeLLMComponents(ctx); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to initialize LLM components: %w", err)
	}

	// Initialize health monitoring
	if err := im.initializeHealthMonitoring(ctx); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to initialize health monitoring: %w", err)
	}

	im.logger.Info("Infrastructure components initialized successfully")
	return nil
}

// Start starts all infrastructure components
func (im *InfrastructureManager) Start(ctx context.Context) error {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	if im.started {
		return fmt.Errorf("infrastructure manager already started")
	}

	ctx, span := managerTracer.Start(ctx, "infrastructure_manager.start")
	defer span.End()

	im.logger.Info("Starting infrastructure components...")

	// Start health monitoring
	if im.healthManager != nil {
		im.waitGroup.Add(1)
		go func() {
			defer im.waitGroup.Done()
			im.healthManager.StartBackgroundChecks(ctx)
		}()
	}

	// Start any other background services here

	im.started = true
	im.logger.Info("Infrastructure components started successfully")

	return nil
}

// Stop gracefully stops all infrastructure components
func (im *InfrastructureManager) Stop(ctx context.Context) error {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	if !im.started || im.stopping {
		return nil
	}

	im.stopping = true
	ctx, span := managerTracer.Start(ctx, "infrastructure_manager.stop")
	defer span.End()

	im.logger.Info("Stopping infrastructure components...")

	// Signal all components to stop
	close(im.stopChan)

	// Stop health manager
	if im.healthManager != nil {
		im.healthManager.Stop()
	}

	// Wait for all goroutines to finish
	done := make(chan struct{})
	go func() {
		im.waitGroup.Wait()
		close(done)
	}()

	// Wait for graceful shutdown or timeout
	select {
	case <-done:
		im.logger.Info("All infrastructure components stopped gracefully")
	case <-ctx.Done():
		im.logger.Warn("Infrastructure shutdown timed out")
	}

	// Close connections
	if im.redis != nil {
		if err := im.redis.Close(); err != nil {
			im.logger.Error("Failed to close Redis connection", "error", err)
		}
	}

	if im.database != nil {
		if err := im.database.Close(); err != nil {
			im.logger.Error("Failed to close database connection", "error", err)
		}
	}

	im.logger.Info("Infrastructure components stopped")
	return nil
}

// GetHealthManager returns the health manager
func (im *InfrastructureManager) GetHealthManager() *HealthManager {
	return im.healthManager
}

// GetDatabase returns the database connection
func (im *InfrastructureManager) GetDatabase() *database.DB {
	return im.database
}

// GetRedis returns the Redis client
func (im *InfrastructureManager) GetRedis() *RedisClient {
	return im.redis
}

// GetLLMCache returns the LLM cache
func (im *InfrastructureManager) GetLLMCache() *LLMCache {
	return im.llmCache
}

// GetSessionManager returns the session manager
func (im *InfrastructureManager) GetSessionManager() *SessionManager {
	return im.sessionManager
}

// GetRateLimiter returns the rate limiter
func (im *InfrastructureManager) GetRateLimiter() RateLimiter {
	return im.rateLimiter
}

// GetSecurityValidator returns the security validator
func (im *InfrastructureManager) GetSecurityValidator() *SecurityValidator {
	return im.securityValidator
}

// GetAuditLogger returns the audit logger
func (im *InfrastructureManager) GetAuditLogger() *AuditLogger {
	return im.auditLogger
}

// GetMiddleware returns HTTP middleware stack
func (im *InfrastructureManager) GetMiddleware() []func(http.Handler) http.Handler {
	var middleware []func(http.Handler) http.Handler

	// Add security middleware
	if im.securityMiddleware != nil {
		middleware = append(middleware, im.securityMiddleware.Handler)
	}

	// Add rate limiting middleware
	if im.rateLimitMiddleware != nil {
		middleware = append(middleware, im.rateLimitMiddleware.Handler)
	}

	return middleware
}

// WaitForShutdown waits for shutdown signals
func (im *InfrastructureManager) WaitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		im.logger.Info("Received shutdown signal", "signal", sig.String())
	case <-im.stopChan:
		im.logger.Info("Received internal stop signal")
	}
}

// initializeDatabase initializes the database connection
func (im *InfrastructureManager) initializeDatabase(ctx context.Context) error {
	db, err := database.New(&im.config.Database, im.logger)
	if err != nil {
		return err
	}

	im.database = db
	im.logger.Info("Database initialized successfully")
	return nil
}

// initializeRedis initializes the Redis connection
func (im *InfrastructureManager) initializeRedis(ctx context.Context) error {
	redis, err := NewRedisClient(&im.config.Redis, im.logger)
	if err != nil {
		return err
	}

	im.redis = redis
	im.logger.Info("Redis initialized successfully")
	return nil
}

// initializeSecurity initializes security components
func (im *InfrastructureManager) initializeSecurity(ctx context.Context) error {
	// Initialize security validator
	validator, err := NewSecurityValidator(&im.llmConfig.Security, im.logger)
	if err != nil {
		return err
	}
	im.securityValidator = validator

	// Initialize audit logger
	im.auditLogger = NewAuditLogger(im.logger, &im.llmConfig.Security)

	// Initialize security middleware
	im.securityMiddleware = NewSecurityMiddleware(validator, &im.llmConfig.Security, im.logger)

	im.logger.Info("Security components initialized successfully")
	return nil
}

// initializeRateLimit initializes rate limiting
func (im *InfrastructureManager) initializeRateLimit(ctx context.Context) error {
	if !im.llmConfig.RateLimit.Enabled {
		im.logger.Info("Rate limiting disabled")
		return nil
	}

	// Use Redis rate limiter if Redis is available, otherwise use in-memory
	if im.redis != nil {
		im.rateLimiter = NewRedisRateLimiter(im.redis, &im.llmConfig.RateLimit, im.logger)
	} else {
		im.rateLimiter = NewTokenBucketLimiter(&im.llmConfig.RateLimit, im.logger)
	}

	// Initialize rate limit middleware
	im.rateLimitMiddleware = NewRateLimitMiddleware(im.rateLimiter, &im.llmConfig.RateLimit, im.logger)

	im.logger.Info("Rate limiting initialized successfully")
	return nil
}

// initializeLLMComponents initializes LLM-specific components
func (im *InfrastructureManager) initializeLLMComponents(ctx context.Context) error {
	// Initialize LLM cache
	if im.redis != nil {
		im.llmCache = NewLLMCache(im.redis, "llm", 1*time.Hour)
	}

	// Initialize session manager
	if im.redis != nil {
		im.sessionManager = NewSessionManager(im.redis, "hackai", 24*time.Hour)
	}

	im.logger.Info("LLM components initialized successfully")
	return nil
}

// initializeHealthMonitoring initializes health monitoring
func (im *InfrastructureManager) initializeHealthMonitoring(ctx context.Context) error {
	im.healthManager = NewHealthManager(&im.llmConfig.Monitoring, im.logger, "1.0.0")

	// Register health checkers
	if im.database != nil {
		im.healthManager.RegisterChecker(NewDatabaseHealthChecker(im.database, im.logger))
	}

	if im.redis != nil {
		im.healthManager.RegisterChecker(NewRedisHealthChecker(im.redis, im.logger))
	}

	if im.rateLimiter != nil {
		im.healthManager.RegisterChecker(NewRateLimitHealthChecker(im.rateLimiter, im.logger))
	}

	if im.securityValidator != nil {
		im.healthManager.RegisterChecker(NewSecurityHealthChecker(im.securityValidator, im.logger))
	}

	im.logger.Info("Health monitoring initialized successfully")
	return nil
}
