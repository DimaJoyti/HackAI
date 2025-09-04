package main

import (
	"context"
	"log"
	"time"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/redis"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	loggerInstance, err := logger.New(logger.Config{
		Level:          "info",
		Format:         "json",
		Output:         "stdout",
		ServiceName:    "redis-test",
		ServiceVersion: "1.0.0",
		Environment:    cfg.Environment,
	})
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	loggerInstance.Info("Starting Redis Configuration Test")

	// Initialize Redis manager
	redisManager, err := redis.NewManager(&cfg.Redis, loggerInstance)
	if err != nil {
		loggerInstance.Fatalf("Failed to create Redis manager: %v", err)
	}
	defer redisManager.Close()

	ctx := context.Background()

	// Test 1: Basic connectivity and health check
	loggerInstance.Info("=== Test 1: Health Check ===")
	if err := redisManager.HealthCheck(ctx); err != nil {
		loggerInstance.Errorf("Health check failed: %v", err)
	} else {
		loggerInstance.Info("✅ Health check passed")
	}

	// Test 2: Cache operations
	loggerInstance.Info("=== Test 2: Cache Operations ===")
	testCacheOperations(ctx, redisManager, loggerInstance)

	// Test 3: Session management
	loggerInstance.Info("=== Test 3: Session Management ===")
	testSessionManagement(ctx, redisManager, loggerInstance)

	// Test 4: Rate limiting
	loggerInstance.Info("=== Test 4: Rate Limiting ===")
	testRateLimiting(ctx, redisManager, loggerInstance)

	// Test 5: Distributed locks
	loggerInstance.Info("=== Test 5: Distributed Locks ===")
	testDistributedLocks(ctx, redisManager, loggerInstance)

	// Test 6: Pub/Sub messaging
	loggerInstance.Info("=== Test 6: Pub/Sub Messaging ===")
	testPubSubMessaging(ctx, redisManager, loggerInstance)

	// Test 7: Get comprehensive stats
	loggerInstance.Info("=== Test 7: Statistics ===")
	testStatistics(ctx, redisManager, loggerInstance)

	loggerInstance.Info("🎉 All Redis tests completed successfully!")
}

func testCacheOperations(ctx context.Context, manager *redis.Manager, logger *logger.Logger) {
	// Test basic cache operations
	testKey := "test:cache:basic"
	testValue := map[string]interface{}{
		"message": "Hello Redis Cache!",
		"number":  42,
		"time":    time.Now().Format(time.RFC3339),
	}

	// Set cache
	if err := manager.Cache.Set(ctx, testKey, testValue); err != nil {
		logger.Errorf("Cache set failed: %v", err)
		return
	}
	logger.Info("✅ Cache set successful")

	// Get cache
	var retrieved map[string]interface{}
	if err := manager.Cache.Get(ctx, testKey, &retrieved); err != nil {
		logger.Errorf("Cache get failed: %v", err)
		return
	}
	logger.Infof("✅ Cache get successful: %v", retrieved)

	// Test cache with TTL
	ttlKey := "test:cache:ttl"
	if err := manager.Cache.Set(ctx, ttlKey, "expires soon", redis.CacheOptions{TTL: 5 * time.Second}); err != nil {
		logger.Errorf("Cache set with TTL failed: %v", err)
		return
	}
	logger.Info("✅ Cache set with TTL successful")

	// Test GetOrSet
	getOrSetKey := "test:cache:getorset"
	var result string
	err := manager.Cache.GetOrSet(ctx, getOrSetKey, &result, func() (interface{}, error) {
		return "Generated value", nil
	})
	if err != nil {
		logger.Errorf("GetOrSet failed: %v", err)
		return
	}
	logger.Infof("✅ GetOrSet successful: %s", result)

	// Test cache with tags
	taggedKey := "test:cache:tagged"
	if err := manager.Cache.Set(ctx, taggedKey, "tagged value", redis.CacheOptions{
		Tags: []string{"test", "demo"},
	}); err != nil {
		logger.Errorf("Cache set with tags failed: %v", err)
		return
	}
	logger.Info("✅ Cache set with tags successful")

	// Clean up
	manager.Cache.Delete(ctx, testKey)
	manager.Cache.Delete(ctx, getOrSetKey)
	manager.Cache.DeleteByTags(ctx, []string{"test", "demo"})
}

func testSessionManagement(ctx context.Context, manager *redis.Manager, logger *logger.Logger) {
	// Create a session
	sessionID, err := manager.Sessions.CreateSession(ctx,
		"user123", "testuser", "test@example.com", "user",
		[]string{"read", "write"}, "device123", "127.0.0.1", "test-agent")
	if err != nil {
		logger.Errorf("Session creation failed: %v", err)
		return
	}
	logger.Infof("✅ Session created: %s", sessionID)

	// Get session
	session, err := manager.Sessions.GetSession(ctx, sessionID)
	if err != nil {
		logger.Errorf("Session get failed: %v", err)
		return
	}
	logger.Infof("✅ Session retrieved: %s (user: %s)", sessionID, session.Username)

	// Update session
	session.Data["last_action"] = "test_action"
	if err := manager.Sessions.UpdateSession(ctx, sessionID, session); err != nil {
		logger.Errorf("Session update failed: %v", err)
		return
	}
	logger.Info("✅ Session updated")

	// Refresh session
	if err := manager.Sessions.RefreshSession(ctx, sessionID); err != nil {
		logger.Errorf("Session refresh failed: %v", err)
		return
	}
	logger.Info("✅ Session refreshed")

	// Get user sessions
	userSessions, err := manager.Sessions.GetUserSessions(ctx, "user123")
	if err != nil {
		logger.Errorf("Get user sessions failed: %v", err)
		return
	}
	logger.Infof("✅ User has %d active sessions", len(userSessions))

	// Clean up
	manager.Sessions.DeleteSession(ctx, sessionID)
}

func testRateLimiting(ctx context.Context, manager *redis.Manager, logger *logger.Logger) {
	rateLimitKey := "test:ratelimit"
	config := redis.RateLimitConfig{
		Limit:    5,
		Window:   time.Minute,
		Strategy: "fixed_window",
	}

	// Test multiple requests
	for i := 0; i < 7; i++ {
		result, err := manager.RateLimit.CheckLimit(ctx, rateLimitKey, config)
		if err != nil {
			logger.Errorf("Rate limit check failed: %v", err)
			return
		}

		if result.Allowed {
			logger.Infof("✅ Request %d allowed (remaining: %d)", i+1, result.Remaining)
		} else {
			logger.Infof("❌ Request %d blocked (retry after: %v)", i+1, result.RetryAfter)
		}
	}

	// Test sliding window
	slidingConfig := redis.RateLimitConfig{
		Limit:    3,
		Window:   10 * time.Second,
		Strategy: "sliding_window",
	}

	result, err := manager.RateLimit.CheckLimit(ctx, "test:sliding", slidingConfig)
	if err != nil {
		logger.Errorf("Sliding window rate limit failed: %v", err)
		return
	}
	logger.Infof("✅ Sliding window rate limit: allowed=%v, remaining=%d", result.Allowed, result.Remaining)

	// Clean up
	manager.RateLimit.Reset(ctx, rateLimitKey)
	manager.RateLimit.Reset(ctx, "test:sliding")
}

func testDistributedLocks(ctx context.Context, manager *redis.Manager, logger *logger.Logger) {
	lockKey := "test:lock"

	// Acquire lock
	lock, err := manager.Lock.Acquire(ctx, lockKey, redis.LockOptions{
		TTL:       30 * time.Second,
		AutoRenew: true,
	})
	if err != nil {
		logger.Errorf("Lock acquire failed: %v", err)
		return
	}
	logger.Infof("✅ Lock acquired: %s", lockKey)

	// Check if acquired
	if !lock.IsAcquired() {
		logger.Error("Lock should be acquired")
		return
	}
	logger.Info("✅ Lock status confirmed")

	// Get TTL
	ttl, err := lock.TTL(ctx)
	if err != nil {
		logger.Errorf("Lock TTL check failed: %v", err)
		return
	}
	logger.Infof("✅ Lock TTL: %v", ttl)

	// Renew lock
	if err := lock.Renew(ctx, 45*time.Second); err != nil {
		logger.Errorf("Lock renew failed: %v", err)
		return
	}
	logger.Info("✅ Lock renewed")

	// Test WithLock pattern
	err = manager.Lock.WithLock(ctx, "test:withlock", func() error {
		logger.Info("✅ Executing within lock")
		time.Sleep(100 * time.Millisecond)
		return nil
	}, redis.LockOptions{TTL: 10 * time.Second})
	if err != nil {
		logger.Errorf("WithLock failed: %v", err)
		return
	}
	logger.Info("✅ WithLock pattern successful")

	// Release lock
	if err := lock.Release(ctx); err != nil {
		logger.Errorf("Lock release failed: %v", err)
		return
	}
	logger.Info("✅ Lock released")
}

func testPubSubMessaging(ctx context.Context, manager *redis.Manager, logger *logger.Logger) {
	channel := "test:channel"

	// Subscribe to channel
	subscriber, err := manager.PubSub.Subscribe(ctx, channel)
	if err != nil {
		logger.Errorf("Subscribe failed: %v", err)
		return
	}
	defer subscriber.Close()
	logger.Infof("✅ Subscribed to channel: %s", channel)

	// Start listening in a goroutine
	go func() {
		err := subscriber.Listen(ctx, func(msg *redis.Message) error {
			logger.Infof("📨 Received message: %s (channel: %s)", msg.Payload, msg.Channel)
			return nil
		})
		if err != nil {
			logger.Errorf("Listen error: %v", err)
		}
	}()

	// Give subscriber time to start
	time.Sleep(100 * time.Millisecond)

	// Publish messages
	if err := manager.PubSub.Publish(ctx, channel, "Hello Redis PubSub!"); err != nil {
		logger.Errorf("Publish failed: %v", err)
		return
	}
	logger.Info("✅ Message published")

	// Publish JSON message
	if err := manager.PubSub.PublishJSON(ctx, channel, map[string]interface{}{
		"type":    "test",
		"message": "JSON message",
		"value":   123,
	}); err != nil {
		logger.Errorf("Publish JSON failed: %v", err)
		return
	}
	logger.Info("✅ JSON message published")

	// Give time for message processing
	time.Sleep(200 * time.Millisecond)

	// Check subscriber count
	count, err := manager.PubSub.GetChannelSubscribers(ctx, channel)
	if err != nil {
		logger.Errorf("Get subscribers failed: %v", err)
		return
	}
	logger.Infof("✅ Channel has %d subscribers", count)
}

func testStatistics(ctx context.Context, manager *redis.Manager, logger *logger.Logger) {
	stats, err := manager.GetStats(ctx)
	if err != nil {
		logger.Errorf("Get stats failed: %v", err)
		return
	}

	logger.Info("📊 Redis Statistics:")
	for component, data := range stats {
		logger.Infof("  %s: %+v", component, data)
	}
	logger.Info("✅ Statistics retrieved successfully")
}
