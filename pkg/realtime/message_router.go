package realtime

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var messageRouterTracer = otel.Tracer("hackai/realtime/message_router")

// MessageRouter routes messages between components
type MessageRouter struct {
	logger       *logger.Logger
	routes       map[string]*Route
	handlers     map[MessageType][]MessageHandler
	middleware   []MessageMiddleware
	messageQueue chan *RoutedMessage
	messageCount int64
	running      bool
	stopChan     chan struct{}
	wg           sync.WaitGroup
	mutex        sync.RWMutex
}

// Route represents a message route
type Route struct {
	ID           string                 `json:"id"`
	Pattern      string                 `json:"pattern"`
	Handler      MessageHandler         `json:"-"`
	Middleware   []MessageMiddleware    `json:"-"`
	Filters      map[string]interface{} `json:"filters"`
	Priority     int                    `json:"priority"`
	Active       bool                   `json:"active"`
	MessageCount int64                  `json:"message_count"`
	CreatedAt    time.Time              `json:"created_at"`
	LastUsed     time.Time              `json:"last_used"`
}

// RoutedMessage represents a message with routing information
type RoutedMessage struct {
	Message     *RealtimeMessage       `json:"message"`
	Route       *Route                 `json:"route"`
	Context     context.Context        `json:"-"`
	Metadata    map[string]interface{} `json:"metadata"`
	Timestamp   time.Time              `json:"timestamp"`
	ProcessedAt time.Time              `json:"processed_at,omitempty"`
}

// MessageHandler interface for handling routed messages
type MessageHandler interface {
	HandleMessage(ctx context.Context, message *RealtimeMessage) error
	GetHandlerType() string
	GetPriority() int
}

// MessageMiddleware interface for message middleware
type MessageMiddleware interface {
	ProcessMessage(ctx context.Context, message *RealtimeMessage, next func() error) error
	GetMiddlewareType() string
}

// NewMessageRouter creates a new message router
func NewMessageRouter(logger *logger.Logger) *MessageRouter {
	return &MessageRouter{
		logger:       logger,
		routes:       make(map[string]*Route),
		handlers:     make(map[MessageType][]MessageHandler),
		middleware:   []MessageMiddleware{},
		messageQueue: make(chan *RoutedMessage, 1000),
		stopChan:     make(chan struct{}),
	}
}

// Start starts the message router
func (mr *MessageRouter) Start(ctx context.Context) error {
	ctx, span := messageRouterTracer.Start(ctx, "message_router_start")
	defer span.End()

	mr.mutex.Lock()
	defer mr.mutex.Unlock()

	if mr.running {
		return fmt.Errorf("message router is already running")
	}

	mr.logger.Info("Starting message router")

	// Start message processing workers
	mr.wg.Add(3)
	go mr.messageProcessor(ctx)
	go mr.routeMonitor(ctx)
	go mr.metricsCollector(ctx)

	mr.running = true

	span.SetAttributes(
		attribute.Bool("router_started", true),
		attribute.Int("queue_size", cap(mr.messageQueue)),
	)

	mr.logger.Info("Message router started successfully")
	return nil
}

// Stop stops the message router
func (mr *MessageRouter) Stop() error {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()

	if !mr.running {
		return nil
	}

	mr.logger.Info("Stopping message router")

	// Signal stop to workers
	close(mr.stopChan)

	// Close message queue
	close(mr.messageQueue)

	// Wait for workers to finish
	mr.wg.Wait()

	mr.running = false
	mr.logger.Info("Message router stopped")
	return nil
}

// RouteMessage routes a message through the system
func (mr *MessageRouter) RouteMessage(ctx context.Context, message *RealtimeMessage) error {
	ctx, span := messageRouterTracer.Start(ctx, "route_message")
	defer span.End()

	// Find matching route
	route := mr.findRoute(message)
	if route == nil {
		// No specific route found, use default handlers
		return mr.handleWithDefaultHandlers(ctx, message)
	}

	// Create routed message
	routedMessage := &RoutedMessage{
		Message:   message,
		Route:     route,
		Context:   ctx,
		Metadata:  make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	span.SetAttributes(
		attribute.String("message_id", message.ID),
		attribute.String("message_type", string(message.Type)),
		attribute.String("route_id", route.ID),
		attribute.String("route_pattern", route.Pattern),
	)

	// Queue message for processing
	select {
	case mr.messageQueue <- routedMessage:
		atomic.AddInt64(&mr.messageCount, 1)
		return nil
	default:
		err := fmt.Errorf("message queue is full")
		span.RecordError(err)
		return err
	}
}

// RegisterRoute registers a new route
func (mr *MessageRouter) RegisterRoute(id, pattern string, handler MessageHandler, priority int) error {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()

	if _, exists := mr.routes[id]; exists {
		return fmt.Errorf("route already exists: %s", id)
	}

	route := &Route{
		ID:           id,
		Pattern:      pattern,
		Handler:      handler,
		Middleware:   []MessageMiddleware{},
		Filters:      make(map[string]interface{}),
		Priority:     priority,
		Active:       true,
		MessageCount: 0,
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
	}

	mr.routes[id] = route

	mr.logger.Info("Route registered",
		"route_id", id,
		"pattern", pattern,
		"handler_type", handler.GetHandlerType(),
		"priority", priority)

	return nil
}

// UnregisterRoute unregisters a route
func (mr *MessageRouter) UnregisterRoute(id string) error {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()

	if _, exists := mr.routes[id]; !exists {
		return fmt.Errorf("route not found: %s", id)
	}

	delete(mr.routes, id)

	mr.logger.Info("Route unregistered", "route_id", id)
	return nil
}

// RegisterHandler registers a message handler for a specific message type
func (mr *MessageRouter) RegisterHandler(messageType MessageType, handler MessageHandler) {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()

	if mr.handlers[messageType] == nil {
		mr.handlers[messageType] = []MessageHandler{}
	}

	mr.handlers[messageType] = append(mr.handlers[messageType], handler)

	mr.logger.Info("Message handler registered",
		"message_type", messageType,
		"handler_type", handler.GetHandlerType())
}

// AddMiddleware adds middleware to the router
func (mr *MessageRouter) AddMiddleware(middleware MessageMiddleware) {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()

	mr.middleware = append(mr.middleware, middleware)

	mr.logger.Info("Message middleware added",
		"middleware_type", middleware.GetMiddlewareType())
}

// GetMessageCount gets the total number of messages processed
func (mr *MessageRouter) GetMessageCount() int64 {
	return atomic.LoadInt64(&mr.messageCount)
}

// GetRoutes gets all registered routes
func (mr *MessageRouter) GetRoutes() []*Route {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()

	routes := make([]*Route, 0, len(mr.routes))
	for _, route := range mr.routes {
		routes = append(routes, route)
	}

	return routes
}

// GetRouterStats gets router statistics
func (mr *MessageRouter) GetRouterStats() *RouterStats {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()

	stats := &RouterStats{
		TotalMessages:   atomic.LoadInt64(&mr.messageCount),
		ActiveRoutes:    0,
		QueueSize:       len(mr.messageQueue),
		QueueCapacity:   cap(mr.messageQueue),
		HandlerCount:    0,
		MiddlewareCount: len(mr.middleware),
		LastUpdated:     time.Now(),
	}

	// Count active routes
	for _, route := range mr.routes {
		if route.Active {
			stats.ActiveRoutes++
		}
	}

	// Count handlers
	for _, handlers := range mr.handlers {
		stats.HandlerCount += len(handlers)
	}

	return stats
}

// RouterStats represents router statistics
type RouterStats struct {
	TotalMessages   int64     `json:"total_messages"`
	ActiveRoutes    int       `json:"active_routes"`
	QueueSize       int       `json:"queue_size"`
	QueueCapacity   int       `json:"queue_capacity"`
	HandlerCount    int       `json:"handler_count"`
	MiddlewareCount int       `json:"middleware_count"`
	LastUpdated     time.Time `json:"last_updated"`
}

// findRoute finds a matching route for a message
func (mr *MessageRouter) findRoute(message *RealtimeMessage) *Route {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()

	var bestRoute *Route
	highestPriority := -1

	for _, route := range mr.routes {
		if !route.Active {
			continue
		}

		// Simple pattern matching - can be extended for complex routing
		if mr.matchesPattern(message, route.Pattern) && mr.matchesFilters(message, route.Filters) {
			if route.Priority > highestPriority {
				highestPriority = route.Priority
				bestRoute = route
			}
		}
	}

	return bestRoute
}

// matchesPattern checks if a message matches a route pattern
func (mr *MessageRouter) matchesPattern(message *RealtimeMessage, pattern string) bool {
	// Simple pattern matching - can be extended for regex or glob patterns
	switch pattern {
	case "*":
		return true
	case message.Channel:
		return true
	case string(message.Type):
		return true
	default:
		return false
	}
}

// matchesFilters checks if a message matches route filters
func (mr *MessageRouter) matchesFilters(message *RealtimeMessage, filters map[string]interface{}) bool {
	if len(filters) == 0 {
		return true
	}

	// Simple filter matching
	for key, expectedValue := range filters {
		var actualValue interface{}

		switch key {
		case "type":
			actualValue = string(message.Type)
		case "channel":
			actualValue = message.Channel
		case "source":
			actualValue = message.Source
		case "priority":
			actualValue = int(message.Priority)
		default:
			if value, exists := message.Data[key]; exists {
				actualValue = value
			} else if value, exists := message.Metadata[key]; exists {
				actualValue = value
			} else {
				return false
			}
		}

		if actualValue != expectedValue {
			return false
		}
	}

	return true
}

// handleWithDefaultHandlers handles a message with default handlers
func (mr *MessageRouter) handleWithDefaultHandlers(ctx context.Context, message *RealtimeMessage) error {
	mr.mutex.RLock()
	handlers, exists := mr.handlers[message.Type]
	mr.mutex.RUnlock()

	if !exists || len(handlers) == 0 {
		mr.logger.Debug("No handlers found for message type", "message_type", message.Type)
		return nil
	}

	// Process through middleware first
	return mr.processMiddleware(ctx, message, func() error {
		// Execute all handlers for this message type
		for _, handler := range handlers {
			if err := handler.HandleMessage(ctx, message); err != nil {
				mr.logger.Error("Handler failed",
					"handler_type", handler.GetHandlerType(),
					"message_id", message.ID,
					"error", err)
				return err
			}
		}
		return nil
	})
}

// processMiddleware processes message through middleware chain
func (mr *MessageRouter) processMiddleware(ctx context.Context, message *RealtimeMessage, next func() error) error {
	if len(mr.middleware) == 0 {
		return next()
	}

	// Create middleware chain
	var chain func(int) error
	chain = func(index int) error {
		if index >= len(mr.middleware) {
			return next()
		}

		middleware := mr.middleware[index]
		return middleware.ProcessMessage(ctx, message, func() error {
			return chain(index + 1)
		})
	}

	return chain(0)
}

// Background workers

// messageProcessor processes messages from the queue
func (mr *MessageRouter) messageProcessor(ctx context.Context) {
	defer mr.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-mr.stopChan:
			return
		case routedMessage, ok := <-mr.messageQueue:
			if !ok {
				return
			}

			mr.processRoutedMessage(routedMessage)
		}
	}
}

// processRoutedMessage processes a single routed message
func (mr *MessageRouter) processRoutedMessage(routedMessage *RoutedMessage) {
	ctx, span := messageRouterTracer.Start(routedMessage.Context, "process_routed_message")
	defer span.End()

	span.SetAttributes(
		attribute.String("message_id", routedMessage.Message.ID),
		attribute.String("route_id", routedMessage.Route.ID),
	)

	// Update route statistics
	routedMessage.Route.MessageCount++
	routedMessage.Route.LastUsed = time.Now()

	// Process through route middleware first
	err := mr.processRouteMiddleware(ctx, routedMessage, func() error {
		// Execute route handler
		return routedMessage.Route.Handler.HandleMessage(ctx, routedMessage.Message)
	})

	routedMessage.ProcessedAt = time.Now()

	if err != nil {
		span.RecordError(err)
		mr.logger.Error("Failed to process routed message",
			"message_id", routedMessage.Message.ID,
			"route_id", routedMessage.Route.ID,
			"error", err)
	} else {
		mr.logger.Debug("Message processed successfully",
			"message_id", routedMessage.Message.ID,
			"route_id", routedMessage.Route.ID,
			"processing_time", time.Since(routedMessage.Timestamp))
	}
}

// processRouteMiddleware processes message through route-specific middleware
func (mr *MessageRouter) processRouteMiddleware(ctx context.Context, routedMessage *RoutedMessage, next func() error) error {
	middleware := routedMessage.Route.Middleware
	if len(middleware) == 0 {
		return mr.processMiddleware(ctx, routedMessage.Message, next)
	}

	// Create route middleware chain
	var chain func(int) error
	chain = func(index int) error {
		if index >= len(middleware) {
			return mr.processMiddleware(ctx, routedMessage.Message, next)
		}

		mw := middleware[index]
		return mw.ProcessMessage(ctx, routedMessage.Message, func() error {
			return chain(index + 1)
		})
	}

	return chain(0)
}

// routeMonitor monitors route performance and health
func (mr *MessageRouter) routeMonitor(ctx context.Context) {
	defer mr.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-mr.stopChan:
			return
		case <-ticker.C:
			mr.monitorRoutes()
		}
	}
}

// monitorRoutes monitors route performance
func (mr *MessageRouter) monitorRoutes() {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()

	now := time.Now()
	inactiveThreshold := 10 * time.Minute

	for id, route := range mr.routes {
		if route.Active && now.Sub(route.LastUsed) > inactiveThreshold {
			mr.logger.Debug("Route has been inactive",
				"route_id", id,
				"last_used", route.LastUsed,
				"message_count", route.MessageCount)
		}
	}
}

// metricsCollector collects router metrics
func (mr *MessageRouter) metricsCollector(ctx context.Context) {
	defer mr.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-mr.stopChan:
			return
		case <-ticker.C:
			mr.collectMetrics()
		}
	}
}

// collectMetrics collects and logs router metrics
func (mr *MessageRouter) collectMetrics() {
	stats := mr.GetRouterStats()

	mr.logger.Debug("Message router metrics",
		"total_messages", stats.TotalMessages,
		"active_routes", stats.ActiveRoutes,
		"queue_size", stats.QueueSize,
		"queue_capacity", stats.QueueCapacity,
		"handler_count", stats.HandlerCount,
		"middleware_count", stats.MiddlewareCount)
}
