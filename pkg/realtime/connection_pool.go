package realtime

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var connectionPoolTracer = otel.Tracer("hackai/realtime/connection_pool")

// ConnectionPool manages real-time connections
type ConnectionPool struct {
	maxConnections    int
	logger            *logger.Logger
	connections       map[string]*ConnectionInfo
	connectionsByType map[ConnectionType]map[string]*ConnectionInfo
	running           bool
	startTime         time.Time
	stopChan          chan struct{}
	wg                sync.WaitGroup
	mutex             sync.RWMutex
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(maxConnections int, logger *logger.Logger) *ConnectionPool {
	return &ConnectionPool{
		maxConnections:    maxConnections,
		logger:            logger,
		connections:       make(map[string]*ConnectionInfo),
		connectionsByType: make(map[ConnectionType]map[string]*ConnectionInfo),
		stopChan:          make(chan struct{}),
	}
}

// Start starts the connection pool
func (cp *ConnectionPool) Start(ctx context.Context) error {
	ctx, span := connectionPoolTracer.Start(ctx, "connection_pool_start")
	defer span.End()

	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	if cp.running {
		return fmt.Errorf("connection pool is already running")
	}

	cp.logger.Info("Starting connection pool",
		"max_connections", cp.maxConnections)

	cp.startTime = time.Now()

	// Start background workers
	cp.wg.Add(1)
	go cp.connectionMonitorWorker(ctx)

	cp.running = true

	span.SetAttributes(
		attribute.Bool("pool_started", true),
		attribute.Int("max_connections", cp.maxConnections),
	)

	cp.logger.Info("Connection pool started successfully")
	return nil
}

// Stop stops the connection pool
func (cp *ConnectionPool) Stop() error {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	if !cp.running {
		return nil
	}

	cp.logger.Info("Stopping connection pool")

	// Signal stop to workers
	close(cp.stopChan)

	// Wait for workers to finish
	cp.wg.Wait()

	cp.running = false
	cp.logger.Info("Connection pool stopped")
	return nil
}

// AddConnection adds a connection to the pool
func (cp *ConnectionPool) AddConnection(ctx context.Context, info *ConnectionInfo) error {
	ctx, span := connectionPoolTracer.Start(ctx, "add_connection")
	defer span.End()

	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	// Check if we've reached the maximum number of connections
	if len(cp.connections) >= cp.maxConnections {
		err := fmt.Errorf("maximum connections reached: %d", cp.maxConnections)
		span.RecordError(err)
		return err
	}

	// Check if connection already exists
	if _, exists := cp.connections[info.ID]; exists {
		err := fmt.Errorf("connection already exists: %s", info.ID)
		span.RecordError(err)
		return err
	}

	// Add to connections map
	cp.connections[info.ID] = info

	// Add to type-specific map
	if cp.connectionsByType[info.Type] == nil {
		cp.connectionsByType[info.Type] = make(map[string]*ConnectionInfo)
	}
	cp.connectionsByType[info.Type][info.ID] = info

	span.SetAttributes(
		attribute.String("connection_id", info.ID),
		attribute.String("connection_type", string(info.Type)),
		attribute.String("remote_addr", info.RemoteAddr),
		attribute.Int("total_connections", len(cp.connections)),
	)

	cp.logger.Info("Connection added to pool",
		"connection_id", info.ID,
		"type", info.Type,
		"remote_addr", info.RemoteAddr,
		"total_connections", len(cp.connections))

	return nil
}

// RemoveConnection removes a connection from the pool
func (cp *ConnectionPool) RemoveConnection(ctx context.Context, connectionID string) error {
	ctx, span := connectionPoolTracer.Start(ctx, "remove_connection")
	defer span.End()

	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	info, exists := cp.connections[connectionID]
	if !exists {
		err := fmt.Errorf("connection not found: %s", connectionID)
		span.RecordError(err)
		return err
	}

	// Remove from connections map
	delete(cp.connections, connectionID)

	// Remove from type-specific map
	if typeMap, exists := cp.connectionsByType[info.Type]; exists {
		delete(typeMap, connectionID)
		if len(typeMap) == 0 {
			delete(cp.connectionsByType, info.Type)
		}
	}

	span.SetAttributes(
		attribute.String("connection_id", connectionID),
		attribute.String("connection_type", string(info.Type)),
		attribute.Int("total_connections", len(cp.connections)),
	)

	cp.logger.Info("Connection removed from pool",
		"connection_id", connectionID,
		"type", info.Type,
		"total_connections", len(cp.connections))

	return nil
}

// GetConnectionInfo gets connection information
func (cp *ConnectionPool) GetConnectionInfo(connectionID string) (*ConnectionInfo, error) {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()

	info, exists := cp.connections[connectionID]
	if !exists {
		return nil, fmt.Errorf("connection not found: %s", connectionID)
	}

	return info, nil
}

// GetActiveConnections gets all active connections
func (cp *ConnectionPool) GetActiveConnections() []*ConnectionInfo {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()

	connections := make([]*ConnectionInfo, 0, len(cp.connections))
	for _, info := range cp.connections {
		connections = append(connections, info)
	}

	return connections
}

// GetConnectionsByType gets connections by type
func (cp *ConnectionPool) GetConnectionsByType(connectionType ConnectionType) []*ConnectionInfo {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()

	typeMap, exists := cp.connectionsByType[connectionType]
	if !exists {
		return []*ConnectionInfo{}
	}

	connections := make([]*ConnectionInfo, 0, len(typeMap))
	for _, info := range typeMap {
		connections = append(connections, info)
	}

	return connections
}

// GetConnectionCount gets the number of active connections
func (cp *ConnectionPool) GetConnectionCount() int {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	return len(cp.connections)
}

// GetConnectionCountByType gets the number of connections by type
func (cp *ConnectionPool) GetConnectionCountByType(connectionType ConnectionType) int {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()

	typeMap, exists := cp.connectionsByType[connectionType]
	if !exists {
		return 0
	}

	return len(typeMap)
}

// UpdateConnectionActivity updates the last activity time for a connection
func (cp *ConnectionPool) UpdateConnectionActivity(connectionID string) error {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	info, exists := cp.connections[connectionID]
	if !exists {
		return fmt.Errorf("connection not found: %s", connectionID)
	}

	info.LastActivity = time.Now()
	return nil
}

// CleanupStaleConnections removes stale connections
func (cp *ConnectionPool) CleanupStaleConnections() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	now := time.Now()
	staleConnections := []string{}
	staleTimeout := 5 * time.Minute // Configurable timeout

	for id, info := range cp.connections {
		if now.Sub(info.LastActivity) > staleTimeout {
			staleConnections = append(staleConnections, id)
		}
	}

	for _, id := range staleConnections {
		if info, exists := cp.connections[id]; exists {
			// Remove from connections map
			delete(cp.connections, id)

			// Remove from type-specific map
			if typeMap, exists := cp.connectionsByType[info.Type]; exists {
				delete(typeMap, id)
				if len(typeMap) == 0 {
					delete(cp.connectionsByType, info.Type)
				}
			}

			cp.logger.Info("Removed stale connection",
				"connection_id", id,
				"type", info.Type,
				"last_activity", info.LastActivity)
		}
	}

	if len(staleConnections) > 0 {
		cp.logger.Info("Cleaned up stale connections", "count", len(staleConnections))
	}
}

// GetPoolStats gets connection pool statistics
func (cp *ConnectionPool) GetPoolStats() *ConnectionPoolStats {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()

	stats := &ConnectionPoolStats{
		TotalConnections:  len(cp.connections),
		MaxConnections:    cp.maxConnections,
		ConnectionsByType: make(map[ConnectionType]int),
		Uptime:            time.Since(cp.startTime),
		LastUpdated:       time.Now(),
	}

	for connType, typeMap := range cp.connectionsByType {
		stats.ConnectionsByType[connType] = len(typeMap)
	}

	return stats
}

// ConnectionPoolStats represents connection pool statistics
type ConnectionPoolStats struct {
	TotalConnections  int                    `json:"total_connections"`
	MaxConnections    int                    `json:"max_connections"`
	ConnectionsByType map[ConnectionType]int `json:"connections_by_type"`
	Uptime            time.Duration          `json:"uptime"`
	LastUpdated       time.Time              `json:"last_updated"`
}

// connectionMonitorWorker monitors connections and performs cleanup
func (cp *ConnectionPool) connectionMonitorWorker(ctx context.Context) {
	defer cp.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cp.stopChan:
			return
		case <-ticker.C:
			cp.CleanupStaleConnections()
			cp.logPoolStats()
		}
	}
}

// logPoolStats logs connection pool statistics
func (cp *ConnectionPool) logPoolStats() {
	stats := cp.GetPoolStats()

	cp.logger.Debug("Connection pool stats",
		"total_connections", stats.TotalConnections,
		"max_connections", stats.MaxConnections,
		"websocket_connections", stats.ConnectionsByType[ConnectionTypeWebSocket],
		"sse_connections", stats.ConnectionsByType[ConnectionTypeSSE],
		"uptime", stats.Uptime)
}
