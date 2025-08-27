package realtime

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

var streamTracer = otel.Tracer("hackai/realtime/stream")

// StreamManager manages real-time data streams
type StreamManager struct {
	config   StreamConfig
	logger   *logger.Logger
	streams  map[string]*Stream
	running  bool
	stopChan chan struct{}
	wg       sync.WaitGroup
	mutex    sync.RWMutex
}

// Stream represents a real-time data stream
type Stream struct {
	ID            string                       `json:"id"`
	Name          string                       `json:"name"`
	Description   string                       `json:"description"`
	Type          StreamType                   `json:"type"`
	Status        StreamStatus                 `json:"status"`
	Buffer        []StreamEvent                `json:"-"`
	Subscribers   map[string]*StreamSubscriber `json:"-"`
	Config        StreamConfiguration          `json:"config"`
	Metadata      map[string]interface{}       `json:"metadata"`
	CreatedAt     time.Time                    `json:"created_at"`
	LastActivity  time.Time                    `json:"last_activity"`
	EventCount    int64                        `json:"event_count"`
	BytesStreamed int64                        `json:"bytes_streamed"`
	ctx           context.Context
	cancel        context.CancelFunc
	mutex         sync.RWMutex
}

// StreamType represents the type of stream
type StreamType string

const (
	StreamTypeEvent   StreamType = "event"
	StreamTypeData    StreamType = "data"
	StreamTypeLog     StreamType = "log"
	StreamTypeMetrics StreamType = "metrics"
	StreamTypeVideo   StreamType = "video"
	StreamTypeAudio   StreamType = "audio"
	StreamTypeCustom  StreamType = "custom"
)

// StreamStatus represents the status of a stream
type StreamStatus string

const (
	StreamStatusActive  StreamStatus = "active"
	StreamStatusPaused  StreamStatus = "paused"
	StreamStatusStopped StreamStatus = "stopped"
	StreamStatusError   StreamStatus = "error"
)

// StreamEvent represents an event in a stream
type StreamEvent struct {
	ID        string                 `json:"id"`
	StreamID  string                 `json:"stream_id"`
	Type      string                 `json:"type"`
	Data      interface{}            `json:"data"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
	Size      int64                  `json:"size"`
}

// StreamSubscriber represents a stream subscriber
type StreamSubscriber struct {
	ID             string                 `json:"id"`
	ConnectionID   string                 `json:"connection_id"`
	StreamID       string                 `json:"stream_id"`
	Filters        map[string]interface{} `json:"filters"`
	EventQueue     chan StreamEvent       `json:"-"`
	Active         bool                   `json:"active"`
	CreatedAt      time.Time              `json:"created_at"`
	LastActivity   time.Time              `json:"last_activity"`
	EventsReceived int64                  `json:"events_received"`
	ctx            context.Context
	cancel         context.CancelFunc
}

// StreamConfiguration represents stream configuration
type StreamConfiguration struct {
	BufferSize        int           `json:"buffer_size"`
	FlushInterval     time.Duration `json:"flush_interval"`
	MaxEventSize      int64         `json:"max_event_size"`
	RetentionPeriod   time.Duration `json:"retention_period"`
	CompressionLevel  int           `json:"compression_level"`
	EnablePersistence bool          `json:"enable_persistence"`
}

// NewStreamManager creates a new stream manager
func NewStreamManager(config StreamConfig, logger *logger.Logger) *StreamManager {
	return &StreamManager{
		config:   config,
		logger:   logger,
		streams:  make(map[string]*Stream),
		stopChan: make(chan struct{}),
	}
}

// Start starts the stream manager
func (sm *StreamManager) Start(ctx context.Context) error {
	ctx, span := streamTracer.Start(ctx, "stream_manager_start")
	defer span.End()

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if sm.running {
		return fmt.Errorf("stream manager is already running")
	}

	sm.logger.Info("Starting stream manager",
		"buffer_size", sm.config.BufferSize,
		"flush_interval", sm.config.FlushInterval,
		"enable_persistence", sm.config.EnablePersistence)

	// Start background workers
	sm.wg.Add(2)
	go sm.streamCleanupWorker(ctx)
	go sm.bufferFlushWorker(ctx)

	sm.running = true

	span.SetAttributes(
		attribute.Bool("manager_started", true),
		attribute.Int("buffer_size", sm.config.BufferSize),
		attribute.Bool("persistence_enabled", sm.config.EnablePersistence),
	)

	sm.logger.Info("Stream manager started successfully")
	return nil
}

// Stop stops the stream manager
func (sm *StreamManager) Stop() error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if !sm.running {
		return nil
	}

	sm.logger.Info("Stopping stream manager")

	// Signal stop to workers
	close(sm.stopChan)

	// Stop all streams
	for _, stream := range sm.streams {
		stream.Stop()
	}

	// Wait for workers to finish
	sm.wg.Wait()

	sm.running = false
	sm.logger.Info("Stream manager stopped")
	return nil
}

// CreateStream creates a new stream
func (sm *StreamManager) CreateStream(ctx context.Context, name, description string, streamType StreamType) (*Stream, error) {
	ctx, span := streamTracer.Start(ctx, "create_stream")
	defer span.End()

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	streamID := uuid.New().String()
	streamCtx, cancel := context.WithCancel(ctx)

	stream := &Stream{
		ID:          streamID,
		Name:        name,
		Description: description,
		Type:        streamType,
		Status:      StreamStatusActive,
		Buffer:      make([]StreamEvent, 0, sm.config.BufferSize),
		Subscribers: make(map[string]*StreamSubscriber),
		Config: StreamConfiguration{
			BufferSize:        sm.config.BufferSize,
			FlushInterval:     sm.config.FlushInterval,
			MaxEventSize:      1024 * 1024, // 1MB default
			RetentionPeriod:   sm.config.MaxStreamAge,
			CompressionLevel:  sm.config.CompressionLevel,
			EnablePersistence: sm.config.EnablePersistence,
		},
		Metadata:      make(map[string]interface{}),
		CreatedAt:     time.Now(),
		LastActivity:  time.Now(),
		EventCount:    0,
		BytesStreamed: 0,
		ctx:           streamCtx,
		cancel:        cancel,
	}

	sm.streams[streamID] = stream

	span.SetAttributes(
		attribute.String("stream_id", streamID),
		attribute.String("stream_name", name),
		attribute.String("stream_type", string(streamType)),
	)

	sm.logger.Info("Stream created",
		"stream_id", streamID,
		"name", name,
		"type", streamType)

	// Start stream worker
	go sm.streamWorker(stream)

	return stream, nil
}

// DeleteStream deletes a stream
func (sm *StreamManager) DeleteStream(ctx context.Context, streamID string) error {
	ctx, span := streamTracer.Start(ctx, "delete_stream")
	defer span.End()

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		err := fmt.Errorf("stream not found: %s", streamID)
		span.RecordError(err)
		return err
	}

	// Stop the stream
	stream.Stop()

	// Remove from streams map
	delete(sm.streams, streamID)

	span.SetAttributes(
		attribute.String("stream_id", streamID),
	)

	sm.logger.Info("Stream deleted", "stream_id", streamID)
	return nil
}

// GetStream gets a stream by ID
func (sm *StreamManager) GetStream(streamID string) (*Stream, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		return nil, fmt.Errorf("stream not found: %s", streamID)
	}

	return stream, nil
}

// GetStreams gets all streams
func (sm *StreamManager) GetStreams() []*Stream {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	streams := make([]*Stream, 0, len(sm.streams))
	for _, stream := range sm.streams {
		streams = append(streams, stream)
	}

	return streams
}

// PublishEvent publishes an event to a stream
func (sm *StreamManager) PublishEvent(ctx context.Context, streamID string, eventType string, data interface{}) error {
	ctx, span := streamTracer.Start(ctx, "publish_stream_event")
	defer span.End()

	stream, err := sm.GetStream(streamID)
	if err != nil {
		span.RecordError(err)
		return err
	}

	event := StreamEvent{
		ID:        uuid.New().String(),
		StreamID:  streamID,
		Type:      eventType,
		Data:      data,
		Metadata:  make(map[string]interface{}),
		Timestamp: time.Now(),
		Size:      int64(len(fmt.Sprintf("%v", data))), // Simplified size calculation
	}

	span.SetAttributes(
		attribute.String("stream_id", streamID),
		attribute.String("event_id", event.ID),
		attribute.String("event_type", eventType),
		attribute.Int64("event_size", event.Size),
	)

	return stream.AddEvent(event)
}

// SubscribeToStream subscribes to a stream
func (sm *StreamManager) SubscribeToStream(ctx context.Context, connectionID, streamID string) (*StreamSubscriber, error) {
	ctx, span := streamTracer.Start(ctx, "subscribe_to_stream")
	defer span.End()

	stream, err := sm.GetStream(streamID)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}

	subscriber := stream.AddSubscriber(connectionID)

	span.SetAttributes(
		attribute.String("connection_id", connectionID),
		attribute.String("stream_id", streamID),
		attribute.String("subscriber_id", subscriber.ID),
	)

	sm.logger.Info("Stream subscription created",
		"connection_id", connectionID,
		"stream_id", streamID,
		"subscriber_id", subscriber.ID)

	return subscriber, nil
}

// UnsubscribeFromStream unsubscribes from a stream
func (sm *StreamManager) UnsubscribeFromStream(ctx context.Context, connectionID, streamID string) error {
	ctx, span := streamTracer.Start(ctx, "unsubscribe_from_stream")
	defer span.End()

	stream, err := sm.GetStream(streamID)
	if err != nil {
		span.RecordError(err)
		return err
	}

	stream.RemoveSubscriber(connectionID)

	span.SetAttributes(
		attribute.String("connection_id", connectionID),
		attribute.String("stream_id", streamID),
	)

	sm.logger.Info("Stream subscription removed",
		"connection_id", connectionID,
		"stream_id", streamID)

	return nil
}

// Background workers

// streamCleanupWorker cleans up old streams and events
func (sm *StreamManager) streamCleanupWorker(ctx context.Context) {
	defer sm.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sm.stopChan:
			return
		case <-ticker.C:
			sm.cleanupOldStreams()
		}
	}
}

// bufferFlushWorker flushes stream buffers periodically
func (sm *StreamManager) bufferFlushWorker(ctx context.Context) {
	defer sm.wg.Done()

	ticker := time.NewTicker(sm.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sm.stopChan:
			return
		case <-ticker.C:
			sm.flushAllBuffers()
		}
	}
}

// streamWorker processes events for a specific stream
func (sm *StreamManager) streamWorker(stream *Stream) {
	defer func() {
		sm.logger.Info("Stream worker stopped", "stream_id", stream.ID)
	}()

	ticker := time.NewTicker(stream.Config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stream.ctx.Done():
			return
		case <-ticker.C:
			stream.FlushBuffer()
		}
	}
}

// cleanupOldStreams removes old inactive streams
func (sm *StreamManager) cleanupOldStreams() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	now := time.Now()
	oldStreams := []string{}

	for id, stream := range sm.streams {
		if stream.Status == StreamStatusStopped ||
			(stream.Status == StreamStatusActive && now.Sub(stream.LastActivity) > sm.config.MaxStreamAge) {
			oldStreams = append(oldStreams, id)
		}
	}

	for _, id := range oldStreams {
		if stream, exists := sm.streams[id]; exists {
			stream.Stop()
			delete(sm.streams, id)
			sm.logger.Info("Cleaned up old stream", "stream_id", id)
		}
	}

	if len(oldStreams) > 0 {
		sm.logger.Info("Cleaned up old streams", "count", len(oldStreams))
	}
}

// flushAllBuffers flushes all stream buffers
func (sm *StreamManager) flushAllBuffers() {
	sm.mutex.RLock()
	streams := make([]*Stream, 0, len(sm.streams))
	for _, stream := range sm.streams {
		streams = append(streams, stream)
	}
	sm.mutex.RUnlock()

	for _, stream := range streams {
		if stream.Status == StreamStatusActive {
			stream.FlushBuffer()
		}
	}
}

// Stream methods

// Stop stops the stream
func (s *Stream) Stop() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.Status == StreamStatusStopped {
		return
	}

	s.Status = StreamStatusStopped
	s.cancel()

	// Stop all subscribers
	for _, subscriber := range s.Subscribers {
		subscriber.Stop()
	}

	s.Subscribers = make(map[string]*StreamSubscriber)
}

// AddEvent adds an event to the stream
func (s *Stream) AddEvent(event StreamEvent) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.Status != StreamStatusActive {
		return fmt.Errorf("stream is not active: %s", s.Status)
	}

	// Check event size
	if event.Size > s.Config.MaxEventSize {
		return fmt.Errorf("event size exceeds maximum: %d > %d", event.Size, s.Config.MaxEventSize)
	}

	// Add to buffer
	s.Buffer = append(s.Buffer, event)
	s.EventCount++
	s.BytesStreamed += event.Size
	s.LastActivity = time.Now()

	// Send to subscribers
	for _, subscriber := range s.Subscribers {
		if subscriber.Active {
			select {
			case subscriber.EventQueue <- event:
				subscriber.EventsReceived++
				subscriber.LastActivity = time.Now()
			default:
				// Queue is full, log warning
			}
		}
	}

	// Flush buffer if full
	if len(s.Buffer) >= s.Config.BufferSize {
		s.flushBuffer()
	}

	return nil
}

// AddSubscriber adds a subscriber to the stream
func (s *Stream) AddSubscriber(connectionID string) *StreamSubscriber {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	subscriberID := uuid.New().String()
	ctx, cancel := context.WithCancel(s.ctx)

	subscriber := &StreamSubscriber{
		ID:             subscriberID,
		ConnectionID:   connectionID,
		StreamID:       s.ID,
		Filters:        make(map[string]interface{}),
		EventQueue:     make(chan StreamEvent, 100),
		Active:         true,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		EventsReceived: 0,
		ctx:            ctx,
		cancel:         cancel,
	}

	s.Subscribers[connectionID] = subscriber

	// Start subscriber worker
	go s.subscriberWorker(subscriber)

	return subscriber
}

// RemoveSubscriber removes a subscriber from the stream
func (s *Stream) RemoveSubscriber(connectionID string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if subscriber, exists := s.Subscribers[connectionID]; exists {
		subscriber.Stop()
		delete(s.Subscribers, connectionID)
	}
}

// FlushBuffer flushes the stream buffer
func (s *Stream) FlushBuffer() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.flushBuffer()
}

// flushBuffer internal method to flush buffer (must be called with lock held)
func (s *Stream) flushBuffer() {
	if len(s.Buffer) == 0 {
		return
	}

	// In a real implementation, you would persist the buffer to storage
	// For now, we just clear it
	s.Buffer = s.Buffer[:0]
}

// subscriberWorker processes events for a subscriber
func (s *Stream) subscriberWorker(subscriber *StreamSubscriber) {
	defer func() {
		close(subscriber.EventQueue)
	}()

	for {
		select {
		case <-subscriber.ctx.Done():
			return
		case event, ok := <-subscriber.EventQueue:
			if !ok {
				return
			}

			// Process event for subscriber
			// In a real implementation, you would send this to the actual connection
			_ = event // Placeholder
		}
	}
}

// StreamSubscriber methods

// Stop stops the subscriber
func (ss *StreamSubscriber) Stop() {
	ss.Active = false
	if ss.cancel != nil {
		ss.cancel()
	}
}
