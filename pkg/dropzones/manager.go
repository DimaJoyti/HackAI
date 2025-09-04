package dropzones

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/realtime"
)

var dropZoneTracer = otel.Tracer("hackai/dropzones")

// DefaultDropZoneManager implements the DropZoneManager interface
type DefaultDropZoneManager struct {
	dropZones       map[string]*DropZone
	processingQueue map[string]*ProcessingRequest
	results         map[string]*ProcessingResult
	router          DropZoneRouter
	coordinator     AgentCoordinator
	analyzer        ContentAnalyzer
	realtimeSystem  *realtime.RealtimeSystem
	logger          *logger.Logger

	// Configuration
	config *ManagerConfig

	// Concurrency control
	mutex           sync.RWMutex
	processingMutex sync.RWMutex

	// Background workers
	workers    []*ProcessingWorker
	workerPool chan *ProcessingRequest
	resultChan chan *ProcessingResult
	eventChan  chan *DropZoneEvent

	// Lifecycle management
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running bool
}

// ManagerConfig represents configuration for the drop zone manager
type ManagerConfig struct {
	MaxDropZones        int           `json:"max_drop_zones"`
	MaxConcurrentTasks  int           `json:"max_concurrent_tasks"`
	WorkerCount         int           `json:"worker_count"`
	QueueSize           int           `json:"queue_size"`
	ResultRetention     time.Duration `json:"result_retention"`
	MetricsInterval     time.Duration `json:"metrics_interval"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	EnableRealTime      bool          `json:"enable_real_time"`
	EnableMetrics       bool          `json:"enable_metrics"`
}

// ProcessingWorker handles processing requests
type ProcessingWorker struct {
	id       int
	manager  *DefaultDropZoneManager
	logger   *logger.Logger
	stopChan chan struct{}
}

// NewDefaultDropZoneManager creates a new drop zone manager
func NewDefaultDropZoneManager(
	router DropZoneRouter,
	coordinator AgentCoordinator,
	analyzer ContentAnalyzer,
	realtimeSystem *realtime.RealtimeSystem,
	config *ManagerConfig,
	logger *logger.Logger,
) *DefaultDropZoneManager {
	ctx, cancel := context.WithCancel(context.Background())

	manager := &DefaultDropZoneManager{
		dropZones:       make(map[string]*DropZone),
		processingQueue: make(map[string]*ProcessingRequest),
		results:         make(map[string]*ProcessingResult),
		router:          router,
		coordinator:     coordinator,
		analyzer:        analyzer,
		realtimeSystem:  realtimeSystem,
		logger:          logger,
		config:          config,
		workerPool:      make(chan *ProcessingRequest, config.QueueSize),
		resultChan:      make(chan *ProcessingResult, config.QueueSize),
		eventChan:       make(chan *DropZoneEvent, config.QueueSize),
		ctx:             ctx,
		cancel:          cancel,
	}

	// Create workers
	for i := 0; i < config.WorkerCount; i++ {
		worker := &ProcessingWorker{
			id:       i,
			manager:  manager,
			logger:   logger,
			stopChan: make(chan struct{}),
		}
		manager.workers = append(manager.workers, worker)
	}

	return manager
}

// Start starts the drop zone manager
func (dm *DefaultDropZoneManager) Start(ctx context.Context) error {
	ctx, span := dropZoneTracer.Start(ctx, "drop_zone_manager.start")
	defer span.End()

	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	if dm.running {
		return fmt.Errorf("drop zone manager is already running")
	}

	dm.logger.Info("Starting drop zone manager",
		"worker_count", dm.config.WorkerCount,
		"queue_size", dm.config.QueueSize)

	// Start workers
	for _, worker := range dm.workers {
		dm.wg.Add(1)
		go worker.run()
	}

	// Start background processes
	dm.wg.Add(3)
	go dm.resultProcessor()
	go dm.eventProcessor()
	go dm.metricsCollector()

	if dm.config.EnableMetrics {
		dm.wg.Add(1)
		go dm.healthChecker()
	}

	dm.running = true

	span.SetAttributes(
		attribute.Bool("manager_started", true),
		attribute.Int("worker_count", dm.config.WorkerCount),
	)

	dm.logger.Info("Drop zone manager started successfully")
	return nil
}

// Stop stops the drop zone manager
func (dm *DefaultDropZoneManager) Stop() error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	if !dm.running {
		return fmt.Errorf("drop zone manager is not running")
	}

	dm.logger.Info("Stopping drop zone manager")

	// Stop workers
	for _, worker := range dm.workers {
		close(worker.stopChan)
	}

	// Cancel context and wait for goroutines
	dm.cancel()
	dm.wg.Wait()

	dm.running = false

	dm.logger.Info("Drop zone manager stopped successfully")
	return nil
}

// CreateDropZone creates a new drop zone
func (dm *DefaultDropZoneManager) CreateDropZone(ctx context.Context, config *DropZoneConfig) (*DropZone, error) {
	ctx, span := dropZoneTracer.Start(ctx, "drop_zone_manager.create_drop_zone",
		trace.WithAttributes(
			attribute.String("drop_zone.id", config.ID),
			attribute.String("drop_zone.type", string(config.Type)),
		),
	)
	defer span.End()

	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	// Check if drop zone already exists
	if _, exists := dm.dropZones[config.ID]; exists {
		err := fmt.Errorf("drop zone already exists: %s", config.ID)
		span.RecordError(err)
		return nil, err
	}

	// Check limits
	if len(dm.dropZones) >= dm.config.MaxDropZones {
		err := fmt.Errorf("maximum number of drop zones reached: %d", dm.config.MaxDropZones)
		span.RecordError(err)
		return nil, err
	}

	// Create drop zone context
	dzCtx, dzCancel := context.WithCancel(dm.ctx)

	// Create drop zone
	dropZone := &DropZone{
		Config:          config,
		Status:          DropZoneStatusActive,
		ActiveAgents:    make([]string, 0),
		QueuedRequests:  0,
		ProcessingCount: 0,
		TotalProcessed:  0,
		LastActivity:    time.Now(),
		Metrics: &DropZoneMetrics{
			LastUpdated: time.Now(),
		},
		ctx:    dzCtx,
		cancel: dzCancel,
	}

	// Store drop zone
	dm.dropZones[config.ID] = dropZone

	// Register with router
	if err := dm.router.RegisterDropZone(ctx, dropZone); err != nil {
		delete(dm.dropZones, config.ID)
		dzCancel()
		span.RecordError(err)
		return nil, fmt.Errorf("failed to register drop zone with router: %w", err)
	}

	// Emit event
	event := &DropZoneEvent{
		ID:         uuid.New().String(),
		Type:       EventTypeDropZoneStatus,
		DropZoneID: config.ID,
		Data: map[string]interface{}{
			"status": DropZoneStatusActive,
			"action": "created",
		},
		Timestamp: time.Now(),
		Source:    "drop_zone_manager",
		Severity:  "info",
	}

	select {
	case dm.eventChan <- event:
	default:
		dm.logger.Warn("Event channel full, dropping event", "event_id", event.ID)
	}

	span.SetAttributes(
		attribute.Bool("drop_zone_created", true),
		attribute.String("drop_zone.status", string(dropZone.Status)),
	)

	dm.logger.Info("Drop zone created successfully",
		"drop_zone_id", config.ID,
		"type", config.Type,
		"status", dropZone.Status)

	return dropZone, nil
}

// GetDropZone retrieves a drop zone by ID
func (dm *DefaultDropZoneManager) GetDropZone(ctx context.Context, id string) (*DropZone, error) {
	ctx, span := dropZoneTracer.Start(ctx, "drop_zone_manager.get_drop_zone",
		trace.WithAttributes(
			attribute.String("drop_zone.id", id),
		),
	)
	defer span.End()

	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	dropZone, exists := dm.dropZones[id]
	if !exists {
		err := fmt.Errorf("drop zone not found: %s", id)
		span.RecordError(err)
		return nil, err
	}

	span.SetAttributes(
		attribute.String("drop_zone.status", string(dropZone.Status)),
		attribute.Int("drop_zone.queued_requests", dropZone.QueuedRequests),
	)

	return dropZone, nil
}

// SubmitData submits data to a drop zone for processing
func (dm *DefaultDropZoneManager) SubmitData(ctx context.Context, dropZoneID string, data *DropZoneData) (*ProcessingRequest, error) {
	ctx, span := dropZoneTracer.Start(ctx, "drop_zone_manager.submit_data",
		trace.WithAttributes(
			attribute.String("drop_zone.id", dropZoneID),
			attribute.String("data.type", string(data.Type)),
			attribute.Int64("data.size", data.Size),
		),
	)
	defer span.End()

	// Get drop zone
	dropZone, err := dm.GetDropZone(ctx, dropZoneID)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}

	// Check drop zone status
	if dropZone.Status != DropZoneStatusActive {
		err := fmt.Errorf("drop zone is not active: %s", dropZone.Status)
		span.RecordError(err)
		return nil, err
	}

	// Validate data
	if err := dm.validateData(ctx, dropZone, data); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("data validation failed: %w", err)
	}

	// Generate checksum if not provided
	if data.Checksum == "" {
		hash := sha256.Sum256([]byte(data.Content))
		data.Checksum = hex.EncodeToString(hash[:])
	}

	// Analyze content
	analysis, err := dm.analyzer.AnalyzeContent(ctx, data)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("content analysis failed: %w", err)
	}

	// Create processing request
	request := &ProcessingRequest{
		ID:          uuid.New().String(),
		DropZoneID:  dropZoneID,
		Data:        data,
		AgentIDs:    analysis.RequiredAgents,
		Options:     make(map[string]interface{}),
		Timeout:     dropZone.Config.ProcessingTimeout,
		Priority:    data.Priority,
		SubmittedAt: time.Now(),
		SubmittedBy: data.Source,
	}

	// Store request
	dm.processingMutex.Lock()
	dm.processingQueue[request.ID] = request
	dm.processingMutex.Unlock()

	// Update drop zone metrics
	dm.mutex.Lock()
	dropZone.QueuedRequests++
	dropZone.LastActivity = time.Now()
	dm.mutex.Unlock()

	// Submit to worker pool
	select {
	case dm.workerPool <- request:
		// Request queued successfully
	default:
		// Queue is full
		dm.processingMutex.Lock()
		delete(dm.processingQueue, request.ID)
		dm.processingMutex.Unlock()

		dm.mutex.Lock()
		dropZone.QueuedRequests--
		dm.mutex.Unlock()

		err := fmt.Errorf("processing queue is full")
		span.RecordError(err)
		return nil, err
	}

	// Emit event
	event := &DropZoneEvent{
		ID:         uuid.New().String(),
		Type:       EventTypeDataSubmitted,
		DropZoneID: dropZoneID,
		RequestID:  request.ID,
		Data: map[string]interface{}{
			"data_type": data.Type,
			"size":      data.Size,
			"priority":  data.Priority,
		},
		Timestamp: time.Now(),
		Source:    "drop_zone_manager",
		Severity:  "info",
	}

	select {
	case dm.eventChan <- event:
	default:
		dm.logger.Warn("Event channel full, dropping event", "event_id", event.ID)
	}

	span.SetAttributes(
		attribute.String("request.id", request.ID),
		attribute.String("analysis.threat_level", analysis.ThreatLevel),
		attribute.Float64("analysis.confidence", analysis.Confidence),
	)

	dm.logger.Info("Data submitted for processing",
		"request_id", request.ID,
		"drop_zone_id", dropZoneID,
		"data_type", data.Type,
		"size", data.Size,
		"priority", data.Priority)

	return request, nil
}

// validateData validates submitted data against drop zone configuration
func (dm *DefaultDropZoneManager) validateData(ctx context.Context, dropZone *DropZone, data *DropZoneData) error {
	// Check data size
	if data.Size > dropZone.Config.MaxDataSize {
		return fmt.Errorf("data size exceeds maximum: %d > %d", data.Size, dropZone.Config.MaxDataSize)
	}

	// Check allowed data types
	if len(dropZone.Config.AllowedDataTypes) > 0 {
		allowed := false
		for _, allowedType := range dropZone.Config.AllowedDataTypes {
			if data.Type == allowedType {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("data type not allowed: %s", data.Type)
		}
	}

	// Use content analyzer for additional validation
	validationRules := make(map[string]interface{})
	return dm.analyzer.ValidateContent(ctx, data, validationRules)
}

// GetProcessingStatus retrieves the status of a processing request
func (dm *DefaultDropZoneManager) GetProcessingStatus(ctx context.Context, requestID string) (*ProcessingResult, error) {
	ctx, span := dropZoneTracer.Start(ctx, "drop_zone_manager.get_processing_status",
		trace.WithAttributes(
			attribute.String("request.id", requestID),
		),
	)
	defer span.End()

	dm.processingMutex.RLock()
	defer dm.processingMutex.RUnlock()

	result, exists := dm.results[requestID]
	if !exists {
		err := fmt.Errorf("processing result not found: %s", requestID)
		span.RecordError(err)
		return nil, err
	}

	span.SetAttributes(
		attribute.String("result.status", string(result.Status)),
		attribute.Float64("result.confidence", result.Confidence),
	)

	return result, nil
}

// ListDropZones returns all drop zones
func (dm *DefaultDropZoneManager) ListDropZones(ctx context.Context) ([]*DropZone, error) {
	ctx, span := dropZoneTracer.Start(ctx, "drop_zone_manager.list_drop_zones")
	defer span.End()

	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	dropZones := make([]*DropZone, 0, len(dm.dropZones))
	for _, dz := range dm.dropZones {
		dropZones = append(dropZones, dz)
	}

	span.SetAttributes(
		attribute.Int("drop_zones.count", len(dropZones)),
	)

	return dropZones, nil
}

// Health checks the health of the drop zone manager
func (dm *DefaultDropZoneManager) Health() error {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	if !dm.running {
		return fmt.Errorf("drop zone manager is not running")
	}

	// Check worker pool
	if len(dm.workerPool) == cap(dm.workerPool) {
		return fmt.Errorf("worker pool is full")
	}

	// Check if any drop zones are overloaded
	for id, dz := range dm.dropZones {
		if dz.Status == DropZoneStatusOverloaded {
			return fmt.Errorf("drop zone %s is overloaded", id)
		}
	}

	return nil
}

// run starts the processing worker
func (pw *ProcessingWorker) run() {
	defer pw.manager.wg.Done()

	pw.logger.Info("Processing worker started", "worker_id", pw.id)

	for {
		select {
		case request := <-pw.manager.workerPool:
			pw.processRequest(request)
		case <-pw.stopChan:
			pw.logger.Info("Processing worker stopped", "worker_id", pw.id)
			return
		case <-pw.manager.ctx.Done():
			pw.logger.Info("Processing worker stopped due to context cancellation", "worker_id", pw.id)
			return
		}
	}
}

// processRequest processes a single request
func (pw *ProcessingWorker) processRequest(request *ProcessingRequest) {
	ctx, span := dropZoneTracer.Start(pw.manager.ctx, "processing_worker.process_request",
		trace.WithAttributes(
			attribute.String("request.id", request.ID),
			attribute.String("drop_zone.id", request.DropZoneID),
			attribute.Int("worker.id", pw.id),
		),
	)
	defer span.End()

	startTime := time.Now()

	// Create processing result
	result := &ProcessingResult{
		ID:        uuid.New().String(),
		RequestID: request.ID,
		Status:    ProcessingStatusProcessing,
		Results:   make(map[string]interface{}),
		StartTime: startTime,
		Metadata:  make(map[string]interface{}),
	}

	// Update drop zone metrics
	pw.manager.mutex.Lock()
	if dz, exists := pw.manager.dropZones[request.DropZoneID]; exists {
		dz.QueuedRequests--
		dz.ProcessingCount++
		dz.LastActivity = time.Now()
	}
	pw.manager.mutex.Unlock()

	// Store initial result
	pw.manager.processingMutex.Lock()
	pw.manager.results[request.ID] = result
	delete(pw.manager.processingQueue, request.ID)
	pw.manager.processingMutex.Unlock()

	// Emit processing started event
	event := &DropZoneEvent{
		ID:         uuid.New().String(),
		Type:       EventTypeProcessingStarted,
		DropZoneID: request.DropZoneID,
		RequestID:  request.ID,
		Data: map[string]interface{}{
			"worker_id":  pw.id,
			"start_time": startTime,
		},
		Timestamp: time.Now(),
		Source:    "processing_worker",
		Severity:  "info",
	}

	select {
	case pw.manager.eventChan <- event:
	default:
		pw.logger.Warn("Event channel full, dropping event", "event_id", event.ID)
	}

	// Assign agents
	agentIDs, err := pw.manager.coordinator.AssignAgents(ctx, request)
	if err != nil {
		pw.completeProcessing(result, request, err, span)
		return
	}

	result.ProcessedBy = agentIDs

	// Simulate processing (in real implementation, this would call actual agents)
	pw.simulateProcessing(ctx, request, result)

	// Complete processing
	pw.completeProcessing(result, request, nil, span)
}

// simulateProcessing simulates agent processing (placeholder for actual implementation)
func (pw *ProcessingWorker) simulateProcessing(ctx context.Context, request *ProcessingRequest, result *ProcessingResult) {
	// Simulate processing time based on data size and complexity
	processingTime := time.Duration(request.Data.Size/1024) * time.Millisecond
	if processingTime < 100*time.Millisecond {
		processingTime = 100 * time.Millisecond
	}
	if processingTime > 5*time.Second {
		processingTime = 5 * time.Second
	}

	select {
	case <-time.After(processingTime):
		// Processing completed
		result.Results["status"] = "completed"
		result.Results["processed_size"] = request.Data.Size
		result.Results["processing_time"] = processingTime
		result.Confidence = 0.95
	case <-ctx.Done():
		// Processing cancelled
		result.Status = ProcessingStatusCancelled
		result.Errors = append(result.Errors, "processing cancelled")
	}
}

// completeProcessing completes the processing and updates metrics
func (pw *ProcessingWorker) completeProcessing(result *ProcessingResult, request *ProcessingRequest, err error, span trace.Span) {
	endTime := time.Now()
	result.EndTime = &endTime
	result.Duration = endTime.Sub(result.StartTime)

	if err != nil {
		result.Status = ProcessingStatusFailed
		result.Errors = append(result.Errors, err.Error())
		span.RecordError(err)
	} else if result.Status != ProcessingStatusCancelled {
		result.Status = ProcessingStatusCompleted
	}

	// Update drop zone metrics
	pw.manager.mutex.Lock()
	if dz, exists := pw.manager.dropZones[request.DropZoneID]; exists {
		dz.ProcessingCount--
		dz.TotalProcessed++
		dz.LastActivity = time.Now()

		// Update metrics
		if dz.Metrics != nil {
			dz.Metrics.TotalRequests++
			if result.Status == ProcessingStatusCompleted {
				dz.Metrics.SuccessfulRequests++
			} else {
				dz.Metrics.FailedRequests++
			}
			dz.Metrics.LastUpdated = time.Now()
		}
	}
	pw.manager.mutex.Unlock()

	// Update result
	pw.manager.processingMutex.Lock()
	pw.manager.results[request.ID] = result
	pw.manager.processingMutex.Unlock()

	// Release agents
	if len(result.ProcessedBy) > 0 {
		pw.manager.coordinator.ReleaseAgents(pw.manager.ctx, result.ProcessedBy)
	}

	// Send result to result channel
	select {
	case pw.manager.resultChan <- result:
	default:
		pw.logger.Warn("Result channel full, dropping result", "request_id", request.ID)
	}

	span.SetAttributes(
		attribute.String("result.status", string(result.Status)),
		attribute.Int64("result.duration_ms", result.Duration.Milliseconds()),
		attribute.Float64("result.confidence", result.Confidence),
	)

	pw.logger.Info("Processing completed",
		"request_id", request.ID,
		"worker_id", pw.id,
		"status", result.Status,
		"duration", result.Duration,
		"confidence", result.Confidence)
}

// resultProcessor processes completed results
func (dm *DefaultDropZoneManager) resultProcessor() {
	defer dm.wg.Done()

	dm.logger.Info("Result processor started")

	for {
		select {
		case result := <-dm.resultChan:
			dm.handleProcessingResult(result)
		case <-dm.ctx.Done():
			dm.logger.Info("Result processor stopped")
			return
		}
	}
}

// handleProcessingResult handles a completed processing result
func (dm *DefaultDropZoneManager) handleProcessingResult(result *ProcessingResult) {
	// Emit completion event
	eventType := EventTypeProcessingCompleted
	if result.Status == ProcessingStatusFailed {
		eventType = EventTypeProcessingFailed
	}

	event := &DropZoneEvent{
		ID:         uuid.New().String(),
		Type:       eventType,
		DropZoneID: "", // Will be filled from request
		RequestID:  result.RequestID,
		Data: map[string]interface{}{
			"status":     result.Status,
			"duration":   result.Duration,
			"confidence": result.Confidence,
		},
		Timestamp: time.Now(),
		Source:    "result_processor",
		Severity:  "info",
	}

	// Find drop zone ID from request
	dm.processingMutex.RLock()
	if request, exists := dm.processingQueue[result.RequestID]; exists {
		event.DropZoneID = request.DropZoneID
	}
	dm.processingMutex.RUnlock()

	// Send event
	select {
	case dm.eventChan <- event:
	default:
		dm.logger.Warn("Event channel full, dropping event", "event_id", event.ID)
	}

	// Publish to real-time system if enabled
	if dm.config.EnableRealTime && dm.realtimeSystem != nil {
		channel := fmt.Sprintf("dropzone.%s.results", event.DropZoneID)
		data := map[string]interface{}{
			"result": result,
			"event":  event,
		}

		if err := dm.realtimeSystem.PublishMessage(dm.ctx, channel, data); err != nil {
			dm.logger.Error("Failed to publish result to real-time system", "error", err)
		}
	}
}

// eventProcessor processes drop zone events
func (dm *DefaultDropZoneManager) eventProcessor() {
	defer dm.wg.Done()

	dm.logger.Info("Event processor started")

	for {
		select {
		case event := <-dm.eventChan:
			dm.handleDropZoneEvent(event)
		case <-dm.ctx.Done():
			dm.logger.Info("Event processor stopped")
			return
		}
	}
}

// handleDropZoneEvent handles a drop zone event
func (dm *DefaultDropZoneManager) handleDropZoneEvent(event *DropZoneEvent) {
	// Log event
	dm.logger.Debug("Processing drop zone event",
		"event_id", event.ID,
		"type", event.Type,
		"drop_zone_id", event.DropZoneID,
		"severity", event.Severity)

	// Publish to real-time system if enabled
	if dm.config.EnableRealTime && dm.realtimeSystem != nil {
		channel := fmt.Sprintf("dropzone.%s.events", event.DropZoneID)
		data := map[string]interface{}{
			"event": event,
		}

		if err := dm.realtimeSystem.PublishMessage(dm.ctx, channel, data); err != nil {
			dm.logger.Error("Failed to publish event to real-time system", "error", err)
		}
	}

	// Handle specific event types
	switch event.Type {
	case EventTypeDropZoneStatus:
		dm.handleDropZoneStatusEvent(event)
	case EventTypeProcessingFailed:
		dm.handleProcessingFailedEvent(event)
	}
}

// handleDropZoneStatusEvent handles drop zone status events
func (dm *DefaultDropZoneManager) handleDropZoneStatusEvent(event *DropZoneEvent) {
	// Update drop zone status if needed
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	if dz, exists := dm.dropZones[event.DropZoneID]; exists {
		if dataMap, ok := event.Data.(map[string]interface{}); ok {
			if status, ok := dataMap["status"].(string); ok {
				dz.Status = status
				dz.LastActivity = time.Now()
			}
		}
	}
}

// handleProcessingFailedEvent handles processing failed events
func (dm *DefaultDropZoneManager) handleProcessingFailedEvent(event *DropZoneEvent) {
	// Could implement retry logic, alerting, etc.
	dm.logger.Warn("Processing failed",
		"event_id", event.ID,
		"drop_zone_id", event.DropZoneID,
		"request_id", event.RequestID)
}

// metricsCollector collects and updates metrics
func (dm *DefaultDropZoneManager) metricsCollector() {
	defer dm.wg.Done()

	ticker := time.NewTicker(dm.config.MetricsInterval)
	defer ticker.Stop()

	dm.logger.Info("Metrics collector started")

	for {
		select {
		case <-ticker.C:
			dm.updateMetrics()
		case <-dm.ctx.Done():
			dm.logger.Info("Metrics collector stopped")
			return
		}
	}
}

// updateMetrics updates drop zone metrics
func (dm *DefaultDropZoneManager) updateMetrics() {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	for _, dz := range dm.dropZones {
		if dz.Metrics == nil {
			continue
		}

		// Calculate throughput
		if dz.Metrics.TotalRequests > 0 {
			elapsed := time.Since(dz.Metrics.LastUpdated).Seconds()
			if elapsed > 0 {
				dz.Metrics.ThroughputPerSecond = float64(dz.Metrics.TotalRequests) / elapsed
			}
		}

		// Calculate error rate
		if dz.Metrics.TotalRequests > 0 {
			dz.Metrics.ErrorRate = float64(dz.Metrics.FailedRequests) / float64(dz.Metrics.TotalRequests)
		}

		// Update queue depth
		dz.Metrics.QueueDepth = dz.QueuedRequests

		// Update last updated time
		dz.Metrics.LastUpdated = time.Now()
	}
}

// healthChecker performs periodic health checks
func (dm *DefaultDropZoneManager) healthChecker() {
	defer dm.wg.Done()

	ticker := time.NewTicker(dm.config.HealthCheckInterval)
	defer ticker.Stop()

	dm.logger.Info("Health checker started")

	for {
		select {
		case <-ticker.C:
			dm.performHealthCheck()
		case <-dm.ctx.Done():
			dm.logger.Info("Health checker stopped")
			return
		}
	}
}

// performHealthCheck performs a health check on all drop zones
func (dm *DefaultDropZoneManager) performHealthCheck() {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	for id, dz := range dm.dropZones {
		// Check if drop zone is overloaded
		if dz.QueuedRequests > dz.Config.MaxQueueSize*80/100 { // 80% threshold
			if dz.Status != DropZoneStatusOverloaded {
				dz.Status = DropZoneStatusOverloaded

				event := &DropZoneEvent{
					ID:         uuid.New().String(),
					Type:       EventTypeDropZoneStatus,
					DropZoneID: id,
					Data: map[string]interface{}{
						"status":      DropZoneStatusOverloaded,
						"queue_depth": dz.QueuedRequests,
						"max_queue":   dz.Config.MaxQueueSize,
					},
					Timestamp: time.Now(),
					Source:    "health_checker",
					Severity:  "warning",
				}

				select {
				case dm.eventChan <- event:
				default:
					dm.logger.Warn("Event channel full, dropping event", "event_id", event.ID)
				}
			}
		} else if dz.Status == DropZoneStatusOverloaded {
			// Recovery from overloaded state
			dz.Status = DropZoneStatusActive

			event := &DropZoneEvent{
				ID:         uuid.New().String(),
				Type:       EventTypeDropZoneStatus,
				DropZoneID: id,
				Data: map[string]interface{}{
					"status":      DropZoneStatusActive,
					"action":      "recovered",
					"queue_depth": dz.QueuedRequests,
				},
				Timestamp: time.Now(),
				Source:    "health_checker",
				Severity:  "info",
			}

			select {
			case dm.eventChan <- event:
			default:
				dm.logger.Warn("Event channel full, dropping event", "event_id", event.ID)
			}
		}
	}
}

// Additional interface methods implementation

// UpdateDropZone updates a drop zone configuration
func (dm *DefaultDropZoneManager) UpdateDropZone(ctx context.Context, id string, config *DropZoneConfig) error {
	ctx, span := dropZoneTracer.Start(ctx, "drop_zone_manager.update_drop_zone")
	defer span.End()

	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	dropZone, exists := dm.dropZones[id]
	if !exists {
		err := fmt.Errorf("drop zone not found: %s", id)
		span.RecordError(err)
		return err
	}

	// Update configuration
	config.UpdatedAt = time.Now()
	dropZone.Config = config

	span.SetAttributes(
		attribute.String("drop_zone.id", id),
		attribute.String("drop_zone.type", string(config.Type)),
	)

	dm.logger.Info("Drop zone updated", "drop_zone_id", id)
	return nil
}

// DeleteDropZone deletes a drop zone
func (dm *DefaultDropZoneManager) DeleteDropZone(ctx context.Context, id string) error {
	ctx, span := dropZoneTracer.Start(ctx, "drop_zone_manager.delete_drop_zone")
	defer span.End()

	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	dropZone, exists := dm.dropZones[id]
	if !exists {
		err := fmt.Errorf("drop zone not found: %s", id)
		span.RecordError(err)
		return err
	}

	// Cancel drop zone context
	dropZone.cancel()

	// Unregister from router
	if err := dm.router.UnregisterDropZone(ctx, id); err != nil {
		dm.logger.Warn("Failed to unregister drop zone from router", "error", err)
	}

	// Remove from map
	delete(dm.dropZones, id)

	span.SetAttributes(
		attribute.String("drop_zone.id", id),
		attribute.Bool("drop_zone_deleted", true),
	)

	dm.logger.Info("Drop zone deleted", "drop_zone_id", id)
	return nil
}

// CancelProcessing cancels a processing request
func (dm *DefaultDropZoneManager) CancelProcessing(ctx context.Context, requestID string) error {
	ctx, span := dropZoneTracer.Start(ctx, "drop_zone_manager.cancel_processing")
	defer span.End()

	dm.processingMutex.Lock()
	defer dm.processingMutex.Unlock()

	// Check if request exists
	if _, exists := dm.processingQueue[requestID]; !exists {
		if result, exists := dm.results[requestID]; exists {
			if result.Status == ProcessingStatusCompleted || result.Status == ProcessingStatusFailed {
				err := fmt.Errorf("processing already completed: %s", requestID)
				span.RecordError(err)
				return err
			}
		} else {
			err := fmt.Errorf("processing request not found: %s", requestID)
			span.RecordError(err)
			return err
		}
	}

	// Update result status
	if result, exists := dm.results[requestID]; exists {
		result.Status = ProcessingStatusCancelled
		endTime := time.Now()
		result.EndTime = &endTime
		result.Duration = endTime.Sub(result.StartTime)
	}

	span.SetAttributes(
		attribute.String("request.id", requestID),
		attribute.Bool("processing_cancelled", true),
	)

	dm.logger.Info("Processing cancelled", "request_id", requestID)
	return nil
}
