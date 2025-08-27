package ingestion

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/llm/providers"
	"github.com/dimajoyti/hackai/pkg/llm/vectordb"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var ingestionTracer = otel.Tracer("hackai/llm/ingestion")

// IngestionPipeline processes documents for vector storage
type IngestionPipeline struct {
	chunker     DocumentChunker
	embedder    providers.LLMProvider
	vectorDB    *vectordb.VectorDBManager
	processor   *DocumentProcessor
	config      PipelineConfig
	logger      *logger.Logger
	metrics     *PipelineMetrics
	workers     []*Worker
	jobQueue    chan *IngestionJob
	resultQueue chan *IngestionResult
	stopChan    chan struct{}
	wg          sync.WaitGroup
}

// PipelineConfig configures the ingestion pipeline
type PipelineConfig struct {
	WorkerCount         int           `json:"worker_count"`
	BatchSize           int           `json:"batch_size"`
	ChunkSize           int           `json:"chunk_size"`
	ChunkOverlap        int           `json:"chunk_overlap"`
	MaxRetries          int           `json:"max_retries"`
	RetryDelay          time.Duration `json:"retry_delay"`
	EnableDeduplication bool          `json:"enable_deduplication"`
	EnableMetadata      bool          `json:"enable_metadata"`
	QueueSize           int           `json:"queue_size"`
}

// IngestionJob represents a document ingestion job
type IngestionJob struct {
	ID        string                 `json:"id"`
	Document  RawDocument            `json:"document"`
	Options   IngestionOptions       `json:"options"`
	Metadata  map[string]interface{} `json:"metadata"`
	CreatedAt time.Time              `json:"created_at"`
	Priority  int                    `json:"priority"`
}

// RawDocument represents an unprocessed document
type RawDocument struct {
	ID       string                 `json:"id"`
	Content  string                 `json:"content"`
	Type     string                 `json:"type"`
	Source   string                 `json:"source"`
	Metadata map[string]interface{} `json:"metadata"`
}

// IngestionOptions configures how a document should be processed
type IngestionOptions struct {
	ChunkSize         int                    `json:"chunk_size,omitempty"`
	ChunkOverlap      int                    `json:"chunk_overlap,omitempty"`
	CustomMetadata    map[string]interface{} `json:"custom_metadata,omitempty"`
	SkipDuplication   bool                   `json:"skip_duplication"`
	EmbeddingProvider string                 `json:"embedding_provider,omitempty"`
}

// IngestionResult represents the result of document ingestion
type IngestionResult struct {
	JobID          string        `json:"job_id"`
	DocumentID     string        `json:"document_id"`
	ChunksCreated  int           `json:"chunks_created"`
	ProcessingTime time.Duration `json:"processing_time"`
	Success        bool          `json:"success"`
	Error          error         `json:"error,omitempty"`
	Timestamp      time.Time     `json:"timestamp"`
}

// DocumentChunk represents a processed document chunk
type DocumentChunk struct {
	ID         string                 `json:"id"`
	Content    string                 `json:"content"`
	Embedding  []float64              `json:"embedding"`
	Metadata   map[string]interface{} `json:"metadata"`
	ParentID   string                 `json:"parent_id"`
	ChunkIndex int                    `json:"chunk_index"`
	Hash       string                 `json:"hash"`
}

// PipelineMetrics tracks pipeline performance
type PipelineMetrics struct {
	DocumentsProcessed  int64         `json:"documents_processed"`
	ChunksCreated       int64         `json:"chunks_created"`
	TotalProcessingTime time.Duration `json:"total_processing_time"`
	ErrorCount          int64         `json:"error_count"`
	AverageChunkSize    float64       `json:"average_chunk_size"`
	mutex               sync.RWMutex
}

// Worker processes ingestion jobs
type Worker struct {
	id       int
	pipeline *IngestionPipeline
	logger   *logger.Logger
}

// NewIngestionPipeline creates a new document ingestion pipeline
func NewIngestionPipeline(
	embedder providers.LLMProvider,
	vectorDB *vectordb.VectorDBManager,
	config PipelineConfig,
	logger *logger.Logger,
) *IngestionPipeline {
	// Set defaults
	if config.WorkerCount == 0 {
		config.WorkerCount = 4
	}
	if config.BatchSize == 0 {
		config.BatchSize = 10
	}
	if config.ChunkSize == 0 {
		config.ChunkSize = 1000
	}
	if config.ChunkOverlap == 0 {
		config.ChunkOverlap = 200
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 1 * time.Second
	}
	if config.QueueSize == 0 {
		config.QueueSize = 100
	}

	pipeline := &IngestionPipeline{
		chunker:     NewTextChunker(config.ChunkSize, config.ChunkOverlap),
		embedder:    embedder,
		vectorDB:    vectorDB,
		processor:   NewDocumentProcessor(logger),
		config:      config,
		logger:      logger,
		metrics:     &PipelineMetrics{},
		jobQueue:    make(chan *IngestionJob, config.QueueSize),
		resultQueue: make(chan *IngestionResult, config.QueueSize),
		stopChan:    make(chan struct{}),
	}

	// Create workers
	for i := 0; i < config.WorkerCount; i++ {
		worker := &Worker{
			id:       i,
			pipeline: pipeline,
			logger:   logger,
		}
		pipeline.workers = append(pipeline.workers, worker)
	}

	return pipeline
}

// Start starts the ingestion pipeline
func (ip *IngestionPipeline) Start(ctx context.Context) error {
	ip.logger.Info("Starting ingestion pipeline",
		"workers", len(ip.workers),
		"queue_size", ip.config.QueueSize)

	// Start workers
	for _, worker := range ip.workers {
		ip.wg.Add(1)
		go worker.run(ctx)
	}

	// Start result processor
	ip.wg.Add(1)
	go ip.processResults(ctx)

	return nil
}

// Stop stops the ingestion pipeline
func (ip *IngestionPipeline) Stop() error {
	ip.logger.Info("Stopping ingestion pipeline")

	close(ip.stopChan)
	close(ip.jobQueue)

	ip.wg.Wait()
	close(ip.resultQueue)

	ip.logger.Info("Ingestion pipeline stopped")
	return nil
}

// IngestDocument submits a document for ingestion
func (ip *IngestionPipeline) IngestDocument(ctx context.Context, doc RawDocument, options IngestionOptions) (string, error) {
	ctx, span := ingestionTracer.Start(ctx, "ingestion_pipeline.ingest_document",
		trace.WithAttributes(
			attribute.String("document_id", doc.ID),
			attribute.String("document_type", doc.Type),
			attribute.Int("content_length", len(doc.Content)),
		),
	)
	defer span.End()

	job := &IngestionJob{
		ID:        fmt.Sprintf("job_%s_%d", doc.ID, time.Now().UnixNano()),
		Document:  doc,
		Options:   options,
		CreatedAt: time.Now(),
		Priority:  1, // Default priority
	}

	select {
	case ip.jobQueue <- job:
		span.SetAttributes(attribute.String("job_id", job.ID))
		ip.logger.Info("Document queued for ingestion",
			"job_id", job.ID,
			"document_id", doc.ID)
		return job.ID, nil
	case <-ctx.Done():
		return "", ctx.Err()
	default:
		return "", fmt.Errorf("ingestion queue is full")
	}
}

// IngestBatch submits multiple documents for batch ingestion
func (ip *IngestionPipeline) IngestBatch(ctx context.Context, docs []RawDocument, options IngestionOptions) ([]string, error) {
	ctx, span := ingestionTracer.Start(ctx, "ingestion_pipeline.ingest_batch",
		trace.WithAttributes(
			attribute.Int("batch_size", len(docs)),
		),
	)
	defer span.End()

	jobIDs := make([]string, 0, len(docs))

	for _, doc := range docs {
		jobID, err := ip.IngestDocument(ctx, doc, options)
		if err != nil {
			span.RecordError(err)
			return jobIDs, fmt.Errorf("failed to queue document %s: %w", doc.ID, err)
		}
		jobIDs = append(jobIDs, jobID)
	}

	return jobIDs, nil
}

// run executes the worker loop
func (w *Worker) run(ctx context.Context) {
	defer w.pipeline.wg.Done()

	w.logger.Info("Worker started", "worker_id", w.id)

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("Worker stopping due to context cancellation", "worker_id", w.id)
			return
		case <-w.pipeline.stopChan:
			w.logger.Info("Worker stopping", "worker_id", w.id)
			return
		case job, ok := <-w.pipeline.jobQueue:
			if !ok {
				w.logger.Info("Worker stopping - job queue closed", "worker_id", w.id)
				return
			}
			w.processJob(ctx, job)
		}
	}
}

// processJob processes a single ingestion job
func (w *Worker) processJob(ctx context.Context, job *IngestionJob) {
	ctx, span := ingestionTracer.Start(ctx, "worker.process_job",
		trace.WithAttributes(
			attribute.String("job_id", job.ID),
			attribute.String("document_id", job.Document.ID),
			attribute.Int("worker_id", w.id),
		),
	)
	defer span.End()

	startTime := time.Now()
	result := &IngestionResult{
		JobID:      job.ID,
		DocumentID: job.Document.ID,
		Timestamp:  startTime,
	}

	// Process document
	chunks, err := w.processDocument(ctx, job)
	if err != nil {
		result.Success = false
		result.Error = err
		span.RecordError(err)
		w.logger.Error("Failed to process document",
			"job_id", job.ID,
			"document_id", job.Document.ID,
			"error", err)
	} else {
		result.Success = true
		result.ChunksCreated = len(chunks)
		span.SetAttributes(attribute.Int("chunks_created", len(chunks)))
	}

	result.ProcessingTime = time.Since(startTime)

	// Send result
	select {
	case w.pipeline.resultQueue <- result:
	case <-ctx.Done():
		return
	}
}

// processDocument processes a document into chunks and stores them
func (w *Worker) processDocument(ctx context.Context, job *IngestionJob) ([]DocumentChunk, error) {
	// 1. Clean and preprocess content
	cleanContent := w.pipeline.processor.CleanContent(job.Document.Content)

	// 2. Chunk the document
	textChunks := w.pipeline.chunker.ChunkText(cleanContent, job.Options.ChunkSize, job.Options.ChunkOverlap)

	// 3. Create document chunks with metadata
	chunks := make([]DocumentChunk, 0, len(textChunks))
	for i, textChunk := range textChunks {
		chunk := DocumentChunk{
			ID:         fmt.Sprintf("%s_chunk_%d", job.Document.ID, i),
			Content:    textChunk,
			ParentID:   job.Document.ID,
			ChunkIndex: i,
			Hash:       w.generateHash(textChunk),
			Metadata: map[string]interface{}{
				"parent_id":     job.Document.ID,
				"chunk_index":   i,
				"document_type": job.Document.Type,
				"source":        job.Document.Source,
				"created_at":    time.Now(),
			},
		}

		// Add custom metadata
		for k, v := range job.Options.CustomMetadata {
			chunk.Metadata[k] = v
		}

		// Add document metadata
		for k, v := range job.Document.Metadata {
			chunk.Metadata[k] = v
		}

		chunks = append(chunks, chunk)
	}

	// 4. Generate embeddings
	if err := w.generateEmbeddings(ctx, chunks); err != nil {
		return nil, fmt.Errorf("failed to generate embeddings: %w", err)
	}

	// 5. Store in vector database
	documents := make([]vectordb.Document, len(chunks))
	for i, chunk := range chunks {
		documents[i] = vectordb.Document{
			ID:        chunk.ID,
			Content:   chunk.Content,
			Embedding: chunk.Embedding,
			Metadata:  chunk.Metadata,
			Timestamp: time.Now(),
		}
	}

	if err := w.pipeline.vectorDB.Store(ctx, documents); err != nil {
		return nil, fmt.Errorf("failed to store documents: %w", err)
	}

	return chunks, nil
}

// generateEmbeddings generates embeddings for document chunks
func (w *Worker) generateEmbeddings(ctx context.Context, chunks []DocumentChunk) error {
	texts := make([]string, len(chunks))
	for i, chunk := range chunks {
		texts[i] = chunk.Content
	}

	embeddings, err := w.pipeline.embedder.EmbedBatch(ctx, texts)
	if err != nil {
		return fmt.Errorf("failed to generate embeddings: %w", err)
	}

	for i, embedding := range embeddings {
		chunks[i].Embedding = embedding
	}

	return nil
}

// generateHash generates a hash for content deduplication
func (w *Worker) generateHash(content string) string {
	hash := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", hash)
}

// processResults processes ingestion results
func (ip *IngestionPipeline) processResults(ctx context.Context) {
	defer ip.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-ip.resultQueue:
			if !ok {
				return
			}
			ip.updateMetrics(result)
		}
	}
}

// updateMetrics updates pipeline metrics
func (ip *IngestionPipeline) updateMetrics(result *IngestionResult) {
	ip.metrics.mutex.Lock()
	defer ip.metrics.mutex.Unlock()

	ip.metrics.DocumentsProcessed++
	ip.metrics.TotalProcessingTime += result.ProcessingTime

	if result.Success {
		ip.metrics.ChunksCreated += int64(result.ChunksCreated)
	} else {
		ip.metrics.ErrorCount++
	}

	// Update average chunk size
	if ip.metrics.DocumentsProcessed > 0 {
		ip.metrics.AverageChunkSize = float64(ip.metrics.ChunksCreated) / float64(ip.metrics.DocumentsProcessed)
	}
}

// GetMetrics returns current pipeline metrics
func (ip *IngestionPipeline) GetMetrics() PipelineMetrics {
	ip.metrics.mutex.RLock()
	defer ip.metrics.mutex.RUnlock()
	return *ip.metrics
}

// DocumentChunker interface for text chunking strategies
type DocumentChunker interface {
	ChunkText(text string, chunkSize, overlap int) []string
}

// TextChunker implements basic text chunking
type TextChunker struct {
	defaultChunkSize int
	defaultOverlap   int
}

// NewTextChunker creates a new text chunker
func NewTextChunker(chunkSize, overlap int) *TextChunker {
	return &TextChunker{
		defaultChunkSize: chunkSize,
		defaultOverlap:   overlap,
	}
}

// ChunkText splits text into overlapping chunks
func (tc *TextChunker) ChunkText(text string, chunkSize, overlap int) []string {
	if chunkSize <= 0 {
		chunkSize = tc.defaultChunkSize
	}
	if overlap < 0 {
		overlap = tc.defaultOverlap
	}

	if len(text) <= chunkSize {
		return []string{text}
	}

	var chunks []string
	start := 0

	for start < len(text) {
		end := start + chunkSize
		if end > len(text) {
			end = len(text)
		}

		// Try to break at word boundaries
		if end < len(text) {
			for i := end - 1; i > start && i > end-100; i-- {
				if text[i] == ' ' || text[i] == '\n' || text[i] == '.' {
					end = i + 1
					break
				}
			}
		}

		chunk := strings.TrimSpace(text[start:end])
		if len(chunk) > 0 {
			chunks = append(chunks, chunk)
		}

		if end >= len(text) {
			break
		}

		start = end - overlap
		if start < 0 {
			start = 0
		}
	}

	return chunks
}

// DocumentProcessor handles document preprocessing
type DocumentProcessor struct {
	logger *logger.Logger
}

// NewDocumentProcessor creates a new document processor
func NewDocumentProcessor(logger *logger.Logger) *DocumentProcessor {
	return &DocumentProcessor{
		logger: logger,
	}
}

// CleanContent cleans and preprocesses document content
func (dp *DocumentProcessor) CleanContent(content string) string {
	// Remove excessive whitespace
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	// Normalize multiple newlines
	for strings.Contains(content, "\n\n\n") {
		content = strings.ReplaceAll(content, "\n\n\n", "\n\n")
	}

	// Normalize multiple spaces
	for strings.Contains(content, "  ") {
		content = strings.ReplaceAll(content, "  ", " ")
	}

	return strings.TrimSpace(content)
}
