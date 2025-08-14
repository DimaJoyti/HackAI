package observability

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// TracingProvider manages OpenTelemetry tracing
type TracingProvider struct {
	provider *trace.TracerProvider
	tracer   oteltrace.Tracer
	config   *config.TracingConfig
	logger   *logger.Logger
	shutdown func(context.Context) error
}

// NewTracingProvider creates a new tracing provider
func NewTracingProvider(cfg *config.TracingConfig, serviceName, serviceVersion string, log *logger.Logger) (*TracingProvider, error) {
	if !cfg.Enabled {
		log.Info("Tracing is disabled")
		return &TracingProvider{
			config:   cfg,
			logger:   log,
			shutdown: func(context.Context) error { return nil },
		}, nil
	}

	// Create resource with service information
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(serviceVersion),
			semconv.ServiceInstanceID(fmt.Sprintf("%s-%d", serviceName, time.Now().Unix())),
			attribute.String("environment", "production"),
			attribute.String("deployment.environment", "production"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create exporter based on endpoint
	var exporter trace.SpanExporter
	if cfg.Endpoint != "" {
		// Use OTLP HTTP exporter
		exporter, err = otlptracehttp.New(context.Background(),
			otlptracehttp.WithEndpoint(cfg.Endpoint),
			otlptracehttp.WithInsecure(), // Use HTTPS in production
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create trace exporter: %w", err)
		}
	} else {
		// Use stdout exporter for development
		exporter, err = newStdoutExporter()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout exporter: %w", err)
		}
	}

	// Create tracer provider
	tp := trace.NewTracerProvider(
		trace.WithBatcher(exporter,
			trace.WithBatchTimeout(5*time.Second),
			trace.WithMaxExportBatchSize(512),
		),
		trace.WithResource(res),
		trace.WithSampler(trace.TraceIDRatioBased(cfg.SampleRate)),
	)

	// Set global tracer provider
	otel.SetTracerProvider(tp)

	// Set global propagator
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tracer := tp.Tracer(serviceName)

	log.Info("Tracing initialized",
		"service", serviceName,
		"endpoint", cfg.Endpoint,
		"sample_rate", cfg.SampleRate,
	)

	return &TracingProvider{
		provider: tp,
		tracer:   tracer,
		config:   cfg,
		logger:   log,
		shutdown: tp.Shutdown,
	}, nil
}

// Tracer returns the OpenTelemetry tracer
func (tp *TracingProvider) Tracer() oteltrace.Tracer {
	if tp.tracer == nil {
		return otel.Tracer("noop")
	}
	return tp.tracer
}

// StartSpan starts a new span with the given name and options
func (tp *TracingProvider) StartSpan(ctx context.Context, name string, opts ...oteltrace.SpanStartOption) (context.Context, oteltrace.Span) {
	if tp.tracer == nil {
		return ctx, oteltrace.SpanFromContext(ctx)
	}
	return tp.tracer.Start(ctx, name, opts...)
}

// StartHTTPSpan starts a span for HTTP requests
func (tp *TracingProvider) StartHTTPSpan(ctx context.Context, method, path string, attrs ...attribute.KeyValue) (context.Context, oteltrace.Span) {
	spanName := fmt.Sprintf("%s %s", method, path)

	defaultAttrs := []attribute.KeyValue{
		semconv.HTTPMethod(method),
		semconv.HTTPRoute(path),
		semconv.HTTPScheme("http"),
	}

	allAttrs := append(defaultAttrs, attrs...)

	return tp.StartSpan(ctx, spanName,
		oteltrace.WithSpanKind(oteltrace.SpanKindServer),
		oteltrace.WithAttributes(allAttrs...),
	)
}

// StartDatabaseSpan starts a span for database operations
func (tp *TracingProvider) StartDatabaseSpan(ctx context.Context, operation, table string, attrs ...attribute.KeyValue) (context.Context, oteltrace.Span) {
	spanName := fmt.Sprintf("db.%s %s", operation, table)

	defaultAttrs := []attribute.KeyValue{
		attribute.String("db.operation", operation),
		attribute.String("db.sql.table", table),
		attribute.String("db.system", "postgresql"),
	}

	allAttrs := append(defaultAttrs, attrs...)

	return tp.StartSpan(ctx, spanName,
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(allAttrs...),
	)
}

// StartExternalSpan starts a span for external service calls
func (tp *TracingProvider) StartExternalSpan(ctx context.Context, service, operation string, attrs ...attribute.KeyValue) (context.Context, oteltrace.Span) {
	spanName := fmt.Sprintf("%s.%s", service, operation)

	defaultAttrs := []attribute.KeyValue{
		attribute.String("service.name", service),
		attribute.String("operation", operation),
	}

	allAttrs := append(defaultAttrs, attrs...)

	return tp.StartSpan(ctx, spanName,
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(allAttrs...),
	)
}

// AddSpanEvent adds an event to the current span
func (tp *TracingProvider) AddSpanEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	span := oteltrace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.AddEvent(name, oteltrace.WithAttributes(attrs...))
	}
}

// SetSpanAttributes sets attributes on the current span
func (tp *TracingProvider) SetSpanAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	span := oteltrace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.SetAttributes(attrs...)
	}
}

// SetSpanStatus sets the status of the current span
func (tp *TracingProvider) SetSpanStatus(ctx context.Context, description string) {
	span := oteltrace.SpanFromContext(ctx)
	if span.IsRecording() {
		// Simplified status setting without status codes
		span.SetAttributes(attribute.String("status", description))
	}
}

// RecordError records an error on the current span
func (tp *TracingProvider) RecordError(ctx context.Context, err error, attrs ...attribute.KeyValue) {
	span := oteltrace.SpanFromContext(ctx)
	if span.IsRecording() && err != nil {
		span.RecordError(err, oteltrace.WithAttributes(attrs...))
		span.SetAttributes(attribute.String("error", err.Error()))
	}
}

// InstrumentFunction wraps a function with tracing
func (tp *TracingProvider) InstrumentFunction(ctx context.Context, name string, fn func(context.Context) error, attrs ...attribute.KeyValue) error {
	ctx, span := tp.StartSpan(ctx, name, oteltrace.WithAttributes(attrs...))
	defer span.End()

	err := fn(ctx)
	if err != nil {
		tp.RecordError(ctx, err)
	}

	return err
}

// InstrumentFunctionWithStringResult wraps a function with tracing and returns a string result
func (tp *TracingProvider) InstrumentFunctionWithStringResult(ctx context.Context, name string, fn func(context.Context) (string, error), attrs ...attribute.KeyValue) (string, error) {
	ctx, span := tp.StartSpan(ctx, name, oteltrace.WithAttributes(attrs...))
	defer span.End()

	result, err := fn(ctx)
	if err != nil {
		tp.RecordError(ctx, err)
	}

	return result, err
}

// Shutdown gracefully shuts down the tracing provider
func (tp *TracingProvider) Shutdown(ctx context.Context) error {
	if tp.shutdown != nil {
		tp.logger.Info("Shutting down tracing provider")
		return tp.shutdown(ctx)
	}
	return nil
}

// Helper functions

// newStdoutExporter creates a stdout exporter for development
func newStdoutExporter() (trace.SpanExporter, error) {
	// For development, we can use a simple stdout exporter
	// In production, this should be replaced with proper exporters
	return &noopExporter{}, nil
}

// noopExporter is a no-op exporter for when tracing is disabled
type noopExporter struct{}

func (e *noopExporter) ExportSpans(ctx context.Context, spans []trace.ReadOnlySpan) error {
	return nil
}

func (e *noopExporter) Shutdown(ctx context.Context) error {
	return nil
}

// TraceMiddleware creates HTTP middleware for tracing
func (tp *TracingProvider) TraceMiddleware(serviceName string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Extract trace context from headers
			ctx = otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(r.Header))

			// Start span
			ctx, span := tp.StartHTTPSpan(ctx, r.Method, r.URL.Path,
				attribute.String("http.user_agent", r.UserAgent()),
				attribute.String("http.client_ip", getClientIP(r)),
				attribute.Int("http.request.content_length", int(r.ContentLength)),
			)
			defer span.End()

			// Create response writer wrapper to capture status code
			wrapper := &responseWriter{ResponseWriter: w, statusCode: 200}

			// Process request
			next.ServeHTTP(wrapper, r.WithContext(ctx))

			// Set span attributes based on response
			span.SetAttributes(
				attribute.Int("http.status_code", wrapper.statusCode),
				attribute.Int("http.response.content_length", wrapper.bytesWritten),
			)

			// Set span status based on HTTP status code
			if wrapper.statusCode >= 400 {
				span.SetAttributes(attribute.String("http.error", fmt.Sprintf("HTTP %d", wrapper.statusCode)))
			}
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture response details
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}
