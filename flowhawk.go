// Package flowhawk is the OpenTelemetry Go SDK plus business-flow tagging and remote-controlled
// collection; the Go twin of @flowhawk/sdk-node and flowhawk-sdk (Python). Usage, first thing in main:
//
//	shutdown, err := flowhawk.Init(flowhawk.Options{Service: "orders"})
//	if err != nil { log.Fatal(err) }
//	defer shutdown(context.Background())
//	http.ListenAndServe(":8080", flowhawk.Middleware(mux))
package flowhawk

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Options configure Init. Every field has an environment default.
type Options struct {
	Service     string
	Version     string // default FLOWHAWK_SERVICE_VERSION or 0.0.0
	Environment string // default FLOWHAWK_ENVIRONMENT or development
	// Endpoint is the OTLP HTTP base URL; default OTEL_EXPORTER_OTLP_ENDPOINT or http://localhost:4318.
	Endpoint string
	// ControlURL is the control plane base URL; default FLOWHAWK_CONTROL_URL or http://localhost:4000.
	ControlURL string
	// APIKey is the workspace ingest key, sent as the bearer token on OTLP exports and /v1/opamp; default
	// FLOWHAWK_API_KEY. Not needed in local dev mode.
	APIKey string
	// CodeSkip are path fragments of your own query helpers, skipped when recording where a query is called;
	// default FLOWHAWK_CODE_SKIP (comma separated).
	CodeSkip []string
	// NoSQLComments turns off the SQL comment tags TagSQL adds (also FLOWHAWK_SQL_COMMENTS=off).
	NoSQLComments bool
}

// StepBuckets are fine buckets so the platform's p95 from business.step.duration is close to the true one
// (same as the Node and Python SDKs).
var StepBuckets = []float64{2, 5, 10, 15, 25, 40, 60, 80, 100, 150, 200, 300, 400, 500, 750, 1000, 1500, 2000, 3000, 4000, 5000, 7500, 10000, 20000, 30000, 60000, 120000, 300000, 600000, 1800000, 3600000, 7200000, 14400000, 43200000, 86400000}

var (
	mu          sync.Mutex
	started     bool
	instruments *stepInstruments
	parts       struct {
		tp      *sdktrace.TracerProvider
		mp      *sdkmetric.MeterProvider
		lp      *sdklog.LoggerProvider
		control *controlClient
		runtime metric.Registration
	}
)

func env(v, key, def string) string {
	if v != "" {
		return v
	}
	if e := os.Getenv(key); e != "" {
		return e
	}
	return def
}

// deltaTemporality: each export carries only its interval, so the platform's rollups can sum rows
// (what OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE=delta selects).
func deltaTemporality(k sdkmetric.InstrumentKind) metricdata.Temporality {
	switch k {
	case sdkmetric.InstrumentKindCounter, sdkmetric.InstrumentKindHistogram, sdkmetric.InstrumentKindObservableCounter:
		return metricdata.DeltaTemporality
	}
	return metricdata.CumulativeTemporality
}

func makeInstruments(m metric.Meter) (*stepInstruments, error) {
	d, err := m.Float64Histogram("business.step.duration", metric.WithUnit("ms"),
		metric.WithDescription("Duration of business step entries"), metric.WithExplicitBucketBoundaries(StepBuckets...))
	if err != nil {
		return nil, err
	}
	r, err := m.Int64Counter("business.step.requests", metric.WithDescription("Business step entries"))
	if err != nil {
		return nil, err
	}
	// A step entry that continued a flow from another service or a queue: the time since the flow's first step started.
	e, err := m.Float64Histogram("business.flow.elapsed", metric.WithUnit("ms"),
		metric.WithDescription("Time from a flow's start to the end of a later step"), metric.WithExplicitBucketBoundaries(StepBuckets...))
	if err != nil {
		return nil, err
	}
	return &stepInstruments{duration: d, requests: r, elapsed: e}, nil
}

func currentInstruments() *stepInstruments {
	mu.Lock()
	defer mu.Unlock()
	return instruments
}

// Init starts tracing, metrics, logs and remote control, and sets the global OpenTelemetry providers and
// propagator. Call it once, first thing in main; later calls do nothing. The returned function flushes and
// stops everything (Shutdown).
func Init(o Options) (func(context.Context) error, error) {
	mu.Lock()
	if started {
		mu.Unlock()
		return Shutdown, nil
	}
	started = true
	mu.Unlock()
	if o.Service == "" {
		o.Service = env("", "OTEL_SERVICE_NAME", "unknown_service")
	}
	if o.CodeSkip != nil {
		SetCodeSkip(o.CodeSkip)
	} else {
		SetCodeSkip(strings.Split(os.Getenv("FLOWHAWK_CODE_SKIP"), ","))
	}
	SetSQLComments(!o.NoSQLComments && os.Getenv("FLOWHAWK_SQL_COMMENTS") != "off", o.Service)
	version := env(o.Version, "FLOWHAWK_SERVICE_VERSION", "0.0.0")
	environment := env(o.Environment, "FLOWHAWK_ENVIRONMENT", "development")
	endpoint := strings.TrimRight(env(o.Endpoint, "OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318"), "/")
	apiKey := env(o.APIKey, "FLOWHAWK_API_KEY", "")
	headers := map[string]string{}
	if apiKey != "" {
		headers["Authorization"] = "Bearer " + apiKey
	}

	// host.name as the other SDKs set it; OTEL_RESOURCE_ATTRIBUTES still wins.
	res, err := resource.New(context.Background(),
		resource.WithHost(),
		resource.WithTelemetrySDK(),
		resource.WithAttributes(
			attribute.String("service.name", o.Service),
			attribute.String("service.version", version),
			attribute.String("deployment.environment", environment),
		),
		resource.WithFromEnv(),
	)
	if err != nil && res == nil {
		return nil, err
	}

	ctx := context.Background()
	spanExp, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(endpoint+"/v1/traces"), otlptracehttp.WithHeaders(headers))
	if err != nil {
		return nil, err
	}
	metricExp, err := otlpmetrichttp.New(ctx, otlpmetrichttp.WithEndpointURL(endpoint+"/v1/metrics"), otlpmetrichttp.WithHeaders(headers),
		otlpmetrichttp.WithTemporalitySelector(deltaTemporality))
	if err != nil {
		return nil, err
	}
	logExp, err := otlploghttp.New(ctx, otlploghttp.WithEndpointURL(endpoint+"/v1/logs"), otlploghttp.WithHeaders(headers))
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		// Record every request, even when the caller didn't sample it; the tail sampler decides what is kept.
		sdktrace.WithSampler(sampler),
		// Tagging runs first so the tail decision sees business.flow.
		sdktrace.WithSpanProcessor(newFlowTagger(o.Service, currentInstruments)),
		sdktrace.WithSpanProcessor(newTailSampler(sdktrace.NewBatchSpanProcessor(spanExp), nil, true)),
	)
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp, sdkmetric.WithInterval(15*time.Second))))
	lp := sdklog.NewLoggerProvider(sdklog.WithResource(res), sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp)))
	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	global.SetLoggerProvider(lp)
	// Sentry first, so a traceparent sent too wins (mobile apps send sentry-trace).
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(SentryTrace{}, propagation.TraceContext{}, BusinessBaggage{}))

	ins, err := makeInstruments(mp.Meter("flowhawk-sdk"))
	if err != nil {
		return nil, err
	}
	reg, err := startRuntimeMetrics(o.Service)
	if err != nil {
		return nil, err
	}
	control := newControlClient(env(o.ControlURL, "FLOWHAWK_CONTROL_URL", "http://localhost:4000"), o.Service, version, apiKey)
	control.start()

	mu.Lock()
	instruments = ins
	parts.tp, parts.mp, parts.lp, parts.control, parts.runtime = tp, mp, lp, control, reg
	mu.Unlock()
	return Shutdown, nil
}

// Shutdown flushes and stops telemetry. Safe to call more than once.
func Shutdown(ctx context.Context) error {
	mu.Lock()
	p := parts
	parts.tp, parts.mp, parts.lp, parts.control, parts.runtime = nil, nil, nil, nil, nil
	instruments = nil
	mu.Unlock()
	if p.tp == nil {
		return nil
	}
	p.control.stop()
	_ = p.runtime.Unregister()
	return errors.Join(p.tp.Shutdown(ctx), p.mp.Shutdown(ctx), p.lp.Shutdown(ctx))
}

// WithStep runs a background job (queue consumer, cron) as a business step entry: a new root span with
// business.* set. An error returned by fn marks the span as an error and is returned.
func WithStep(ctx context.Context, flow, step string, fn func(ctx context.Context) error) error {
	ctx, span := otel.Tracer("flowhawk-sdk").Start(ctx, step, trace.WithNewRoot(),
		trace.WithAttributes(attribute.String(AttrFlow, flow), attribute.String(AttrStep, step), attribute.String(AttrEntry, "true")))
	defer span.End()
	err := fn(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	return err
}

// Middleware traces incoming HTTP requests (otelhttp), so they can be matched to business steps.
func Middleware(h http.Handler) http.Handler {
	return otelhttp.NewHandler(h, "http.server", otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
		return r.Method
	}))
}

// Transport traces outgoing HTTP requests and carries the flow to the next service; nil wraps
// http.DefaultTransport.
func Transport(rt http.RoundTripper) http.RoundTripper {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return otelhttp.NewTransport(rt)
}
