package flowhawk

// Continues traces started by Sentry's SDKs (the mobile SDKs, or a web app on @sentry/browser), which send
// "sentry-trace: <trace id>-<span id>[-<sampled>]" instead of W3C traceparent. The trace ids are the same 32-hex
// ids the server stores for Sentry events, so the phone's transaction and this service's spans join.

import (
	"context"
	"regexp"
	"strings"

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

var sentryTraceRe = regexp.MustCompile(`^([0-9a-f]{32})-([0-9a-f]{16})(?:-([01]))?$`)

// ParseSentryTrace returns the trace and span id of a sentry-trace header, ok false when it isn't one
// (pinned by packages/schema/sentry-trace-vectors.json in every SDK).
func ParseSentryTrace(header string) (trace.TraceID, trace.SpanID, bool) {
	m := sentryTraceRe.FindStringSubmatch(strings.ToLower(strings.TrimSpace(header)))
	if m == nil {
		return trace.TraceID{}, trace.SpanID{}, false
	}
	tid, err1 := trace.TraceIDFromHex(m[1])
	sid, err2 := trace.SpanIDFromHex(m[2])
	if err1 != nil || err2 != nil {
		return trace.TraceID{}, trace.SpanID{}, false
	}
	return tid, sid, true
}

// SentryTrace extracts sentry-trace as the remote parent. List it before propagation.TraceContext so a
// traceparent sent too wins. The parent always counts as sampled: Flowhawk's sampling decides what is kept, not
// the app's tracesSampleRate. It injects nothing (outgoing calls carry traceparent).
type SentryTrace struct{}

var _ propagation.TextMapPropagator = SentryTrace{}

func (SentryTrace) Inject(context.Context, propagation.TextMapCarrier) {}

func (SentryTrace) Extract(ctx context.Context, carrier propagation.TextMapCarrier) context.Context {
	tid, sid, ok := ParseSentryTrace(carrier.Get("sentry-trace"))
	if !ok {
		return ctx
	}
	sc := trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled, Remote: true})
	return trace.ContextWithRemoteSpanContext(ctx, sc)
}

func (SentryTrace) Fields() []string { return nil }
