package flowhawk

import (
	"context"
	"log/slog"
	"os"
	"slices"

	"go.opentelemetry.io/contrib/bridges/otelslog"
)

// Logs: a log/slog handler that sends records to OpenTelemetry, correlated with the active span and its
// business flow and filtered by the flow's collection policy (level, drop and redact).
//
//	log := flowhawk.Logger()                                   // OTel only (and stderr with FLOWHAWK_LOG_CONSOLE=1)
//	slog.SetDefault(slog.New(flowhawk.Handler(slog.Default().Handler()))) // keep your handler, add OTel

var levelRank = map[string]slog.Level{"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError}

func logAllowed(level slog.Level, p *Policy) bool {
	// No config yet: everything goes out (still with the default redaction).
	return p == nil || (p.Logs.Enabled && level >= levelRank[p.Logs.Level])
}

func policyOf(ctx context.Context) (*Policy, *FlowStep) {
	fs := flowPtr(ctx)
	flow := ""
	if fs != nil {
		flow = fs.Flow
	}
	return current().PolicyFor(flow), fs
}

// policyHandler filters and tags records for the flow, then hands them to the OTel bridge.
type policyHandler struct{ next slog.Handler }

func (h policyHandler) Enabled(ctx context.Context, level slog.Level) bool {
	p, _ := policyOf(ctx)
	return logAllowed(level, p) && h.next.Enabled(ctx, level)
}

func (h policyHandler) Handle(ctx context.Context, r slog.Record) error {
	p, fs := policyOf(ctx)
	if !logAllowed(r.Level, p) {
		return nil
	}
	drop, redact := attributeRules(p) // the default redaction when there is no policy
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		if slices.Contains(drop, a.Key) {
			return true
		}
		if slices.Contains(redact, a.Key) {
			a = slog.String(a.Key, "[redacted]")
		}
		out.AddAttrs(a)
		return true
	})
	if fs != nil {
		out.AddAttrs(slog.String(AttrFlow, fs.Flow), slog.String(AttrStep, fs.Step))
	}
	return h.next.Handle(ctx, out)
}

func (h policyHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return policyHandler{h.next.WithAttrs(as)}
}

func (h policyHandler) WithGroup(name string) slog.Handler {
	return policyHandler{h.next.WithGroup(name)}
}

// tee sends each record to every handler that wants it.
type tee []slog.Handler

func (t tee) Enabled(ctx context.Context, l slog.Level) bool {
	return slices.ContainsFunc(t, func(h slog.Handler) bool { return h.Enabled(ctx, l) })
}

func (t tee) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range t {
		if h.Enabled(ctx, r.Level) {
			_ = h.Handle(ctx, r.Clone())
		}
	}
	return nil
}

func (t tee) WithAttrs(as []slog.Attr) slog.Handler {
	out := make(tee, len(t))
	for i, h := range t {
		out[i] = h.WithAttrs(as)
	}
	return out
}

func (t tee) WithGroup(name string) slog.Handler {
	out := make(tee, len(t))
	for i, h := range t {
		out[i] = h.WithGroup(name)
	}
	return out
}

func otelHandler() slog.Handler {
	return policyHandler{otelslog.NewHandler("flowhawk-sdk")}
}

// Handler returns a handler that passes every record to next unchanged and also sends it to Flowhawk,
// filtered by the flow's policy. next may be nil.
func Handler(next slog.Handler) slog.Handler {
	if next == nil {
		return otelHandler()
	}
	return tee{next, otelHandler()}
}

// Logger is a slog.Logger that sends to Flowhawk (and to stderr when FLOWHAWK_LOG_CONSOLE=1).
// Pass the request's context (log.InfoContext(ctx, ...)) so records carry the trace and the flow.
func Logger() *slog.Logger {
	var console slog.Handler
	if os.Getenv("FLOWHAWK_LOG_CONSOLE") == "1" {
		console = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	}
	return slog.New(Handler(console))
}
