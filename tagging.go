package flowhawk

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Business-flow tagging: which flow and step every span belongs to. A span inherits
// business.flow/business.step from its parent span (same process) or from baggage (another
// process). A span that inherits nothing and matches a step itself is an entry (business.entry="true"), and so is a
// server request or queue consumer that inherits a flow and matches a later step of it (handoffStep: the flow moved on
// to another service). Entries get the step metrics; an entry that continued a flow also records the time since the
// flow started (business.flow.elapsed), the flow's end-to-end time so far. Same rules as the Node and Python SDKs.

const (
	AttrFlow  = "business.flow"
	AttrStep  = "business.step"
	AttrEntry = "business.entry"
)

// sampler records every span, whatever the caller decided: with OpenTelemetry's default (parent-based) sampler a
// request whose caller sent `traceparent ...-00` records nothing, so a caller sampling 10% would hide 90% of this
// service's requests from the flow numbers. The tail sampler decides what is kept; step metrics count every request.
// Same in every SDK.
var sampler = sdktrace.AlwaysSample()

const endedMax = 10_000

// spanFlow is a span's flow and step, when the flow started (epoch ms, 0 if unknown) and whether this span continued
// it into a new step.
type spanFlow struct {
	FlowStep
	start   float64
	handoff bool
}

// flows remembers the flow of spans still open, and of recently ended ones: code keeps running in a
// span's context after the span ends, and logs and metrics written there still belong to the flow.
var flows = struct {
	sync.Mutex
	open  map[trace.SpanID]spanFlow
	ended map[trace.SpanID]spanFlow
	order []trace.SpanID // ring of ended span ids, oldest first
	next  int
}{open: map[trace.SpanID]spanFlow{}, ended: map[trace.SpanID]spanFlow{}}

func flowOfSpan(id trace.SpanID) (spanFlow, bool) {
	if !id.IsValid() {
		return spanFlow{}, false
	}
	flows.Lock()
	defer flows.Unlock()
	if fs, ok := flows.open[id]; ok {
		return fs, true
	}
	fs, ok := flows.ended[id]
	return fs, ok
}

// FlowOf is the business flow and step of the active span in ctx.
func FlowOf(ctx context.Context) (FlowStep, bool) {
	fs, ok := flowOfSpan(trace.SpanContextFromContext(ctx).SpanID())
	return fs.FlowStep, ok
}

func fromBaggage(ctx context.Context) (spanFlow, bool) {
	b := baggage.FromContext(ctx)
	flow, step := b.Member(AttrFlow).Value(), b.Member(AttrStep).Value()
	if flow == "" || step == "" {
		return spanFlow{}, false
	}
	return spanFlow{FlowStep: FlowStep{flow, step}, start: float64(parseFlowStart(b.Member(AttrFlowStart).Value(), time.Now().UnixMilli()))}, true
}

func attrString(attrs []attribute.KeyValue, keys ...string) string {
	for _, k := range keys {
		for _, a := range attrs {
			if string(a.Key) == k && a.Value.Type() == attribute.STRING && a.Value.AsString() != "" {
				return a.Value.AsString()
			}
		}
	}
	return ""
}

func hasAttr(attrs []attribute.KeyValue, key string) bool {
	for _, a := range attrs {
		if string(a.Key) == key && a.Value.Emit() != "" {
			return true
		}
	}
	return false
}

// spanFacts are the facts for MatchStep from a span's start-time attributes.
func spanFacts(name string, attrs []attribute.KeyValue, service string) SpanFacts {
	path := attrString(attrs, "url.path", "http.target")
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return SpanFacts{
		Service:    service,
		Method:     attrString(attrs, "http.request.method", "http.method"),
		Path:       path,
		SpanName:   name,
		Queue:      attrString(attrs, "messaging.destination.name", "messaging.destination"),
		Attributes: stringAttributes(attrs),
	}
}

// stringAttributes: start-time attributes as strings for Where matches (strings, numbers and booleans; slices left out).
func stringAttributes(attrs []attribute.KeyValue) map[string]string {
	out := make(map[string]string, len(attrs))
	for _, kv := range attrs {
		switch kv.Value.Type() {
		case attribute.STRING, attribute.BOOL, attribute.INT64, attribute.FLOAT64:
			out[string(kv.Key)] = kv.Value.Emit()
		}
	}
	return out
}

func kindName(k trace.SpanKind) string {
	switch k {
	case trace.SpanKindServer:
		return "server"
	case trace.SpanKindClient:
		return "client"
	case trace.SpanKindProducer:
		return "producer"
	case trace.SpanKindConsumer:
		return "consumer"
	}
	return "internal"
}

// entryKind: spans that may enter a step when they inherit no flow are a server request, a queue consumer, or a root
// internal span (a job, a CLI command, a pipeline run). Every SDK and the collector use the same rule.
func entryKind(kind trace.SpanKind, hasParent bool) bool {
	return entryMatch(kindName(kind), hasParent) == "all"
}

// ------------------------------------------------------------ code location of database calls

var (
	codeSkipMu sync.RWMutex
	codeSkip   []string
	goroot     = filepath.ToSlash(runtime.GOROOT())
)

const sdkPkg = "github.com/flowhawk-dev/flowhawk-go."

// SetCodeSkip sets the path fragments of the app's own query helpers, skipped when picking a query's code
// location (FLOWHAWK_CODE_SKIP).
func SetCodeSkip(paths []string) {
	out := []string{}
	for _, p := range paths {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	codeSkipMu.Lock()
	codeSkip = out
	codeSkipMu.Unlock()
}

type codeFrame struct {
	file string
	line int
}

// appFrames are up to max stack frames in the app's own code (not the standard library, dependencies or
// this SDK), innermost first, relative to the working directory.
func appFrames(skip, max int) []codeFrame {
	pcs := make([]uintptr, 64)
	n := runtime.Callers(skip+1, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	cwd, _ := os.Getwd()
	root := strings.TrimRight(filepath.ToSlash(cwd), "/") + "/"
	out := []codeFrame{}
	for len(out) < max {
		f, more := frames.Next()
		file := filepath.ToSlash(f.File)
		lib := file == "" ||
			(goroot != "" && strings.HasPrefix(file, goroot+"/")) ||
			strings.Contains(file, "/pkg/mod/") ||
			strings.Contains(file, "@v") ||
			strings.Contains(file, "/vendor/") ||
			strings.HasPrefix(f.Function, "go.opentelemetry.io/") ||
			(strings.HasPrefix(f.Function, sdkPkg) && !strings.HasSuffix(file, "_test.go")) ||
			!strings.Contains(file, "/") // -trimpath standard library files
		if !lib {
			out = append(out, codeFrame{strings.TrimPrefix(file, root), f.Line})
		}
		if !more {
			break
		}
	}
	return out
}

// pickFrame is the innermost frame outside the skipped helpers, or the innermost frame when all are skipped.
func pickFrame(frames []codeFrame) (codeFrame, bool) {
	if len(frames) == 0 {
		return codeFrame{}, false
	}
	codeSkipMu.RLock()
	skip := codeSkip
	codeSkipMu.RUnlock()
outer:
	for _, f := range frames {
		for _, p := range skip {
			if strings.Contains(f.file, p) {
				continue outer
			}
		}
		return f, true
	}
	return frames[0], true
}

// ------------------------------------------------------------ span processor

type stepInstruments struct {
	duration metric.Float64Histogram
	requests metric.Int64Counter
	elapsed  metric.Float64Histogram // nil in tests that don't record it
}

// FlowTagger tags spans with their business flow and step and records the step metrics of entry spans.
// Register it before the TailSampler so the tail decision sees business.flow.
type FlowTagger struct {
	service     string
	instruments func() *stepInstruments
}

var _ sdktrace.SpanProcessor = (*FlowTagger)(nil)

func newFlowTagger(service string, instruments func() *stepInstruments) *FlowTagger {
	return &FlowTagger{service: service, instruments: instruments}
}

func (t *FlowTagger) OnStart(parent context.Context, s sdktrace.ReadWriteSpan) {
	id := s.SpanContext().SpanID()
	attrs := s.Attributes()
	if s.SpanKind() == trace.SpanKindClient && (hasAttr(attrs, "db.system") || hasAttr(attrs, "db.system.name")) && !hasAttr(attrs, "code.file.path") {
		frames := appFrames(2, 3)
		if at, ok := pickFrame(frames); ok {
			lines := make([]string, len(frames))
			for i, f := range frames {
				lines[i] = f.file + ":" + strconv.Itoa(f.line)
			}
			s.SetAttributes(
				attribute.String("code.file.path", at.file),
				attribute.Int("code.line.number", at.line),
				attribute.String("code.stacktrace", strings.Join(lines, "\n")),
			)
		}
	}
	startMs := float64(s.StartTime().UnixNano()) / 1e6
	var inherited spanFlow
	has := false
	if p := s.Parent(); p.IsValid() && !p.IsRemote() {
		inherited, has = flowOfSpan(p.SpanID())
	}
	if !has {
		inherited, has = fromBaggage(parent)
	}
	if flow, step := attrString(attrs, AttrFlow), attrString(attrs, AttrStep); flow != "" && step != "" {
		// Set explicitly (WithStep): already an entry. It continues the flow it runs in when that is the same flow.
		fs := spanFlow{FlowStep: FlowStep{flow, step}, start: startMs}
		if has && inherited.Flow == flow && inherited.Step != step && inherited.start > 0 {
			fs.start, fs.handoff = inherited.start, true
		}
		flows.Lock()
		flows.open[id] = fs
		flows.Unlock()
		return
	}
	var fs spanFlow
	ok, entry := false, false
	// Matching needs the business map; until a config arrives nothing is matched.
	c := current()
	if has {
		fs, ok = spanFlow{FlowStep: inherited.FlowStep, start: inherited.start}, true
		if c != nil {
			if next, moved := handoffStep(c.Map, inherited.FlowStep, kindName(s.SpanKind()), spanFacts(s.Name(), attrs, t.service)); moved {
				fs, entry = spanFlow{FlowStep: next, start: inherited.start, handoff: inherited.start > 0}, true
			}
		}
	} else if c != nil {
		if may := entryMatch(kindName(s.SpanKind()), s.Parent().IsValid()); may != "none" {
			if m, matched := matchStep(c.Map, spanFacts(s.Name(), attrs, t.service), may == "inner"); matched {
				fs, ok, entry = spanFlow{FlowStep: m, start: startMs}, true, true
			}
		}
	}
	if !ok {
		return
	}
	s.SetAttributes(attribute.String(AttrFlow, fs.Flow), attribute.String(AttrStep, fs.Step))
	if entry {
		s.SetAttributes(attribute.String(AttrEntry, "true"))
	}
	flows.Lock()
	flows.open[id] = fs
	flows.Unlock()
}

// failedByRule holds entry spans that ended without an error status but that their step's failWhen rules count as failed
// (a 402, an outcome the app set). The tail decision keeps them as errors and they are exported with an error status,
// so traces agree with the step metrics. Bounded like the ended spans.
var failedByRule = struct {
	sync.Mutex
	set   map[trace.SpanID]bool
	order []trace.SpanID
}{set: map[trace.SpanID]bool{}}

func markFailedByRule(id trace.SpanID) {
	failedByRule.Lock()
	defer failedByRule.Unlock()
	failedByRule.set[id] = true
	failedByRule.order = append(failedByRule.order, id)
	if len(failedByRule.order) > endedMax {
		delete(failedByRule.set, failedByRule.order[0])
		failedByRule.order = failedByRule.order[1:]
	}
}

// spanFailed: marked as an error, or failed by its step's rules (failedByRule).
func spanFailed(s sdktrace.ReadOnlySpan) bool {
	if s.Status().Code == codes.Error {
		return true
	}
	failedByRule.Lock()
	defer failedByRule.Unlock()
	return failedByRule.set[s.SpanContext().SpanID()]
}

func (t *FlowTagger) OnEnd(s sdktrace.ReadOnlySpan) {
	id := s.SpanContext().SpanID()
	flows.Lock()
	fs, ok := flows.open[id]
	if ok {
		delete(flows.open, id)
		if len(flows.order) < endedMax {
			flows.order = append(flows.order, id)
		} else {
			delete(flows.ended, flows.order[flows.next])
			flows.order[flows.next] = id
			flows.next = (flows.next + 1) % endedMax
		}
		flows.ended[id] = fs
	}
	flows.Unlock()

	attrs := s.Attributes()
	if attrString(attrs, AttrEntry) != "true" {
		return
	}
	flow, step := attrString(attrs, AttrFlow), attrString(attrs, AttrStep)
	isError := s.Status().Code == codes.Error
	failed := isError
	if cfg := current(); cfg != nil {
		failed = stepFailed(cfg.Map, FlowStep{Flow: flow, Step: step}, stringAttributes(attrs), isError)
	}
	if failed && !isError {
		markFailedByRule(id)
	}
	if p := current().PolicyFor(flow); p != nil && !p.Metrics.Enabled {
		return
	}
	ins := t.instruments()
	if ins == nil {
		return
	}
	status := "ok"
	if failed {
		status = "error"
	}
	set := metric.WithAttributes(attribute.String(AttrFlow, flow), attribute.String(AttrStep, step), attribute.String("status", status))
	ctx := context.Background()
	ins.duration.Record(ctx, float64(s.EndTime().Sub(s.StartTime()).Nanoseconds())/1e6, set)
	ins.requests.Add(ctx, 1, set)
	if fs.handoff && fs.start > 0 && ins.elapsed != nil {
		ins.elapsed.Record(ctx, flowElapsedMs(fs.start, float64(s.EndTime().UnixNano())/1e6), set)
	}
}

func (t *FlowTagger) Shutdown(context.Context) error {
	flows.Lock()
	flows.open = map[trace.SpanID]spanFlow{}
	flows.ended = map[trace.SpanID]spanFlow{}
	flows.order, flows.next = nil, 0
	flows.Unlock()
	return nil
}

func (t *FlowTagger) ForceFlush(context.Context) error { return nil }

// ------------------------------------------------------------ propagation

// BusinessBaggage is a W3C baggage propagator that also writes business.flow/business.step for the current
// span, so the next service inherits the flow. Use it instead of (not next to) propagation.Baggage.
type BusinessBaggage struct{ inner propagation.Baggage }

var _ propagation.TextMapPropagator = BusinessBaggage{}

func (p BusinessBaggage) Inject(ctx context.Context, carrier propagation.TextMapCarrier) {
	if fs, ok := flowOfSpan(trace.SpanContextFromContext(ctx).SpanID()); ok {
		b := baggage.FromContext(ctx)
		if m, err := baggage.NewMemberRaw(AttrFlow, fs.Flow); err == nil {
			b, _ = b.SetMember(m)
		}
		if m, err := baggage.NewMemberRaw(AttrStep, fs.Step); err == nil {
			b, _ = b.SetMember(m)
		}
		b = b.DeleteMember(AttrFlowStart)
		if fs.start > 0 {
			if m, err := baggage.NewMemberRaw(AttrFlowStart, strconv.FormatInt(int64(fs.start+0.5), 10)); err == nil {
				b, _ = b.SetMember(m)
			}
		}
		ctx = baggage.ContextWithBaggage(ctx, b)
	}
	p.inner.Inject(ctx, carrier)
}

func (p BusinessBaggage) Extract(ctx context.Context, carrier propagation.TextMapCarrier) context.Context {
	return p.inner.Extract(ctx, carrier)
}

func (p BusinessBaggage) Fields() []string { return p.inner.Fields() }
