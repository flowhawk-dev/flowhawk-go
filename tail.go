package flowhawk

import (
	"context"
	"math"
	"slices"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Per-process tail decision. Spans are buffered per trace until the trace's local root (no parent,
// or a remote parent) ends; then the whole trace is kept or dropped by the flow's collection policy
// and forwarded to the export processor. Same rules as the Node and Python SDKs.

// TraceHash is the deterministic position of a trace id in [0, 1): every service decides the same for a trace.
func TraceHash(id trace.TraceID) float64 {
	h := id.String()
	// The low 52 bits of the (random) trace id; exact in a float64.
	n, _ := strconv.ParseUint(h[len(h)-13:], 16, 64)
	return float64(n) / (1 << 52)
}

// jsRound is Math.round: halves round up.
func jsRound(x float64) int { return int(math.Floor(x + 0.5)) }

// Decision is the keep/drop decision for a trace (or one span of it).
type Decision struct {
	Keep       bool
	Reason     string // "error" | "slow" | "sampled" | "ai"
	SampleRate int
}

var drop = Decision{}

func durationMs(s sdktrace.ReadOnlySpan) float64 {
	return float64(s.EndTime().Sub(s.StartTime()).Nanoseconds()) / 1e6
}

// Decide is the keep/drop decision for one trace. A nil policy means no config yet: keep everything.
func Decide(id trace.TraceID, spans []sdktrace.ReadOnlySpan, root sdktrace.ReadOnlySpan, p *Policy, rate float64) Decision {
	if p == nil {
		return Decision{true, "sampled", 1}
	}
	errored := slices.ContainsFunc(spans, spanFailed)
	if !p.Traces.Enabled {
		if errored {
			return Decision{true, "error", 1}
		}
		return drop
	}
	if errored && p.Traces.KeepErrors {
		return Decision{true, "error", 1}
	}
	if root != nil && p.Traces.KeepSlowerThanMs != nil && durationMs(root) > *p.Traces.KeepSlowerThanMs {
		return Decision{true, "slow", 1}
	}
	if rate > 0 && TraceHash(id) < rate {
		return Decision{true, "sampled", max(1, jsRound(1/rate))}
	}
	return drop
}

// isAISpan: model calls (gen_ai spans) are small and carry the AI cost, so each one is kept, at weight 1,
// whatever the trace's decision.
func isAISpan(s sdktrace.ReadOnlySpan) bool {
	a := s.Attributes()
	return attrString(a, "gen_ai.system", "gen_ai.provider.name") != ""
}

func spanDecision(s sdktrace.ReadOnlySpan, d Decision) Decision {
	if !isAISpan(s) {
		return d
	}
	if d.Keep {
		return Decision{true, d.Reason, 1}
	}
	return Decision{true, "ai", 1}
}

// finalSpan is an ended span with the policy's drop/redact (the default redaction without one) and the decision's tags applied.
type finalSpan struct {
	sdktrace.ReadOnlySpan
	attrs []attribute.KeyValue
}

func (s finalSpan) Attributes() []attribute.KeyValue { return s.attrs }

// Status: a run its step's rules failed (failWhen) is exported as an error, so traces agree with the step metrics.
func (s finalSpan) Status() sdktrace.Status {
	st := s.ReadOnlySpan.Status()
	if st.Code != codes.Error && spanFailed(s.ReadOnlySpan) {
		return sdktrace.Status{Code: codes.Error, Description: "failed by the step's failWhen rule"}
	}
	return st
}

func finalize(s sdktrace.ReadOnlySpan, p *Policy, d Decision) sdktrace.ReadOnlySpan {
	reason := d.Reason
	if reason == "" {
		reason = "sampled"
	}
	drop, redact := attributeRules(p) // the default redaction when there is no policy
	out := make([]attribute.KeyValue, 0, len(s.Attributes())+2)
	for _, a := range s.Attributes() {
		k := string(a.Key)
		if k == "SampleRate" || k == "flowhawk.keep_reason" {
			continue
		}
		if slices.Contains(drop, k) {
			continue
		}
		if slices.Contains(redact, k) {
			a = attribute.String(k, "[redacted]")
		}
		out = append(out, a)
	}
	out = append(out, attribute.String("SampleRate", strconv.Itoa(d.SampleRate)), attribute.String("flowhawk.keep_reason", reason))
	return finalSpan{s, out}
}

func isLocalRoot(s sdktrace.ReadOnlySpan) bool {
	p := s.Parent()
	return !p.IsValid() || p.IsRemote()
}

type pending struct {
	firstAt time.Time
	spans   []sdktrace.ReadOnlySpan
}

type decided struct {
	d    Decision
	flow string
	at   time.Time
}

type settled struct {
	spans []sdktrace.ReadOnlySpan
	d     Decision
	flow  string
}

// TailSampler buffers spans per trace and forwards the kept ones, finalized, to the next processor.
type TailSampler struct {
	next      sdktrace.SpanProcessor
	maxTraces int
	maxSpans  int
	maxAge    time.Duration
	config    func() *RemoteConfig
	mu        sync.Mutex
	pending   map[trace.TraceID]*pending
	order     []trace.TraceID // insertion order of pending
	decided   map[trace.TraceID]decided
	stop      chan struct{}
	stopOnce  sync.Once
}

var _ sdktrace.SpanProcessor = (*TailSampler)(nil)

// NewTailSampler wraps the export processor. config defaults to the applied remote config; sweep starts the
// background sweep that settles traces whose root never ends locally.
func newTailSampler(next sdktrace.SpanProcessor, config func() *RemoteConfig, sweep bool) *TailSampler {
	if config == nil {
		config = current
	}
	t := &TailSampler{
		next: next, maxTraces: 5000, maxSpans: 500, maxAge: 30 * time.Second, config: config,
		pending: map[trace.TraceID]*pending{}, decided: map[trace.TraceID]decided{}, stop: make(chan struct{}),
	}
	if sweep {
		go t.sweeper()
	}
	return t
}

func (t *TailSampler) OnStart(ctx context.Context, s sdktrace.ReadWriteSpan) { t.next.OnStart(ctx, s) }

func (t *TailSampler) OnEnd(s sdktrace.ReadOnlySpan) {
	var out []settled
	t.mu.Lock()
	tid := s.SpanContext().TraceID()
	if late, ok := t.decided[tid]; ok {
		out = append(out, settled{[]sdktrace.ReadOnlySpan{s}, late.d, late.flow})
	} else {
		p, ok := t.pending[tid]
		if !ok {
			if len(t.pending) >= t.maxTraces && len(t.order) > 0 {
				out = append(out, t.settle(t.order[0], nil))
			}
			p = &pending{firstAt: time.Now()}
			t.pending[tid] = p
			t.order = append(t.order, tid)
		}
		p.spans = append(p.spans, s)
		root := isLocalRoot(s)
		if root || len(p.spans) >= t.maxSpans {
			var r sdktrace.ReadOnlySpan
			if root {
				r = s
			}
			out = append(out, t.settle(tid, r))
		}
	}
	t.mu.Unlock()
	for _, x := range out {
		t.emit(x)
	}
}

// settle takes the decision for a buffered trace. Called with t.mu held.
func (t *TailSampler) settle(tid trace.TraceID, root sdktrace.ReadOnlySpan) settled {
	p := t.pending[tid]
	delete(t.pending, tid)
	if i := slices.Index(t.order, tid); i >= 0 {
		t.order = slices.Delete(t.order, i, i+1)
	}
	cfg := t.config()
	flow := ""
	if root != nil {
		flow = attrString(root.Attributes(), AttrFlow)
	} else {
		for _, s := range p.spans {
			if f := attrString(s.Attributes(), AttrFlow); f != "" {
				flow = f
				break
			}
		}
	}
	d := Decide(tid, p.spans, root, cfg.PolicyFor(flow), cfg.RateFor(flow, time.Now()))
	if len(t.decided) >= t.maxTraces*4 {
		for k := range t.decided { // drop an arbitrary old decision
			delete(t.decided, k)
			break
		}
	}
	t.decided[tid] = decided{d, flow, time.Now()}
	return settled{p.spans, d, flow}
}

func (t *TailSampler) emit(x settled) {
	p := t.config().PolicyFor(x.flow)
	for _, s := range x.spans {
		sd := spanDecision(s, x.d)
		if !sd.Keep {
			stats.dropped.Add(1)
			continue
		}
		stats.kept.Add(1)
		t.next.OnEnd(finalize(s, p, sd))
	}
}

func (t *TailSampler) sweep() {
	now := time.Now()
	var out []settled
	t.mu.Lock()
	for _, tid := range slices.Clone(t.order) {
		if now.Sub(t.pending[tid].firstAt) > t.maxAge {
			out = append(out, t.settle(tid, nil))
		}
	}
	for tid, d := range t.decided {
		if now.Sub(d.at) > t.maxAge {
			delete(t.decided, tid)
		}
	}
	t.mu.Unlock()
	for _, x := range out {
		t.emit(x)
	}
}

func (t *TailSampler) sweeper() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-tick.C:
			func() {
				defer func() { _ = recover() }() // never take the host app down
				t.sweep()
			}()
		}
	}
}

// buffered is the number of traces currently buffered (tests).
func (t *TailSampler) buffered() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pending)
}

func (t *TailSampler) settleAll() {
	t.mu.Lock()
	var out []settled
	for _, tid := range slices.Clone(t.order) {
		out = append(out, t.settle(tid, nil))
	}
	t.mu.Unlock()
	for _, x := range out {
		t.emit(x)
	}
}

func (t *TailSampler) ForceFlush(ctx context.Context) error {
	t.settleAll()
	return t.next.ForceFlush(ctx)
}

func (t *TailSampler) Shutdown(ctx context.Context) error {
	t.stopOnce.Do(func() { close(t.stop) })
	t.settleAll()
	return t.next.Shutdown(ctx)
}
