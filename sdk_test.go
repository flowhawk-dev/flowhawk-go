package flowhawk

// Parity tests with packages/sdk-node/src/sdk.test.ts and packages/sdk-python/tests/test_sdk.py: the same
// hashes, sample rates, route cases and tagging rules.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

const mapJSON = `{"flows": [{"id": "checkout", "name": "Checkout", "criticality": "critical", "steps": [
  {"id": "place-order", "name": "Place order", "match": [{"route": "POST /checkout"}]},
  {"id": "create-order", "name": "Create order", "match": [{"service": "orders", "route": "POST /orders"}]}]}]}`

// defaultPolicy() from packages/schema/src/index.ts, for a critical and a background flow.
const checkoutPolicy = `{"flow": "checkout", "traces": {"enabled": true, "sampleRate": 0.25, "keepErrors": true, "keepSlowerThanMs": 1000},
  "logs": {"enabled": true, "level": "info"}, "attributes": {"drop": [], "redact": ["user.email", "card.number"]}}`
const backgroundPolicy = `{"flow": "default", "traces": {"enabled": true, "sampleRate": 0, "keepErrors": true},
  "logs": {"enabled": true, "level": "warn"}, "attributes": {"drop": [], "redact": ["user.email"]}}`

func mustConfig(t *testing.T, extra string) *RemoteConfig {
	t.Helper()
	raw := `{"map": ` + mapJSON + `, "policies": {"checkout": ` + checkoutPolicy + `}, "defaultPolicy": ` + backgroundPolicy + extra + `}`
	c, err := ParseRemoteConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func withConfig(t *testing.T, c *RemoteConfig) {
	t.Helper()
	setApplied("h", c)
	t.Cleanup(func() { setApplied("", nil) })
}

const (
	low  = "0af7651916cd43dd8000000000000001"
	high = "0af7651916cd43ddffffffffffffffff"
)

func tid(s string) trace.TraceID {
	id, err := trace.TraceIDFromHex(s)
	if err != nil {
		panic(err)
	}
	return id
}

var spanN byte

type fakeOpts struct {
	ms     float64
	err    bool
	attrs  []attribute.KeyValue
	parent bool
}

// fake is a minimal ended span for the decision functions.
func fake(traceID string, o fakeOpts) sdktrace.ReadOnlySpan {
	spanN++
	sc := trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid(traceID), SpanID: trace.SpanID{1, spanN}, TraceFlags: trace.FlagsSampled})
	stub := tracetest.SpanStub{
		Name: "x", SpanContext: sc, SpanKind: trace.SpanKindServer,
		Attributes: append([]attribute.KeyValue{attribute.String(AttrFlow, "checkout")}, o.attrs...),
		StartTime:  time.Unix(0, 0), EndTime: time.Unix(0, int64(o.ms*1e6)),
	}
	if o.parent {
		stub.Parent = trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid(traceID), SpanID: trace.SpanID{2, spanN}})
	}
	if o.err {
		stub.Status = sdktrace.Status{Code: codes.Error}
	}
	return stub.Snapshot()
}

// ---------- hash and tail decision ----------

func TestTraceHashMatchesNode(t *testing.T) {
	for id, want := range map[string]float64{ // traceHash() from packages/sdk-node/src/tail.ts
		"0af7651916cd43dd8448eb211c80319c": 0.5574046243010349,
		"4bf92f3577b34da6a3ce929d0e0e4736": 0.9107943104795146,
		"00000000000000000000000000000001": 2.220446049250313e-16,
		"ffffffffffffffffffffffffffffffff": 0.9999999999999998,
		"5b8efff798038103d269b633813fc60c": 0.6069827126306135,
		"a3ce929d0e0e47364bf92f3577b34da6": 0.5740256000325217,
	} {
		if got := TraceHash(tid(id)); got != want {
			t.Errorf("TraceHash(%s) = %v, want %v", id, got, want)
		}
	}
}

func TestDecisions(t *testing.T) {
	c := mustConfig(t, "")
	p := c.PolicyFor("checkout")
	ro := func(spans ...sdktrace.ReadOnlySpan) []sdktrace.ReadOnlySpan { return spans }

	e := fake(high, fakeOpts{err: true})
	if d := Decide(tid(high), ro(e), e, p, 0.25); d != (Decision{true, "error", 1}) {
		t.Errorf("errors: %+v", d)
	}
	s := fake(high, fakeOpts{ms: 1500})
	if d := Decide(tid(high), ro(s), s, p, 0.25); d != (Decision{true, "slow", 1}) {
		t.Errorf("slow: %+v", d)
	}
	a, b := fake(low, fakeOpts{}), fake(high, fakeOpts{})
	if d := Decide(tid(low), ro(a), a, p, 0.25); d != (Decision{true, "sampled", 4}) {
		t.Errorf("sampled: %+v", d)
	}
	if d := Decide(tid(high), ro(b), b, p, 0.25); d.Keep {
		t.Errorf("high hash kept: %+v", d)
	}
	// No config: keep everything. Traces off: only errors.
	if !Decide(tid(high), ro(b), b, nil, 1).Keep {
		t.Error("no config dropped a trace")
	}
	off := *p
	off.Traces.Enabled = false
	if Decide(tid(low), ro(a), a, &off, 1).Keep || !Decide(tid(high), ro(e), e, &off, 1).Keep {
		t.Error("traces disabled")
	}
	noKeep := *p
	noKeep.Traces.KeepErrors = false
	if Decide(tid(high), ro(e), nil, &noKeep, 0.25).Keep {
		t.Error("keepErrors false kept an error")
	}
}

// Math.max(1, Math.round(1 / rate)) from Node; 0.4 -> 2.5 rounds up.
func TestSampleRateIsJSRoundOfInverse(t *testing.T) {
	p := mustConfig(t, "").PolicyFor("checkout")
	a := fake(low, fakeOpts{})
	for rate, want := range map[float64]int{0.3: 3, 0.25: 4, 0.1: 10, 0.15: 7, 0.4: 3, 0.6: 2, 0.07: 14, 1.0 / 3: 3, 0.0001: 10000, 1: 1} {
		if got := Decide(tid(low), []sdktrace.ReadOnlySpan{a}, a, p, rate).SampleRate; got != want {
			t.Errorf("rate %v: SampleRate %d, want %d", rate, got, want)
		}
	}
}

func TestModelCallsKeptAtWeight1(t *testing.T) {
	p := mustConfig(t, "").PolicyFor("checkout")
	ai := fake(high, fakeOpts{attrs: []attribute.KeyValue{attribute.String("gen_ai.system", "anthropic")}})
	plain := fake(high, fakeOpts{})
	dropped := Decide(tid(high), []sdktrace.ReadOnlySpan{ai, plain}, nil, p, 0.25)
	if dropped.Keep {
		t.Fatal("trace should drop")
	}
	if d := spanDecision(ai, dropped); d != (Decision{true, "ai", 1}) {
		t.Errorf("ai span: %+v", d)
	}
	if spanDecision(plain, dropped).Keep {
		t.Error("plain span kept")
	}
	sampled := Decide(tid(low), []sdktrace.ReadOnlySpan{fake(low, fakeOpts{})}, nil, p, 0.25)
	other := fake(low, fakeOpts{attrs: []attribute.KeyValue{attribute.String("gen_ai.provider.name", "openai")}})
	if d := spanDecision(other, sampled); d != (Decision{true, "sampled", 1}) {
		t.Errorf("sampled ai span: %+v", d)
	}
}

func TestBoostRaisesRateUntilExpiry(t *testing.T) {
	c := mustConfig(t, `, "boosts": {"checkout": {"rate": 1, "until": "2099-01-01T00:00:00.000Z"}, "x": {"rate": 1, "until": "2000-01-01T00:00:00Z"}}`)
	now := time.Now()
	if c.RateFor("checkout", now) != 1 || c.RateFor("x", now) != 0 {
		t.Error("boost")
	}
	if mustConfig(t, "").RateFor("checkout", now) != 0.25 {
		t.Error("policy rate")
	}
	var none *RemoteConfig
	if none.RateFor("checkout", now) != 1 {
		t.Error("no config")
	}
}

func attrMap(kvs []attribute.KeyValue) map[string]string {
	m := map[string]string{}
	for _, kv := range kvs {
		m[string(kv.Key)] = kv.Value.Emit()
	}
	return m
}

func TestFinalizeDropsRedactsAndTags(t *testing.T) {
	p := *mustConfig(t, "").PolicyFor("checkout")
	p.Attributes.Drop, p.Attributes.Redact = []string{"secret"}, []string{"user.email"}
	s := finalize(fake(low, fakeOpts{attrs: []attribute.KeyValue{
		attribute.String("user.email", "a@b.c"), attribute.String("secret", "x"), attribute.String("keep", "y"),
	}}), &p, Decision{true, "sampled", 4})
	a := attrMap(s.Attributes())
	if a["user.email"] != "[redacted]" || a["keep"] != "y" || a["SampleRate"] != "4" || a["flowhawk.keep_reason"] != "sampled" {
		t.Errorf("attrs %v", a)
	}
	if _, ok := a["secret"]; ok {
		t.Error("secret kept")
	}
}

type collect struct {
	mu  sync.Mutex
	out []sdktrace.ReadOnlySpan
}

func (c *collect) OnStart(context.Context, sdktrace.ReadWriteSpan) {}
func (c *collect) OnEnd(s sdktrace.ReadOnlySpan) {
	c.mu.Lock()
	c.out = append(c.out, s)
	c.mu.Unlock()
}
func (c *collect) Shutdown(context.Context) error   { return nil }
func (c *collect) ForceFlush(context.Context) error { return nil }

var secretAttrs = []attribute.KeyValue{
	attribute.String("user.email", "a@b.c"), attribute.String("card.number", "4242424242424242"),
	attribute.String("http.request.header.authorization", "Bearer s3cret"), attribute.String("keep", "y"),
}

// Redaction fails closed: with no policy loaded (before the first config, or dropped as stale) spans
// and logs still get the default redaction.
func TestNoPolicyLoadedStillRedactsSpansAndLogs(t *testing.T) {
	if strings.Join(DefaultRedactAttributes, ",") != "user.email,card.number,http.request.header.authorization" {
		t.Fatalf("DefaultRedactAttributes %v differs from the schema default", DefaultRedactAttributes)
	}
	check := func(what string, a map[string]string) {
		t.Helper()
		for _, k := range DefaultRedactAttributes {
			if a[k] != "[redacted]" {
				t.Errorf("%s: %s = %q, want [redacted]", what, k, a[k])
			}
		}
		if a["keep"] != "y" {
			t.Errorf("%s: other attributes kept: %v", what, a)
		}
	}
	check("finalize", attrMap(finalize(fake(high, fakeOpts{attrs: secretAttrs}), nil, Decision{true, "sampled", 1}).Attributes()))

	next := &collect{}
	ts := newTailSampler(next, func() *RemoteConfig { return nil }, false)
	ts.OnEnd(fake(high, fakeOpts{attrs: secretAttrs}))
	if len(next.out) != 1 {
		t.Fatalf("no config keeps everything, got %d spans", len(next.out))
	}
	check("tail sampler", attrMap(next.out[0].Attributes()))

	setApplied("", nil)
	rec := &recordHandler{}
	args := make([]any, 0, len(secretAttrs)*2)
	for _, kv := range secretAttrs {
		args = append(args, string(kv.Key), kv.Value.AsString())
	}
	slog.New(policyHandler{rec}).InfoContext(context.Background(), "checkout started", args...)
	if len(rec.recs) != 1 {
		t.Fatalf("records %v", rec.recs)
	}
	check("log", recAttrs(rec.recs[0]))
}

func TestTailSamplerBuffersUntilLocalRoot(t *testing.T) {
	cfg := mustConfig(t, "")
	next := &collect{}
	ts := newTailSampler(next, func() *RemoteConfig { return cfg }, false)
	ts.OnEnd(fake(high, fakeOpts{parent: true, err: true})) // local child, errored
	if len(next.out) != 0 || ts.buffered() != 1 {
		t.Fatal("child not buffered")
	}
	ts.OnEnd(fake(high, fakeOpts{})) // root
	if len(next.out) != 2 {
		t.Fatalf("got %d spans", len(next.out))
	}
	for _, s := range next.out {
		if attrMap(s.Attributes())["flowhawk.keep_reason"] != "error" {
			t.Error("keep reason")
		}
	}
	ts.OnEnd(fake(high, fakeOpts{parent: true})) // late span follows the decision
	if len(next.out) != 3 {
		t.Error("late span")
	}
	_ = ts.Shutdown(context.Background())
}

// ---------- route matching ----------

func TestRouteMatchingParity(t *testing.T) {
	// matches({route}, {service: "web", method, path}) from packages/schema/src/match.ts
	for _, c := range []struct {
		route, method, path string
		want                bool
	}{
		{"POST /checkout", "POST", "/checkout", true},
		{"POST /checkout", "post", "/checkout/", true},
		{"POST /checkout", "GET", "/checkout", false},
		{"GET /products/:id", "GET", "/products/p1", true},
		{"GET /products/:id", "GET", "/products/p1/x", false},
		{"GET /products/:id", "GET", "/products/", false},
		{"/files/*", "PUT", "/files/a/b/c", true},
		{"/files/*", "PUT", "/files/", true},
		{"GET /a.b", "GET", "/aXb", false},
		{"GET /a.b", "GET", "/a.b", true},
		{"  get   /x  ", "GET", "/x", true},
		{"/x", "", "/x", true},
		{"GET /x", "", "/x", false},
		{"GET /x", "GET", "", false},
		{"GET /(a)", "GET", "/(a)", true},
		{"GET /orders/:id/items", "GET", "/orders/42/items", true},
		{"GET /", "GET", "/", true},
		{"GET /", "GET", "", false},
	} {
		if got := matches(StepMatch{Route: c.route}, SpanFacts{Service: "web", Method: c.method, Path: c.path}); got != c.want {
			t.Errorf("%q %s %q = %v", c.route, c.method, c.path, got)
		}
	}
}

func TestMatchStepServiceAndSpanName(t *testing.T) {
	c := mustConfig(t, "")
	if _, ok := MatchStep(c.Map, SpanFacts{Service: "web", Method: "POST", Path: "/orders"}); ok {
		t.Error("service mismatch matched")
	}
	if fs, _ := MatchStep(c.Map, SpanFacts{Service: "orders", Method: "POST", Path: "/orders"}); fs != (FlowStep{"checkout", "create-order"}) {
		t.Errorf("got %v", fs)
	}
	m := BusinessMap{Flows: []Flow{{ID: "p", Steps: []Step{{ID: "b", Match: []StepMatch{{Service: "payments", SpanName: "payout.batch"}}}}}}}
	if fs, _ := MatchStep(m, SpanFacts{Service: "payments", SpanName: "payout.batch"}); fs.Step != "b" {
		t.Error("span name")
	}
}

// ---------- remote config ----------

func TestParseRemoteConfigFillsDefaultsAndRejectsInvalid(t *testing.T) {
	raw := `{"map": ` + mapJSON + `, "policies": {"checkout": {"flow": "checkout", "traces": {"sampleRate": 0.5}, "logs": {}}},
	  "defaultPolicy": {"flow": "default", "traces": {"sampleRate": 0}, "logs": {"level": "warn"}}}`
	c, err := ParseRemoteConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	p := c.Policies["checkout"]
	if !p.Traces.Enabled || !p.Traces.KeepErrors || p.Traces.KeepSlowerThanMs != nil || p.Logs.Level != "info" || !p.Logs.Enabled ||
		len(p.Attributes.Drop) != 0 || p.LLM.CapturePrompts || !p.Metrics.Enabled || !p.Metrics.Custom {
		t.Errorf("defaults: %+v", p)
	}
	if len(c.Boosts) != 0 || c.Metrics.Runtime != "standard" {
		t.Error("boosts/metrics defaults")
	}
	whereOnly := `{"map": {"flows": [{"id": "c", "name": "C", "criticality": "critical", "steps": [{"id": "s", "name": "S", "match": [{"where": {"graphql.operation.name": "createOrder"}}]}]}]}, "defaultPolicy": {"flow": "d", "traces": {"sampleRate": 0}, "logs": {}}}`
	if _, err := ParseRemoteConfig([]byte(whereOnly)); err != nil {
		t.Errorf("a where-only match is valid (schema): %v", err)
	}
	flow := `{"id": "checkout", "name": "C", "criticality": "critical", "steps": [{"id": "s", "name": "S", "match": [{"route": "/x"}]}]}`
	for name, bad := range map[string]string{
		"rate":      strings.Replace(raw, `"sampleRate": 0}`, `"sampleRate": 2}`, 1),
		"duplicate": `{"map": {"flows": [` + flow + `,` + flow + `]}, "defaultPolicy": {"flow": "d", "traces": {"sampleRate": 0}, "logs": {}}}`,
		"no match":  `{"map": {"flows": [{"id": "c", "name": "C", "criticality": "critical", "steps": [{"id": "s", "name": "S", "match": [{"service": "web"}]}]}]}, "defaultPolicy": {"flow": "d", "traces": {"sampleRate": 0}, "logs": {}}}`,
		"bad id":    strings.Replace(raw, `"flow": "checkout"`, `"flow": "Bad_Id"`, 1),
		"runtime":   `{"map": {"flows": []}, "defaultPolicy": {"flow": "d", "traces": {"sampleRate": 1}, "logs": {}}, "metrics": {"runtime": "loud"}}`,
	} {
		if _, err := ParseRemoteConfig([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// ---------- tagging, propagation, logs, llm ----------

func provider(service string, ins func() *stepInstruments) (*sdktrace.TracerProvider, *tracetest.InMemoryExporter) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(newFlowTagger(service, ins)), sdktrace.WithSyncer(exp))
	return tp, exp
}

func flowAttrs(s tracetest.SpanStub) [3]string {
	a := attrMap(s.Attributes)
	return [3]string{a[AttrFlow], a[AttrStep], a[AttrEntry]}
}

func TestFlowTaggingEntryParentAndBaggage(t *testing.T) {
	withConfig(t, mustConfig(t, ""))
	tp, exp := provider("web", func() *stepInstruments { return nil })
	tr := tp.Tracer("t")
	ctx, root := tr.Start(context.Background(), "POST", trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attribute.String("http.method", "POST"), attribute.String("http.target", "/checkout?x=1")))
	cctx, child := tr.Start(ctx, "db", trace.WithSpanKind(trace.SpanKindClient))
	carrier := propagation.MapCarrier{}
	BusinessBaggage{}.Inject(cctx, carrier)
	if !strings.Contains(carrier.Get("baggage"), "business.flow=checkout") {
		t.Errorf("baggage %q", carrier.Get("baggage"))
	}
	child.End()
	root.End()
	if !regexp.MustCompile(`business\.flow\.start=\d+`).MatchString(carrier.Get("baggage")) {
		t.Errorf("no flow start in %q", carrier.Get("baggage"))
	}
	// Downstream service: a SERVER span inherits checkout via baggage and matches the flow's next step, so it enters
	// create-order and keeps the flow's start time; a gateway that matches the step it inherited stays in it.
	start := strconv.FormatInt(time.Now().UnixMilli()-1500, 10)
	bctx := flowBaggage(t, "checkout", "place-order", start)
	orders, _ := provider("orders", func() *stepInstruments { return nil })
	rctx, remote := orders.Tracer("t").Start(bctx, "POST", trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attribute.String("http.request.method", "POST"), attribute.String("url.path", "/orders")))
	out := propagation.MapCarrier{}
	BusinessBaggage{}.Inject(rctx, out)
	if !strings.Contains(out.Get("baggage"), "business.step=create-order") || !strings.Contains(out.Get("baggage"), "business.flow.start="+start) {
		t.Errorf("downstream baggage %q", out.Get("baggage"))
	}
	remote.End()
	_, gw := tr.Start(bctx, "POST", trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attribute.String("http.request.method", "POST"), attribute.String("url.path", "/checkout")))
	gw.End()
	spans := exp.GetSpans()
	if got := flowAttrs(spans[1]); got != [3]string{"checkout", "place-order", "true"} {
		t.Errorf("root %v", got)
	}
	if got := flowAttrs(spans[0]); got != [3]string{"checkout", "place-order", ""} {
		t.Errorf("child %v", got)
	}
	if got := flowAttrs(spans[2]); got != [3]string{"checkout", "place-order", ""} {
		t.Errorf("gateway %v", got)
	}
	_ = tp.Shutdown(context.Background())
	_ = orders.Shutdown(context.Background())
}

// flowBaggage is a context carrying a flow's baggage as an upstream service sends it (start "" leaves it out).
func flowBaggage(t *testing.T, flow, step, start string) context.Context {
	t.Helper()
	f, _ := baggage.NewMember(AttrFlow, flow)
	st, _ := baggage.NewMember(AttrStep, step)
	ms := []baggage.Member{f, st}
	if start != "" {
		s, _ := baggage.NewMember(AttrFlowStart, start)
		ms = append(ms, s)
	}
	b, err := baggage.New(ms...)
	if err != nil {
		t.Fatal(err)
	}
	return baggage.ContextWithBaggage(context.Background(), b)
}

func TestHandoffStepRecordsEndToEndTime(t *testing.T) {
	withConfig(t, mustConfig(t, ""))
	reader := sdkmetric.NewManualReader(sdkmetric.WithTemporalitySelector(deltaTemporality))
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	ins, err := makeInstruments(mp.Meter("flowhawk-sdk"))
	if err != nil {
		t.Fatal(err)
	}
	tp, exp := provider("orders", func() *stepInstruments { return ins })
	tr := tp.Tracer("t")
	elapsed := func() []metricdata.HistogramDataPoint[float64] {
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(context.Background(), &rm); err != nil {
			t.Fatal(err)
		}
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if m.Name == "business.flow.elapsed" {
					return m.Data.(metricdata.Histogram[float64]).DataPoints
				}
			}
		}
		return nil
	}
	// The first step: an entry, but nothing to continue, so no end-to-end time.
	_, first := tr.Start(context.Background(), "POST", trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attribute.String("http.method", "POST"), attribute.String("http.target", "/checkout")))
	first.End()
	if pts := elapsed(); len(pts) != 0 {
		t.Errorf("first step recorded %v", pts)
	}
	// The next step in this service, 2 s after the flow started upstream.
	_, next := tr.Start(flowBaggage(t, "checkout", "place-order", strconv.FormatInt(time.Now().UnixMilli()-2000, 10)), "POST", trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attribute.String("http.request.method", "POST"), attribute.String("url.path", "/orders")))
	next.End()
	pts := elapsed()
	if len(pts) != 1 || pts[0].Count != 1 || pts[0].Sum < 2000 || pts[0].Sum > 10_000 {
		t.Fatalf("elapsed %+v", pts)
	}
	if a := attrMap(pts[0].Attributes.ToSlice()); a[AttrFlow] != "checkout" || a[AttrStep] != "create-order" || a["status"] != "ok" {
		t.Errorf("labels %v", a)
	}
	if got := flowAttrs(exp.GetSpans()[1]); got != [3]string{"checkout", "create-order", "true"} {
		t.Errorf("handoff %v", got)
	}
	// Baggage from an older SDK without a start: the step still moves on, without an end-to-end time.
	_, old := tr.Start(flowBaggage(t, "checkout", "place-order", ""), "POST", trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attribute.String("http.request.method", "POST"), attribute.String("url.path", "/orders")))
	old.End()
	if pts := elapsed(); len(pts) != 0 {
		t.Errorf("old baggage recorded %v", pts)
	}
	if got := flowAttrs(exp.GetSpans()[2]); got != [3]string{"checkout", "create-order", "true"} {
		t.Errorf("old handoff %v", got)
	}
}

// Same cases in every SDK and the collector: a consumer and a root internal span enter steps; a nested internal or a client span doesn't.
const jobsMapJSON = `{"flows": [{"id": "fulfilment", "name": "Fulfilment", "criticality": "important", "steps": [
  {"id": "ship", "name": "Ship", "match": [{"queue": "orders.paid"}]},
  {"id": "export", "name": "Export", "match": [{"spanName": "export-orders"}]}]}]}`

func TestFlowTaggingConsumersAndRootInternalSpansAreEntries(t *testing.T) {
	c, err := ParseRemoteConfig([]byte(`{"map": ` + jobsMapJSON + `, "policies": {}, "defaultPolicy": ` + backgroundPolicy + `}`))
	if err != nil {
		t.Fatal(err)
	}
	withConfig(t, c)
	tp, exp := provider("worker", func() *stepInstruments { return nil })
	tr := tp.Tracer("t")
	bg := context.Background()
	_, s := tr.Start(bg, "orders.paid process", trace.WithSpanKind(trace.SpanKindConsumer), trace.WithAttributes(attribute.String("messaging.destination.name", "orders.paid")))
	s.End()
	_, s = tr.Start(bg, "export-orders", trace.WithSpanKind(trace.SpanKindInternal))
	s.End()
	mctx, main := tr.Start(bg, "main", trace.WithSpanKind(trace.SpanKindInternal))
	_, s = tr.Start(mctx, "export-orders", trace.WithSpanKind(trace.SpanKindInternal))
	s.End()
	main.End()
	_, s = tr.Start(bg, "export-orders", trace.WithSpanKind(trace.SpanKindClient))
	s.End()
	want := [][3]string{
		{"orders.paid process", "ship", "true"},
		{"export-orders", "export", "true"},
		{"export-orders", "export", "true"},
		{"main", "", ""},
		{"export-orders", "", ""},
	}
	spans := exp.GetSpans()
	if len(spans) != len(want) {
		t.Fatalf("%d spans", len(spans))
	}
	for i, w := range want {
		a := flowAttrs(spans[i])
		if got := [3]string{spans[i].Name, a[1], a[2]}; got != w {
			t.Errorf("span %d: %v, want %v", i, got, w)
		}
	}
	_ = tp.Shutdown(context.Background())
}

func TestNothingMatchedBeforeConfig(t *testing.T) {
	setApplied("", nil)
	tp, exp := provider("web", func() *stepInstruments { return nil })
	_, s := tp.Tracer("t").Start(context.Background(), "POST", trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attribute.String("http.method", "POST"), attribute.String("http.target", "/checkout")))
	s.End()
	if _, ok := attrMap(exp.GetSpans()[0].Attributes)[AttrFlow]; ok {
		t.Error("tagged without config")
	}
}

type recordHandler struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *recordHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.recs = append(h.recs, r)
	h.mu.Unlock()
	return nil
}
func (h *recordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordHandler) WithGroup(string) slog.Handler      { return h }

func recAttrs(r slog.Record) map[string]string {
	m := map[string]string{}
	r.Attrs(func(a slog.Attr) bool { m[a.Key] = a.Value.String(); return true })
	return m
}

func TestLogPolicyLevelAndRedaction(t *testing.T) {
	withConfig(t, mustConfig(t, ""))
	tp, _ := provider("web", func() *stepInstruments { return nil })
	ctx, root := tp.Tracer("t").Start(context.Background(), "POST", trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attribute.String("http.method", "POST"), attribute.String("http.target", "/checkout")))
	rec := &recordHandler{}
	log := slog.New(policyHandler{rec})
	log.DebugContext(ctx, "dropped") // checkout logs at info
	log.InfoContext(ctx, "kept", "user.email", "a@b.c")
	log.InfoContext(context.Background(), "unmatched") // the default policy logs at warn
	log.WarnContext(context.Background(), "warned")
	root.End()
	if len(rec.recs) != 2 || rec.recs[0].Message != "kept" || rec.recs[1].Message != "warned" {
		t.Fatalf("records %v", rec.recs)
	}
	a := recAttrs(rec.recs[0])
	if a[AttrFlow] != "checkout" || a["user.email"] != "[redacted]" {
		t.Errorf("attrs %v", a)
	}
}

func TestTraceLLMCaptureOnlyWithPolicy(t *testing.T) {
	tp, exp := provider("web", func() *stepInstruments { return nil })
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	withConfig(t, mustConfig(t, ""))
	_, call := TraceLLM(context.Background(), LLMRequest{System: "anthropic", Model: "claude-haiku-5-5", Input: "hi"})
	call.Record(LLMResult{Output: "hello", InputTokens: 3, OutputTokens: 5})
	call.End(nil)

	on := mustConfig(t, "")
	on.DefaultPolicy.LLM.CapturePrompts = true
	withConfig(t, on)
	_, call = TraceLLM(context.Background(), LLMRequest{System: "anthropic", Model: "claude-haiku-5-5", Input: "hi"})
	call.Record(LLMResult{Output: "hello", OutputTokens: 5, FinishReason: "end_turn"})
	call.End(nil)
	_, call = TraceLLM(context.Background(), LLMRequest{System: "anthropic", Model: "m"})
	call.End(&json.SyntaxError{})

	s := exp.GetSpans()
	off, capt, failed := attrMap(s[0].Attributes), attrMap(s[1].Attributes), attrMap(s[2].Attributes)
	if s[0].SpanKind != trace.SpanKindClient || s[0].Name != "chat claude-haiku-5-5" || off["gen_ai.usage.output_tokens"] != "5" {
		t.Errorf("off %v", off)
	}
	if _, ok := off["gen_ai.prompt"]; ok {
		t.Error("prompt captured without policy")
	}
	if capt["gen_ai.prompt"] != "hi" || capt["gen_ai.completion"] != "hello" || capt["gen_ai.response.model"] != "claude-haiku-5-5" {
		t.Errorf("capture %v", capt)
	}
	if failed["error.type"] != "SyntaxError" || s[2].Status.Code != codes.Error {
		t.Errorf("failed %v", failed)
	}
}

func TestEntrySpansRecordDeltaStepHistogram(t *testing.T) {
	withConfig(t, mustConfig(t, ""))
	reader := sdkmetric.NewManualReader(sdkmetric.WithTemporalitySelector(deltaTemporality))
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	ins, err := makeInstruments(mp.Meter("flowhawk-sdk"))
	if err != nil {
		t.Fatal(err)
	}
	tp, _ := provider("web", func() *stepInstruments { return ins })
	_, s := tp.Tracer("t").Start(context.Background(), "POST", trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attribute.String("http.method", "POST"), attribute.String("http.target", "/checkout")))
	s.SetStatus(codes.Error, "")
	s.End()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	found := map[string]metricdata.Metrics{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			found[m.Name] = m
		}
	}
	h := found["business.step.duration"].Data.(metricdata.Histogram[float64])
	if found["business.step.duration"].Unit != "ms" || h.Temporality != metricdata.DeltaTemporality {
		t.Error("histogram unit/temporality")
	}
	pt := h.DataPoints[0]
	if len(pt.Bounds) != len(StepBuckets) || pt.Count != 1 {
		t.Errorf("point %+v", pt)
	}
	if a := attrMap(pt.Attributes.ToSlice()); a[AttrFlow] != "checkout" || a[AttrStep] != "place-order" || a["status"] != "error" {
		t.Errorf("labels %v", a)
	}
	if found["business.step.requests"].Data.(metricdata.Sum[int64]).Temporality != metricdata.DeltaTemporality {
		t.Error("requests temporality")
	}
}

func TestControlClientSendsTheIngestKeyAsBearerToken(t *testing.T) {
	t.Cleanup(func() { setApplied("", nil) })
	var mu sync.Mutex
	seen := []string{}
	cfg := `{"map": ` + mapJSON + `, "policies": {}, "defaultPolicy": ` + backgroundPolicy + `}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("authorization")
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		seen = append(seen, auth)
		mu.Unlock()
		if auth == "Bearer wrong" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"instance_uid": "x", "poll_interval_s": 60, "remote_config": {"config_hash": "abc", "config": ` + cfg + `}}`))
	}))
	defer srv.Close()
	ctx := context.Background()
	c := newControlClient(srv.URL, "shop", "", "flowhawk_ingest_abc")
	if next, err := c.poll(ctx); err != nil || next != 60*time.Second {
		t.Fatalf("poll: %v %v", next, err)
	}
	if h, cfg := CurrentConfig(); h != "abc" || cfg == nil || c.status.Status != "APPLIED" {
		t.Error("config not applied")
	}
	if _, err := newControlClient(srv.URL, "shop", "", "").poll(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := newControlClient(srv.URL, "shop", "", "wrong").poll(ctx); err == nil || !strings.Contains(err.Error(), "ingest key was rejected") {
		t.Errorf("401: %v", err)
	}
	if strings.Join(seen, ",") != "Bearer flowhawk_ingest_abc,,Bearer wrong" {
		t.Errorf("seen %q", seen)
	}
}

func TestControlClientKeepsPreviousConfigOnInvalidOne(t *testing.T) {
	withConfig(t, mustConfig(t, ""))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"remote_config": {"config_hash": "bad", "config": {"map": {"flows": []}}}}`))
	}))
	defer srv.Close()
	c := newControlClient(srv.URL, "shop", "", "")
	if _, err := c.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h, _ := CurrentConfig(); h != "h" || c.status.Status != "FAILED" {
		t.Errorf("hash %s status %+v", h, c.status)
	}
}

func metricsConfig(t *testing.T, custom bool) *RemoteConfig {
	t.Helper()
	pol := `{"flow": "checkout", "traces": {"sampleRate": 0.25}, "logs": {}, "metrics": {"enabled": true, "custom": ` + map[bool]string{true: "true", false: "false"}[custom] + `}}`
	c, err := ParseRemoteConfig([]byte(`{"map": {"flows": []}, "policies": {"checkout": ` + pol + `}, "defaultPolicy": ` +
		strings.Replace(pol, `"flow": "checkout"`, `"flow": "default"`, 1) +
		`, "metrics": {"runtime": "off", "services": {"orders": {"runtime": "full"}}, "keep": {"orders.placed": ["plan"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAppMetricsCarryFlowAndKeepOnlyDeclaredLabels(t *testing.T) {
	c := metricsConfig(t, true)
	fs := &FlowStep{"checkout", "place-order"}
	eq := func(got map[string]any, ok bool, want map[string]any) {
		t.Helper()
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(want)
		if !ok || !bytes.Equal(g, w) {
			t.Errorf("got %s %v, want %s", g, ok, w)
		}
	}
	got, ok := pointLabels("orders.placed", Labels{"plan": "team", "user_id": "u1"}, fs, c)
	eq(got, ok, map[string]any{"plan": "team", AttrFlow: "checkout", AttrStep: "place-order"})
	got, ok = pointLabels("queue.depth", Labels{"queue": "emails"}, nil, c)
	eq(got, ok, map[string]any{"queue": "emails"})
	got, ok = pointLabels("x", Labels{AttrFlow: "payouts"}, fs, c)
	eq(got, ok, map[string]any{AttrFlow: "payouts"})
	if _, ok := pointLabels("orders.placed", Labels{"plan": "team"}, fs, metricsConfig(t, false)); ok {
		t.Error("custom metrics off")
	}
	c.Metrics.Drop = []string{"queue.depth"}
	if _, ok := pointLabels("queue.depth", Labels{"queue": "emails"}, nil, c); ok {
		t.Error("dropped metric recorded")
	}
}

func TestRuntimeLevelDefaults(t *testing.T) {
	c := metricsConfig(t, true)
	var none *RemoteConfig
	if c.RuntimeLevel("orders") != "full" || c.RuntimeLevel("web") != "off" || none.RuntimeLevel("web") != "standard" {
		t.Error("runtime levels")
	}
}

func TestDatabaseSpansGetCodeLocation(t *testing.T) {
	tp, exp := provider("svc", func() *stepInstruments { return nil })
	_, s := tp.Tracer("t").Start(context.Background(), "SELECT", trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.String("db.system", "postgresql")))
	s.End()
	a := attrMap(exp.GetSpans()[0].Attributes)
	if a["code.file.path"] != "sdk_test.go" || !strings.Contains(a["code.stacktrace"], "sdk_test.go:") {
		t.Errorf("code location %v", a)
	}
	frames := []codeFrame{{"lib/db.go", 42}, {"services/orders/repo.go", 12}}
	SetCodeSkip([]string{"lib/db.go"})
	if f, _ := pickFrame(frames); f != frames[1] {
		t.Error("skip helper")
	}
	SetCodeSkip([]string{"lib/", "services/"})
	if f, _ := pickFrame(frames); f != frames[0] {
		t.Error("all skipped")
	}
	SetCodeSkip(nil)
}

func TestWithStepAndMiddleware(t *testing.T) {
	withConfig(t, mustConfig(t, ""))
	tp, exp := provider("web", func() *stepInstruments { return nil })
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	boom := errors.New("boom")
	if err := WithStep(context.Background(), "payouts", "run-batch", func(ctx context.Context) error {
		if fs, _ := FlowOf(ctx); fs.Step != "run-batch" {
			t.Error("flow in ctx")
		}
		return boom
	}); err != boom {
		t.Error("error not returned")
	}
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fs, _ := FlowOf(r.Context()); fs.Step != "place-order" {
			t.Errorf("request flow %v", fs)
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/checkout?x=1", nil))
	s := exp.GetSpans()
	if got := flowAttrs(s[0]); got != [3]string{"payouts", "run-batch", "true"} || s[0].Status.Code != codes.Error {
		t.Errorf("with step %v", got)
	}
	if got := flowAttrs(s[1]); got != [3]string{"checkout", "place-order", "true"} || s[1].Name != "POST" {
		t.Errorf("middleware %v %s", got, s[1].Name)
	}
}

func TestInitExportsWithTheIngestKey(t *testing.T) {
	var mu sync.Mutex
	auth := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth[r.URL.Path] = r.Header.Get("authorization")
		mu.Unlock()
		if r.URL.Path == "/v1/opamp" {
			_, _ = w.Write([]byte(`{"poll_interval_s": 60}`))
		}
	}))
	defer srv.Close()
	shutdown, err := Init(Options{Service: "shop", Endpoint: srv.URL, ControlURL: srv.URL, APIKey: "flowhawk_ingest_abc"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, s := otel.Tracer("t").Start(context.Background(), "work")
	Count(ctx, "orders.placed", 1, Labels{"plan": "team"})
	Logger().WarnContext(ctx, "hello")
	s.End()
	time.Sleep(200 * time.Millisecond) // the first control poll
	if err := shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/v1/traces", "/v1/metrics", "/v1/logs", "/v1/opamp"} {
		if auth[p] != "Bearer flowhawk_ingest_abc" {
			t.Errorf("%s: authorization %q", p, auth[p])
		}
	}
}

func TestIngestKeyGoesOnlyToHTTPSOrThisMachine(t *testing.T) {
	key := "flowhawk_ingest_abc"
	for _, ok := range []string{"https://api.flowhawk.dev", "http://localhost:4000", "http://127.0.0.1:4000", "http://[::1]:4000", "http://api.localhost"} {
		if why := insecureControlURL(ok, key, false); why != "" {
			t.Fatalf("%s: %s", ok, why)
		}
	}
	if why := insecureControlURL("http://api.flowhawk.dev", key, false); !strings.Contains(why, "refusing to send the ingest key to http://api.flowhawk.dev") {
		t.Fatalf("plain http to a remote host: %q", why)
	}
	if insecureControlURL("http://api:4000", key, true) != "" || insecureControlURL("http://api:4000", "", false) != "" {
		t.Fatal("allowed on a private network, and nothing secret without a key")
	}
}

func TestSQLCommentTags(t *testing.T) {
	SetSQLComments(true, "orders")
	t.Cleanup(func() { sqlComments.Store(nil) })
	setApplied("", nil)
	tp, _ := provider("orders", func() *stepInstruments { return nil })
	_, span := tp.Tracer("t").Start(context.Background(), "handler", trace.WithAttributes(attribute.String(AttrFlow, "checkout"), attribute.String(AttrStep, "pay it")))
	sid := span.SpanContext().SpanID()
	at := func(traceID string) context.Context {
		return trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid(traceID), SpanID: sid, TraceFlags: trace.FlagsSampled}))
	}
	// No config yet: every trace is kept, so every query carries its traceparent.
	if got, want := SQLComment(at(high)), "/*flow='checkout',service='orders',step='pay%20it',traceparent='00-"+high+"-"+sid.String()+"-01'*/"; got != want {
		t.Fatalf("comment %q, want %q", got, want)
	}
	withConfig(t, mustConfig(t, "")) // checkout keeps 25% of traces
	if got := SQLComment(at(high)); got != "/*flow='checkout',service='orders',step='pay%20it'*/" {
		t.Fatalf("unsampled %q", got)
	}
	if got := SQLComment(at(low)); !strings.Contains(got, "traceparent='00-"+low+"-") {
		t.Fatalf("sampled %q", got)
	}
	if got := TagSQL(at(high), "SELECT 1;"); got != "SELECT 1 /*flow='checkout',service='orders',step='pay%20it'*/;" {
		t.Fatalf("tagged %q", got)
	}
	if got := TagSQL(at(high), "SELECT 1 /*flow='x'*/"); got != "SELECT 1 /*flow='x'*/" {
		t.Fatalf("already tagged %q", got)
	}
	if got := TagSQL(context.Background(), "SELECT 1"); got != "SELECT 1" {
		t.Fatalf("outside a flow %q", got)
	}
	SetSQLComments(false, "orders")
	if got := TagSQL(at(high), "SELECT 1"); got != "SELECT 1" {
		t.Fatalf("turned off %q", got)
	}
	span.End()
}

func TestMatchVectorsSharedWithEverySDK(t *testing.T) {
	raw, err := readVectors("match-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Map   BusinessMap `json:"map"`
		Match []struct {
			Name  string `json:"name"`
			Inner bool   `json:"inner"`
			Facts struct {
				Service    string            `json:"service"`
				Method     string            `json:"method"`
				Path       string            `json:"path"`
				SpanName   string            `json:"spanName"`
				Queue      string            `json:"queue"`
				Attributes map[string]string `json:"attributes"`
			} `json:"facts"`
			Expect *FlowStepJSON `json:"expect"`
		} `json:"match"`
		Entry []struct {
			Kind      string `json:"kind"`
			HasParent bool   `json:"hasParent"`
			Expect    string `json:"expect"`
		} `json:"entry"`
		Glob []struct {
			Pattern string `json:"pattern"`
			Value   string `json:"value"`
			Expect  bool   `json:"expect"`
		} `json:"glob"`
		Handoff []struct {
			Name      string       `json:"name"`
			Kind      string       `json:"kind"`
			Inherited FlowStepJSON `json:"inherited"`
			Facts     struct {
				Service  string `json:"service"`
				Method   string `json:"method"`
				Path     string `json:"path"`
				SpanName string `json:"spanName"`
				Queue    string `json:"queue"`
			} `json:"facts"`
			Expect *FlowStepJSON `json:"expect"`
		} `json:"handoff"`
		FlowStart []struct {
			Value  string `json:"value"`
			Now    int64  `json:"now"`
			Expect *int64 `json:"expect"`
		} `json:"flowStart"`
		Failed []struct {
			Name       string            `json:"name"`
			Flow       string            `json:"flow"`
			Step       string            `json:"step"`
			Attributes map[string]string `json:"attributes"`
			Error      bool              `json:"error"`
			Expect     bool              `json:"expect"`
		} `json:"failed"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Match {
		f := c.Facts
		got, ok := matchStep(v.Map, SpanFacts{Service: f.Service, Method: f.Method, Path: f.Path, SpanName: f.SpanName, Queue: f.Queue, Attributes: f.Attributes}, c.Inner)
		if c.Expect == nil {
			if ok {
				t.Errorf("%s: got %v, want no match", c.Name, got)
			}
		} else if !ok || got.Flow != c.Expect.Flow || got.Step != c.Expect.Step {
			t.Errorf("%s: got %v %v, want %v", c.Name, got, ok, *c.Expect)
		}
	}
	for _, c := range v.Entry {
		if got := entryMatch(c.Kind, c.HasParent); got != c.Expect {
			t.Errorf("entryMatch(%s, %v) = %s, want %s", c.Kind, c.HasParent, got, c.Expect)
		}
	}
	for _, c := range v.Glob {
		if got := globMatch(c.Pattern, c.Value); got != c.Expect {
			t.Errorf("globMatch(%q, %q) = %v", c.Pattern, c.Value, got)
		}
	}
	if len(v.Handoff) == 0 || len(v.FlowStart) == 0 {
		t.Fatal("no handoff or flowStart vectors")
	}
	for _, c := range v.Handoff {
		f := c.Facts
		got, ok := handoffStep(v.Map, FlowStep{c.Inherited.Flow, c.Inherited.Step}, c.Kind, SpanFacts{Service: f.Service, Method: f.Method, Path: f.Path, SpanName: f.SpanName, Queue: f.Queue})
		if c.Expect == nil {
			if ok {
				t.Errorf("%s: got %v, want none", c.Name, got)
			}
		} else if !ok || got.Flow != c.Expect.Flow || got.Step != c.Expect.Step {
			t.Errorf("%s: got %v %v, want %v", c.Name, got, ok, *c.Expect)
		}
	}
	for _, c := range v.FlowStart {
		want := int64(0)
		if c.Expect != nil {
			want = *c.Expect
		}
		if got := parseFlowStart(c.Value, c.Now); got != want {
			t.Errorf("parseFlowStart(%q) = %d, want %d", c.Value, got, want)
		}
	}
	for _, c := range v.Failed {
		if got := stepFailed(v.Map, FlowStep{Flow: c.Flow, Step: c.Step}, c.Attributes, c.Error); got != c.Expect {
			t.Errorf("stepFailed: %s: got %v", c.Name, got)
		}
	}
}

// A step's failWhen rules fail a run with no error status: the step metric, the tail decision and the exported span agree.
func TestFailWhenFailsARunWithoutAnErrorStatus(t *testing.T) {
	raw := `{"map": {"flows": [{"id": "shop", "name": "Shop", "criticality": "critical", "steps": [
	  {"id": "pay", "name": "Pay", "match": [{"route": "POST /pay"}], "failWhen": [{"http.response.status_code": "4*"}]}]}]},
	  "policies": {}, "defaultPolicy": {"flow": "default", "traces": {"enabled": true, "sampleRate": 0, "keepErrors": true},
	  "logs": {"enabled": true, "level": "warn"}, "attributes": {"drop": [], "redact": []}}}`
	cfg, err := ParseRemoteConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	withConfig(t, cfg)
	reader := sdkmetric.NewManualReader()
	meter := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("t")
	dur, _ := meter.Float64Histogram("business.step.duration")
	reqs, _ := meter.Int64Counter("business.step.requests")
	ins := &stepInstruments{duration: dur, requests: reqs}
	next := &collect{}
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(newFlowTagger("api", func() *stepInstruments { return ins })),
		sdktrace.WithSpanProcessor(newTailSampler(next, func() *RemoteConfig { return cfg }, false)))
	tr := tp.Tracer("t")
	for _, code := range []int{402, 200} {
		_, s := tr.Start(context.Background(), "POST", trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(attribute.String("http.request.method", "POST"), attribute.String("url.path", "/pay")))
		s.SetAttributes(attribute.Int("http.response.status_code", code))
		s.End()
	}
	if len(next.out) != 1 {
		t.Fatalf("kept %d spans, want the failed run only", len(next.out))
	}
	if next.out[0].Status().Code != codes.Error || attrMap(next.out[0].Attributes())["flowhawk.keep_reason"] != "error" {
		t.Errorf("the failed run is exported as a kept error: %v", next.out[0].Status())
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	statuses := map[string]uint64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if h, ok := m.Data.(metricdata.Histogram[float64]); ok {
				for _, p := range h.DataPoints {
					v, _ := p.Attributes.Value("status")
					statuses[v.AsString()] += p.Count
				}
			}
		}
	}
	if statuses["error"] != 1 || statuses["ok"] != 1 {
		t.Errorf("step metric statuses %v", statuses)
	}
}

// A request whose caller didn't sample it (traceparent ...-00) still records: the step metric counts it and the tail
// sampler decides whether it is kept.
func TestARequestWhoseCallerDidNotSampleItStillCounts(t *testing.T) {
	cfg := mustConfig(t, "")
	cfg.Policies["checkout"].Traces.SampleRate = 1
	withConfig(t, cfg)
	reader := sdkmetric.NewManualReader()
	meter := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("t")
	dur, _ := meter.Float64Histogram("business.step.duration")
	reqs, _ := meter.Int64Counter("business.step.requests")
	ins := &stepInstruments{duration: dur, requests: reqs}
	next := &collect{}
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sampler),
		sdktrace.WithSpanProcessor(newFlowTagger("web", func() *stepInstruments { return ins })),
		sdktrace.WithSpanProcessor(newTailSampler(next, func() *RemoteConfig { return cfg }, false)))
	ctx := propagation.TraceContext{}.Extract(context.Background(),
		propagation.MapCarrier{"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00"})
	_, s := tp.Tracer("t").Start(ctx, "POST /checkout", trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attribute.String("http.request.method", "POST"), attribute.String("url.path", "/checkout")))
	if !s.IsRecording() {
		t.Fatal("the span records")
	}
	s.End()
	if len(next.out) != 1 || next.out[0].SpanContext().TraceID().String() != "0af7651916cd43dd8448eb211c80319c" {
		t.Fatalf("kept %d spans", len(next.out))
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var count uint64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if h, ok := m.Data.(metricdata.Histogram[float64]); ok {
				for _, p := range h.DataPoints {
					count += p.Count
				}
			}
		}
	}
	if count != 1 {
		t.Errorf("step metric count %d, want 1", count)
	}
}

type FlowStepJSON struct {
	Flow string `json:"flow"`
	Step string `json:"step"`
}
