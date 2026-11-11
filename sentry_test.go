package flowhawk

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

func TestSentryTraceContinuesTheTraceAndTraceparentWins(t *testing.T) {
	raw, err := readVectors("sentry-trace-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Vectors []struct {
			Header  string  `json:"header"`
			TraceID *string `json:"traceId"`
			SpanID  *string `json:"spanId"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	for _, v := range f.Vectors {
		tid, sid, ok := ParseSentryTrace(v.Header)
		if (v.TraceID != nil) != ok {
			t.Fatalf("%q: ok=%v", v.Header, ok)
		}
		if ok && (tid.String() != *v.TraceID || sid.String() != *v.SpanID) {
			t.Fatalf("%q: got %s %s", v.Header, tid, sid)
		}
	}
	p := propagation.NewCompositeTextMapPropagator(SentryTrace{}, propagation.TraceContext{}, BusinessBaggage{})
	sc := trace.SpanContextFromContext(p.Extract(context.Background(), propagation.MapCarrier{"sentry-trace": f.Vectors[1].Header, "baggage": "sentry-trace_id=x"}))
	if sc.TraceID().String() != *f.Vectors[1].TraceID || sc.SpanID().String() != *f.Vectors[1].SpanID || !sc.IsSampled() || !sc.IsRemote() {
		t.Fatalf("got %+v", sc)
	}
	both := trace.SpanContextFromContext(p.Extract(context.Background(), propagation.MapCarrier{"sentry-trace": f.Vectors[0].Header, "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"}))
	if both.TraceID().String() != "0af7651916cd43dd8448eb211c80319c" {
		t.Fatalf("traceparent should win, got %s", both.TraceID())
	}
	if trace.SpanContextFromContext(p.Extract(context.Background(), propagation.MapCarrier{"sentry-trace": "nope"})).IsValid() {
		t.Fatal("an invalid header is ignored")
	}
}

// readVectors reads a shared test vector file: from packages/schema in the monorepo, or from testdata/ in the
// public flowhawk-go repository, where scripts/release-go.sh copies them.
func readVectors(name string) ([]byte, error) {
	if raw, err := os.ReadFile("../schema/" + name); err == nil {
		return raw, nil
	}
	return os.ReadFile("testdata/" + name)
}
