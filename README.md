# Flowhawk Go SDK

The OpenTelemetry Go SDK plus business-flow tagging, policy-driven tail sampling, redaction, LLM spans and remote control. It behaves like `@flowhawk/sdk-node` and `flowhawk-sdk` (Python). Go 1.26 or later.

```bash
go get github.com/flowhawk-dev/flowhawk-go
```

Docs: [flowhawk.dev/docs/sending-data](https://flowhawk.dev/docs/sending-data).

## Where it sends

On the hosted service, set these where the service runs. The key is a **Services** key from Settings > API keys.

```
FLOWHAWK_API_KEY=<ingest key>
FLOWHAWK_CONTROL_URL=https://api.flowhawk.dev
OTEL_EXPORTER_OTLP_ENDPOINT=https://ingest.flowhawk.dev
FLOWHAWK_ENVIRONMENT=production
```

Without the two addresses the SDK sends to a Flowhawk on this machine (`http://localhost:4000` and `http://localhost:4318`). Set `FLOWHAWK_ENVIRONMENT` where the service runs in production: flow health, flow alerts and the watcher count `production` and `prod` only, and an SDK with no environment reports `development`.

```go
import flowhawk "github.com/flowhawk-dev/flowhawk-go"

func main() {
	shutdown, err := flowhawk.Init(flowhawk.Options{Service: "payments"}) // APIKey defaults to FLOWHAWK_API_KEY
	if err != nil {
		log.Fatal(err)
	}
	defer shutdown(context.Background())

	client := &http.Client{Transport: flowhawk.Transport(nil)} // carries the flow to the next service
	log := flowhawk.Logger()                                     // log/slog, filtered by the flow's policy

	mux := http.NewServeMux()
	mux.HandleFunc("POST /checkout", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		flowhawk.Count(ctx, "orders.placed", 1, flowhawk.Labels{"plan": "team"})
		log.InfoContext(ctx, "order placed")

		ctx, call := flowhawk.TraceLLM(ctx, flowhawk.LLMRequest{System: "anthropic", Model: "claude-haiku-5-5", Input: prompt})
		// ... call the model ...
		call.Record(flowhawk.LLMResult{Output: text, InputTokens: in, OutputTokens: out})
		call.End(err)
	})
	http.ListenAndServe(":8080", flowhawk.Middleware(mux))
}
```

Background jobs that no route matches: `flowhawk.WithStep(ctx, "payouts", "run-batch", func(ctx context.Context) error { ... })`.

Init sets the global OpenTelemetry tracer, meter and logger providers and the propagator, so any OpenTelemetry instrumentation library (database drivers, gRPC, messaging) works unchanged and its spans are tagged and sampled too.

Tests: `go test ./...` (Go 1.26).
