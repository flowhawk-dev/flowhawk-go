package flowhawk

import (
	"context"
	"fmt"
	"reflect"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// LLM calls as OpenTelemetry gen_ai CLIENT spans. Prompts and completions are recorded only when the
// flow's policy turns on llm.capturePrompts (off by default and before any config).
//
//	ctx, call := flowhawk.TraceLLM(ctx, flowhawk.LLMRequest{System: "anthropic", Model: "claude-haiku-5-5", Input: prompt})
//	reply, err := client.Messages.New(ctx, ...)
//	call.Record(flowhawk.LLMResult{Output: text, InputTokens: 12, OutputTokens: 80, FinishReason: "end_turn"})
//	call.End(err)

// LLMRequest describes a model call.
type LLMRequest struct {
	System      string // gen_ai.system, e.g. "anthropic"
	Model       string
	Operation   string // default "chat"
	Input       string // recorded only with capturePrompts
	MaxTokens   int
	Temperature *float64
}

// LLMResult is what a model call returned.
type LLMResult struct {
	Output        string // recorded only with capturePrompts
	ResponseModel string
	InputTokens   int
	OutputTokens  int
	FinishReason  string
}

// LLMCall is an open gen_ai span.
type LLMCall struct {
	span          trace.Span
	model         string
	responseModel string
	capture       bool
}

// TraceLLM starts a gen_ai span named "<operation> <model>" and returns a context that carries it.
// End the call with End.
func TraceLLM(ctx context.Context, r LLMRequest) (context.Context, *LLMCall) {
	op := r.Operation
	if op == "" {
		op = "chat"
	}
	flow := ""
	if fs, ok := FlowOf(ctx); ok {
		flow = fs.Flow
	}
	p := current().PolicyFor(flow)
	capture := p != nil && p.LLM.CapturePrompts
	attrs := []attribute.KeyValue{
		attribute.String("gen_ai.system", r.System),
		attribute.String("gen_ai.request.model", r.Model),
		attribute.String("gen_ai.operation.name", op),
	}
	if r.MaxTokens > 0 {
		attrs = append(attrs, attribute.Int("gen_ai.request.max_tokens", r.MaxTokens))
	}
	if r.Temperature != nil {
		attrs = append(attrs, attribute.Float64("gen_ai.request.temperature", *r.Temperature))
	}
	if capture && r.Input != "" {
		attrs = append(attrs, attribute.String("gen_ai.prompt", r.Input))
	}
	ctx, span := otel.Tracer("flowhawk-sdk").Start(ctx, op+" "+r.Model, trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(attrs...))
	return ctx, &LLMCall{span: span, model: r.Model, capture: capture}
}

// Record records the response on the span (the completion only with capturePrompts).
func (c *LLMCall) Record(r LLMResult) {
	if r.ResponseModel != "" {
		c.responseModel = r.ResponseModel
	}
	if r.InputTokens > 0 {
		c.span.SetAttributes(attribute.Int("gen_ai.usage.input_tokens", r.InputTokens))
	}
	if r.OutputTokens > 0 {
		c.span.SetAttributes(attribute.Int("gen_ai.usage.output_tokens", r.OutputTokens))
	}
	if r.FinishReason != "" {
		c.span.SetAttributes(attribute.StringSlice("gen_ai.response.finish_reasons", []string{r.FinishReason}))
	}
	if c.capture && r.Output != "" {
		c.span.SetAttributes(attribute.String("gen_ai.completion", r.Output))
	}
}

// End ends the span; a non-nil err marks it as an error.
func (c *LLMCall) End(err error) {
	if err == nil {
		m := c.responseModel
		if m == "" {
			m = c.model
		}
		c.span.SetAttributes(attribute.String("gen_ai.response.model", m))
	} else {
		c.span.SetAttributes(attribute.String("error.type", errorType(err)))
		c.span.RecordError(err)
		c.span.SetStatus(codes.Error, err.Error())
	}
	c.span.End()
}

func errorType(err error) string {
	t := reflect.TypeOf(err)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Name() == "" {
		return fmt.Sprintf("%T", err)
	}
	return t.Name()
}
