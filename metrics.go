package flowhawk

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// App metrics with flow context: Count, Histogram, UpDown and Gauge over the OpenTelemetry Meter API; the Go
// twin of metrics.ts in @flowhawk/sdk-node. Recorded inside a request, a point gets business.flow and
// business.step from the active span. The catalog's label allowlist (metrics/*.yaml) is applied before
// recording, so labels nobody declared never create series.

// Labels are a metric point's labels: string, bool, int or float64 values.
type Labels map[string]any

// MetricOption sets a metric's unit or description (used when the instrument is first created).
type MetricOption func(*metricOpts)

type metricOpts struct{ unit, description string }

func Unit(u string) MetricOption        { return func(o *metricOpts) { o.unit = u } }
func Description(d string) MetricOption { return func(o *metricOpts) { o.description = d } }

func toOpts(opts []MetricOption) metricOpts {
	var o metricOpts
	for _, f := range opts {
		f(&o)
	}
	return o
}

// pointLabels are the labels a point is recorded with; ok is false when the metric is turned off in the
// catalog or the flow's policy has custom metrics off.
func pointLabels(name string, labels Labels, flow *FlowStep, c *RemoteConfig) (map[string]any, bool) {
	if c.metricDropped(name) {
		return nil, false
	}
	fs := flow
	if f, ok := labels[AttrFlow]; ok && f != nil {
		step := ""
		if s, ok := labels[AttrStep]; ok && s != nil {
			step = fmt.Sprint(s)
		}
		fs = &FlowStep{fmt.Sprint(f), step}
	}
	if fs != nil {
		if p := c.PolicyFor(fs.Flow); p != nil && !p.Metrics.Custom {
			return nil, false
		}
	}
	var keep []string
	hasKeep := false
	if c != nil {
		keep, hasKeep = c.Metrics.Keep[name]
	}
	out := map[string]any{}
	for k, v := range labels {
		if k == AttrFlow || k == AttrStep || (hasKeep && !slices.Contains(keep, k)) {
			continue
		}
		out[k] = v
	}
	if fs != nil {
		out[AttrFlow] = fs.Flow
		if fs.Step != "" {
			out[AttrStep] = fs.Step
		}
	}
	return out, true
}

func toAttrs(m map[string]any) attribute.Set {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	kvs := make([]attribute.KeyValue, 0, len(m))
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			kvs = append(kvs, attribute.String(k, v))
		case bool:
			kvs = append(kvs, attribute.Bool(k, v))
		case int:
			kvs = append(kvs, attribute.Int(k, v))
		case int64:
			kvs = append(kvs, attribute.Int64(k, v))
		case float64:
			kvs = append(kvs, attribute.Float64(k, v))
		default:
			kvs = append(kvs, attribute.String(k, fmt.Sprint(v)))
		}
	}
	return attribute.NewSet(kvs...)
}

func flowPtr(ctx context.Context) *FlowStep {
	if fs, ok := FlowOf(ctx); ok {
		return &fs
	}
	return nil
}

var appInstruments sync.Map // kind+name -> instrument

func instrument[T any](kind, name string, o metricOpts, make func(metric.Meter, string, metricOpts) (T, error)) (T, bool) {
	key := kind + "\x00" + name
	if v, ok := appInstruments.Load(key); ok {
		return v.(T), true
	}
	inst, err := make(otel.Meter("flowhawk-app"), name, o)
	if err != nil {
		var zero T
		return zero, false
	}
	v, _ := appInstruments.LoadOrStore(key, inst)
	return v.(T), true
}

// Count adds to a counter (orders placed, emails sent). Inside a request it carries the request's flow and step.
func Count(ctx context.Context, name string, value float64, labels Labels, opts ...MetricOption) {
	attrs, ok := pointLabels(name, labels, flowPtr(ctx), current())
	if !ok {
		return
	}
	c, ok := instrument("counter", name, toOpts(opts), func(m metric.Meter, n string, o metricOpts) (metric.Float64Counter, error) {
		return m.Float64Counter(n, metric.WithUnit(o.unit), metric.WithDescription(o.description))
	})
	if ok {
		c.Add(ctx, value, metric.WithAttributeSet(toAttrs(attrs)))
	}
}

// Histogram records a distribution (render time, basket size).
func Histogram(ctx context.Context, name string, value float64, labels Labels, opts ...MetricOption) {
	attrs, ok := pointLabels(name, labels, flowPtr(ctx), current())
	if !ok {
		return
	}
	h, ok := instrument("histogram", name, toOpts(opts), func(m metric.Meter, n string, o metricOpts) (metric.Float64Histogram, error) {
		return m.Float64Histogram(n, metric.WithUnit(o.unit), metric.WithDescription(o.description))
	})
	if ok {
		h.Record(ctx, value, metric.WithAttributeSet(toAttrs(attrs)))
	}
}

// UpDown moves a value up or down (items in a queue, open connections).
func UpDown(ctx context.Context, name string, delta float64, labels Labels, opts ...MetricOption) {
	attrs, ok := pointLabels(name, labels, flowPtr(ctx), current())
	if !ok {
		return
	}
	u, ok := instrument("updown", name, toOpts(opts), func(m metric.Meter, n string, o metricOpts) (metric.Float64UpDownCounter, error) {
		return m.Float64UpDownCounter(n, metric.WithUnit(o.unit), metric.WithDescription(o.description))
	})
	if ok {
		u.Add(ctx, delta, metric.WithAttributeSet(toAttrs(attrs)))
	}
}

// GaugePoint is one value a gauge reports, with its own labels.
type GaugePoint struct {
	Value  float64
	Labels Labels
}

// Gauge reports a value read on each export (queue depth, pool usage). It is read outside any request, so it
// reaches flows through the service unless the labels name a flow.
func Gauge(name string, read func() float64, labels Labels, opts ...MetricOption) error {
	return GaugePoints(name, func() []GaugePoint { return []GaugePoint{{Value: read()}} }, labels, opts...)
}

// GaugePoints is Gauge for several labelled values at once (depth per queue).
func GaugePoints(name string, read func() []GaugePoint, labels Labels, opts ...MetricOption) error {
	o := toOpts(opts)
	_, err := otel.Meter("flowhawk-app").Float64ObservableGauge(name, metric.WithUnit(o.unit), metric.WithDescription(o.description),
		metric.WithFloat64Callback(func(_ context.Context, obs metric.Float64Observer) (err error) {
			defer func() {
				if r := recover(); r != nil {
					err = nil // a failing read reports nothing
				}
			}()
			c := current()
			for _, pt := range read() {
				merged := Labels{}
				for k, v := range labels {
					merged[k] = v
				}
				for k, v := range pt.Labels {
					merged[k] = v
				}
				if attrs, ok := pointLabels(name, merged, nil, c); ok {
					obs.Observe(pt.Value, metric.WithAttributeSet(toAttrs(attrs)))
				}
			}
			return nil
		}))
	return err
}
