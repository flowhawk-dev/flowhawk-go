package flowhawk

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

// Process metrics, the Go twin of runtime.ts in @flowhawk/sdk-node: the "standard" set is CPU and memory;
// "full" adds garbage collections, goroutines and heap. The level comes from workspace.yaml (metrics.runtime,
// with per-service overrides) through the remote config and is read on every export.

func rssBytes() float64 {
	if b, err := os.ReadFile("/proc/self/statm"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 1 {
			if pages, err := strconv.ParseFloat(f[1], 64); err == nil {
				return pages * float64(os.Getpagesize())
			}
		}
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.Sys)
}

func startRuntimeMetrics(service string) (metric.Registration, error) {
	meter := otel.Meter("flowhawk-runtime")
	cores := float64(runtime.NumCPU())
	var mu sync.Mutex
	lastCPU, lastAt := cpuTime(), time.Now()

	cpu, err := meter.Float64ObservableGauge("process.cpu.utilization", metric.WithUnit("1"),
		metric.WithDescription("CPU time used by the process per second of wall time, divided by the available cores"))
	if err != nil {
		return nil, err
	}
	mem, err := meter.Float64ObservableGauge("process.memory.usage", metric.WithUnit("By"), metric.WithDescription("Resident set size"))
	if err != nil {
		return nil, err
	}
	gcs, err := meter.Int64ObservableCounter("go.gc.count", metric.WithDescription("Completed garbage collection cycles"))
	if err != nil {
		return nil, err
	}
	goroutines, err := meter.Int64ObservableGauge("go.goroutines", metric.WithDescription("Live goroutines"))
	if err != nil {
		return nil, err
	}
	heap, err := meter.Int64ObservableGauge("go.memory.heap", metric.WithUnit("By"), metric.WithDescription("Bytes of allocated heap objects"))
	if err != nil {
		return nil, err
	}
	return meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		c := current()
		level := c.RuntimeLevel(service)
		on := func(name string, levels ...string) bool {
			if c.metricDropped(name) {
				return false
			}
			for _, l := range levels {
				if l == level {
					return true
				}
			}
			return false
		}
		mu.Lock()
		nowCPU, now := cpuTime(), time.Now()
		used, wall := (nowCPU - lastCPU).Seconds(), now.Sub(lastAt).Seconds()
		lastCPU, lastAt = nowCPU, now
		mu.Unlock()
		if wall > 0 && on("process.cpu.utilization", "standard", "full") {
			o.ObserveFloat64(cpu, used/wall/cores)
		}
		if on("process.memory.usage", "standard", "full") {
			o.ObserveFloat64(mem, rssBytes())
		}
		if level == "full" {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if on("go.gc.count", "full") {
				o.ObserveInt64(gcs, int64(m.NumGC))
			}
			if on("go.goroutines", "full") {
				o.ObserveInt64(goroutines, int64(runtime.NumGoroutine()))
			}
			if on("go.memory.heap", "full") {
				o.ObserveInt64(heap, int64(m.HeapAlloc))
			}
		}
		return nil
	}, cpu, mem, gcs, goroutines, heap)
}
