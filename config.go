package flowhawk

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"time"
)

// The remote config the control plane serves on /v1/opamp: SdkRemoteConfig in packages/schema/src/api.ts,
// validated with the same rules and defaults as the zod schemas in packages/schema/src/config.ts (and the
// Python SDK's config.py).

// StepMatch is one rule that ties a span to a step.
type StepMatch struct {
	Service  string `json:"service,omitempty"`
	Route    string `json:"route,omitempty"`
	SpanName string `json:"spanName,omitempty"`
	Queue    string `json:"queue,omitempty"`
	// Where: span attributes that must all match; `*` is any characters.
	Where map[string]string `json:"where,omitempty"`
}

type Step struct {
	ID    string      `json:"id"`
	Name  string      `json:"name"`
	Match []StepMatch `json:"match"`
	// FailWhen: rules on an entry span's attributes that fail the run without an error status (stepFailed).
	FailWhen []map[string]string `json:"failWhen,omitempty"`
}

type Flow struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Criticality string `json:"criticality"`
	Steps       []Step `json:"steps"`
}

// BusinessMap is the customer's flows and the rules that match spans to their steps.
type BusinessMap struct {
	Flows []Flow `json:"flows"`
}

// DefaultRedactAttributes are the attributes redacted by default (DEFAULT_REDACT_ATTRIBUTES in
// packages/schema/src/index.ts). They apply when no policy is loaded (before the first config, or after
// the control plane has been unreachable), so redaction fails closed.
var DefaultRedactAttributes = []string{"user.email", "card.number", "http.request.header.authorization", "http.request.header.cookie", "http.response.header.set-cookie", "http.request.header.x-api-key"}

// attributeRules are the attributes a policy drops and redacts; with no policy, nothing is dropped
// and the default redaction applies.
func attributeRules(p *Policy) (drop, redact []string) {
	if p == nil {
		return nil, DefaultRedactAttributes
	}
	return p.Attributes.Drop, p.Attributes.Redact
}

// Policy is a flow's collection policy (CollectionPolicy in packages/schema/src/config.ts).
type Policy struct {
	Flow   string `json:"flow"`
	Traces struct {
		Enabled          bool     `json:"enabled"`
		SampleRate       float64  `json:"sampleRate"`
		KeepErrors       bool     `json:"keepErrors"`
		KeepSlowerThanMs *float64 `json:"keepSlowerThanMs,omitempty"`
	} `json:"traces"`
	Logs struct {
		Enabled bool   `json:"enabled"`
		Level   string `json:"level"`
	} `json:"logs"`
	Metrics struct {
		Enabled bool `json:"enabled"`
		Custom  bool `json:"custom"`
	} `json:"metrics"`
	Attributes struct {
		Drop   []string `json:"drop"`
		Redact []string `json:"redact"`
	} `json:"attributes"`
	LLM struct {
		CapturePrompts bool `json:"capturePrompts"`
	} `json:"llm"`
}

// Boost raises a flow's sample rate until a time.
type Boost struct {
	Rate  float64 `json:"rate"`
	Until string  `json:"until"`
}

// MetricsConfig is the remote config's metrics block: runtime level, per-service overrides, label allowlists.
type MetricsConfig struct {
	Runtime  string                    `json:"runtime"`
	Services map[string]ServiceMetrics `json:"services"`
	// Keep maps a metric name to the labels its points keep (the catalog's labels.keep).
	Keep map[string][]string `json:"keep"`
	// Drop are metrics turned off in the catalog.
	Drop []string `json:"drop"`
}

type ServiceMetrics struct {
	Runtime string `json:"runtime,omitempty"`
}

// RemoteConfig is the config applied in this process.
type RemoteConfig struct {
	Map           BusinessMap        `json:"map"`
	Policies      map[string]*Policy `json:"policies"`
	DefaultPolicy *Policy            `json:"defaultPolicy"`
	Boosts        map[string]Boost   `json:"boosts"`
	Metrics       MetricsConfig      `json:"metrics"`
}

// ConfigError is a remote config that failed validation.
type ConfigError struct{ msg string }

func (e *ConfigError) Error() string { return e.msg }

func cfgErr(format string, a ...any) error { return &ConfigError{fmt.Sprintf(format, a...)} }

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

var (
	criticalities = []string{"critical", "important", "background"}
	logLevels     = []string{"debug", "info", "warn", "error"}
	metricLevels  = []string{"off", "standard", "full"}
)

// Raw shapes with pointers, so missing fields can get the schema's defaults.
type rawPolicy struct {
	Flow   *string `json:"flow"`
	Traces *struct {
		Enabled          *bool    `json:"enabled"`
		SampleRate       *float64 `json:"sampleRate"`
		KeepErrors       *bool    `json:"keepErrors"`
		KeepSlowerThanMs *float64 `json:"keepSlowerThanMs"`
	} `json:"traces"`
	Logs *struct {
		Enabled *bool   `json:"enabled"`
		Level   *string `json:"level"`
	} `json:"logs"`
	Metrics *struct {
		Enabled *bool `json:"enabled"`
		Custom  *bool `json:"custom"`
	} `json:"metrics"`
	Attributes *struct {
		Drop   []string `json:"drop"`
		Redact []string `json:"redact"`
	} `json:"attributes"`
	LLM *struct {
		CapturePrompts *bool `json:"capturePrompts"`
	} `json:"llm"`
}

type rawConfig struct {
	Map           *BusinessMap         `json:"map"`
	Policies      map[string]rawPolicy `json:"policies"`
	DefaultPolicy *rawPolicy           `json:"defaultPolicy"`
	Boosts        map[string]Boost     `json:"boosts"`
	Metrics       *struct {
		Runtime  *string                   `json:"runtime"`
		Services map[string]ServiceMetrics `json:"services"`
		Keep     map[string][]string       `json:"keep"`
		Drop     []string                  `json:"drop"`
	} `json:"metrics"`
}

func or[T any](p *T, d T) T {
	if p == nil {
		return d
	}
	return *p
}

func parsePolicy(r *rawPolicy, where string) (*Policy, error) {
	if r == nil {
		return nil, cfgErr("%s: expected object", where)
	}
	p := &Policy{}
	if r.Flow == nil || !idRe.MatchString(*r.Flow) {
		return nil, cfgErr("%s.flow: ids are lowercase letters, digits and dashes", where)
	}
	p.Flow = *r.Flow
	if r.Traces == nil {
		return nil, cfgErr("%s.traces: expected object", where)
	}
	if r.Traces.SampleRate == nil || math.IsNaN(*r.Traces.SampleRate) || *r.Traces.SampleRate < 0 || *r.Traces.SampleRate > 1 {
		return nil, cfgErr("%s.traces.sampleRate: must be in 0..1", where)
	}
	p.Traces.SampleRate = *r.Traces.SampleRate
	p.Traces.Enabled = or(r.Traces.Enabled, true)
	p.Traces.KeepErrors = or(r.Traces.KeepErrors, true)
	if s := r.Traces.KeepSlowerThanMs; s != nil {
		if *s <= 0 {
			return nil, cfgErr("%s.traces.keepSlowerThanMs: must be positive", where)
		}
		p.Traces.KeepSlowerThanMs = s
	}
	if r.Logs == nil {
		return nil, cfgErr("%s.logs: expected object", where)
	}
	p.Logs.Enabled = or(r.Logs.Enabled, true)
	p.Logs.Level = or(r.Logs.Level, "info")
	if !slices.Contains(logLevels, p.Logs.Level) {
		return nil, cfgErr("%s.logs.level: expected one of debug, info, warn, error", where)
	}
	p.Metrics.Enabled, p.Metrics.Custom = true, true
	if r.Metrics != nil {
		p.Metrics.Enabled = or(r.Metrics.Enabled, true)
		p.Metrics.Custom = or(r.Metrics.Custom, true)
	}
	p.Attributes.Drop, p.Attributes.Redact = []string{}, []string{}
	if r.Attributes != nil {
		if r.Attributes.Drop != nil {
			p.Attributes.Drop = r.Attributes.Drop
		}
		if r.Attributes.Redact != nil {
			p.Attributes.Redact = r.Attributes.Redact
		}
	}
	if r.LLM != nil {
		p.LLM.CapturePrompts = or(r.LLM.CapturePrompts, false)
	}
	return p, nil
}

func validateMap(m *BusinessMap) error {
	if m == nil {
		return cfgErr("map.flows: expected array")
	}
	flows := map[string]bool{}
	for i, f := range m.Flows {
		where := fmt.Sprintf("map.flows[%d]", i)
		if !idRe.MatchString(f.ID) {
			return cfgErr("%s.id: ids are lowercase letters, digits and dashes", where)
		}
		if !slices.Contains(criticalities, f.Criticality) {
			return cfgErr("%s.criticality: expected one of critical, important, background", where)
		}
		if len(f.Steps) == 0 {
			return cfgErr("%s.steps: expected a non-empty array", where)
		}
		if flows[f.ID] {
			return cfgErr("duplicate flow id %s", f.ID)
		}
		flows[f.ID] = true
		steps := map[string]bool{}
		for j, s := range f.Steps {
			sw := fmt.Sprintf("%s.steps[%d]", where, j)
			if !idRe.MatchString(s.ID) {
				return cfgErr("%s.id: ids are lowercase letters, digits and dashes", sw)
			}
			if len(s.Match) == 0 {
				return cfgErr("%s.match: expected a non-empty array", sw)
			}
			for k, m := range s.Match {
				if m.Route == "" && m.SpanName == "" && m.Queue == "" && len(m.Where) == 0 {
					return cfgErr("%s.match[%d]: a match needs a route, spanName, queue or where", sw, k)
				}
			}
			if steps[s.ID] {
				return cfgErr("duplicate step %s.%s", f.ID, s.ID)
			}
			steps[s.ID] = true
		}
	}
	return nil
}

// ParseRemoteConfig validates a received config and fills the schema's defaults.
func ParseRemoteConfig(raw []byte) (*RemoteConfig, error) {
	var r rawConfig
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, cfgErr("config: %v", err)
	}
	if err := validateMap(r.Map); err != nil {
		return nil, err
	}
	c := &RemoteConfig{Map: *r.Map, Policies: map[string]*Policy{}, Boosts: r.Boosts}
	if c.Boosts == nil {
		c.Boosts = map[string]Boost{}
	}
	for flow, rp := range r.Policies {
		p, err := parsePolicy(&rp, "policies."+flow)
		if err != nil {
			return nil, err
		}
		c.Policies[flow] = p
	}
	dp, err := parsePolicy(r.DefaultPolicy, "defaultPolicy")
	if err != nil {
		return nil, err
	}
	c.DefaultPolicy = dp
	c.Metrics = MetricsConfig{Runtime: "standard", Services: map[string]ServiceMetrics{}, Keep: map[string][]string{}, Drop: []string{}}
	if m := r.Metrics; m != nil {
		c.Metrics.Runtime = or(m.Runtime, "standard")
		if !slices.Contains(metricLevels, c.Metrics.Runtime) {
			return nil, cfgErr("metrics.runtime: expected one of off, standard, full")
		}
		for name, s := range m.Services {
			if s.Runtime != "" && !slices.Contains(metricLevels, s.Runtime) {
				return nil, cfgErr("metrics.services.%s.runtime: expected one of off, standard, full", name)
			}
			c.Metrics.Services[name] = s
		}
		if m.Keep != nil {
			c.Metrics.Keep = m.Keep
		}
		if m.Drop != nil {
			c.Metrics.Drop = m.Drop
		}
	}
	return c, nil
}

// PolicyFor is the flow's policy, or the default policy for unmatched telemetry.
func (c *RemoteConfig) PolicyFor(flow string) *Policy {
	if c == nil {
		return nil
	}
	if p, ok := c.Policies[flow]; ok && flow != "" {
		return p
	}
	return c.DefaultPolicy
}

// RateFor is the flow's sample rate or an active boost, whichever is higher.
func (c *RemoteConfig) RateFor(flow string, now time.Time) float64 {
	p := c.PolicyFor(flow)
	if p == nil {
		return 1 // no config yet: keep everything
	}
	boosted := 0.0
	if b, ok := c.Boosts[flow]; ok && flow != "" {
		if until, err := time.Parse(time.RFC3339Nano, b.Until); err == nil && until.After(now) {
			boosted = b.Rate
		}
	}
	return min(1, max(p.Traces.SampleRate, boosted))
}

// RuntimeLevel is the runtime metrics level for a service: off, standard or full. Standard until a config arrives.
func (c *RemoteConfig) RuntimeLevel(service string) string {
	if c == nil {
		return "standard"
	}
	if s, ok := c.Metrics.Services[service]; ok && s.Runtime != "" {
		return s.Runtime
	}
	if c.Metrics.Runtime != "" {
		return c.Metrics.Runtime
	}
	return "standard"
}

func (c *RemoteConfig) metricDropped(name string) bool {
	return c != nil && slices.Contains(c.Metrics.Drop, name)
}
