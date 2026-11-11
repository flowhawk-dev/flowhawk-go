package flowhawk

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Matching spans to business steps: a port of packages/schema/src/match.ts (and the collector's
// match.go), so a Go service tags the same spans as a Node or Python one.

// SpanFacts are what a step match looks at.
type SpanFacts struct {
	Service  string
	Method   string
	Path     string // without the query string
	SpanName string
	Queue    string
	// Attributes are the span's start-time attributes as strings, for Where matches.
	Attributes map[string]string
}

// FlowStep is the business flow and step a span belongs to.
type FlowStep struct{ Flow, Step string }

type compiledRoute struct {
	method string
	re     *regexp.Regexp
}

var routeCache sync.Map // route -> compiledRoute

func compileRoute(route string) compiledRoute {
	if c, ok := routeCache.Load(route); ok {
		return c.(compiledRoute)
	}
	parts := strings.Fields(route)
	method, path := "", ""
	switch {
	case len(parts) > 1:
		method, path = strings.ToUpper(parts[0]), parts[1]
	case len(parts) == 1:
		path = parts[0]
	}
	segs := strings.Split(path, "/")
	for i, s := range segs {
		switch {
		case strings.HasPrefix(s, ":"):
			segs[i] = "[^/]+"
		case s == "*":
			segs[i] = ".*"
		default:
			segs[i] = regexp.QuoteMeta(s)
		}
	}
	c := compiledRoute{method: method, re: regexp.MustCompile("^" + strings.Join(segs, "/") + "/?$")}
	routeCache.Store(route, c)
	return c
}

func matches(m StepMatch, f SpanFacts) bool {
	if m.Service != "" && m.Service != f.Service {
		return false
	}
	if m.Route != "" {
		if f.Path == "" {
			return false
		}
		r := compileRoute(m.Route)
		if r.method != "" && strings.ToUpper(f.Method) != r.method {
			return false
		}
		if !r.re.MatchString(f.Path) {
			return false
		}
	}
	if m.SpanName != "" && m.SpanName != f.SpanName {
		return false
	}
	if m.Queue != "" && m.Queue != f.Queue {
		return false
	}
	for k, v := range m.Where {
		if !globMatch(v, f.Attributes[k]) {
			return false
		}
	}
	return true
}

var globCache sync.Map // pattern -> *regexp.Regexp

// globMatch: `*` is any characters (`"*"` alone: the attribute is set); everything else matches itself.
func globMatch(pattern, value string) bool {
	if value == "" {
		return false
	}
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}
	if re, ok := globCache.Load(pattern); ok {
		return re.(*regexp.Regexp).MatchString(value)
	}
	parts := strings.Split(pattern, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	re := regexp.MustCompile("(?s)^" + strings.Join(parts, ".*") + "$")
	globCache.Store(pattern, re)
	return re.MatchString(value)
}

// innerMatch: a match with no route and no queue can start a step on a span inside a request.
func innerMatch(m StepMatch) bool { return m.Route == "" && m.Queue == "" }

// entryMatch says which matches a span that inherits no flow may take: "all" for a server, a consumer or a root
// internal span; "inner" (span name and where only) for an internal span inside a request; "none" for client and
// producer spans. Same rule in every SDK and the collector (packages/schema/match-vectors.json).
func entryMatch(kind string, hasParent bool) string {
	switch kind {
	case "server", "consumer":
		return "all"
	case "internal":
		if hasParent {
			return "inner"
		}
		return "all"
	}
	return "none"
}

// MatchStep is the first step in the map whose rules match the span, in map order.
func MatchStep(m BusinessMap, f SpanFacts) (FlowStep, bool) { return matchStep(m, f, false) }

// matchStep with inner set only takes span name and where matches (a span inside a request).
func matchStep(m BusinessMap, f SpanFacts, inner bool) (FlowStep, bool) {
	for _, flow := range m.Flows {
		for _, step := range flow.Steps {
			for _, sm := range step.Match {
				if (!inner || innerMatch(sm)) && matches(sm, f) {
					return FlowStep{flow.ID, step.ID}, true
				}
			}
		}
	}
	return FlowStep{}, false
}

// handoffStep is the step a span that inherits a flow moves on to: a server request or queue consumer whose own match
// is another step of the same flow. The caller's flow wins over a match in another flow; the inherited step stays
// where it is. Same rule in every SDK and the collector (handoffStep in packages/schema/src/match.ts).
func handoffStep(m BusinessMap, inherited FlowStep, kind string, f SpanFacts) (FlowStep, bool) {
	if kind != "server" && kind != "consumer" {
		return FlowStep{}, false
	}
	for _, flow := range m.Flows {
		if flow.ID != inherited.Flow {
			continue
		}
		for _, step := range flow.Steps {
			for _, sm := range step.Match {
				if matches(sm, f) {
					if step.ID == inherited.Step {
						return FlowStep{}, false
					}
					return FlowStep{flow.ID, step.ID}, true
				}
			}
		}
		return FlowStep{}, false
	}
	return FlowStep{}, false
}

// AttrFlowStart is the baggage key for the time a flow started (epoch milliseconds), set at its first entry.
const AttrFlowStart = "business.flow.start"

// parseFlowStart is the flow start a span carries on: whole epoch milliseconds, else 0 (missing, garbled or more
// than a minute ahead).
func parseFlowStart(v string, nowMs int64) int64 {
	if v == "" || len(v) > 15 {
		return 0
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0
		}
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 || n > nowMs+60_000 {
		return 0
	}
	return n
}

// flowElapsedMs is the end-to-end time of a step entry that continued a flow, never negative (clock skew).
func flowElapsedMs(startMs, endMs float64) float64 {
	if endMs < startMs {
		return 0
	}
	return endMs - startMs
}

// stepFailed is stepFailed in packages/schema/src/match.ts: a run fails when its entry span is an error, or when one of
// its step's failWhen rules (all of a rule's attributes, matched like where) matches the attributes it ended with.
func stepFailed(m BusinessMap, fs FlowStep, attrs map[string]string, isError bool) bool {
	if isError {
		return true
	}
	for _, f := range m.Flows {
		if f.ID != fs.Flow {
			continue
		}
		for _, s := range f.Steps {
			if s.ID != fs.Step {
				continue
			}
			for _, rule := range s.FailWhen {
				all := len(rule) > 0
				for k, v := range rule {
					if !globMatch(v, attrs[k]) {
						all = false
						break
					}
				}
				if all {
					return true
				}
			}
		}
	}
	return false
}
