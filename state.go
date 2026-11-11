package flowhawk

import "sync/atomic"

// The remote config currently applied in this process, swapped atomically by the control client;
// everything else reads it through current().

type applied struct {
	hash   string
	config *RemoteConfig
}

var appliedConfig atomic.Pointer[applied]

func setApplied(hash string, c *RemoteConfig) {
	if c == nil {
		appliedConfig.Store(nil)
		return
	}
	appliedConfig.Store(&applied{hash, c})
}

// current is the applied config, or nil before one arrives (keep everything, tag nothing).
func current() *RemoteConfig {
	if a := appliedConfig.Load(); a != nil {
		return a.config
	}
	return nil
}

// CurrentConfig is the remote config currently applied and its hash, or nil before the first one arrives.
func CurrentConfig() (hash string, config *RemoteConfig) {
	if a := appliedConfig.Load(); a != nil {
		return a.hash, a.config
	}
	return "", nil
}

// Counters reported in the control-plane health message.
var stats struct{ kept, dropped atomic.Int64 }
