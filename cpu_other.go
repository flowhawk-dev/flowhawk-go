//go:build !unix

package flowhawk

import "time"

// cpuTime is not measured on this platform; process.cpu.utilization then reports 0.
func cpuTime() time.Duration { return 0 }
