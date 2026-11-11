//go:build unix

package flowhawk

import (
	"syscall"
	"time"
)

// cpuTime is the user plus system CPU time the process has used.
func cpuTime() time.Duration {
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}
