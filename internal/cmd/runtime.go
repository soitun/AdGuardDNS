package cmd

import (
	"context"
	"log/slog"
	"runtime"
	"runtime/debug"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// setMaxThreads sets the maximum number of threads for the Go runtime, if
// necessary.  l must not be nil, n must not be negative.
func setMaxThreads(ctx context.Context, l *slog.Logger, n int) {
	if n == 0 {
		l.Log(ctx, slogutil.LevelTrace, "go max threads not set")

		return
	}

	debug.SetMaxThreads(n)

	l.InfoContext(ctx, "set go max threads", "n", n)
}

// setLockingEventsRate sets the rate at which blocking and mutex contention
// events are reported in the blocking profile.  Values of zero or less disable
// reporting.  l must not be nil.
func setLockingEventsRate(
	ctx context.Context,
	l *slog.Logger,
	blockingRate,
	mutexContentionRate int,
) {
	if blockingRate > 0 {
		l.InfoContext(ctx, "set block profile rate", "n", blockingRate)
		runtime.SetBlockProfileRate(blockingRate)
	} else {
		l.Log(ctx, slogutil.LevelTrace, "block profile rate is not set")
	}

	if mutexContentionRate > 0 {
		l.InfoContext(ctx, "set mutex profile fraction", "n", mutexContentionRate)
		runtime.SetMutexProfileFraction(mutexContentionRate)
	} else {
		l.Log(ctx, slogutil.LevelTrace, "mutex profile fraction is not set")
	}
}
