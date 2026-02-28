package dnssvc

import (
	"context"
	"time"

	"github.com/AdguardTeam/golibs/contextutil"
)

// contextConstructor is a [contextutil.Constructor] implementation that returns
// a context with the given timeout.
type contextConstructor struct {
	timeout time.Duration
}

// newContextConstructor returns a new properly initialized *contextConstructor.
func newContextConstructor(timeout time.Duration) (c *contextConstructor) {
	return &contextConstructor{
		timeout: timeout,
	}
}

// type check
var _ contextutil.Constructor = (*contextConstructor)(nil)

// New implements the [contextutil.Constructor] interface for
// *contextConstructor.  It returns a context with timeout and the corresponding
// cancellation function.
func (c *contextConstructor) New(
	parent context.Context,
) (ctx context.Context, cancel context.CancelFunc) {
	return context.WithTimeout(parent, c.timeout)
}
