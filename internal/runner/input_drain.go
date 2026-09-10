package runner

import (
	"time"

	"github.com/safedep/dry/log"
)

// inputDrainGrace bounds the join of the stdin reader after its context is
// cancelled. Both platform readers in internal/pty return on cancellation,
// the Unix one from its poll timeout and the Windows one from the wake key it
// writes to the console. The bound covers a reader that cannot be woken, such
// as a console with no WriteConsoleInputW, so teardown never waits on a
// keystroke.
const inputDrainGrace = 200 * time.Millisecond

func waitForInputReader(inputDone <-chan struct{}) {
	select {
	case <-inputDone:
	case <-time.After(inputDrainGrace):
		log.Debugf("input drain grace exceeded, leaving the stdin reader to exit with the process")
	}
}
