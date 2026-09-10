//go:build !windows

package runner

import (
	"time"

	"github.com/safedep/dry/log"
)

// inputDrainGrace bounds the wait for the stdin reader. The reader is a poll
// loop with its own short timeout, so it notices the cancelled context and
// returns. The bound is a safety net against a reader that does not, never
// the expected path.
const inputDrainGrace = 200 * time.Millisecond

func waitForInputReader(inputDone <-chan struct{}) {
	select {
	case <-inputDone:
	case <-time.After(inputDrainGrace):
		log.Debugf("input drain grace exceeded, leaving the stdin reader to exit with the process")
	}
}
