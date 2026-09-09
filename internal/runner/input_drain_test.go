package runner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// A read on the Windows console cannot be cancelled, so the stdin reader can
// still be parked when runPTY tears down. The wait has to end anyway, or the
// process stays alive until the developer presses a key. A regression here
// shows up as this test timing out, not as a user report.
func TestWaitForInputReader(t *testing.T) {
	t.Run("returns as soon as the reader ends", func(t *testing.T) {
		inputDone := make(chan struct{})
		close(inputDone)

		start := time.Now()
		waitForInputReader(inputDone)

		assert.Less(t, time.Since(start), inputDrainGrace,
			"a reader that already ended must not cost the grace")
	})

	t.Run("returns when the reader stays parked", func(t *testing.T) {
		// Never closed, which is a reader blocked in a read that no
		// cancellation can reach.
		inputDone := make(chan struct{})

		done := make(chan struct{})
		go func() {
			defer close(done)
			waitForInputReader(inputDone)
		}()

		select {
		case <-done:
		case <-time.After(10 * inputDrainGrace):
			t.Fatal("waitForInputReader did not return, so PMG would hang until a key is pressed")
		}
	})
}
