//go:build !windows

package runner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// The stdin reader here ends on its own within its poll timeout, so PMG waits
// for it rather than abandoning it, and the grace only bounds that wait.
func TestWaitForInputReaderWaitsForTheReader(t *testing.T) {
	readerRuntime := 20 * time.Millisecond
	inputDone := make(chan struct{})
	go func() {
		time.Sleep(readerRuntime)
		close(inputDone)
	}()

	start := time.Now()
	waitForInputReader(inputDone)
	elapsed := time.Since(start)

	assert.GreaterOrEqual(t, elapsed, readerRuntime, "it waits for the reader to finish")
	assert.Less(t, elapsed, inputDrainGrace, "and returns before the grace expires")
}
