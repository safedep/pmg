//go:build windows

package runner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// PMG selects the PTY mode only when stdin is a terminal, so the stdin reader
// is always parked in a read on a console handle and can never notice the
// cancelled context. Any wait would add its full length to the exit of every
// interactive run.
func TestWaitForInputReaderDoesNotWait(t *testing.T) {
	// Never closed, which is what the reader always looks like here.
	inputDone := make(chan struct{})

	start := time.Now()
	waitForInputReader(inputDone)

	assert.Less(t, time.Since(start), 10*time.Millisecond, "the exit must not pay for a reader that cannot end")
}
