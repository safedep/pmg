package runner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// waitForInputReader has to return whether or not the stdin reader ever ends.
// A reader that cannot be woken never ends, and waiting for it is what held
// `pmg npm install` open on Windows until the developer pressed a key.
func TestWaitForInputReaderAlwaysReturns(t *testing.T) {
	parked := make(chan struct{})
	finished := make(chan struct{})
	close(finished)

	tests := []struct {
		name      string
		inputDone chan struct{}
	}{
		{"a reader that never ends", parked},
		{"a reader that already ended", finished},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, returnsWithin(t, tt.inputDone, 5*time.Second),
				"PMG would hang until a key is pressed")
		})
	}
}

// The reader normally ends on its own once its context is cancelled, so PMG
// joins it rather than abandoning it, and the grace only bounds that join.
func TestWaitForInputReaderJoinsTheReader(t *testing.T) {
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

func returnsWithin(t *testing.T, inputDone <-chan struct{}, limit time.Duration) bool {
	t.Helper()

	done := make(chan struct{})
	go func() {
		defer close(done)
		waitForInputReader(inputDone)
	}()

	select {
	case <-done:
		return true
	case <-time.After(limit):
		return false
	}
}
