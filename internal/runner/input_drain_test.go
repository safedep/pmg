package runner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// waitForInputReader has to return whether or not the stdin reader ever ends.
// On Windows the reader is blocked in a read that no cancellation can reach,
// so it never ends. Waiting for it is what held `pmg npm install` open until
// the developer pressed a key.
func TestWaitForInputReaderAlwaysReturns(t *testing.T) {
	parked := make(chan struct{})
	finished := make(chan struct{})
	close(finished)

	tests := []struct {
		name      string
		inputDone chan struct{}
	}{
		{"a reader parked in a read that cannot be cancelled", parked},
		{"a reader that already ended", finished},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, returnsWithin(t, tt.inputDone, 5*time.Second),
				"PMG would hang until a key is pressed")
		})
	}
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
