package ui

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// fakeChildExit satisfies the transparentExit interface, standing in for
// *runner.ChildExitError without a cross-package import.
type fakeChildExit struct {
	code     int
	signaled bool
	pmName   string
}

func (e *fakeChildExit) Error() string    { return fmt.Sprintf("%s exited with code %d", e.pmName, e.code) }
func (e *fakeChildExit) ExitCode() int    { return e.code }
func (e *fakeChildExit) Transparent() bool { return true }
func (e *fakeChildExit) IsSignaled() bool { return e.signaled }

func withVerbosity(t *testing.T, level VerbosityLevel) {
	t.Helper()
	prev := verbosityLevel
	verbosityLevel = level
	t.Cleanup(func() { verbosityLevel = prev })
}

func TestClassifyExit(t *testing.T) {
	t.Run("genuine non-zero child exit prints a dim notice and mirrors the code", func(t *testing.T) {
		withVerbosity(t, VerbosityLevelNormal)

		d := classifyExit(&fakeChildExit{code: 1, pmName: "npm"})

		assert.True(t, d.transparent)
		assert.Equal(t, 1, d.code)
		assert.True(t, d.notice)
		assert.Equal(t, "↳ pmg: npm exited with code 1", d.message)
	})

	t.Run("transparent exit is detected even when wrapped", func(t *testing.T) {
		withVerbosity(t, VerbosityLevelNormal)

		wrapped := fmt.Errorf("failed to execute command: %w", &fakeChildExit{code: 2, pmName: "pnpm"})
		d := classifyExit(wrapped)

		assert.True(t, d.transparent)
		assert.Equal(t, 2, d.code)
		assert.True(t, d.notice)
	})

	t.Run("signal termination is silent but still mirrors the code", func(t *testing.T) {
		withVerbosity(t, VerbosityLevelNormal)

		d := classifyExit(&fakeChildExit{code: 130, signaled: true, pmName: "npm"})

		assert.True(t, d.transparent)
		assert.Equal(t, 130, d.code)
		assert.False(t, d.notice)
		assert.Empty(t, d.message)
	})

	t.Run("silent mode suppresses the notice", func(t *testing.T) {
		withVerbosity(t, VerbosityLevelSilent)

		d := classifyExit(&fakeChildExit{code: 1, pmName: "npm"})

		assert.True(t, d.transparent)
		assert.Equal(t, 1, d.code)
		assert.False(t, d.notice)
	})

	t.Run("non-transparent error falls through to the loud path", func(t *testing.T) {
		d := classifyExit(errors.New("some PMG failure"))

		assert.False(t, d.transparent)
		assert.False(t, d.notice)
	})
}
