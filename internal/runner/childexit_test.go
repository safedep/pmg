package runner

import (
	"context"
	"errors"
	"os/exec"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/pty"
	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractExit(t *testing.T) {
	t.Run("direct non-zero exit resolves the real code", func(t *testing.T) {
		err := exec.Command("sh", "-c", "exit 2").Run()
		require.Error(t, err)

		code, signaled, resolved := extractExit(err)
		assert.Equal(t, 2, code)
		assert.False(t, signaled)
		assert.True(t, resolved)
	})

	t.Run("direct signal termination resolves to 128+signum", func(t *testing.T) {
		err := exec.Command("sh", "-c", "kill -INT $$").Run()
		require.Error(t, err)

		code, signaled, resolved := extractExit(err)
		assert.Equal(t, 130, code) // 128 + SIGINT(2)
		assert.True(t, signaled)
		assert.True(t, resolved)
	})

	t.Run("pty exit error reads its fields directly", func(t *testing.T) {
		code, signaled, resolved := extractExit(&pty.ExitError{Code: 1})
		assert.Equal(t, 1, code)
		assert.False(t, signaled)
		assert.True(t, resolved)

		code, signaled, resolved = extractExit(&pty.ExitError{Code: 143, Signaled: true})
		assert.Equal(t, 143, code)
		assert.True(t, signaled)
		assert.True(t, resolved)
	})

	t.Run("non-exit error is unresolved", func(t *testing.T) {
		_, _, resolved := extractExit(errors.New("failed to launch binary"))
		assert.False(t, resolved)
	})
}

func TestDecideExit(t *testing.T) {
	runErr := errors.New("npm failed")

	t.Run("plain child exit becomes a transparent ChildExitError", func(t *testing.T) {
		err := decideExit(runErr, 1, false, true, "npm")

		var ce *ChildExitError
		require.True(t, errors.As(err, &ce))
		assert.Equal(t, 1, ce.ExitCode())
		assert.True(t, ce.Transparent())
		assert.False(t, ce.IsSignaled())
		assert.Equal(t, "npm", ce.PMName)
	})

	t.Run("signaled child exit is transparent and signaled", func(t *testing.T) {
		err := decideExit(runErr, 130, true, true, "npm")

		var ce *ChildExitError
		require.True(t, errors.As(err, &ce))
		assert.True(t, ce.IsSignaled())
		assert.Equal(t, 130, ce.ExitCode())
	})

	t.Run("unresolved exit is a visible launch failure", func(t *testing.T) {
		err := decideExit(runErr, -1, false, false, "npm")

		usefulErr, ok := usefulerror.AsUsefulError(err)
		require.True(t, ok)
		assert.Equal(t, errcodes.PackageManagerExecutionFailed, usefulErr.Code())
		assert.Equal(t, "Failed to execute package manager command", usefulErr.HumanError())

		var ce *ChildExitError
		assert.False(t, errors.As(err, &ce))
	})
}

// A restrictive sandbox routinely denies benign operations, so observed
// violations must NOT make a child's own non-zero exit loud. They are persisted
// for forensic review but the exit stays transparent (issue #309).
func TestClassifyStaysTransparentDespiteViolations(t *testing.T) {
	result := sandbox.NewExecutionResult(sandbox.WithExecutionResultSandbox(&fakeViolationSandbox{
		report: &sandbox.ViolationReport{
			SandboxName: sandbox.DriverSeatbelt,
			PolicyName:  "npm-restrictive",
			Violations: []sandbox.Violation{
				{Kind: sandbox.ViolationKindFSRead, Target: "./.npmrc"},
				{Kind: sandbox.ViolationKindFSRead, Target: "./.env"},
			},
		},
	}))

	childErr := exec.Command("sh", "-c", "exit 1").Run()
	require.Error(t, childErr)

	err := classify(childErr, result, "npm")

	var ce *ChildExitError
	require.True(t, errors.As(err, &ce), "non-zero exit under sandbox must stay transparent")
	assert.Equal(t, 1, ce.ExitCode())
}

type fakeViolationSandbox struct {
	report *sandbox.ViolationReport
}

func (f *fakeViolationSandbox) Execute(context.Context, *exec.Cmd, *sandbox.SandboxPolicy) (*sandbox.ExecutionResult, error) {
	return sandbox.NewExecutionResult(), nil
}
func (f *fakeViolationSandbox) Name() sandbox.DriverName { return sandbox.DriverSeatbelt }
func (f *fakeViolationSandbox) IsAvailable() bool        { return true }
func (f *fakeViolationSandbox) Close() error             { return nil }
func (f *fakeViolationSandbox) BestEffortViolation(error) (*sandbox.ViolationReport, error) {
	return f.report, nil
}
