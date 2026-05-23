package executor

import (
	"context"
	"errors"
	"os/exec"
	"testing"

	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeViolationSandbox struct {
	report *sandbox.ViolationReport
}

func (f *fakeViolationSandbox) Execute(context.Context, *exec.Cmd, *sandbox.SandboxPolicy) (*sandbox.ExecutionResult, error) {
	return sandbox.NewExecutionResult(), nil
}

func (f *fakeViolationSandbox) Name() sandbox.DriverName {
	return sandbox.DriverSeatbelt
}

func (f *fakeViolationSandbox) IsAvailable() bool {
	return true
}

func (f *fakeViolationSandbox) Close() error {
	return nil
}

func (f *fakeViolationSandbox) BestEffortViolation(error) (*sandbox.ViolationReport, error) {
	return f.report, nil
}

// WrapCommandExecutionError must never claim the sandbox blocked a command.
// Even when violations were observed, the user-facing error stays the package
// manager's native exit; a neutral breadcrumb points at the forensic command.
func TestWrapCommandExecutionErrorDoesNotAttributeFailureToSandbox(t *testing.T) {
	result := sandbox.NewExecutionResult(sandbox.WithExecutionResultSandbox(&fakeViolationSandbox{
		report: &sandbox.ViolationReport{
			SandboxName:   sandbox.DriverSeatbelt,
			PolicyName:    "npm-restrictive",
			CorrelationID: "run-1",
			Violations: []sandbox.Violation{
				{
					Kind:       sandbox.ViolationKindFSRead,
					RawKind:    "file-read",
					Target:     "./.env",
					RuleTarget: "**/.env",
					RuleLabel:  "read access denied: ./.env",
				},
			},
		},
	}))

	err := WrapCommandExecutionError(errors.New("npm failed"), result, 1)

	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.PackageManagerExecutionFailed, usefulErr.Code())
	assert.Equal(t, "Package manager command exited with code: 1", usefulErr.HumanError())
	assert.NotContains(t, usefulErr.Help(), "./.env")
	assert.Contains(t, usefulErr.AdditionalHelp(), "pmg sandbox violations list")
}

func TestWrapCommandExecutionErrorOmitsBreadcrumbWhenNoViolations(t *testing.T) {
	result := sandbox.NewExecutionResult(sandbox.WithExecutionResultSandbox(&fakeViolationSandbox{
		report: nil,
	}))

	err := WrapCommandExecutionError(errors.New("npm failed"), result, 1)

	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.PackageManagerExecutionFailed, usefulErr.Code())
	assert.NotContains(t, usefulErr.AdditionalHelp(), "pmg sandbox violations list")
}

func TestWrapCommandExecutionErrorReturnsNilOnNilError(t *testing.T) {
	assert.NoError(t, WrapCommandExecutionError(nil, nil, 0))
}
