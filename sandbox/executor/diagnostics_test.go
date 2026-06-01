package executor

import (
	"context"
	"errors"
	"os/exec"
	"testing"

	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
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

func TestObserveViolationsCountsObservedViolations(t *testing.T) {
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

	assert.Equal(t, 1, ObserveViolations(result, errors.New("npm failed")))
}

func TestObserveViolationsReturnsZeroWhenNoReport(t *testing.T) {
	result := sandbox.NewExecutionResult(sandbox.WithExecutionResultSandbox(&fakeViolationSandbox{
		report: nil,
	}))

	assert.Equal(t, 0, ObserveViolations(result, errors.New("npm failed")))
}

func TestObserveViolationsReturnsZeroOnNilResult(t *testing.T) {
	assert.Equal(t, 0, ObserveViolations(nil, errors.New("npm failed")))
}
