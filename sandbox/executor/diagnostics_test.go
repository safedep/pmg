package executor

import (
	"context"
	"errors"
	"os/exec"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeViolationSandbox struct {
	report *sandbox.ViolationReport
	err    error
}

func (f *fakeViolationSandbox) Execute(context.Context, *exec.Cmd, *sandbox.SandboxPolicy, *sandbox.ExecutionContext) (*sandbox.ExecutionResult, error) {
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
	return f.report, f.err
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

func TestObserveViolationsCountsEnvScrubsWithoutDriverReport(t *testing.T) {
	result := sandbox.NewExecutionResult(sandbox.WithExecutionResultSandbox(&fakeViolationSandbox{report: nil}))
	result.SetEnvScrub(sandbox.EnvScrub{
		Names:       []string{"AWS_SECRET_ACCESS_KEY", "GOOGLE_APPLICATION_CREDENTIALS"},
		SandboxName: sandbox.DriverLandlock,
		PolicyName:  "pipx",
		Process:     "pipx",
	})

	assert.Equal(t, 2, ObserveViolations(result, errors.New("pipx failed")))
}

func TestObserveViolationsKeepsEnvScrubsWhenDiagnosticsFail(t *testing.T) {
	result := sandbox.NewExecutionResult(sandbox.WithExecutionResultSandbox(&fakeViolationSandbox{
		err: errors.New("audit socket unavailable"),
	}))
	result.SetEnvScrub(sandbox.EnvScrub{
		Names:       []string{"AWS_SECRET_ACCESS_KEY"},
		SandboxName: sandbox.DriverLandlock,
		PolicyName:  "npm",
		Process:     "npm",
	})

	assert.Equal(t, 1, ObserveViolations(result, errors.New("npm failed")))
}

func TestObserveViolationsPersistsEnvScrubToCache(t *testing.T) {
	t.Setenv("PMG_CACHE_DIR", t.TempDir())
	config.Reload()
	t.Cleanup(config.Reload)

	result := sandbox.NewExecutionResult(sandbox.WithExecutionResultSandbox(&fakeViolationSandbox{}))
	result.SetEnvScrub(sandbox.EnvScrub{
		Names:       []string{"GOOGLE_APPLICATION_CREDENTIALS"},
		SandboxName: sandbox.DriverLandlock,
		PolicyName:  "pipx",
		Process:     "pipx",
	})

	require.Equal(t, 1, ObserveViolations(result, errors.New("pipx failed")))

	entry, err := sandbox.NewViolationCache(config.Get().SandboxViolationCacheDir()).Latest()
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.NotNil(t, entry.Record.Report)

	report := entry.Record.Report
	assert.Equal(t, sandbox.DriverLandlock, report.SandboxName)
	assert.Equal(t, "pipx", report.PolicyName)
	require.Len(t, report.Violations, 1)
	assert.Equal(t, sandbox.ViolationKindEnvScrub, report.Violations[0].Kind)
	assert.Equal(t, "GOOGLE_APPLICATION_CREDENTIALS", report.Violations[0].Target)
}
