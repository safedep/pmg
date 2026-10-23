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

// isolateViolationCache points the violation cache at a temporary directory,
// so a test never writes a record into the user's real cache.
func isolateViolationCache(t *testing.T) *sandbox.ViolationCache {
	t.Helper()
	t.Setenv("PMG_CACHE_DIR", t.TempDir())
	config.Reload()
	t.Cleanup(config.Reload)

	return sandbox.NewViolationCache(config.Get().SandboxViolationCacheDir())
}

func envFileReadReport() *sandbox.ViolationReport {
	return &sandbox.ViolationReport{
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
	}
}

func TestObserveViolationsCountsObservedViolations(t *testing.T) {
	isolateViolationCache(t)
	result := sandbox.NewExecutionResult(sandbox.WithExecutionResultSandbox(&fakeViolationSandbox{
		report: envFileReadReport(),
	}))

	result.SetExitError(errors.New("npm failed"))
	assert.Equal(t, 1, ObserveViolations(result))
}

func TestObserveViolationsReturnsZeroWhenNoReport(t *testing.T) {
	isolateViolationCache(t)
	result := sandbox.NewExecutionResult(sandbox.WithExecutionResultSandbox(&fakeViolationSandbox{
		report: nil,
	}))

	result.SetExitError(errors.New("npm failed"))
	assert.Equal(t, 0, ObserveViolations(result))
}

func TestObserveViolationsReturnsZeroOnNilResult(t *testing.T) {
	assert.Equal(t, 0, ObserveViolations(nil))
}

func TestObserveViolationsCountsEnvScrubsWithoutDriverReport(t *testing.T) {
	isolateViolationCache(t)
	result := sandbox.NewExecutionResult(sandbox.WithExecutionResultSandbox(&fakeViolationSandbox{report: nil}))
	result.SetEnvScrub(sandbox.EnvScrub{
		Names:       []string{"AWS_SECRET_ACCESS_KEY", "GOOGLE_APPLICATION_CREDENTIALS"},
		SandboxName: sandbox.DriverLandlock,
		PolicyName:  "pipx",
		Process:     "pipx",
	})

	result.SetExitError(errors.New("pipx failed"))
	assert.Equal(t, 2, ObserveViolations(result))
}

func TestObserveViolationsKeepsEnvScrubsWhenDiagnosticsFail(t *testing.T) {
	isolateViolationCache(t)
	result := sandbox.NewExecutionResult(sandbox.WithExecutionResultSandbox(&fakeViolationSandbox{
		err: errors.New("audit socket unavailable"),
	}))
	result.SetEnvScrub(sandbox.EnvScrub{
		Names:       []string{"AWS_SECRET_ACCESS_KEY"},
		SandboxName: sandbox.DriverLandlock,
		PolicyName:  "npm",
		Process:     "npm",
	})

	result.SetExitError(errors.New("npm failed"))
	assert.Equal(t, 1, ObserveViolations(result))
}

func TestObserveViolationsPersistsEnvScrubToCache(t *testing.T) {
	cache := isolateViolationCache(t)

	result := sandbox.NewExecutionResult(sandbox.WithExecutionResultSandbox(&fakeViolationSandbox{}))
	result.SetEnvScrub(sandbox.EnvScrub{
		Names:       []string{"GOOGLE_APPLICATION_CREDENTIALS"},
		SandboxName: sandbox.DriverLandlock,
		PolicyName:  "pipx",
		Process:     "pipx",
	})

	result.SetExitError(errors.New("pipx failed"))
	require.Equal(t, 1, ObserveViolations(result))

	entry, err := cache.Latest()
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.NotNil(t, entry.Record.Report)

	report := entry.Record.Report
	assert.Equal(t, sandbox.DriverLandlock, report.SandboxName)
	assert.Equal(t, "pipx", report.PolicyName)
	assert.False(t, report.CleanExit)
	require.Len(t, report.Violations, 1)
	assert.Equal(t, sandbox.ViolationKindEnvScrub, report.Violations[0].Kind)
	assert.Equal(t, "GOOGLE_APPLICATION_CREDENTIALS", report.Violations[0].Target)
}

// A program can catch a denial and exit 0, so a clean run must record the
// driver's denials. It must not record a scrub-only report, because most
// runs scrub a variable and those records would push denials out of the cache.
func TestObserveViolationsOnCleanRun(t *testing.T) {
	scrub := sandbox.EnvScrub{
		Names:       []string{"AWS_SECRET_ACCESS_KEY"},
		SandboxName: sandbox.DriverSeatbelt,
		PolicyName:  "npm-restrictive",
		Process:     "npm",
	}

	tests := []struct {
		name      string
		report    *sandbox.ViolationReport
		diagErr   error
		scrub     *sandbox.EnvScrub
		wantCount int
		wantKinds []sandbox.ViolationKind
	}{
		{
			name:      "denial is recorded",
			report:    envFileReadReport(),
			wantCount: 1,
			wantKinds: []sandbox.ViolationKind{sandbox.ViolationKindFSRead},
		},
		{
			name:      "denial is recorded with the env scrub",
			report:    envFileReadReport(),
			scrub:     &scrub,
			wantCount: 2,
			wantKinds: []sandbox.ViolationKind{sandbox.ViolationKindFSRead, sandbox.ViolationKindEnvScrub},
		},
		{
			name:  "env scrub alone is not recorded",
			scrub: &scrub,
		},
		{
			name:    "env scrub is not recorded when diagnostics fail",
			diagErr: errors.New("log query failed"),
			scrub:   &scrub,
		},
		{
			name: "nothing is recorded without a denial",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cache := isolateViolationCache(t)
			result := sandbox.NewExecutionResult(sandbox.WithExecutionResultSandbox(&fakeViolationSandbox{
				report: tc.report,
				err:    tc.diagErr,
			}))
			if tc.scrub != nil {
				result.SetEnvScrub(*tc.scrub)
			}

			assert.Equal(t, tc.wantCount, ObserveViolations(result))

			entry, err := cache.Latest()
			require.NoError(t, err)
			if tc.wantCount == 0 {
				assert.Nil(t, entry)
				return
			}

			require.NotNil(t, entry)
			kinds := make([]sandbox.ViolationKind, 0, len(entry.Record.Report.Violations))
			for _, v := range entry.Record.Report.Violations {
				kinds = append(kinds, v.Kind)
			}
			assert.ElementsMatch(t, tc.wantKinds, kinds)
			assert.True(t, entry.Record.Report.CleanExit)
		})
	}
}
