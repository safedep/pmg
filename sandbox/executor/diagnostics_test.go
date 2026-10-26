package executor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
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

func TestAuditReport(t *testing.T) {
	read := func(target, process string) sandbox.Violation {
		return sandbox.Violation{Kind: sandbox.ViolationKindFSRead, Target: target, RuleTarget: "/Users/dev/.ssh", Process: process}
	}

	tests := []struct {
		name   string
		report *sandbox.ViolationReport
		want   []audit.SandboxViolation
	}{
		{
			name: "repeats of one denial become one entry with a count",
			report: &sandbox.ViolationReport{Violations: []sandbox.Violation{
				read("/Users/dev/.ssh/id_rsa", "node"),
				read("/Users/dev/.ssh/config", "node"),
				read("/Users/dev/.ssh/id_rsa", "node"),
				read("/Users/dev/.ssh/id_rsa", "node"),
			}},
			want: []audit.SandboxViolation{
				{Kind: sandbox.ViolationKindFSRead, Path: "/Users/dev/.ssh/id_rsa", Rule: "/Users/dev/.ssh", Process: "node", Count: 3},
				{Kind: sandbox.ViolationKindFSRead, Path: "/Users/dev/.ssh/config", Rule: "/Users/dev/.ssh", Process: "node", Count: 1},
			},
		},
		{
			name: "another process or kind is another entry",
			report: &sandbox.ViolationReport{Violations: []sandbox.Violation{
				read("/Users/dev/.npmrc", "node"),
				read("/Users/dev/.npmrc", "sh"),
				{Kind: sandbox.ViolationKindFSWrite, Target: "/Users/dev/.npmrc", Process: "node"},
			}},
			want: []audit.SandboxViolation{
				{Kind: sandbox.ViolationKindFSRead, Path: "/Users/dev/.npmrc", Rule: "/Users/dev/.ssh", Process: "node", Count: 1},
				{Kind: sandbox.ViolationKindFSRead, Path: "/Users/dev/.npmrc", Rule: "/Users/dev/.ssh", Process: "sh", Count: 1},
				{Kind: sandbox.ViolationKindFSWrite, Path: "/Users/dev/.npmrc", Process: "node", Count: 1},
			},
		},
		{
			name: "env scrubs and noise stay out",
			report: &sandbox.ViolationReport{
				SandboxName: sandbox.DriverSeatbelt,
				Violations: []sandbox.Violation{
					{Kind: sandbox.ViolationKindEnvScrub, Target: "AWS_SECRET_ACCESS_KEY", Process: "node"},
					{Kind: sandbox.ViolationKindFSWrite, Target: "/dev/dtracehelper", Process: "node"},
					{Kind: sandbox.ViolationKindGenericDeny, Process: "node"},
					read("/Users/dev/.ssh/id_rsa", "node"),
				},
			},
			want: []audit.SandboxViolation{
				{Kind: sandbox.ViolationKindFSRead, Path: "/Users/dev/.ssh/id_rsa", Rule: "/Users/dev/.ssh", Process: "node", Count: 1},
			},
		},
		{
			name: "only env scrubs and noise report nothing",
			report: &sandbox.ViolationReport{
				SandboxName: sandbox.DriverSeatbelt,
				Violations: []sandbox.Violation{
					{Kind: sandbox.ViolationKindEnvScrub, Target: "AWS_SECRET_ACCESS_KEY"},
					{Kind: sandbox.ViolationKindGenericDeny},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := auditReport(tc.report)
			assert.Equal(t, len(tc.want) > 0, ok)
			assert.ElementsMatch(t, tc.want, got.Violations)
		})
	}
}

func TestAuditReportRanksAndSplitsTargets(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)
	port := func(p uint16) *uint16 { return &p }

	report := &sandbox.ViolationReport{
		SandboxName: sandbox.DriverSeatbelt,
		PolicyName:  "npm",
		CleanExit:   true,
		Violations: []sandbox.Violation{
			{Kind: sandbox.ViolationKindNetworkBind, Target: "local:*:0", Process: "python3"},
			{Kind: sandbox.ViolationKindNetworkConnect, Target: "1.2.3.4:443", Process: "curl"},
			{Kind: sandbox.ViolationKindExec, Target: "/usr/bin/curl", Process: "sh"},
			{Kind: sandbox.ViolationKindNetworkConnect, Target: "/private/var/run/mDNSResponder", Process: "node"},
			{Kind: sandbox.ViolationKindFSRead, Target: filepath.Join(cwd, ".env"), Process: "node"},
		},
	}

	got, ok := auditReport(report)
	require.True(t, ok)
	assert.Equal(t, sandbox.DriverSeatbelt, got.Driver)
	assert.Equal(t, "npm", got.Profile)
	assert.True(t, got.CleanExit)

	require.Len(t, got.Violations, 5)
	assert.Equal(t, audit.SandboxViolation{Kind: sandbox.ViolationKindFSRead, Path: filepath.Join(cwd, ".env"), Process: "node", Count: 1},
		got.Violations[0], "a project secret ranks first")
	assert.ElementsMatch(t, []audit.SandboxViolation{
		{Kind: sandbox.ViolationKindNetworkBind, Host: "*", Port: port(0), Process: "python3", Count: 1},
		{Kind: sandbox.ViolationKindNetworkConnect, Host: "1.2.3.4", Port: port(443), Process: "curl", Count: 1},
		{Kind: sandbox.ViolationKindExec, Executable: "/usr/bin/curl", Process: "sh", Count: 1},
		{Kind: sandbox.ViolationKindNetworkConnect, Path: "/private/var/run/mDNSResponder", Process: "node", Count: 1},
	}, got.Violations[1:])
}
