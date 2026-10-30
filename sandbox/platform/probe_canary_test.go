package platform

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/pmg/sandbox"
)

type fakeSandbox struct {
	name        sandbox.DriverName
	available   bool
	executeErr  error
	executedRun bool
	closed      bool
}

func (f *fakeSandbox) Execute(ctx context.Context, cmd *exec.Cmd, policy *sandbox.SandboxPolicy, rt *sandbox.ExecutionContext) (*sandbox.ExecutionResult, error) {
	if f.executeErr != nil {
		return nil, f.executeErr
	}
	return sandbox.NewExecutionResult(
		sandbox.WithExecutionResultSandbox(f),
		sandbox.WithExecutionResultExecuted(f.executedRun),
	), nil
}

func (f *fakeSandbox) Name() sandbox.DriverName { return f.name }
func (f *fakeSandbox) IsAvailable() bool        { return f.available }
func (f *fakeSandbox) Close() error             { f.closed = true; return nil }

func trueCmd(ctx context.Context) *exec.Cmd  { return exec.CommandContext(ctx, "true") }
func falseCmd(ctx context.Context) *exec.Cmd { return exec.CommandContext(ctx, "false") }

func killedCmd(ctx context.Context) *exec.Cmd {
	return exec.CommandContext(ctx, "sh", "-c", "kill -9 $$")
}

func missingCmd(ctx context.Context) *exec.Cmd {
	return exec.CommandContext(ctx, "/nonexistent/pmg-canary")
}

// maskedCanaryCmd exits 0 with no output, as cat does when the sandbox
// masks the target with /dev/null. The macOS printf binary rejects an
// empty format, so true stands in for cat.
func maskedCanaryCmd(ctx context.Context) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "true")
	cmd.Args = []string{"cat", canaryTargetPath}
	return cmd
}

// deniedCanaryCmd fails as cat does when the sandbox denies the read.
func deniedCanaryCmd(ctx context.Context) *exec.Cmd {
	return exec.CommandContext(ctx, "sh", "-c", "echo 'cat: "+canaryTargetPath+": Permission denied' >&2; exit 1")
}

func TestRunCanary(t *testing.T) {
	tests := []struct {
		name    string
		factory canarySandboxFactory
		cmd     canaryCommandFactory
		want    sandbox.ProbeStatus
	}{
		{
			name:    "ok blocks read",
			factory: func() (sandbox.Sandbox, error) { return &fakeSandbox{name: "fake", available: true}, nil },
			cmd:     deniedCanaryCmd,
			want:    sandbox.ProbeStatusOK,
		},
		{
			name:    "fail exit without a denial",
			factory: func() (sandbox.Sandbox, error) { return &fakeSandbox{name: "fake", available: true}, nil },
			cmd:     falseCmd,
			want:    sandbox.ProbeStatusFail,
		},
		{
			name:    "ok masks read",
			factory: func() (sandbox.Sandbox, error) { return &fakeSandbox{name: "fake", available: true}, nil },
			cmd:     maskedCanaryCmd,
			want:    sandbox.ProbeStatusOK,
		},
		{
			name:    "fail did not block",
			factory: func() (sandbox.Sandbox, error) { return &fakeSandbox{name: "fake", available: true}, nil },
			cmd:     trueCmd,
			want:    sandbox.ProbeStatusFail,
		},
		{
			name:    "fail killed by a signal",
			factory: func() (sandbox.Sandbox, error) { return &fakeSandbox{name: "fake", available: true}, nil },
			cmd:     killedCmd,
			want:    sandbox.ProbeStatusFail,
		},
		{
			name:    "fail did not start",
			factory: func() (sandbox.Sandbox, error) { return &fakeSandbox{name: "fake", available: true}, nil },
			cmd:     missingCmd,
			want:    sandbox.ProbeStatusFail,
		},
		{
			name:    "skip not available",
			factory: func() (sandbox.Sandbox, error) { return &fakeSandbox{name: "fake", available: false}, nil },
			cmd:     falseCmd,
			want:    sandbox.ProbeStatusSkipped,
		},
		{
			name:    "fail constructor error",
			factory: func() (sandbox.Sandbox, error) { return nil, errors.New("boom") },
			cmd:     falseCmd,
			want:    sandbox.ProbeStatusFail,
		},
		{
			name: "fail execute error",
			factory: func() (sandbox.Sandbox, error) {
				return &fakeSandbox{name: "fake", available: true, executeErr: errors.New("setup failed")}, nil
			},
			cmd:  falseCmd,
			want: sandbox.ProbeStatusFail,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := runCanary(context.Background(), "canary.fake", "fake", tc.factory, tc.cmd)
			assert.Equal(t, "canary.fake", res.Name)
			assert.Equal(t, tc.want, res.Status)
		})
	}
}

// Without the guard, cat exits 1 and names the missing target, and the
// probe would report OK.
func TestRunCanaryTargetMissing(t *testing.T) {
	orig := canaryTargetPath
	canaryTargetPath = filepath.Join(t.TempDir(), "missing")
	t.Cleanup(func() { canaryTargetPath = orig })

	factory := func() (sandbox.Sandbox, error) { return &fakeSandbox{name: "fake", available: true}, nil }
	res := runCanary(context.Background(), "canary.fake", "fake", factory, defaultCanaryCommand)
	assert.Equal(t, sandbox.ProbeStatusFail, res.Status)
	assert.Contains(t, res.Summary, "not found")
}

func TestCanaryPolicy(t *testing.T) {
	p := canaryPolicy()
	require.NoError(t, p.ValidateResolved())
	assert.Contains(t, p.Filesystem.DenyRead, canaryTargetPath)
	// Seatbelt denies by default. Without a read allowance the canary
	// cannot load its libraries, and the kernel kills it with SIGABRT.
	assert.Contains(t, p.Filesystem.AllowRead, "/")
	if runtime.GOOS == "windows" {
		return
	}
	// Seatbelt matches the resolved path. On macOS /etc is a link.
	resolved, err := filepath.EvalSymlinks(canaryTargetPath)
	require.NoError(t, err)
	assert.Contains(t, p.Filesystem.DenyRead, resolved)
}

func TestCanaryTargetExistsOnThisHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the sandbox is not supported on Windows")
	}
	// A missing target makes cat exit 1 without a denial, and the probe
	// would report that as a block. macOS has no /etc/hostname.
	_, err := os.Stat(canaryTargetPath)
	require.NoError(t, err)
}

func TestDriverInstallFix_BubblewrapIsDistroNeutral(t *testing.T) {
	fix := driverInstallFix(sandbox.DriverBubblewrap)
	assert.Contains(t, fix.Description, "distribution package manager")
	assert.Empty(t, fix.Command)
	assert.Equal(t, "https://github.com/containers/bubblewrap", fix.Docs)
}

func TestDefaultProbes_NotEmpty(t *testing.T) {
	probes := DefaultProbes()
	assert.NotEmpty(t, probes)
}
