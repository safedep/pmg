package platform

import (
	"context"
	"errors"
	"os/exec"
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

func (f *fakeSandbox) Execute(ctx context.Context, cmd *exec.Cmd, policy *sandbox.SandboxPolicy) (*sandbox.ExecutionResult, error) {
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

func maskedCanaryCmd(ctx context.Context) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "printf", "")
	cmd.Args = []string{"cat", "", canaryTargetPath}
	return cmd
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
			cmd:     falseCmd,
			want:    sandbox.ProbeStatusOK,
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

func TestDenyAllCanaryPolicy(t *testing.T) {
	p := denyAllCanaryPolicy()
	require.NoError(t, p.ValidateResolved())
	assert.Contains(t, p.Filesystem.DenyRead, canaryTargetPath)
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
