package sandbox

import (
	"context"
	"errors"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/runner"
	"github.com/safedep/pmg/packagemanager"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type execCapture struct {
	calls          int
	pc             *packagemanager.ParsedCommand
	opts           runner.ExecuteOptions
	sandboxEnabled bool
	err            error
}

func runExecCommand(t *testing.T, cfg *config.RuntimeConfig, capture *execCapture, args ...string) error {
	t.Helper()

	run := func(_ context.Context, pc *packagemanager.ParsedCommand, opts runner.ExecuteOptions) error {
		capture.calls++
		capture.pc = pc
		capture.opts = opts
		capture.sandboxEnabled = cfg.Config.Sandbox.Enabled
		return capture.err
	}

	cmd := newExecCommand(run, func() *config.RuntimeConfig { return cfg })
	cmd.SetArgs(args)
	return cmd.Execute()
}

func TestExecSplitsCommandFromArgs(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantExe  string
		wantArgs []string
	}{
		{"plain", []string{"sh", "-c", "echo hi"}, "sh", []string{"-c", "echo hi"}},
		{"after dash", []string{"--", "sh", "-c", "echo hi"}, "sh", []string{"-c", "echo hi"}},
		{"program flags pass through", []string{"claude", "--debug", "-p", "x"}, "claude", []string{"--debug", "-p", "x"}},
		{"program name starting with dash", []string{"--", "-weird", "arg"}, "-weird", []string{"arg"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capture := &execCapture{}
			require.NoError(t, runExecCommand(t, &config.RuntimeConfig{}, capture, tc.args...))

			require.Equal(t, 1, capture.calls)
			assert.Equal(t, tc.wantExe, capture.pc.Command.Exe)
			assert.Equal(t, tc.wantArgs, capture.pc.Command.Args)
		})
	}
}

func TestExecRequiresCommand(t *testing.T) {
	capture := &execCapture{}
	err := runExecCommand(t, &config.RuntimeConfig{}, capture)

	var usefulErr usefulerror.UsefulError
	require.ErrorAs(t, err, &usefulErr)
	assert.Equal(t, errcodes.InvalidArgument, usefulErr.Code())
	assert.Equal(t, 0, capture.calls)
}

func TestExecForcesSandboxOnAndRequiresIt(t *testing.T) {
	cfg := &config.RuntimeConfig{DryRun: true}
	capture := &execCapture{}

	require.NoError(t, runExecCommand(t, cfg, capture, "/usr/local/bin/claude", "--resume"))

	assert.True(t, capture.sandboxEnabled, "exec turns the sandbox on for the run")
	assert.True(t, capture.opts.RequireSandbox, "a disabled policy must be an error, not a run without a sandbox")
	assert.Equal(t, pmgsandbox.WorkloadExec, capture.opts.PackageManagerName)
	assert.Equal(t, "claude", capture.opts.ProcessLabel)
	assert.Equal(t, runner.ExecutionModeAuto, capture.opts.Mode)
	assert.True(t, capture.opts.DryRun)
}

func TestExecNetworkFlagsLandInTheConfig(t *testing.T) {
	cfg := &config.RuntimeConfig{}
	capture := &execCapture{}

	require.NoError(t, runExecCommand(t, cfg, capture,
		"--network-mode", "enforce", "--network-allow", "api.anthropic.com:443", "--network-deny", "*:*", "--", "claude", "--network-mode"))

	require.Equal(t, 1, capture.calls)
	assert.Equal(t, config.SandboxNetworkModeEnforce, cfg.Config.Sandbox.NetworkMode)
	assert.Equal(t, []string{"api.anthropic.com:443"}, cfg.SandboxNetworkAllow)
	assert.Equal(t, []string{"*:*"}, cfg.SandboxNetworkDeny)
	assert.Equal(t, []string{"--network-mode"}, capture.pc.Command.Args, "a flag after the program belongs to the program")
}

func TestExecKeepsTheConfigNetworkModeWithoutTheFlag(t *testing.T) {
	cfg := &config.RuntimeConfig{}
	cfg.Config.Sandbox.NetworkMode = config.SandboxNetworkModeEnforce
	capture := &execCapture{}

	require.NoError(t, runExecCommand(t, cfg, capture, "true"))
	assert.Equal(t, config.SandboxNetworkModeEnforce, cfg.Config.Sandbox.NetworkMode)
}

func TestExecRefusesAnUnknownNetworkMode(t *testing.T) {
	capture := &execCapture{}
	err := runExecCommand(t, &config.RuntimeConfig{}, capture, "--network-mode", "loud", "true")

	var usefulErr usefulerror.UsefulError
	require.ErrorAs(t, err, &usefulErr)
	assert.Equal(t, errcodes.InvalidArgument, usefulErr.Code())
	assert.Contains(t, err.Error(), "sandbox.network_mode")
	assert.Equal(t, 0, capture.calls)
}

func TestExecPassesChildExitThrough(t *testing.T) {
	capture := &execCapture{err: &runner.ChildExitError{Code: 7, PMName: "sh"}}
	err := runExecCommand(t, &config.RuntimeConfig{}, capture, "sh", "-c", "exit 7")

	var childErr *runner.ChildExitError
	require.True(t, errors.As(err, &childErr))
	assert.Equal(t, 7, childErr.Code)
}
