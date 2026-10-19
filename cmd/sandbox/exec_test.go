package sandbox

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/runner"
	"github.com/safedep/pmg/packagemanager"
	"github.com/safedep/pmg/proxy/netpolicy"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/executor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type execCapture struct {
	calls          int
	pc             *packagemanager.ParsedCommand
	opts           runner.ExecuteOptions
	sandboxEnabled bool
	err            error

	resolveErr error
	proxyErr   error
	proxy      *fakeNetworkProxy
}

type fakeNetworkProxy struct {
	stopped int
	outcome flows.NetworkOutcome
}

func (p *fakeNetworkProxy) Addr() string  { return "127.0.0.1:4242" }
func (p *fakeNetworkProxy) Env() []string { return packagemanager.ProxyEnv(p.Addr()) }
func (p *fakeNetworkProxy) Stop() flows.NetworkOutcome {
	p.stopped++
	return p.outcome
}

func runExecCommand(t *testing.T, cfg *config.RuntimeConfig, capture *execCapture, args ...string) error {
	t.Helper()

	if capture.proxy == nil {
		capture.proxy = &fakeNetworkProxy{}
	}
	resolution := &executor.Resolution{PackageManager: pmgsandbox.WorkloadExec, Policy: &pmgsandbox.SandboxPolicy{Name: "exec"}}
	deps := execDeps{
		config: cfg,
		resolve: func(pmName string, requireSandbox bool) (*executor.Resolution, error) {
			assert.Equal(t, pmgsandbox.WorkloadExec, pmName)
			assert.True(t, requireSandbox)
			return resolution, capture.resolveErr
		},
		startProxy: func(res *executor.Resolution) (networkProxy, error) {
			assert.Same(t, resolution, res, "the proxy gets the resolution the runner gets")
			return capture.proxy, capture.proxyErr
		},
		run: func(_ context.Context, pc *packagemanager.ParsedCommand, opts runner.ExecuteOptions) error {
			capture.calls++
			capture.pc = pc
			capture.opts = opts
			capture.sandboxEnabled = cfg.Config.Sandbox.Enabled
			return capture.err
		},
	}

	cmd := newExecCommand(deps)
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

func TestExecRunsTheProgramBehindTheNetworkProxy(t *testing.T) {
	capture := &execCapture{}
	require.NoError(t, runExecCommand(t, &config.RuntimeConfig{}, capture, "claude"))

	require.NotNil(t, capture.opts.Sandbox, "the runner gets the resolution the proxy used, so the policy resolves once")
	assert.Equal(t, "127.0.0.1:4242", capture.opts.SandboxProxyAddr, "the driver confines outbound to the proxy under network_via_proxy_only")
	assert.Contains(t, capture.opts.EnvOverrides, "HTTPS_PROXY=http://127.0.0.1:4242")
	assert.Equal(t, 1, capture.proxy.stopped, "the proxy stops after the program")
}

func TestExecStopsWhenThePolicyOrTheProxyFails(t *testing.T) {
	cases := []struct {
		name    string
		capture *execCapture
		want    error
	}{
		{"the policy does not resolve", &execCapture{resolveErr: errors.New("no policy")}, nil},
		{"the proxy does not start", &execCapture{proxyErr: errors.New("port in use")}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.capture.resolveErr
			if want == nil {
				want = tc.capture.proxyErr
			}
			require.ErrorIs(t, runExecCommand(t, &config.RuntimeConfig{}, tc.capture, "claude"), want)
			assert.Equal(t, 0, tc.capture.calls, "a program must not run without the proxy its policy relies on")
		})
	}
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

func TestExecRefusesWideningNetworkFlagsUnderLockdown(t *testing.T) {
	cases := []struct {
		name     string
		fileMode string
		args     []string
		refused  []string
	}{
		{"an allow rule widens", "enforce", []string{"--network-allow", "pastebin.com:443"}, []string{"--network-allow"}},
		{"audit over enforce widens", "enforce", []string{"--network-mode", "audit"}, []string{"--network-mode=audit"}},
		{"a deny rule narrows", "enforce", []string{"--network-deny", "pastebin.com:443"}, nil},
		{"enforce over audit narrows", "audit", []string{"--network-mode", "enforce"}, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.LockedRuntimeConfigForTest()
			cfg.Config.Sandbox.NetworkMode = tc.fileMode
			capture := &execCapture{}

			err := runExecCommand(t, cfg, capture, append(tc.args, "claude")...)
			if tc.refused == nil {
				require.NoError(t, err)
				assert.Equal(t, 1, capture.calls)
				return
			}
			require.Error(t, err)
			for _, flag := range tc.refused {
				assert.Contains(t, err.Error(), flag)
			}
			assert.Contains(t, err.Error(), "globally managed configuration")
			assert.Equal(t, 0, capture.calls)
		})
	}
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

func TestReportNetworkStaysSilentOnACleanRunUnlessVerbose(t *testing.T) {
	var out bytes.Buffer
	clean := flows.NetworkOutcome{Observed: 3, RunID: "abc123def456"}
	require.NoError(t, reportNetwork(&out, clean, false, false))
	assert.Empty(t, out.String(), "a clean run writes nothing to stderr")

	require.NoError(t, reportNetwork(&out, clean, false, true))
	assert.NotContains(t, out.String(), "Network policy", "a clean run has no denial to report")
	assert.Contains(t, out.String(), "Network: 3 destination(s) observed. Propose a profile with: pmg sandbox profile propose --run abc123def456")

	out.Reset()
	require.NoError(t, reportNetwork(&out, flows.NetworkOutcome{RunID: "abc123def456"}, false, true))
	assert.Empty(t, out.String(), "a run that reached no destination writes nothing, even under --verbose")

	denied := flows.NetworkOutcome{
		Report:   &netpolicy.Report{Enforced: true, Denials: []netpolicy.Denial{{Destination: "pastebin.com:443", Rule: "*:*", Count: 2}}},
		Observed: 3,
		RunID:    "abc123def456",
	}
	require.NoError(t, reportNetwork(&out, denied, false, false))
	assert.Contains(t, out.String(), "Network policy denied pastebin.com:443  rule *:*  (2)")
	assert.Contains(t, out.String(), "pmg sandbox allow net-connect=pastebin.com:443")
	assert.Contains(t, out.String(), "Set network_via_proxy_only: true", "an unconfined program can go around the proxy")
	assert.NotContains(t, out.String(), "propose --run", "a proposal adds no rule for a refused destination")

	out.Reset()
	require.NoError(t, reportNetwork(&out, denied, false, true))
	assert.Contains(t, out.String(), "pmg sandbox profile propose --run abc123def456", "verbose names the run after the report")

	out.Reset()
	require.NoError(t, reportNetwork(&out, denied, true, false))
	assert.NotContains(t, out.String(), "network_via_proxy_only", "a confined program cannot go around the proxy")
}

func TestExecPassesChildExitThrough(t *testing.T) {
	capture := &execCapture{err: &runner.ChildExitError{Code: 7, PMName: "sh"}}
	err := runExecCommand(t, &config.RuntimeConfig{}, capture, "sh", "-c", "exit 7")

	var childErr *runner.ChildExitError
	require.True(t, errors.As(err, &childErr))
	assert.Equal(t, 7, childErr.Code)
	assert.Equal(t, 1, capture.proxy.stopped, "the proxy stops and the run is recorded when the program fails")
}
