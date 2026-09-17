package flows

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/runerror"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingParsePackageManager struct {
	err       error
	parsed    *packagemanager.ParsedCommand
	ecosystem packagev1.Ecosystem
}

func (f failingParsePackageManager) Name() string { return "npm" }
func (f failingParsePackageManager) Ecosystem() packagev1.Ecosystem {
	if f.ecosystem != packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED {
		return f.ecosystem
	}
	return packagev1.Ecosystem_ECOSYSTEM_NPM
}
func (f failingParsePackageManager) ParseCommand([]string) (*packagemanager.ParsedCommand, error) {
	return f.parsed, f.err
}

type proxyAuditCapture struct {
	starts      int
	completions int
	manager     string
	args        []string
	outcome     audit.Outcome
	flow        audit.FlowType
	info        *runerror.Info
}

func (c *proxyAuditCapture) start(manager string, args []string) {
	c.starts++
	c.manager = manager
	c.args = append([]string(nil), args...)
}

func (c *proxyAuditCapture) complete(outcome audit.Outcome, flow audit.FlowType, info *runerror.Info) {
	c.completions++
	c.outcome = outcome
	c.flow = flow
	c.info = info
}

func TestRunProxyLifecycle(t *testing.T) {
	t.Cleanup(config.Reload)
	t.Setenv("PMG_CONFIG_DIR", t.TempDir())
	config.Reload()
	cfg := config.Get()
	baseline := *cfg

	tests := []struct {
		name        string
		manager     failingParsePackageManager
		configure   func(*config.RuntimeConfig)
		wantOutcome audit.Outcome
		wantFlow    audit.FlowType
		wantReason  runerror.Reason
		wantCode    *uint32
	}{
		{
			name: "parse failure", manager: failingParsePackageManager{err: errors.New("parse")},
			wantOutcome: audit.OutcomeError, wantReason: runerror.ReasonCommandParseFailed,
		},
		{
			name: "intercepted setup failure",
			manager: failingParsePackageManager{
				parsed: &packagemanager.ParsedCommand{}, ecosystem: packagev1.Ecosystem_ECOSYSTEM_MAVEN,
			},
			wantOutcome: audit.OutcomeError, wantFlow: audit.FlowTypeProxy,
			wantReason: runerror.ReasonEcosystemUnsupported,
		},
		{
			name: "dry run",
			manager: failingParsePackageManager{parsed: &packagemanager.ParsedCommand{
				Command: packagemanager.Command{Exe: "npm"},
			}},
			configure:   func(cfg *config.RuntimeConfig) { cfg.DryRun = true },
			wantOutcome: audit.OutcomeDryRun, wantFlow: audit.FlowTypeProxy,
		},
		{
			name: "skipped child exit",
			manager: failingParsePackageManager{parsed: &packagemanager.ParsedCommand{
				Command: helperProcessCommand(t, 42), IsKnownNonDownloadCommand: true,
			}},
			configure:   func(cfg *config.RuntimeConfig) { cfg.Config.Proxy.InstallOnly = true },
			wantOutcome: audit.OutcomeError, wantReason: runerror.ReasonProcessExited,
			wantCode: uint32Pointer(42),
		},
		{
			name: "intercepted child exit",
			manager: failingParsePackageManager{parsed: &packagemanager.ParsedCommand{
				Command: helperProcessCommand(t, 42),
			}},
			wantOutcome: audit.OutcomeError, wantFlow: audit.FlowTypeProxy,
			wantReason: runerror.ReasonProcessExited, wantCode: uint32Pointer(42),
		},
		{
			name: "skipped success",
			manager: failingParsePackageManager{parsed: &packagemanager.ParsedCommand{
				Command: helperProcessCommand(t, 0), IsKnownNonDownloadCommand: true,
			}},
			configure:   func(cfg *config.RuntimeConfig) { cfg.Config.Proxy.InstallOnly = true },
			wantOutcome: audit.OutcomeSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			*cfg = baseline
			cfg.Config.Sandbox.Enabled = false
			if tt.configure != nil {
				tt.configure(cfg)
			}

			capture := &proxyAuditCapture{}
			err := runProxyWithAudit(context.Background(), tt.manager, []string{"install", "pkg"},
				capture.start, capture.complete)

			assert.Equal(t, 1, capture.starts)
			assert.Equal(t, 1, capture.completions)
			assert.Equal(t, "npm", capture.manager)
			assert.Equal(t, []string{"install", "pkg"}, capture.args)
			assert.Equal(t, tt.wantOutcome, capture.outcome)
			assert.Equal(t, tt.wantFlow, capture.flow)
			if tt.wantReason == runerror.ReasonUnspecified {
				assert.NoError(t, err)
				assert.Nil(t, capture.info)
				return
			}

			require.Error(t, err)
			require.NotNil(t, capture.info)
			assert.Equal(t, tt.wantReason, capture.info.Reason)
			assert.Equal(t, tt.wantCode, capture.info.ExitCode)
		})
	}
}

func TestProxyFlowChildProcess(t *testing.T) {
	for i, arg := range os.Args {
		if arg != "--" || i+1 >= len(os.Args) {
			continue
		}
		code, err := strconv.Atoi(os.Args[i+1])
		require.NoError(t, err)
		os.Exit(code)
	}
}

func helperProcessCommand(t *testing.T, exitCode int) packagemanager.Command {
	t.Helper()
	executable, err := os.Executable()
	require.NoError(t, err)
	return packagemanager.Command{
		Exe:  executable,
		Args: []string{"-test.run=^TestProxyFlowChildProcess$", "--", strconv.Itoa(exitCode)},
	}
}

func TestRunProxyClassifiesParseFailure(t *testing.T) {
	cause := errors.New("private parse detail")
	err := RunProxy(context.Background(), failingParsePackageManager{err: cause}, []string{"install"})

	require.ErrorIs(t, err, cause)
	info := runerror.From(err)
	require.NotNil(t, info)
	assert.Equal(t, runerror.ReasonCommandParseFailed, info.Reason)
	assert.Equal(t, "PMG could not parse the package-manager command.", info.Message)
}

func TestRunProxySessionCompletesOnce(t *testing.T) {
	tests := []struct {
		name        string
		result      proxyRunResult
		err         error
		wantOutcome audit.Outcome
		wantInfo    bool
	}{
		{
			name: "success", result: proxyRunResult{outcome: ui.OutcomeSuccess, flow: audit.FlowTypeProxy},
			wantOutcome: audit.OutcomeSuccess,
		},
		{
			name: "dry run", result: proxyRunResult{outcome: ui.OutcomeDryRun, flow: audit.FlowTypeProxy},
			wantOutcome: audit.OutcomeDryRun,
		},
		{
			name: "early error", err: errors.New("unknown failure"),
			wantOutcome: audit.OutcomeError, wantInfo: true,
		},
		{
			name:   "blocked with child error",
			result: proxyRunResult{outcome: ui.OutcomeBlocked, flow: audit.FlowTypeProxy},
			err: runerror.Wrap(errors.New("child failed"), runerror.ReasonProcessExited,
				"npm exited with code 42."),
			wantOutcome: audit.OutcomeBlocked, wantInfo: true,
		},
		{
			name:   "user cancelled with child error",
			result: proxyRunResult{outcome: ui.OutcomeUserCancelled, flow: audit.FlowTypeProxy},
			err: runerror.Wrap(errors.New("child failed"), runerror.ReasonProcessExited,
				"npm exited with code 42."),
			wantOutcome: audit.OutcomeUserCancelled, wantInfo: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			var gotOutcome audit.Outcome
			var gotInfo *runerror.Info
			err := runProxySession(func() (proxyRunResult, error) {
				return tt.result, tt.err
			}, func(outcome audit.Outcome, _ audit.FlowType, info *runerror.Info) {
				calls++
				gotOutcome = outcome
				gotInfo = info
			})

			assert.ErrorIs(t, err, tt.err)
			assert.Equal(t, 1, calls)
			assert.Equal(t, tt.wantOutcome, gotOutcome)
			if tt.wantInfo {
				require.NotNil(t, gotInfo)
			} else {
				assert.Nil(t, gotInfo)
			}
		})
	}
}

func uint32Pointer(value uint32) *uint32 {
	return &value
}
