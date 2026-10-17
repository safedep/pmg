package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/safedep/dry/log"
	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/netflags"
	"github.com/safedep/pmg/internal/runner"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/executor"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// execRunner runs the command through PMG's shared execution path. Tests
// replace it to observe the parsed command and options without a sandbox.
type execRunner func(ctx context.Context, pc *packagemanager.ParsedCommand, opts runner.ExecuteOptions) error

type networkProxy interface {
	Addr() string
	Env() []string
	Stop() flows.NetworkOutcome
}

// execDeps are the seams of pmg sandbox exec.
type execDeps struct {
	config     *config.RuntimeConfig
	resolve    func(pmName string, requireSandbox bool) (*executor.Resolution, error)
	startProxy func(res *executor.Resolution) (networkProxy, error)
	run        execRunner
}

// NewExecCommand returns the `pmg sandbox exec` subcommand.
func NewExecCommand() *cobra.Command {
	return newExecCommand(execDeps{
		config:  config.Get(),
		resolve: executor.ResolvePolicy,
		startProxy: func(res *executor.Resolution) (networkProxy, error) {
			return flows.StartNetworkProxy(res)
		},
		run: runner.ExecuteWithOptions,
	})
}

func newExecCommand(deps execDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exec [--] <command> [args...]",
		Short: "Run any command in the PMG sandbox",
		Long: `Run a program under the exec sandbox profile. The program keeps its own stdin,
stdout, stderr and exit code. Flag parsing stops at the first non-flag argument.

The program's outbound connections go through a PMG proxy that applies the
network rules of the profile by host and port. The proxy reads no traffic.
Every run records the destinations it reached. After a first run, build the
profile that allows them and nothing else with:

  pmg sandbox profile propose --last --new <name>

Run with --verbose to see the destination count and the run id after the
program exits.`,
		Example: `  pmg sandbox exec -- claude
  pmg sandbox exec --sandbox-allow preset=codex -- codex
  pmg sandbox exec --sandbox-profile ./my-exec.yml -- make test
  pmg sandbox exec --network-mode enforce --network-deny '*:*' --network-allow api.anthropic.com:443 -- claude`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runExec(cmd.Context(), cmd.Flags(), args, deps); err != nil {
				return sandboxErrorExit(cmd, err)
			}
			return nil
		},
	}

	cmd.Flags().SetInterspersed(false)
	netflags.AddModeFlag(cmd.Flags(), &deps.config.Config.Sandbox.NetworkMode, "sandbox.network_mode")
	netflags.AddRuleFlags(cmd.Flags(), &deps.config.SandboxNetworkAllow, &deps.config.SandboxNetworkDeny)
	return cmd
}

func runExec(ctx context.Context, fs *pflag.FlagSet, args []string, deps execDeps) error {
	cfg := deps.config
	if len(args) == 0 {
		return invalidArgumentError(
			"no command to run",
			"Usage: pmg sandbox exec -- <command> [args...]",
		)
	}

	if err := config.ValidateSandboxNetworkMode(cfg.Config.Sandbox.NetworkMode); err != nil {
		return netflags.WrapModeError(err)
	}

	// A locked managed config owns the network policy. A flag that only
	// narrows it stays allowed. The root flags are checked before this.
	if cfg.IsLocked() {
		if widening := netflags.Widening(fs, cfg.Config.Sandbox.NetworkMode); len(widening) > 0 {
			return config.NewManagedFlagOverrideError(widening)
		}
	}

	analytics.TrackCommandSandboxExec()

	// The user asked for the sandbox by name, so this run behaves as if the
	// --sandbox flag was set. The install-only gate in config.ConfigureSandbox
	// does not apply. RequireSandbox turns a disabled policy into an error.
	cfg.Config.Sandbox.Enabled = true

	command, commandArgs := args[0], args[1:]
	audit.LogExecStarted(pmgsandbox.WorkloadExec, command, commandArgs)

	err := runExecWithProxy(ctx, command, commandArgs, deps)

	outcome := audit.OutcomeSuccess
	if err != nil {
		outcome = audit.OutcomeError
	}
	audit.LogSessionComplete(outcome, audit.FlowTypeExec, nil)

	return err
}

// runExecWithProxy resolves the policy once for the proxy and the driver,
// and runs the program behind the proxy. The report goes to stderr only
// when a deny rule matched.
func runExecWithProxy(ctx context.Context, command string, commandArgs []string, deps execDeps) error {
	res, err := deps.resolve(pmgsandbox.WorkloadExec, true)
	if err != nil {
		return err
	}

	proxy, err := deps.startProxy(res)
	if err != nil {
		return err
	}

	runErr := deps.run(ctx, &packagemanager.ParsedCommand{
		Command: packagemanager.Command{Exe: command, Args: commandArgs},
	}, runner.ExecuteOptions{
		PackageManagerName: pmgsandbox.WorkloadExec,
		ProcessLabel:       filepath.Base(command),
		DryRun:             deps.config.DryRun,
		Mode:               runner.ExecutionModeAuto,
		RequireSandbox:     true,
		Sandbox:            res,
		SandboxProxyAddr:   proxy.Addr(),
		EnvOverrides:       proxy.Env(),
	})

	// The program's exit code is the contract, so a failed report write
	// does not replace it.
	if err := reportNetwork(os.Stderr, proxy.Stop(), confinesOutbound(res), ui.Verbose()); err != nil {
		log.Warnf("failed to write the network report: %v", err)
	}
	return runErr
}

func confinesOutbound(res *executor.Resolution) bool {
	return res.Policy != nil && utils.SafelyGetValue(res.Policy.NetworkViaProxyOnly)
}

// reportNetwork writes the denials, then the proposal hint. Exec wraps
// interactive programs, so a clean run stays silent and the hint prints only
// under --verbose. A denial is already a report, so its hint always prints.
// Under enforce without network_via_proxy_only the policy applies only to
// connections that reach the proxy, and the report says so.
func reportNetwork(w io.Writer, outcome flows.NetworkOutcome, confined, verbose bool) error {
	if outcome.Report == nil {
		if !verbose {
			return nil
		}
		return ui.PrintNetworkObservation(w, outcome.Observed, outcome.RunID)
	}
	if err := ui.PrintNetworkPolicy(w, outcome.Report); err != nil {
		return err
	}
	if outcome.Report.Enforced && !confined {
		if _, err := fmt.Fprintf(w, "  %s\n", ui.Colors.Dim("The policy applies to connections that reach the proxy. Set network_via_proxy_only: true in the profile to confine the program to it.")); err != nil {
			return err
		}
	}
	return ui.PrintNetworkObservation(w, outcome.Observed, outcome.RunID)
}
