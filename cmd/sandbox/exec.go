package sandbox

import (
	"context"
	"path/filepath"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/runner"
	"github.com/safedep/pmg/packagemanager"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

// execRunner runs the command through PMG's shared execution path. Tests
// replace it to observe the parsed command and options without a sandbox.
type execRunner func(ctx context.Context, pc *packagemanager.ParsedCommand, opts runner.ExecuteOptions) error

// NewExecCommand returns the `pmg sandbox exec` subcommand.
func NewExecCommand() *cobra.Command {
	return newExecCommand(runner.ExecuteWithOptions, config.Get)
}

func newExecCommand(run execRunner, getConfig func() *config.RuntimeConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exec [--] <command> [args...]",
		Short: "Run any command in the PMG sandbox",
		Long: `Run a program under the exec sandbox profile. The program keeps its own stdin,
stdout, stderr and exit code. Flag parsing stops at the first non-flag argument.
Put -- before a program name that starts with a dash.

See https://github.com/safedep/pmg/blob/main/docs/sandbox-exec.md`,
		Example: `  pmg sandbox exec -- claude
  pmg sandbox exec --sandbox-allow preset=codex -- codex
  pmg sandbox exec --sandbox-profile ./my-exec.yml -- make test`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runExec(cmd.Context(), args, run, getConfig()); err != nil {
				return sandboxErrorExit(cmd, err)
			}
			return nil
		},
	}

	cmd.Flags().SetInterspersed(false)
	return cmd
}

func runExec(ctx context.Context, args []string, run execRunner, cfg *config.RuntimeConfig) error {
	if len(args) == 0 {
		return invalidArgumentError(
			"no command to run",
			"Usage: pmg sandbox exec -- <command> [args...]",
		)
	}

	analytics.TrackCommandSandboxExec()

	// The user asked for the sandbox by name, so this run behaves as if the
	// --sandbox flag was set. The install-only gate in config.ConfigureSandbox
	// does not apply. RequireSandbox turns a disabled policy into an error.
	cfg.Config.Sandbox.Enabled = true

	command, commandArgs := args[0], args[1:]
	audit.LogExecStarted(pmgsandbox.WorkloadExec, command, commandArgs)

	err := run(ctx, &packagemanager.ParsedCommand{
		Command: packagemanager.Command{Exe: command, Args: commandArgs},
	}, runner.ExecuteOptions{
		PackageManagerName: pmgsandbox.WorkloadExec,
		ProcessLabel:       filepath.Base(command),
		DryRun:             cfg.DryRun,
		Mode:               runner.ExecutionModeAuto,
		RequireSandbox:     true,
	})

	outcome := audit.OutcomeSuccess
	if err != nil {
		outcome = audit.OutcomeError
	}
	audit.LogSessionComplete(outcome, audit.FlowTypeExec)

	return err
}
