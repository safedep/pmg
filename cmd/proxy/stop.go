package proxy

import (
	"fmt"
	"os"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/spf13/cobra"
)

var failOnViolation bool

func newStopCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the running persistent PMG proxy server",
		// Failures here are user-facing policy outcomes, not usage errors.
		SilenceUsage: true,
		RunE:         runStop,
	}
	cmd.Flags().BoolVar(&failOnViolation, "fail-on-violation", false,
		"Exit non-zero if any package was blocked during the proxy session")
	return cmd
}

func runStop(cmd *cobra.Command, _ []string) error {
	cfg := config.Get()
	statePath := proxyserver.ResolveStatePath(stateFlag, cfg)

	res, err := proxyserver.Stop(cmd.Context(), cfg, statePath)
	if err != nil {
		return err
	}

	if res.StateVerified {
		if _, werr := fmt.Fprintf(os.Stdout, "PMG proxy stopped — %d package(s) blocked\n", res.BlockedCount); werr != nil {
			return werr
		}
	} else {
		if _, werr := fmt.Fprintf(os.Stdout, "PMG proxy (pid %d) stopped (final state unavailable)\n", res.PID); werr != nil {
			return werr
		}
	}

	return stopExitError(res, failOnViolation)
}

// stopExitError maps a stop result to the command's exit status. With
// --fail-on-violation: any blocked package fails, and an unverifiable final
// state (e.g. a crashed proxy) fails closed — a security gate must not pass on
// an unverifiable run. Without the flag, stop always succeeds.
func stopExitError(res proxyserver.StopResult, failOnViolation bool) error {
	if !failOnViolation {
		return nil
	}

	if !res.StateVerified {
		return usefulerror.NewUsefulError().
			WithCode(errcodes.ProxyPackagesBlocked).
			WithMsg("proxy shut down but the blocked-package count could not be verified").
			WithHelp("The proxy may have crashed; treat this run as failed and re-run")
	}

	if res.BlockedCount > 0 {
		return usefulerror.NewUsefulError().
			WithCode(errcodes.ProxyPackagesBlocked).
			WithMsg(fmt.Sprintf("%d package(s) were blocked by the proxy", res.BlockedCount)).
			WithHelp("Review the proxy logs for details on blocked packages")
	}

	return nil
}
