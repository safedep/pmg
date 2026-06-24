package proxy

import (
	"fmt"
	"os"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/safedep/pmg/internal/ui"
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
		ui.ErrorExit(err)
	}

	// On a policy violation the framed error carries the message; return before
	// printing the plain summary so the blocked count is not stated twice.
	if verr := stopExitError(res, failOnViolation); verr != nil {
		ui.ErrorExit(verr)
	}

	summary := fmt.Sprintf("PMG proxy stopped — %d package(s) blocked\n", res.BlockedCount)
	if !res.StateVerified {
		summary = fmt.Sprintf("PMG proxy (pid %d) stopped (final state unavailable)\n", res.PID)
	}
	if _, werr := fmt.Fprint(os.Stdout, summary); werr != nil {
		ui.ErrorExit(werr)
	}

	return nil
}

// stopExitError maps a stop result to the command's exit status. With
// --fail-on-violation: any blocked package fails, and an unverifiable final
// state (e.g. a crashed proxy) fails closed — a security gate must not pass on
// an unverifiable run. Without the flag, stop always succeeds.
func stopExitError(res proxyserver.StopResult, failOnViolation bool) error {
	if !failOnViolation {
		return nil
	}

	// HumanError drives the displayed message; Msg drives Error()/logs and the
	// --verbose tail. Set both from one string so verbose shows the real
	// message instead of usefulerror's "unknown error" fallback.
	if !res.StateVerified {
		msg := "Proxy shut down but the blocked-package count could not be verified"
		return usefulerror.NewUsefulError().
			WithCode(errcodes.ProxyPolicyViolation).
			WithHumanError(msg).
			WithMsg(msg).
			WithHelp("The proxy may have crashed; treat this run as failed and re-run")
	}

	if res.BlockedCount > 0 {
		msg := fmt.Sprintf("%d package(s) were blocked by the proxy", res.BlockedCount)
		return usefulerror.NewUsefulError().
			WithCode(errcodes.ProxyPolicyViolation).
			WithHumanError(msg).
			WithMsg(msg).
			WithHelp("Review the proxy logs for details on blocked packages")
	}

	return nil
}
