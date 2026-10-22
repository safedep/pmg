package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/safedep/dry/log"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/proxy/netpolicy"
	"github.com/spf13/cobra"
)

var (
	failOnViolation bool
	ifRunning       bool
	reportPath      string
)

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
	cmd.Flags().BoolVar(&ifRunning, "if-running", false,
		"Exit zero when no proxy runs on the state file")
	cmd.Flags().StringVar(&reportPath, "report", "",
		"Write the stop result as JSON to this file")
	return cmd
}

func writeStopReport(path string, r proxyserver.StopReport) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal stop report: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write stop report: %w", err)
	}
	return nil
}

func runStop(_ *cobra.Command, _ []string) error {
	cfg := config.Get()
	statePath := proxyserver.ResolveStatePath(stateFlag, cfg.CacheDir())

	res, err := proxyserver.Stop(statePath)
	if ifRunning && errors.Is(err, proxyserver.ErrNoProxy) {
		if reportPath != "" {
			if werr := writeStopReport(reportPath, proxyserver.StopReport{}); werr != nil {
				ui.ErrorExit(werr)
			}
		}
		_, werr := fmt.Fprintln(os.Stdout, "No PMG proxy runs on this state file. Nothing to stop.")
		return werr
	}
	if err != nil {
		ui.ErrorExit(err)
	}

	if reportPath != "" {
		if werr := writeStopReport(reportPath, res.Report(stopViolation(res))); werr != nil {
			ui.ErrorExit(werr)
		}
	}

	// Surface the daemon's cloud flush outcome before the violation gate, so it
	// shows on both the success and the failure path (the daemon's own logs are
	// not visible to this process). nil means cloud sync is disabled.
	if res.CloudSync != nil {
		line := fmt.Sprintf("Synced %d event(s) to SafeDep Cloud\n", res.CloudSync.Synced)
		if res.CloudSync.Error != "" {
			line = fmt.Sprintf("Cloud sync failed: %s\n", res.CloudSync.Error)
		}
		if _, werr := fmt.Fprint(os.Stdout, line); werr != nil {
			ui.ErrorExit(werr)
		}
	}

	if _, werr := fmt.Fprint(os.Stdout, networkReport(res)+observationLine(res)); werr != nil {
		ui.ErrorExit(werr)
	}

	// On a policy violation the framed error states the blocked count, so exit
	// here before the plain summary to avoid stating the count twice.
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
	msg := stopViolation(res)
	if msg == "" {
		return nil
	}

	help := "Review the proxy logs for details on blocked packages and denied connections"
	if !res.StateVerified {
		help = "The proxy may have crashed; treat this run as failed and re-run"
	}
	// HumanError drives the displayed message; Msg drives Error()/logs and the
	// --verbose tail. Set both from one string so verbose shows the real
	// message instead of usefulerror's "unknown error" fallback.
	return usefulerror.NewUsefulError().
		WithCode(errcodes.ProxyPolicyViolation).
		WithHumanError(msg).
		WithMsg(msg).
		WithHelp(help)
}

// stopViolation names what --fail-on-violation fails on, or empty when the
// run has no violation.
func stopViolation(res proxyserver.StopResult) string {
	if !res.StateVerified {
		return "Proxy shut down but the blocked-package count could not be verified"
	}
	var violations []string
	if res.BlockedCount > 0 {
		violations = append(violations, fmt.Sprintf("%d package(s) were blocked by the proxy", res.BlockedCount))
	}
	if denied := res.Network.DeniedCount(); denied > 0 {
		violations = append(violations, fmt.Sprintf("%d connection(s) were denied by the network policy", denied))
	}
	return strings.Join(violations, " and ")
}

// observationLine points at the proposal command. Empty when the proxy saw
// no destination, or when the daemon predates the run id.
func observationLine(res proxyserver.StopResult) string {
	if res.Observed == 0 || res.RunID == "" {
		return ""
	}
	return fmt.Sprintf("Destinations: %d observed. Propose a profile with: pmg sandbox profile propose --run %s\n", res.Observed, res.RunID)
}

// networkReport renders the network policy block of the stop report: the
// mode and the counts, one line per denial, then the profile chain and the
// enforced ports. Empty when the daemon had no policy.
func networkReport(res proxyserver.StopResult) string {
	n := res.Network
	if n == nil {
		return ""
	}

	action, denied, wouldDeny := "would deny", 0, 0
	for _, d := range n.Denials {
		wouldDeny += d.Count
	}
	if n.Enforced() {
		action, denied, wouldDeny = "denied", wouldDeny, 0
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Network policy: %s, %d denied, %d would deny\n", n.Mode, denied, wouldDeny)
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	for _, d := range n.Denials {
		cells := []string{"  " + action, d.Destination, "rule " + d.Rule}
		if client := denialClient(d); client != "" {
			cells = append(cells, client)
		}
		if _, err := fmt.Fprintln(tw, strings.Join(cells, "\t")); err != nil {
			log.Warnf("failed to render the network policy report: %v", err)
		}
	}
	if err := tw.Flush(); err != nil {
		log.Warnf("failed to render the network policy report: %v", err)
	}
	fmt.Fprintf(&b, "Profile: %s", n.Profile())
	if res.Enforce != nil {
		fmt.Fprintf(&b, "  ports %s", res.Enforce.PortList())
	}
	b.WriteString("\n")
	return b.String()
}

// denialClient names the program and the pid behind a denial, or the
// container address. A proxy-aware client without kernel enforcement has
// no name.
func denialClient(d netpolicy.Denial) string {
	client := d.Client
	if d.PID != 0 {
		client = fmt.Sprintf("%s pid %d", client, d.PID)
	}
	if d.Count > 1 {
		client += fmt.Sprintf(" (%d)", d.Count)
	}
	return strings.TrimSpace(client)
}
