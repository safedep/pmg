package proxy

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/proxystate"
	"github.com/spf13/cobra"
)

const (
	stopPollInterval = 200 * time.Millisecond
	stopPollTimeout  = 10 * time.Second
)

func newStopCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the running persistent PMG proxy server",
		RunE:  runStop,
	}
}

func runStop(_ *cobra.Command, _ []string) error {
	cfg := config.Get()
	statePath := proxystate.StatePath(cfg.ConfigDir())

	state, err := proxystate.Read(statePath)
	if err != nil {
		return fmt.Errorf("no proxy state found — is the proxy running? (%w)", err)
	}

	if !state.IsRunning() {
		_ = proxystate.Remove(statePath)
		return fmt.Errorf("proxy process (pid %d) is not running; state file cleaned up", state.PID)
	}

	proc, err := os.FindProcess(state.PID)
	if err != nil {
		return fmt.Errorf("find proxy process (pid %d): %w", state.PID, err)
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("send SIGTERM to proxy (pid %d): %w", state.PID, err)
	}

	// Wait for the process to exit so we can read the final blocked count it writes.
	deadline := time.Now().Add(stopPollTimeout)
	for time.Now().Before(deadline) {
		if !state.IsRunning() {
			break
		}
		time.Sleep(stopPollInterval)
	}

	// Read the final state the proxy wrote on shutdown (has BlockedCount).
	final, rerr := proxystate.Read(statePath)
	_ = proxystate.Remove(statePath)

	if rerr != nil {
		// Proxy exited but didn't write final state (e.g. crash). Treat as clean.
		if _, werr := fmt.Fprintf(os.Stdout, "PMG proxy (pid %d) stopped\n", state.PID); werr != nil {
			return werr
		}
		return nil
	}

	if _, werr := fmt.Fprintf(os.Stdout, "PMG proxy stopped — analyzed packages, %d blocked\n", final.BlockedCount); werr != nil {
		return werr
	}

	if final.BlockedCount > 0 {
		return usefulerror.NewUsefulError().
			WithCode(errcodes.ProxyPackagesBlocked).
			WithMsg(fmt.Sprintf("%d package(s) were blocked by the proxy", final.BlockedCount)).
			WithHelp("Review the proxy logs for details on blocked packages")
	}

	return nil
}
