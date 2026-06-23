package proxy

import (
	"fmt"
	"os"
	"syscall"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/proxystate"
	"github.com/spf13/cobra"
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

	if _, err := fmt.Fprintf(os.Stdout, "Sent SIGTERM to PMG proxy (pid %d, addr %s)\n", state.PID, state.Addr); err != nil {
		return fmt.Errorf("write stop message: %w", err)
	}

	return nil
}
