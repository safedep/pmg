package proxy

import (
	"fmt"
	"os"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/proxystate"
	"github.com/spf13/cobra"
)

func newStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the status of the persistent PMG proxy server",
		RunE:  runStatus,
	}
}

func runStatus(_ *cobra.Command, _ []string) error {
	cfg := config.Get()
	statePath := proxystate.StatePath(cfg.ConfigDir())

	state, err := proxystate.Read(statePath)
	if err != nil {
		if _, werr := fmt.Fprintln(os.Stdout, "PMG proxy: not running (no state file)"); werr != nil {
			return werr
		}
		return nil
	}

	if state.IsRunning() {
		_, err = fmt.Fprintf(os.Stdout, "PMG proxy: running (pid %d, addr %s, ca %s)\n",
			state.PID, state.Addr, state.CACertPath)
	} else {
		_, err = fmt.Fprintf(os.Stdout, "PMG proxy: stopped (stale state for pid %d — run 'pmg proxy stop' to clean up)\n", state.PID)
	}

	return err
}
