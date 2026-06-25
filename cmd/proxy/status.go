package proxy

import (
	"fmt"
	"os"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/safedep/pmg/internal/ui"
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
	statePath := proxyserver.ResolveStatePath(stateFlag, cfg.CacheDir())

	st := proxyserver.GetStatus(statePath)

	var line string
	switch {
	case !st.Found:
		line = "PMG proxy: not running (no state file)\n"
	case st.Running:
		line = fmt.Sprintf("PMG proxy: running (pid %d, addr %s, ca %s)\n", st.PID, st.Addr, st.CACert)
	default:
		line = fmt.Sprintf("PMG proxy: stopped (stale state for pid %d — run 'pmg proxy stop' to clean up)\n", st.PID)
	}

	if _, err := fmt.Fprint(os.Stdout, line); err != nil {
		ui.ErrorExit(err)
	}

	return nil
}
