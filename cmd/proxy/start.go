package proxy

import (
	"fmt"
	"os"
	"strconv"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/spf13/cobra"
)

var (
	daemonFlag             bool
	portFlag               int
	foregroundInternalFlag bool
)

func newStartCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the persistent PMG proxy server",
		RunE:  runStart,
	}
	cmd.Flags().BoolVarP(&daemonFlag, "daemon", "D", false, "Run the proxy as a detached background process")
	cmd.Flags().IntVar(&portFlag, "port", 0, "Port to bind (default: random)")
	cmd.Flags().BoolVar(&foregroundInternalFlag, "foreground-internal", false, "Internal: run the foreground server (used by --daemon)")
	if err := cmd.Flags().MarkHidden("foreground-internal"); err != nil {
		panic(err)
	}
	return cmd
}

func runStart(cmd *cobra.Command, _ []string) error {
	cfg := config.Get()
	statePath := proxyserver.ResolveStatePath(stateFlag, cfg)

	if daemonFlag && !foregroundInternalFlag {
		args := []string{"proxy", "start", "--foreground-internal", "--state", statePath}
		if portFlag != 0 {
			args = append(args, "--port", strconv.Itoa(portFlag))
		}

		state, err := proxyserver.Daemonize(cfg, statePath, args)
		if err != nil {
			return err
		}

		_, werr := fmt.Fprintf(os.Stdout, "PMG proxy daemon started on %s (pid %d)\n", state.Addr, state.PID)
		return werr
	}

	return proxyserver.Run(cmd.Context(), cfg, statePath, portFlag)
}
