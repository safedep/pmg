package proxy

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/safedep/pmg/internal/ui"
	"github.com/spf13/cobra"
)

var (
	daemonFlag             bool
	logFileFlag            string
	foregroundInternalFlag bool
)

func newStartCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the persistent PMG proxy server",
		RunE:  runStart,
	}

	// Bind --host/--port directly onto the config fields with the loaded config
	// values as defaults, matching PMG's flag pattern (see config/cobra.go): a
	// supplied flag overwrites the field, otherwise the config value stands.
	// Precedence: flag > env > config file > default.
	srv := &config.Get().Config.Proxy.Server

	cmd.Flags().BoolVarP(&daemonFlag, "daemon", "D", false, "Run the proxy as a detached background process")
	cmd.Flags().StringVar(&srv.ListenHost, "host", srv.ListenHost, "Host to bind")
	cmd.Flags().IntVar(&srv.ListenPort, "port", srv.ListenPort, "Port to bind (0 = a random free port)")
	cmd.Flags().StringVar(&logFileFlag, "log-file", "", "File for the daemon's output (default: <cache-dir>/proxy.log)")
	cmd.Flags().BoolVar(&foregroundInternalFlag, "foreground-internal", false, "Internal: run the foreground server (used by --daemon)")
	if err := cmd.Flags().MarkHidden("foreground-internal"); err != nil {
		panic(err)
	}
	return cmd
}

func runStart(cmd *cobra.Command, _ []string) error {
	cfg := config.Get()
	statePath := proxyserver.ResolveStatePath(stateFlag, cfg.CacheDir())
	host := cfg.Config.Proxy.Server.ListenHost
	port := cfg.Config.Proxy.Server.ListenPort

	if daemonFlag && !foregroundInternalFlag {
		if err := startDaemon(cmd, cfg, statePath, host, port); err != nil {
			ui.ErrorExit(err)
		}
		return nil
	}

	if err := proxyserver.Run(cmd.Context(), cfg, statePath, host, port); err != nil {
		ui.ErrorExit(err)
	}
	return nil
}

func startDaemon(cmd *cobra.Command, cfg *config.RuntimeConfig, statePath, host string, port int) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}

	// Daemon log: the --log-file flag if set, else <cache-dir>/proxy.log. The
	// caller owns this path, so ensure its parent directory exists here.
	logPath := logFileFlag
	if logPath == "" {
		logPath = filepath.Join(cfg.CacheDir(), "proxy.log")
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return fmt.Errorf("create daemon log dir: %w", err)
	}

	args := daemonArgs(cmd, statePath, host, port)

	daemonCfg := proxyserver.ProxyDaemonConfig{
		LogPath:      logPath,
		ReadyTimeout: proxyserver.DefaultDaemonReadyTimeout,
	}
	state, err := proxyserver.Daemonize(daemonCfg, statePath, exe, args)
	if err != nil {
		return err
	}

	_, werr := fmt.Fprintf(os.Stdout, "PMG proxy daemon started on %s (pid %d)\n", state.Addr, state.PID)
	return werr
}

func daemonArgs(cmd *cobra.Command, statePath, host string, port int) []string {
	args := append([]string{}, config.ChangedConfigFlagArgs(cmd)...)
	return append(args,
		"proxy", "start", "--foreground-internal",
		"--state", statePath,
		"--host", host,
		"--port", strconv.Itoa(port),
	)
}
