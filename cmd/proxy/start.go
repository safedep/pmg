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
	daemonFlag                   bool
	logFileFlag                  string
	foregroundInternalFlag       bool
	enforceExemptExecutablesFlag []string
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
	cmd.Flags().BoolVar(&srv.Enforce.Enabled, "enforce", srv.Enforce.Enabled,
		"Route every eligible process through the proxy in the kernel (Linux, root). See proxy.server.enforce in the config")
	cmd.Flags().BoolVar(&foregroundInternalFlag, "foreground-internal", false, "Internal: run the foreground server (used by --daemon)")
	cmd.Flags().StringArrayVar(&enforceExemptExecutablesFlag, "enforce-exempt-executable", nil, "Internal: executable globs the parent computed for the daemon, added to proxy.server.enforce.exempt_executables")
	for _, name := range []string{"foreground-internal", "enforce-exempt-executable"} {
		if err := cmd.Flags().MarkHidden(name); err != nil {
			panic(err)
		}
	}
	return cmd
}

func runStart(cmd *cobra.Command, _ []string) error {
	cfg := config.Get()
	opts := proxyserver.RunOptions{
		StatePath:         proxyserver.ResolveStatePath(stateFlag, cfg.CacheDir()),
		Host:              cfg.Config.Proxy.Server.ListenHost,
		Port:              cfg.Config.Proxy.Server.ListenPort,
		Enforce:           cfg.Config.Proxy.Server.Enforce.Enabled,
		ExemptExecutables: enforceExemptExecutablesFlag,
	}

	// The runner walk needs this process's ancestors. The daemon has none
	// after it detaches, so the walk happens here and the result travels in
	// the re-exec arguments.
	if opts.Enforce && !foregroundInternalFlag {
		opts.ExemptExecutables = append(opts.ExemptExecutables, proxyserver.RunnerExemptGlobs()...)
	}

	if daemonFlag && !foregroundInternalFlag {
		if err := startDaemon(cmd, cfg, opts); err != nil {
			ui.ErrorExit(err)
		}
		return nil
	}

	if err := proxyserver.Run(cmd.Context(), cfg, opts); err != nil {
		ui.ErrorExit(err)
	}
	return nil
}

func startDaemon(cmd *cobra.Command, cfg *config.RuntimeConfig, opts proxyserver.RunOptions) error {
	// The daemon is a re-exec; surface its config error instead of a parent-side readiness timeout.
	if err := config.LoadError(); err != nil {
		return err
	}

	// The daemon runs the same checks again. Running them here first turns a
	// missing capability or an untrusted CA into an immediate error with its
	// help, instead of a readiness timeout.
	if opts.Enforce {
		if err := proxyserver.PreflightEnforce(cfg, opts.ExemptExecutables); err != nil {
			return err
		}
	}

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

	args := daemonArgs(cmd, opts)

	daemonCfg := proxyserver.ProxyDaemonConfig{
		LogPath:      logPath,
		ReadyTimeout: proxyserver.DefaultDaemonReadyTimeout,
	}
	if opts.Enforce {
		// Loading and verifying the programs adds to the start.
		daemonCfg.ReadyTimeout = proxyserver.DefaultDaemonReadyTimeout * 3
	}
	state, err := proxyserver.Daemonize(daemonCfg, opts.StatePath, exe, args)
	if err != nil {
		return err
	}

	line := fmt.Sprintf("PMG proxy daemon started on %s (pid %d)\n", state.Addr, state.PID)
	if state.Enforce != nil {
		line = fmt.Sprintf("PMG proxy daemon started on %s (pid %d) with kernel enforcement\n", state.Addr, state.PID)
		for _, w := range state.Enforce.Warnings {
			line += fmt.Sprintf("%s %s\n", ui.Colors.Yellow("⚠"), w)
		}
	}
	_, werr := fmt.Fprint(os.Stdout, line)
	return werr
}

func daemonArgs(cmd *cobra.Command, opts proxyserver.RunOptions) []string {
	args := append([]string{}, config.ChangedConfigFlagArgs(cmd)...)
	args = append(args,
		"proxy", "start", "--foreground-internal",
		"--state", opts.StatePath,
		"--host", opts.Host,
		"--port", strconv.Itoa(opts.Port),
		"--enforce="+strconv.FormatBool(opts.Enforce),
	)
	for _, glob := range opts.ExemptExecutables {
		args = append(args, "--enforce-exempt-executable", glob)
	}
	return args
}
