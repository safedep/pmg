package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/cmd/cloud"
	configCmd "github.com/safedep/pmg/cmd/config"
	"github.com/safedep/pmg/cmd/executors"
	landlockCmd "github.com/safedep/pmg/cmd/landlock"
	"github.com/safedep/pmg/cmd/npm"
	"github.com/safedep/pmg/cmd/pypi"
	sandboxCmd "github.com/safedep/pmg/cmd/sandbox"
	"github.com/safedep/pmg/cmd/setup"
	"github.com/safedep/pmg/cmd/version"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/eventlog"
	"github.com/safedep/pmg/internal/ui"
	appVersion "github.com/safedep/pmg/internal/version"
	"github.com/spf13/cobra"
)

var (
	debug   bool
	silent  bool
	verbose bool
	logFile string
)

func setLogEnv(key, value string) {
	if err := os.Setenv(key, value); err != nil {
		log.Warnf("failed to set %s: %v", key, err)
	}
}

func main() {
	cmd := &cobra.Command{
		Use:              "pmg",
		TraverseChildren: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Always set this first because we will override the log
			// level if debug or verbose is set
			if logFile != "" {
				setLogEnv("APP_LOG_FILE", logFile)
				setLogEnv("APP_LOG_LEVEL", "info")
			}

			// Set the log level when debug is enabled
			if debug {
				setLogEnv("APP_LOG_LEVEL", "debug")
			}

			// Skip stdout logging when debugging is not enabled
			if !debug {
				setLogEnv("APP_LOG_SKIP_STDOUT_LOGGER", "true")
			}

			// Apply config-based verbosity first
			switch config.Get().Config.Verbosity {
			case config.VerbositySilent:
				ui.SetVerbosityLevel(ui.VerbosityLevelSilent)
			case config.VerbosityVerbose:
				ui.SetVerbosityLevel(ui.VerbosityLevelVerbose)
			default:
				ui.SetVerbosityLevel(ui.VerbosityLevelNormal)
			}

			// CLI flags override config
			if silent && verbose {
				ui.Fatalf("pmg: --silent and --verbose cannot be used together")
			}

			if silent {
				ui.SetVerbosityLevel(ui.VerbosityLevelSilent)
			} else if verbose {
				ui.SetVerbosityLevel(ui.VerbosityLevelVerbose)
			}

			log.InitZapLogger("pmg", "cli")

			// Refuse flags that would override a globally managed config before any
			// config-dependent initialization (event logging, audit) runs, so a
			// managed flag like --skip-event-log cannot take effect first.
			if err := config.RejectManagedFlagOverrides(cmd); err != nil {
				ui.ErrorExit(err)
			}

			// Initialize event logging
			var eventlogErr error
			if logFile != "" {
				// If a custom log file is specified, use it for event logging too
				eventlogErr = eventlog.InitializeWithFile(logFile)
			} else {
				// Otherwise use the default log directory
				eventlogErr = eventlog.Initialize()
			}

			if eventlogErr != nil {
				ui.Fatalf("failed to initialize event logging: %v", eventlogErr)
			}

			if err := audit.Initialize(config.Get()); err != nil {
				ui.ErrorExit(err)
			}

			config.FinalizeDependencyCooldownOverride()

			// Parse and validate --sandbox-allow flags after all flags are resolved
			if err := config.FinalizeSandboxAllowOverrides(); err != nil {
				ui.Fatalf("pmg: %v", err)
			}

			if debug {
				logDebugContext()
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}

			return fmt.Errorf("pmg: %s is not a valid command", args[0])
		},
	}

	cmd.PersistentFlags().StringVar(&logFile, "log", "", "Log file to write to")
	cmd.PersistentFlags().BoolVar(&silent, "silent", false, "Silent mode for invisible experience")
	cmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Verbose mode for more information")
	cmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug logging (defaults to stdout)")

	// Apply config flags to the command. This allows for overriding the configuration at runtime
	// using the command line.
	config.ApplyCobraFlags(cmd)

	cmd.AddCommand(npm.NewNpmCommand())
	cmd.AddCommand(npm.NewPnpmCommand())
	cmd.AddCommand(npm.NewBunCommand())
	cmd.AddCommand(npm.NewYarnCommand())
	cmd.AddCommand(executors.NewNpxCommand())
	cmd.AddCommand(executors.NewPnpxCommand())
	cmd.AddCommand(pypi.NewPipCommand())
	cmd.AddCommand(pypi.NewPip3Command())
	cmd.AddCommand(pypi.NewUvCommand())
	cmd.AddCommand(pypi.NewPoetryCommand())
	cmd.AddCommand(version.NewVersionCommand())
	cmd.AddCommand(setup.NewSetupCommand())
	cmd.AddCommand(setup.NewRemoveCommand())
	cmd.AddCommand(sandboxCmd.NewCommand())
	cmd.AddCommand(cloud.NewCloudCommand())
	cmd.AddCommand(configCmd.NewConfigCommand())

	if subcmd := landlockCmd.NewLandlockSandboxExecCommand(); subcmd != nil {
		cmd.AddCommand(subcmd)
	}
	if subcmd := landlockCmd.NewLandlockShimCommand(); subcmd != nil {
		cmd.AddCommand(subcmd)
	}

	// Print Banner on --help / -h
	cmd.SetHelpFunc(func(command *cobra.Command, args []string) {
		fmt.Print(ui.GeneratePMGBanner(appVersion.Version, appVersion.Commit))
		fmt.Println(command.UsageString())
	})

	defer func() {
		if err := eventlog.Close(); err != nil {
			log.Warnf("failed to close eventlog: %v", err)
		}
	}()
	// Defers run LIFO. The spawn must observe the parent's released SQLite
	// handle, so we declare it BEFORE audit.Close's defer (it then runs AFTER
	// audit.Close at exit time).
	defer func() {
		audit.MaybeSpawnBackgroundSync(config.Get())
	}()
	defer func() {
		if err := audit.Close(); err != nil {
			log.Warnf("failed to close audit system: %v", err)
		}
	}()

	// Analytics are best-effort. Do not flush on exit because the PostHog
	// client can block the CLI while draining its queue.
	analytics.TrackCommandRun()
	analytics.TrackCI()

	if err := cmd.Execute(); err != nil {
		type exitCoder interface{ ExitCode() int }
		if ec, ok := err.(exitCoder); ok {
			os.Exit(ec.ExitCode())
		}
		os.Exit(1)
	}
}

func logDebugContext() {
	cfg := config.Get()

	log.Debugf("Command: pmg %s", strings.Join(os.Args[1:], " "))
	log.Debugf("PMG %s (commit: %s) running on %s/%s with %s",
		appVersion.Version, appVersion.Commit, runtime.GOOS, runtime.GOARCH, runtime.Version())
	log.Debugf("Using config file: %s", cfg.ConfigFilePath())
	log.Debugf("Proxy mode enabled: %t, install only: %t", cfg.IsProxyModeEnabled(), cfg.Config.Proxy.InstallOnly)
	log.Debugf("Sandbox enabled: %t, enforce always: %t", cfg.Config.Sandbox.Enabled, cfg.Config.Sandbox.EnforceAlways)
	log.Debugf("Transitive analysis enabled: %t (depth: %d), paranoid: %t", cfg.Config.Transitive, cfg.Config.TransitiveDepth, cfg.Config.Paranoid)
	log.Debugf("Dependency cooldown enabled: %t (days: %d)", cfg.Config.DependencyCooldown.Enabled, cfg.Config.DependencyCooldown.Days)
	log.Debugf("Cloud sync enabled: %t, telemetry disabled: %t", cfg.Config.Cloud.Enabled, cfg.Config.DisableTelemetry)
	log.Debugf("Dry run: %t, insecure installation: %t, trusted packages: %d",
		cfg.DryRun, cfg.InsecureInstallation, len(cfg.Config.TrustedPackages))
}
