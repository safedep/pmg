package main

import (
	"fmt"
	"os"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/cmd/npm"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/ui"
	"github.com/spf13/cobra"
)

var (
	debug        bool
	silent       bool
	verbose      bool
	globalConfig config.Config
)

func main() {
	cmd := &cobra.Command{
		Use:              "pmg",
		TraverseChildren: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if debug {
				os.Setenv("APP_LOG_LEVEL", "debug")
			}

			log.InitZapLogger("pmg", "")

			if silent && verbose {
				fmt.Println("pmg: --silent and --verbose cannot be used together")
				os.Exit(1)
			}

			if silent {
				ui.SetVerbosityLevel(ui.VerbosityLevelSilent)
			} else if verbose {
				ui.SetVerbosityLevel(ui.VerbosityLevelVerbose)
			}

			cmd.SetContext(globalConfig.Inject(cmd.Context()))
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				cmd.Help()
				return nil
			}

			return fmt.Errorf("pmg: %s is not a valid command", args[0])
		},
	}

	cmd.PersistentFlags().BoolVar(&silent, "silent", false, "Silent mode for invisible experience")
	cmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Verbose mode for more information")
	cmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug logging (defaults to stdout)")
	cmd.PersistentFlags().BoolVar(&globalConfig.Transitive, "transitive", true, "Resolve transitive dependencies")
	cmd.PersistentFlags().IntVar(&globalConfig.TransitiveDepth, "transitive-depth", 5,
		"Maximum depth of transitive dependencies to resolve")
	cmd.PersistentFlags().BoolVar(&globalConfig.IncludeDevDependencies, "include-dev-dependencies", false,
		"Include dev dependencies in the dependency graph (slows down resolution)")

	cmd.AddCommand(npm.NewNpmCommand())
	cmd.AddCommand(npm.NewPnpmCommand())

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
