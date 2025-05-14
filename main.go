package main

import (
	"fmt"
	"os"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/cmd/npm"
	"github.com/safedep/pmg/config"
	"github.com/spf13/cobra"
)

var (
	debug        bool
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

	cmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug logging")
	cmd.PersistentFlags().BoolVar(&globalConfig.Transitive, "transitive", true, "Resolve transitive dependencies")
	cmd.PersistentFlags().IntVar(&globalConfig.TransitiveDepth, "transitive-depth", 20,
		"Maximum depth of transitive dependencies to resolve")

	cmd.AddCommand(npm.NewNpmCommand())
	cmd.AddCommand(npm.NewPnpmCommand())

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
