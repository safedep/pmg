package main

import (
	"fmt"
	"os"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/cmd/ecosystems"
	"github.com/spf13/cobra"
)

func main() {
	var debug bool

	cmd := &cobra.Command{
		Use:              "pmg",
		TraverseChildren: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if debug {
				log.Init("pmg-logger", "debug")
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return nil
			}
			return fmt.Errorf("pmg: %s is not a valid command", args[0])
		},
	}

	cmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug logging")

	cmd.AddCommand(ecosystems.NewNpmCommand())

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
