package main

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/safedep/pmg/cmd/ecosystems"
	"github.com/spf13/cobra"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Println("No .env file found or failed to load")
	}

	cmd := &cobra.Command{
		Use:              "pmg",
		TraverseChildren: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return nil
			}
			return fmt.Errorf("pmg: %s is not a valid command", args[0])
		},
	}

	cmd.AddCommand(ecosystems.NewNpmCommand())

	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
