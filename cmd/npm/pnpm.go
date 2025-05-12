package npm

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/safedep/pmg/pkg/common/utils"
	"github.com/safedep/pmg/pkg/registry"
	"github.com/safedep/pmg/pkg/wrapper"
	"github.com/spf13/cobra"
)

func NewPnpmCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                "pnpm [action] [package]",
		Short:              "Scan packages from npm registry",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			execPath, err := utils.GetExecutablePath(string(registry.RegistryPNPM))
			if err != nil {
				fmt.Fprintf(os.Stderr, "pnpm not found: %v\n", err)
				return err
			}

			if len(args) >= 2 && utils.IsInstallCommand(string(registry.RegistryPNPM), args[0]) {
				// Parse arguments to separate flags and packages
				flags, packages := utils.ParseNpmInstallArgs(args[1:])

				// If no packages specified, just pass through to npm
				if len(packages) == 0 {
					return utils.ExecCmd(execPath, args, []string{})
				}

				// Create single wrapper instance for all packages
				pmw := wrapper.NewPackageManagerWrapper(registry.RegistryPNPM, flags, packages, args[0])
				if err := pmw.Wrap(); err != nil {
					return err
				}

				return nil
			}

			if err := utils.ExecCmd(execPath, args, []string{}); err != nil {
				os.Exit(1)
			}
			os.Exit(0)
			return nil
		},
	}
	return cmd
}
