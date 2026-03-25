//go:build linux

package landlock

import (
	"github.com/safedep/pmg/sandbox/platform"
	"github.com/spf13/cobra"
)

// NewLandlockSandboxExecCommand returns the hidden Cobra command used as the
// helper process entry point for the Landlock sandbox driver.
func NewLandlockSandboxExecCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "__landlock_sandbox_exec",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return platform.RunLandlockHelper(args)
		},
	}
}
