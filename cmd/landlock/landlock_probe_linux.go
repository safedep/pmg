//go:build linux

package landlock

import (
	"github.com/safedep/pmg/sandbox/platform"
	"github.com/spf13/cobra"
)

// NewLandlockProbeCommand returns the hidden Cobra command used to detect
// whether the Landlock shim can install seccomp without NO_NEW_PRIVS.
func NewLandlockProbeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "__landlock_probe",
		Hidden:       true,
		SilenceUsage: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return platform.RunLandlockProbe()
		},
	}
	return cmd
}
