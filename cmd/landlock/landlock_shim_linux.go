//go:build linux

package landlock

import (
	"github.com/safedep/pmg/sandbox/platform"
	"github.com/spf13/cobra"
)

// NewLandlockShimCommand returns the hidden command that the Landlock
// helper runs inside the user namespace. See platform.RunLandlockShim.
func NewLandlockShimCommand() *cobra.Command {
	var policyFile string
	var notifySocketFd int

	cmd := &cobra.Command{
		Use:                "__landlock_shim",
		Hidden:             true,
		DisableFlagParsing: false,
		// The shim calls execve at once. It does not need config or analytics.
		PersistentPreRun: func(cmd *cobra.Command, args []string) {},
		RunE: func(cmd *cobra.Command, args []string) error {
			return platform.RunLandlockShim(policyFile, notifySocketFd, args)
		},
	}
	cmd.Flags().StringVar(&policyFile, "policy-file", "", "Path to policy JSON file")
	cmd.Flags().IntVar(&notifySocketFd, "notify-socket-fd", 0, "FD of socketpair end used to send the seccomp notify fd to the supervisor")
	_ = cmd.MarkFlagRequired("policy-file")
	_ = cmd.MarkFlagRequired("notify-socket-fd")
	return cmd
}
