//go:build linux

package landlock

import (
	"github.com/safedep/pmg/sandbox/platform"
	"github.com/spf13/cobra"
)

// NewSeccompShimCommand returns the hidden command that the Bubblewrap driver
// runs inside bwrap. See platform.RunSeccompShim.
func NewSeccompShimCommand() *cobra.Command {
	var allowUnixSockets bool

	cmd := &cobra.Command{
		Use:    platform.SeccompShimCommand,
		Hidden: true,
		// The shim calls execve at once. It does not need config or analytics.
		PersistentPreRun: func(cmd *cobra.Command, args []string) {},
		RunE: func(cmd *cobra.Command, args []string) error {
			return platform.RunSeccompShim(allowUnixSockets, args)
		},
	}
	cmd.Flags().BoolVar(&allowUnixSockets, "allow-unix-sockets", false, "Allow unix socket connections")
	return cmd
}
