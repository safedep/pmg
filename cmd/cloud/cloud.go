package cloud

import (
	"github.com/spf13/cobra"
)

func NewCloudCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cloud",
		Short: "SafeDep Cloud operations",
	}

	cmd.AddCommand(newSyncCommand())
	cmd.AddCommand(newLoginCommand())
	cmd.AddCommand(newLogoutCommand())

	return cmd
}
