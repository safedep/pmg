package proxy

import "github.com/spf13/cobra"

func NewProxyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Manage the persistent PMG proxy server",
	}
	cmd.AddCommand(newStartCommand())
	cmd.AddCommand(newStopCommand())
	cmd.AddCommand(newEnvCommand())
	cmd.AddCommand(newStatusCommand())
	return cmd
}
