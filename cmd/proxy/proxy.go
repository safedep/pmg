package proxy

import "github.com/spf13/cobra"

// stateFlag binds the persistent --state flag shared by all proxy subcommands.
var stateFlag string

func NewProxyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Manage the persistent PMG proxy server",
	}
	cmd.AddCommand(newStartCommand())
	cmd.AddCommand(newStopCommand())
	cmd.AddCommand(newEnvCommand())
	cmd.AddCommand(newStatusCommand())
	cmd.PersistentFlags().StringVar(&stateFlag, "state", "",
		"Path to the proxy state file (default: <cache-dir>/proxy-state.json)")
	return cmd
}
