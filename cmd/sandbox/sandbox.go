// Package sandbox implements the `pmg sandbox` command subtree.
//
// This is the ONLY package permitted to import internal/ui for rendering
// sandbox diagnostics. The sandbox package produces structured probe
// results; presentation lives here.
package sandbox

import "github.com/spf13/cobra"

// NewCommand returns the `pmg sandbox` parent command.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sandbox",
		Short: "Inspect and manage PMG sandbox configuration",
		Long:  "Tools for diagnosing the host sandbox environment and (in future PRs) managing sandbox profiles.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(NewDoctorCommand())
	cmd.AddCommand(NewProfileCommand())
	cmd.AddCommand(NewExplainCommand())
	cmd.AddCommand(NewViolationsCommand())
	cmd.AddCommand(NewAllowCommand())
	cmd.AddCommand(NewProjectCommand())
	return cmd
}
