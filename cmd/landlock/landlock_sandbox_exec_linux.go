//go:build linux

package landlock

import (
	"github.com/safedep/pmg/sandbox/platform"
	"github.com/spf13/cobra"
)

// NewLandlockSandboxExecCommand returns the hidden Cobra command used as the
// helper process entry point for the Landlock sandbox driver.
func NewLandlockSandboxExecCommand() *cobra.Command {
	var policyFile string
	var auditSocket string

	cmd := &cobra.Command{
		Use:    "__landlock_sandbox_exec",
		Hidden: true,
		// Override PersistentPreRun to prevent the parent's full initialization
		// (config loading, event log init, analytics, etc.) from running.
		// RunLandlockHelper initializes its own minimal logger.
		PersistentPreRun: func(cmd *cobra.Command, args []string) {},
		RunE: func(cmd *cobra.Command, args []string) error {
			// args contains everything after "--" (the target command)
			return platform.RunLandlockHelper(policyFile, auditSocket, args)
		},
	}

	cmd.Flags().StringVar(&policyFile, "policy-file", "", "Path to policy JSON file")
	cmd.Flags().StringVar(&auditSocket, "audit-socket", "", "Path to audit unix socket")
	_ = cmd.MarkFlagRequired("policy-file")
	_ = cmd.MarkFlagRequired("audit-socket")

	return cmd
}
