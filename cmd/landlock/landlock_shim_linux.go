//go:build linux

package landlock

import (
	"github.com/safedep/pmg/sandbox/platform"
	"github.com/spf13/cobra"
)

// NewLandlockShimCommand returns the hidden Cobra command used as the
// inside-user-namespace shim. The helper process (pmg __landlock_sandbox_exec)
// clones a child with CLONE_NEWUSER + uid/gid mapping (0 -> host uid) so the
// shim boots as uid 0 inside the ns with CAP_SYS_ADMIN. The shim installs the
// seccomp filter WITHOUT PR_SET_NO_NEW_PRIVS (allowed by CAP_SYS_ADMIN in the
// ns) and applies Landlock; this keeps the shim (and every descendant) with
// dumpable=1, so the helper can open /proc/<pid>/mem to resolve openat(2)
// path arguments for seccomp-notify.
func NewLandlockShimCommand() *cobra.Command {
	var policyFile string
	var notifySocketFd int

	cmd := &cobra.Command{
		Use:                "__landlock_shim",
		Hidden:             true,
		DisableFlagParsing: false,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Skip parent pmg initialization — the shim re-execs the target
			// almost immediately and does not need config/analytics/etc.
		},
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
