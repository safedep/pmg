package cloud

import (
	"time"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/cloudpolicy"
	"github.com/safedep/pmg/internal/cloudsync"
	"github.com/safedep/pmg/internal/ui"
	"github.com/spf13/cobra"
)

// manualSyncLockTimeout caps how long `pmg cloud sync` waits to acquire the
// shared sync lock when an auto-sync child is already running. Long enough to
// let a normal background drain complete, short enough that a stuck process
// surfaces as a usefulerror rather than an indefinite hang.
const manualSyncLockTimeout = 30 * time.Second

var (
	syncTimeout   time.Duration
	requirePolicy bool
)

func newSyncCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Fetch the cloud policy and sync pending audit events to SafeDep Cloud",
		RunE:  runSync,
	}

	cmd.Flags().DurationVar(&syncTimeout, "timeout", 15*time.Minute, "Maximum time to spend on the sync")
	cmd.Flags().BoolVar(&requirePolicy, "require-policy", false,
		"Fetch only the cloud policy, and fail when no cloud policy applies. Run it before the first install of a CI job. Ignores --timeout")

	return cmd
}

func runSync(cmd *cobra.Command, args []string) error {
	cfg := config.Get()

	if !cfg.Config.Cloud.Enabled {
		ui.ErrorExit(usefulerror.NewUsefulError().
			WithCode(errcodes.Lifecycle).
			WithHumanError("Cloud sync is not enabled").
			WithHelp("Set 'cloud.enabled: true' in PMG config to enable cloud sync"))
	}

	if requirePolicy {
		st, warning, err := cloudsync.RequirePolicy(cmd.Context(), cfg)
		if err != nil {
			ui.ErrorExit(err)
		}
		if warning != "" {
			ui.ShowWarning(warning)
		}
		if st.Applied != nil {
			ui.Successf("Cloud policy revision %d applies", st.Applied.Revision)
		}
		return nil
	}

	// The policy fetch runs first, so a user or IT can force a fetch.
	res, err := cloudsync.Run(cmd.Context(), cfg, cloudsync.Plan{
		Policy:      cloudsync.StepForce,
		Events:      cloudsync.StepForce,
		LockTimeout: manualSyncLockTimeout,
		Timeout:     syncTimeout,
	})
	if err != nil {
		ui.ErrorExit(cloudsync.SyncFailureError(err))
	}

	if res.PolicyRan && res.PolicyErr == nil {
		ui.Successf("Fetched the cloud policy: revision %d (%s)", res.Policy.Revision, res.Policy.Status)
	}
	if res.EventsErr == nil {
		ui.Successf("Synced %d events to SafeDep Cloud", res.Synced)
	}

	if res.PolicyErr != nil {
		ui.ErrorExit(cloudsync.PolicyFetchFailureError(res.PolicyErr, appliedPolicyRevision(cfg)))
	}
	if res.EventsErr != nil {
		ui.ErrorExit(cloudsync.SyncFailureError(res.EventsErr))
	}
	return nil
}

// appliedPolicyRevision returns the revision of the cloud policy that pmg
// applies, or 0 when no policy applies.
func appliedPolicyRevision(cfg *config.RuntimeConfig) uint64 {
	st := cloudpolicy.Global().Status()
	if st == nil {
		st = cloudpolicy.Load(cfg, "")
	}
	if st.Applied == nil {
		return 0
	}
	return st.Applied.Revision
}
