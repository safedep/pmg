package cloud

import (
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/cloudsync"
	"github.com/spf13/cobra"
)

// newSyncBackgroundCommand returns the hidden subcommand invoked by the
// detached child that audit.MaybeSpawnBackgroundSync forks. Always exits 0:
// the parent has already returned to the user's shell by the time this runs,
// so a non-zero exit would only show up to whatever (init / launchd) reaped
// the orphaned process.
func newSyncBackgroundCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:    audit.SyncBackgroundSubcommand,
		Short:  "Internal: fetch the cloud policy and drain the cloud sync WAL from a detached child process",
		Hidden: true,
		RunE:   runSyncBackground,
	}
	return cmd
}

// runSyncBackground fetches the cloud policy when cloud.policy is on, also
// when auto_sync is off. It checks auto_sync only before it sends events.
func runSyncBackground(cmd *cobra.Command, args []string) error {
	audit.MarkBackgroundSyncChild()

	cfg := config.Get()
	if !cfg.Config.Cloud.Enabled {
		log.Debugf("Auto-sync: cloud disabled; exiting")
		return nil
	}

	res, err := cloudsync.Run(cmd.Context(), cfg, cloudsync.Plan{
		Policy:  cloudsync.StepDue,
		Events:  cloudsync.StepDue,
		Timeout: cfg.Config.Cloud.AutoSync.Timeout,
	})
	if err != nil {
		log.Warnf("Auto-sync: %v", err)
		return nil
	}

	if res.EventsErr != nil {
		log.Warnf("Auto-sync: sync failed after %d events: %v", res.Synced, res.EventsErr)
	} else if res.EventsRan {
		log.Infof("Auto-sync: drained %d events to SafeDep Cloud", res.Synced)
	}
	return nil
}
