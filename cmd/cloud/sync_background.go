package cloud

import (
	"context"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/audit"
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
		Short:  "Internal: drain the cloud sync WAL from a detached child process",
		Hidden: true,
		RunE:   runSyncBackground,
	}
	return cmd
}

func runSyncBackground(cmd *cobra.Command, args []string) error {
	audit.MarkBackgroundSyncChild()

	cfg := config.Get()

	if analytics.IsDisabled() {
		log.Debugf("Auto-sync: telemetry disabled; exiting")
		return nil
	}

	if !cfg.Config.Cloud.Enabled || !cfg.Config.Cloud.AutoSync.Enabled {
		log.Debugf("Auto-sync: cloud or auto_sync disabled; exiting")
		return nil
	}

	lock := audit.NewSyncLock(cfg.CloudSyncLockPath())

	locked, err := lock.TryLock()
	if err != nil {
		log.Warnf("Auto-sync: failed to acquire lock: %v", err)
		return nil
	}
	if !locked {
		log.Debugf("Auto-sync: another sync is in progress; exiting")
		return nil
	}
	defer func() {
		if err := lock.Unlock(); err != nil {
			log.Warnf("Auto-sync: failed to release lock: %v", err)
		}
	}()

	// Re-check cooldown under the lock to close the TOCTOU window between the
	// parent's pre-fork stat and our acquisition.
	if !audit.SyncCooldownElapsed(cfg.CloudSyncLastRunPath(), cfg.Config.Cloud.AutoSync.MinInterval) {
		log.Debugf("Auto-sync: cooldown still in effect under lock; exiting")
		return nil
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Config.Cloud.AutoSync.Timeout)
	defer cancel()

	bundle, err := audit.NewSyncClientBundle(cfg)
	if err != nil {
		log.Warnf("Auto-sync: failed to initialize sync client: %v", err)
		recordLastSyncAttempt(cfg)
		return nil
	}
	defer func() {
		if err := bundle.Close(); err != nil {
			log.Warnf("Auto-sync: failed to close sync client: %v", err)
		}
	}()

	synced, err := bundle.Sync(ctx)
	recordLastSyncAttempt(cfg)
	if err != nil {
		log.Warnf("Auto-sync: sync failed after %d events: %v", synced, err)
		return nil
	}

	log.Infof("Auto-sync: drained %d events to SafeDep Cloud", synced)
	return nil
}

// recordLastSyncAttempt updates the cooldown timestamp on every attempt so a
// failing cloud endpoint does not cause every PMG invocation to retry.
func recordLastSyncAttempt(cfg *config.RuntimeConfig) {
	if err := audit.WriteLastSyncAttempt(cfg.CloudSyncLastRunPath()); err != nil {
		log.Warnf("failed to update cloud sync lastrun: %v", err)
	}
}
