package cloud

import (
	"context"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/ui"
	"github.com/spf13/cobra"
)

// manualSyncLockTimeout caps how long `pmg cloud sync` waits to acquire the
// shared sync lock when an auto-sync child is already running. Long enough to
// let a normal background drain complete, short enough that a stuck process
// surfaces as a usefulerror rather than an indefinite hang.
const manualSyncLockTimeout = 30 * time.Second

var syncTimeout time.Duration

func newSyncCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync pending audit events to SafeDep Cloud",
		RunE:  runSync,
	}

	cmd.Flags().DurationVar(&syncTimeout, "timeout", 15*time.Minute, "Maximum time to spend syncing events")

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

	lock := audit.NewSyncLock(cfg.CloudSyncLockPath())
	lockCtx, lockCancel := context.WithTimeout(cmd.Context(), manualSyncLockTimeout)
	defer lockCancel()

	locked, err := lock.TryLockContext(lockCtx, 250*time.Millisecond)
	if err != nil {
		ui.ErrorExit(usefulerror.NewUsefulError().
			Wrap(err).
			WithCode(errcodes.Lifecycle).
			WithHumanError("Failed to acquire cloud sync lock").
			WithHelp("Another sync may be in progress; try again shortly"))
	}
	if !locked {
		ui.ErrorExit(usefulerror.NewUsefulError().
			WithCode(errcodes.Lifecycle).
			WithHumanError("Another cloud sync is already in progress").
			WithHelp("Wait for the in-progress sync to finish, then try again"))
	}
	defer func() {
		if err := lock.Unlock(); err != nil {
			log.Warnf("failed to release cloud sync lock: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(cmd.Context(), syncTimeout)
	defer cancel()

	bundle, err := audit.NewSyncClientBundle(cfg)
	if err != nil {
		ui.ErrorExit(usefulerror.NewUsefulError().
			Wrap(err).
			WithCode(errcodes.Lifecycle).
			WithHumanError("Failed to initialize cloud sync client").
			WithHelp("Run 'pmg cloud login' to store credentials, or set SAFEDEP_API_KEY and SAFEDEP_TENANT_ID environment variables"))
	}
	defer func() {
		if err := bundle.Close(); err != nil {
			log.Warnf("failed to close sync client: %v", err)
		}
	}()

	synced, err := bundle.Sync(ctx)
	recordLastSyncAttempt(cfg)
	if err != nil {
		ui.ErrorExit(usefulerror.NewUsefulError().
			Wrap(err).
			WithCode(errcodes.Network).
			WithHumanError("Failed to sync events to SafeDep Cloud").
			WithHelp("Check your network connectivity and ensure SafeDep Cloud is reachable").
			WithAdditionalHelp("Override the cloud endpoint with SAFEDEP_CLOUD_DATA_ADDR if needed"))
	}

	ui.Successf("Synced %d events to SafeDep Cloud", synced)
	return nil
}
