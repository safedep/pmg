package cloud

import (
	"errors"
	"time"

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

	synced, err := audit.DrainToCloud(cmd.Context(), cfg, manualSyncLockTimeout, syncTimeout)
	if err != nil {
		ui.ErrorExit(syncFailureError(err))
	}

	ui.Successf("Synced %d events to SafeDep Cloud", synced)
	return nil
}

// syncFailureError maps a DrainToCloud failure to a user-facing error. Errors
// the backend already classified (authentication, entitlements, quota — via
// gRPC status and usefulerror converters) pass through so the real cause is
// shown; the network-flavored message is only a fallback for errors nothing
// can classify.
func syncFailureError(err error) error {
	if errors.Is(err, audit.ErrSyncInProgress) {
		return usefulerror.NewUsefulError().
			WithCode(errcodes.Lifecycle).
			WithHumanError("Another cloud sync is already in progress").
			WithHelp("Wait for the in-progress sync to finish, then try again")
	}

	if usefulErr, ok := usefulerror.AsUsefulError(err); ok {
		return usefulErr
	}

	return usefulerror.NewUsefulError().
		Wrap(err).
		WithCode(errcodes.Network).
		WithHumanError("Failed to sync events to SafeDep Cloud").
		WithHelp("Check your network connectivity and ensure SafeDep Cloud is reachable").
		WithAdditionalHelp("Override the cloud endpoint with SAFEDEP_CLOUD_DATA_ADDR if needed")
}
