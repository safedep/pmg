package cloud

import (
	"context"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/usefulerror"
	"github.com/spf13/cobra"
)

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

	if analytics.IsDisabled() {
		ui.Infof("Cloud sync is disabled because telemetry is disabled (disable_telemetry or PMG_DISABLE_TELEMETRY)")
		return nil
	}

	if !cfg.Config.Cloud.Enabled {
		ui.ErrorExit(usefulerror.Useful().
			WithCode(usefulerror.ErrCodeLifecycle).
			WithHumanError("Cloud sync is not enabled").
			WithHelp("Set 'cloud.enabled: true' in PMG config to enable cloud sync"))
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), syncTimeout)
	defer cancel()

	bundle, err := audit.NewSyncClientBundle(cfg)
	if err != nil {
		ui.ErrorExit(usefulerror.Useful().
			Wrap(err).
			WithCode(usefulerror.ErrCodeLifecycle).
			WithHumanError("Failed to initialize cloud sync client").
			WithHelp("Run 'pmg cloud login' to store credentials, or set SAFEDEP_API_KEY and SAFEDEP_TENANT_ID environment variables"))
	}
	defer func() {
		if err := bundle.Close(); err != nil {
			log.Warnf("failed to close sync client: %v", err)
		}
	}()

	synced, err := bundle.Sync(ctx)
	if err != nil {
		ui.ErrorExit(usefulerror.Useful().
			Wrap(err).
			WithCode(usefulerror.ErrCodeNetwork).
			WithHumanError("Failed to sync events to SafeDep Cloud").
			WithHelp("Check your network connectivity and ensure SafeDep Cloud is reachable").
			WithAdditionalHelp("Override the cloud endpoint with SAFEDEP_CLOUD_DATA_ADDR if needed"))
	}

	ui.Successf("Synced %d events to SafeDep Cloud", synced)
	return nil
}
