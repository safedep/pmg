package cloud

import (
	"errors"
	"time"

	"github.com/safedep/dry/cloud"
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
// the backend already classified (entitlements, quota — via gRPC status and
// usefulerror converters) pass through so the real cause is shown, except
// auth failures which get credential setup guidance; the network-flavored
// message is only a fallback for errors nothing can classify.
func syncFailureError(err error) error {
	if errors.Is(err, audit.ErrSyncInProgress) {
		return usefulerror.NewUsefulError().
			WithCode(errcodes.Lifecycle).
			WithHumanError("Another cloud sync is already in progress").
			WithHelp("Wait for the in-progress sync to finish, then try again")
	}

	if errors.Is(err, cloud.ErrMissingCredentials) {
		return usefulerror.NewUsefulError().
			Wrap(err).
			WithCode(errcodes.CloudCredentialsNotFound).
			WithHumanError("SafeDep Cloud credentials are not configured").
			WithHelp("Run 'pmg cloud login' to store credentials, or set the SAFEDEP_API_KEY and SAFEDEP_TENANT_ID environment variables")
	}

	if usefulErr, ok := usefulerror.AsUsefulError(err); ok {
		return withCredentialGuidance(usefulErr, err)
	}

	return usefulerror.NewUsefulError().
		Wrap(err).
		WithCode(errcodes.Network).
		WithHumanError("Failed to sync events to SafeDep Cloud").
		WithHelp("Check your network connectivity and ensure SafeDep Cloud is reachable").
		WithAdditionalHelp("Override the cloud endpoint with SAFEDEP_CLOUD_DATA_ADDR if needed")
}

// withCredentialGuidance rebrands generic auth failures (invalid API key,
// wrong tenant, gateway 401/403) with how to fix credentials in pmg. Richer
// classifications like missing entitlements keep their own code and help.
func withCredentialGuidance(usefulErr usefulerror.UsefulError, err error) error {
	code := usefulErr.Code()
	if code != usefulerror.ErrAuthenticationFailed && code != usefulerror.ErrAuthorizationFailed {
		return usefulErr
	}

	return usefulerror.NewUsefulError().
		Wrap(err).
		WithCode(code).
		WithHumanError("SafeDep Cloud rejected your credentials").
		WithHelp("Run 'pmg cloud login' to update credentials, or check the SAFEDEP_API_KEY and SAFEDEP_TENANT_ID environment variables").
		WithAdditionalHelp(usefulErr.AdditionalHelp())
}
