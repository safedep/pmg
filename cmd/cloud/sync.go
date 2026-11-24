package cloud

import (
	"errors"
	"fmt"
	"time"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/audit"
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
		"Fetch only the cloud policy, and fail when no cloud policy applies. Run it before the first install of a CI job. With this flag, --timeout defaults to 10s")

	return cmd
}

func runSync(cmd *cobra.Command, args []string) error {
	cfg := config.Get()

	if requirePolicy {
		timeout := cloudsync.DefaultFetchTimeout
		if cmd.Flags().Changed("timeout") {
			timeout = syncTimeout
		}
		st, err := cloudsync.RequirePolicy(cmd.Context(), cfg, timeout)
		var warning *cloudsync.PolicyWarning
		switch {
		case errors.As(err, &warning):
			ui.ShowWarning(policyWarningText(warning))
		case err != nil:
			ui.ErrorExit(requirePolicyError(err))
		}
		if st.Applied != nil {
			ui.Successf("Cloud policy revision %d applies", st.Applied.Revision)
		}
		return nil
	}

	if !cfg.Config.Cloud.Enabled {
		ui.ErrorExit(usefulerror.NewUsefulError().
			WithCode(errcodes.Lifecycle).
			WithHumanError("Cloud sync is not enabled").
			WithHelp("Set 'cloud.enabled: true' in PMG config to enable cloud sync"))
	}

	// The policy fetch runs first, so a user or IT can force a fetch.
	res, err := cloudsync.Run(cmd.Context(), cfg, cloudsync.Plan{
		Policy:      cloudsync.StepForce,
		Events:      cloudsync.StepForce,
		LockTimeout: manualSyncLockTimeout,
		Timeout:     syncTimeout,
	})
	if err != nil {
		ui.ErrorExit(syncFailureError(err))
	}

	if res.PolicyRan && res.PolicyErr == nil {
		ui.Successf("Fetched the cloud policy: revision %d (%s)", res.Policy.Revision, res.Policy.Status)
	}
	if res.EventsErr == nil {
		ui.Successf("Synced %d events to SafeDep Cloud", res.Synced)
	}

	if res.PolicyErr != nil {
		ui.ErrorExit(policyFetchFailureError(res.PolicyErr, appliedPolicyRevision(cfg)))
	}
	if res.EventsErr != nil {
		ui.ErrorExit(syncFailureError(res.EventsErr))
	}
	return nil
}

// policyWarningText is the warning of a failed policy fetch that does not
// stop pmg cloud sync --require-policy.
func policyWarningText(w *cloudsync.PolicyWarning) string {
	if w.Revision > 0 {
		return fmt.Sprintf("Cannot fetch the cloud policy (%v). The last policy still applies (revision %d).", w.Err, w.Revision)
	}
	return "Your SafeDep plan does not include the cloud policy, so no cloud policy applies. " +
		"Set 'cloud.policy: false' in the PMG config to turn off this warning."
}

// requirePolicyError maps the error of pmg cloud sync --require-policy, when
// no cloud policy applies, to a user-facing error.
func requirePolicyError(err error) error {
	switch {
	case errors.Is(err, cloudsync.ErrPolicyRejected):
		return usefulerror.NewUsefulError().
			Wrap(err).
			WithCode(errcodes.Lifecycle).
			WithHumanError("No cloud policy applies. pmg did not accept the policy that it fetched").
			WithHelp("Run 'pmg setup doctor' to see why the cloud policy does not apply")
	case errors.Is(err, audit.ErrSyncInProgress), errors.Is(err, cloud.ErrMissingCredentials):
		return syncFailureError(err)
	default:
		return policyFetchFailureError(err, 0)
	}
}

// policyFetchFailureError maps a failed policy fetch to a user-facing error.
// pmg keeps the last policy that it applied. applied is the revision of that
// policy, or 0 when no policy applies. A credential or entitlement error keeps
// its own text, because the user must fix the login. Every other error says
// which policy still applies.
func policyFetchFailureError(err error, applied uint64) error {
	usefulErr, ok := usefulerror.AsUsefulError(err)
	if ok && isCredentialCode(usefulErr.Code()) {
		return withCredentialGuidance(usefulErr, err)
	}

	code := errcodes.Network
	help := "Check your network connectivity and ensure SafeDep Cloud is reachable"
	if ok {
		code = usefulErr.Code()
		if !isNetworkCode(code) && usefulErr.Help() != "" {
			help = usefulErr.Help()
		}
	}
	human := "Cannot fetch the cloud policy from SafeDep Cloud. No cloud policy applies yet"
	if applied > 0 {
		human = fmt.Sprintf("Cannot fetch the cloud policy from SafeDep Cloud. The last policy still applies (revision %d)", applied)
	}
	return usefulerror.NewUsefulError().
		Wrap(err).
		WithCode(code).
		WithHumanError(human).
		WithHelp(help).
		WithAdditionalHelp("Run 'pmg setup doctor' to see the policy that pmg applies")
}

func isCredentialCode(code string) bool {
	switch code {
	case usefulerror.ErrAuthenticationFailed, usefulerror.ErrAuthorizationFailed, usefulerror.ErrMissingEntitlements:
		return true
	}
	return false
}

func isNetworkCode(code string) bool {
	switch code {
	case errcodes.Network, errcodes.Timeout, usefulerror.ErrNetworkError:
		return true
	}
	return false
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

// syncFailureError maps a failed sync to a user-facing error. Errors
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
