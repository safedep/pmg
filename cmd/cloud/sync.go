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
	"github.com/safedep/pmg/internal/cloudauth"
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
		st, key, err := cloudsync.RequirePolicy(cmd.Context(), cfg, timeout)
		warnings, err := requirePolicyOutcome(err, key)
		if err != nil {
			ui.ErrorExit(err)
		}
		for _, warning := range warnings {
			ui.ShowWarning(warning)
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
		ui.ErrorExit(syncFailureError(err, nil))
	}

	if res.PolicyRan && res.PolicyErr == nil {
		ui.Successf("Fetched the cloud policy: revision %d (%s)", res.Policy.Revision, res.Policy.Status)
	}
	if res.EventsErr == nil {
		ui.Successf("Synced %d events to SafeDep Cloud", res.Synced)
	}

	warning, err := syncOutcome(res, appliedPolicyRevision(cfg))
	if warning != "" {
		ui.ShowWarning(warning)
	}
	if err != nil {
		ui.ErrorExit(err)
	}
	return nil
}

// requirePolicyOutcome maps the result of cloudsync.RequirePolicy to the
// warnings and the error of pmg cloud sync --require-policy.
func requirePolicyOutcome(err error, key *cloudauth.KeyStatus) ([]string, error) {
	var warnings []string
	var policyWarning *cloudsync.PolicyWarning
	switch {
	case errors.As(err, &policyWarning):
		warnings = append(warnings, policyWarningText(policyWarning, key))
	case err != nil:
		return nil, requirePolicyError(err, key)
	}
	if expiry := keyExpiryWarning(key, err); expiry != "" {
		warnings = append(warnings, expiry)
	}
	return warnings, nil
}

// syncOutcome maps the result of a sync to its warning and its error. applied
// is the revision of the cloud policy that applies, or 0.
func syncOutcome(res *cloudsync.Result, applied uint64) (string, error) {
	warning := keyExpiryWarning(res.Key, res.Err())
	switch {
	case res.PolicyErr != nil:
		return warning, policyFetchFailureError(res.PolicyErr, applied, res.Key)
	case res.EventsErr != nil:
		return warning, syncFailureError(res.EventsErr, res.Key)
	default:
		return warning, nil
	}
}

// keyExpiryWarning warns about a key that expires within
// cloudauth.KeyExpiryWarning. key is the status of the credentials that the
// sync used, or nil when no step used them. It gives no warning when SafeDep
// Cloud rejected the key with err, because the error of the rejection then
// tells the user what to do.
func keyExpiryWarning(key *cloudauth.KeyStatus, err error) string {
	if key == nil || key.State != cloudauth.KeyStateExpiring || isRejection(err) {
		return ""
	}
	return fmt.Sprintf("The SafeDep Cloud API key expires on %s. Replace it before that date. %s.",
		key.ExpiryText(), cloudauth.CredentialHelp(key.Origin))
}

// expiredKeyRejected reports whether SafeDep Cloud rejected the credentials
// with err and the keychain records that the key expired. SafeDep Cloud
// rejects an expired key with a generic authentication error that does not
// give the date.
func expiredKeyRejected(err error, key *cloudauth.KeyStatus) bool {
	return key != nil && key.State == cloudauth.KeyStateExpired && isRejection(err)
}

// isRejection reports whether SafeDep Cloud rejected the credentials with err.
func isRejection(err error) bool {
	usefulErr, ok := usefulerror.AsUsefulError(err)
	return ok && isRejectionCode(usefulErr.Code())
}

func keyOrigin(key *cloudauth.KeyStatus) cloudauth.KeyOrigin {
	if key == nil {
		return cloudauth.KeyOriginUnknown
	}
	return key.Origin
}

// policyWarningText is the warning of a failed policy fetch that does not
// stop pmg cloud sync --require-policy.
func policyWarningText(w *cloudsync.PolicyWarning, key *cloudauth.KeyStatus) string {
	if w.Revision > 0 {
		text := fmt.Sprintf("Cannot fetch the cloud policy (%v). The last policy still applies (revision %d).", w.Err, w.Revision)
		switch {
		case expiredKeyRejected(w.Err, key):
			text += fmt.Sprintf(" The SafeDep Cloud API key expired on %s. %s.", key.ExpiryText(), cloudauth.CredentialHelp(key.Origin))
		case isRejection(w.Err):
			text += " " + cloudauth.CredentialHelp(keyOrigin(key)) + "."
		}
		return text
	}
	return "Your SafeDep plan does not include the cloud policy, so no cloud policy applies. " +
		"Set 'cloud.policy: false' in the PMG config to turn off this warning."
}

// requirePolicyError maps the error of pmg cloud sync --require-policy, when
// no cloud policy applies, to a user-facing error.
func requirePolicyError(err error, key *cloudauth.KeyStatus) error {
	switch {
	case errors.Is(err, cloudsync.ErrPolicyRejected):
		return usefulerror.NewUsefulError().
			Wrap(err).
			WithCode(errcodes.Lifecycle).
			WithHumanError("No cloud policy applies. pmg did not accept the policy that it fetched").
			WithHelp("Run 'pmg setup doctor' to see why the cloud policy does not apply")
	case errors.Is(err, audit.ErrSyncInProgress), errors.Is(err, cloud.ErrMissingCredentials):
		return syncFailureError(err, key)
	default:
		return policyFetchFailureError(err, 0, key)
	}
}

// policyFetchFailureError maps a failed policy fetch to a user-facing error.
// pmg keeps the last policy that it applied. applied is the revision of that
// policy, or 0 when no policy applies. A credential or entitlement error keeps
// its own text, because the user must fix the login. Every other error says
// which policy still applies.
func policyFetchFailureError(err error, applied uint64, key *cloudauth.KeyStatus) error {
	usefulErr, ok := usefulerror.AsUsefulError(err)
	if ok && isCredentialCode(usefulErr.Code()) {
		return withCredentialGuidance(usefulErr, err, key)
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
	return isRejectionCode(code) || code == usefulerror.ErrMissingEntitlements
}

// isRejectionCode reports whether SafeDep Cloud rejected the credentials.
func isRejectionCode(code string) bool {
	return code == usefulerror.ErrAuthenticationFailed || code == usefulerror.ErrAuthorizationFailed
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
func syncFailureError(err error, key *cloudauth.KeyStatus) error {
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
		return withCredentialGuidance(usefulErr, err, key)
	}

	return usefulerror.NewUsefulError().
		Wrap(err).
		WithCode(errcodes.Network).
		WithHumanError("Failed to sync events to SafeDep Cloud").
		WithHelp("Check your network connectivity and ensure SafeDep Cloud is reachable").
		WithAdditionalHelp("Override the cloud endpoint with SAFEDEP_CLOUD_DATA_ADDR if needed")
}

// withCredentialGuidance rebrands generic auth failures (invalid API key,
// wrong tenant, gateway 401/403) with how to fix the credentials in pmg, for
// the origin of key. It gives the date when the keychain records that the key
// expired. Richer classifications like missing entitlements keep their own
// code and help.
func withCredentialGuidance(usefulErr usefulerror.UsefulError, err error, key *cloudauth.KeyStatus) error {
	code := usefulErr.Code()
	if !isRejectionCode(code) {
		return usefulErr
	}

	human := "SafeDep Cloud rejected your credentials"
	if expiredKeyRejected(err, key) {
		human = fmt.Sprintf("SafeDep Cloud rejected the API key. The API key expired on %s", key.ExpiryText())
	}
	return usefulerror.NewUsefulError().
		Wrap(err).
		WithCode(code).
		WithHumanError(human).
		WithHelp(cloudauth.CredentialHelp(keyOrigin(key))).
		WithAdditionalHelp(usefulErr.AdditionalHelp())
}
