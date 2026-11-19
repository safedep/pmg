package cloudsync

import (
	"errors"
	"fmt"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/audit"
)

// PolicyFetchFailureError maps a failed policy fetch to a user-facing error.
// pmg keeps the last policy that it applied. applied is the revision of that
// policy, or 0 when no policy applies. A credential or entitlement error keeps
// its own text, because the user must fix the login. Every other error says
// which policy still applies.
func PolicyFetchFailureError(err error, applied uint64) error {
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

// SyncFailureError maps a failed sync to a user-facing error. Errors
// the backend already classified (entitlements, quota — via gRPC status and
// usefulerror converters) pass through so the real cause is shown, except
// auth failures which get credential setup guidance; the network-flavored
// message is only a fallback for errors nothing can classify.
func SyncFailureError(err error) error {
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
