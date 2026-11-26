package setup

import (
	"errors"
	"fmt"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/pmg/internal/cloudauth"
	"github.com/safedep/pmg/internal/doctor"
)

const checkCloudCredentials = "cloud-credentials"

// cloudCredentialsResult is the doctor result of the SafeDep Cloud
// credentials, from their status or from the error that resolving them
// returned. It makes no network call, so it cannot find a key that SafeDep
// Cloud rejects. pmg cloud sync reports that.
func cloudCredentialsResult(status cloudauth.KeyStatus, resolveErr error) doctor.CheckResult {
	if resolveErr != nil {
		return credentialsErrorResult(status.Origin, resolveErr)
	}

	from := originName(status.Origin)
	day := status.ExpiryText()
	fix := cloudauth.CredentialHelp(status.Origin)

	switch status.State {
	case cloudauth.KeyStateExpired:
		return doctor.CheckResult{
			Status:  doctor.StatusFail,
			Message: fmt.Sprintf("The API key from the %s expired on %s", from, day),
			Fix:     fix,
		}
	case cloudauth.KeyStateExpiring:
		return doctor.CheckResult{
			Status:  doctor.StatusWarn,
			Message: fmt.Sprintf("The API key from the %s expires on %s", from, day),
			Fix:     fix,
		}
	case cloudauth.KeyStateValid:
		return doctor.CheckResult{
			Status:  doctor.StatusPass,
			Message: fmt.Sprintf("API key from the %s, expires on %s", from, day),
		}
	default:
		return doctor.CheckResult{
			Status:  doctor.StatusPass,
			Message: fmt.Sprintf("Credentials from the %s", from),
		}
	}
}

// credentialsErrorResult is the doctor result when pmg cannot resolve the
// credentials. A credential file that pmg cannot use fails the check, because
// pmg then uses no other credentials.
func credentialsErrorResult(origin cloudauth.KeyOrigin, err error) doctor.CheckResult {
	switch {
	case origin == cloudauth.KeyOriginCredentialFile:
		return doctor.CheckResult{
			Status:  doctor.StatusFail,
			Message: fmt.Sprintf("pmg cannot use the credential file that %s names (%v)", cloudauth.CredentialFileEnv, err),
			Fix:     cloudauth.CredentialHelp(origin),
		}
	case errors.Is(err, cloud.ErrMissingCredentials):
		return doctor.CheckResult{
			Status:  doctor.StatusWarn,
			Message: "Cloud sync is on, but pmg finds no SafeDep Cloud credentials",
			Fix:     "Run 'pmg cloud login', or set SAFEDEP_API_KEY and SAFEDEP_TENANT_ID",
		}
	default:
		return doctor.CheckResult{
			Status:  doctor.StatusWarn,
			Message: fmt.Sprintf("pmg cannot read the SafeDep Cloud credentials (%v)", err),
			Fix:     cloudauth.CredentialHelp(origin),
		}
	}
}

func originName(origin cloudauth.KeyOrigin) string {
	switch origin {
	case cloudauth.KeyOriginKeychain:
		return "keychain"
	case cloudauth.KeyOriginEnvironment:
		return "environment"
	case cloudauth.KeyOriginCredentialFile:
		return "credential file"
	default:
		return "default source"
	}
}
