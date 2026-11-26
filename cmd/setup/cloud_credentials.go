package setup

import (
	"fmt"
	"time"

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
		return doctor.CheckResult{
			Status:  doctor.StatusWarn,
			Message: "Cloud sync is on, but pmg finds no SafeDep Cloud credentials",
			Fix:     "Run: pmg cloud login",
		}
	}

	from := originName(status.Origin)
	day := status.ExpiresAt.UTC().Format(time.DateOnly)
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
