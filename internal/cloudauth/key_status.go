package cloudauth

import (
	"os"
	"time"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/log"
)

// KeyExpiryWarning is how long before its expiry pmg warns about an API key.
const KeyExpiryWarning = 14 * 24 * time.Hour

// KeyOrigin is where pmg found the SafeDep Cloud credentials.
type KeyOrigin int

const (
	KeyOriginUnknown KeyOrigin = iota
	KeyOriginKeychain
	KeyOriginEnvironment
	KeyOriginCredentialFile
)

// KeyState is the expiry state of an API key. The keychain records the
// expiry only for a key that was saved with it. pmg cloud login saves a
// pasted key, so its state is KeyStateUnknown.
type KeyState int

const (
	KeyStateUnknown KeyState = iota
	KeyStateValid
	KeyStateExpiring
	KeyStateExpired
)

// KeyStatus is the origin and the expiry state of resolved credentials.
type KeyStatus struct {
	Origin    KeyOrigin
	State     KeyState
	ExpiresAt time.Time
}

// StatusOf returns the origin and the expiry state of creds at now. It makes
// no network call.
func StatusOf(creds *cloud.Credentials, now time.Time) KeyStatus {
	status := KeyStatus{Origin: originOf(creds)}

	expiresAt, ok := creds.APIKeyExpiresAt()
	if !ok {
		return status
	}

	status.ExpiresAt = expiresAt
	switch {
	case !expiresAt.After(now):
		status.State = KeyStateExpired
	case expiresAt.Before(now.Add(KeyExpiryWarning)):
		status.State = KeyStateExpiring
	default:
		status.State = KeyStateValid
	}
	return status
}

// ResolveStatus resolves the credentials as ResolveCredentials does and
// returns their status. It makes no network call. When the resolve fails, the
// origin of the status is KeyOriginCredentialFile if CredentialFileEnv is
// set, because pmg reads only that file then.
func ResolveStatus(now time.Time) (KeyStatus, error) {
	creds, closeFn, err := ResolveCredentials()
	defer func() {
		if err := closeFn(); err != nil {
			log.Warnf("failed to close keychain resolver: %v", err)
		}
	}()
	if err != nil {
		if os.Getenv(CredentialFileEnv) != "" {
			return KeyStatus{Origin: KeyOriginCredentialFile}, err
		}
		return KeyStatus{}, err
	}
	return StatusOf(creds, now), nil
}

// ExpiryText is the expiry of the key in UTC, for a message.
func (s KeyStatus) ExpiryText() string {
	return s.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC")
}

// CredentialHelp says how the user fixes the credentials of origin.
func CredentialHelp(origin KeyOrigin) string {
	switch origin {
	case KeyOriginKeychain:
		return "Run 'pmg cloud login' with a new API key"
	case KeyOriginEnvironment:
		return "Set SAFEDEP_API_KEY and SAFEDEP_TENANT_ID to a valid API key and its tenant"
	case KeyOriginCredentialFile:
		return "Run the job again to get a new credential in the file that " + CredentialFileEnv + " names"
	default:
		return "Run 'pmg cloud login' to update credentials, or check the SAFEDEP_API_KEY and SAFEDEP_TENANT_ID environment variables"
	}
}

// originOf returns where creds came from. ResolveCredentials reads only the
// credential file when CredentialFileEnv is set, and the credentials of that
// file carry no source.
func originOf(creds *cloud.Credentials) KeyOrigin {
	switch creds.Source() {
	case cloud.CredentialSourceKeychain:
		return KeyOriginKeychain
	case cloud.CredentialSourceEnvironment:
		return KeyOriginEnvironment
	}
	if os.Getenv(CredentialFileEnv) != "" {
		return KeyOriginCredentialFile
	}
	return KeyOriginUnknown
}
