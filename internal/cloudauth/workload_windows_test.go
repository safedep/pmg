//go:build windows

package cloudauth

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/internal/cloudauth/cloudauthtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Windows has no owner and no mode bits that pmg can check, so every use
// of a credential file fails there, and pmg uses no other credential.
func TestCredentialFileUnsupportedOnWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cred.json")

	assert.ErrorIs(t, WriteCredentialFile(path, testCredential), ErrCredentialFileUnsupported)
	assert.NoFileExists(t, path)

	require.NoError(t, os.WriteFile(path, []byte(`{"AccessToken":"token","TenantDomain":"acme.safedep.io"}`), 0o600))
	_, err := ReadCredentialFile(path)
	assert.ErrorIs(t, err, ErrCredentialFileUnsupported)

	t.Setenv("SAFEDEP_API_KEY", "env-api-key")
	t.Setenv("SAFEDEP_TENANT_ID", "other.safedep.io")
	t.Setenv(CredentialFileEnv, path)
	_, closeFn, err := ResolveCredentials()
	require.NoError(t, closeFn())
	assert.ErrorIs(t, err, ErrCredentialFileUnsupported, "pmg does not fall back to the API key")

	stub := &cloudauthtest.Exchange{}
	startStubExchange(t, stub)
	_, err = ExchangeToFile(context.Background(), testTenant, filepath.Join(t.TempDir(), "out.json"))
	assert.ErrorIs(t, err, ErrCredentialFileUnsupported)
	assert.Empty(t, stub.Exchanges(), "pmg refuses before it gets a credential")
}
