package truststore

import (
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/safedep/pmg/internal/platform"
	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// persistedCA writes a new PMG CA to a temporary config directory, as
// `pmg setup cert install` does, and returns the directory and the CA.
func persistedCA(t *testing.T) (string, *certmanager.Certificate) {
	t.Helper()
	dir := t.TempDir()
	ca, err := certmanager.GenerateCA(certmanager.DefaultCertManagerConfig())
	require.NoError(t, err)
	require.NoError(t, certmanager.SaveCA(dir, ca))
	return dir, ca
}

// fakePlatform replaces the store lookup and the trust check until the test
// ends.
func fakePlatform(t *testing.T, user, system bool, verifyErr error) *[]string {
	t.Helper()
	var verified []string
	origStores, origVerify := caStores, verifyCATrusted
	caStores = func(*x509.Certificate) (bool, bool, error) { return user, system, nil }
	verifyCATrusted = func(certPath string, _ *x509.Certificate) error {
		verified = append(verified, certPath)
		return verifyErr
	}
	t.Cleanup(func() { caStores, verifyCATrusted = origStores, origVerify })
	return &verified
}

func TestStatusCountsAStoreOnlyWhenTheOSTrustsTheExactCA(t *testing.T) {
	dir, _ := persistedCA(t)
	tests := []struct {
		name              string
		user, system      bool
		verifyErr         error
		wantUser, wantSys bool
		wantErr           bool
	}{
		{name: "both stores hold the CA and the OS trusts it", user: true, system: true, wantUser: true, wantSys: true},
		{name: "only the system store holds the CA", system: true, wantSys: true},
		{name: "a store holds the CA without trust", user: true, verifyErr: fmt.Errorf("%w: no trust settings", ErrCANotTrusted)},
		{name: "no store holds the CA", user: false, system: false},
		{name: "the trust check fails", system: true, verifyErr: assert.AnError, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakePlatform(t, tt.user, tt.system, tt.verifyErr)

			user, system, err := Status(dir)
			if tt.wantErr {
				assert.ErrorIs(t, err, assert.AnError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantUser, user)
			assert.Equal(t, tt.wantSys, system)
		})
	}
}

func TestStatusWithoutAPersistedCA(t *testing.T) {
	verified := fakePlatform(t, true, true, nil)

	user, system, err := Status(t.TempDir())
	require.NoError(t, err)
	assert.False(t, user)
	assert.False(t, system)
	assert.Empty(t, *verified, "with no CA on disk there is nothing to check")
}

func TestGoTrustsCAChecksThePersistedCertificate(t *testing.T) {
	dir, _ := persistedCA(t)
	verified := fakePlatform(t, false, false, ErrCANotTrusted)

	err := GoTrustsCA(dir)
	if !platform.CAUserScopeSupported() {
		require.NoError(t, err, "go reads SSL_CERT_FILE here, so any CA works")
		assert.Empty(t, *verified)
		return
	}
	assert.ErrorIs(t, err, ErrCANotTrusted)
	assert.Equal(t, []string{certmanager.CACertPath(dir)}, *verified)
}

func TestErrorsMatchThePlatformErrors(t *testing.T) {
	assert.ErrorIs(t, ErrCANotTrusted, platform.ErrCANotTrusted)
	assert.ErrorIs(t, ErrUserScopeUnsupported, platform.ErrCAUserScopeUnsupported)
}
