package setup

import (
	"bytes"
	"os"
	"testing"

	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/safedep/pmg/truststore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeStore struct {
	installed     bool
	installErr    error
	uninstalled   bool
	user, system  bool
	userSupported bool
}

func (f *fakeStore) Install(_ []byte, _ truststore.Scope) error {
	if f.installErr != nil {
		return f.installErr
	}
	f.installed = true
	return nil
}
func (f *fakeStore) Uninstall(_ string, _ truststore.Scope) error { f.uninstalled = true; return nil }
func (f *fakeStore) Status(_ string) (bool, bool, error)          { return f.user, f.system, nil }
func (f *fakeStore) UserScopeSupported() bool                     { return f.userSupported }

func TestCertInstallGeneratesSavesAndInstalls(t *testing.T) {
	dir := t.TempDir()
	store := &fakeStore{userSupported: true}
	var out bytes.Buffer

	require.NoError(t, runCertInstall(dir, truststore.ScopeUser, false, store, &out))

	assert.True(t, store.installed)
	_, err := certmanager.LoadCA(dir)
	require.NoError(t, err) // keypair persisted
}

func TestCertInstallIdempotentWhenAlreadyTrusted(t *testing.T) {
	dir := t.TempDir()
	ca, err := certmanager.GenerateCA(certmanager.PersistentCACertManagerConfig())
	require.NoError(t, err)
	require.NoError(t, certmanager.SaveCA(dir, ca))

	store := &fakeStore{user: true, userSupported: true}
	var out bytes.Buffer
	require.NoError(t, runCertInstall(dir, truststore.ScopeUser, false, store, &out))

	assert.False(t, store.installed) // already trusted → no re-install
	assert.Contains(t, out.String(), "already installed")
}

func TestCertInstallLinuxUserNoopIsFriendly(t *testing.T) {
	dir := t.TempDir()
	store := &fakeStore{installErr: truststore.ErrUserScopeUnsupported, userSupported: false}
	var out bytes.Buffer

	require.NoError(t, runCertInstall(dir, truststore.ScopeUser, false, store, &out))
	assert.Contains(t, out.String(), "--system")
}

func TestCertInstallForceRotates(t *testing.T) {
	dir := t.TempDir()
	ca, err := certmanager.GenerateCA(certmanager.PersistentCACertManagerConfig())
	require.NoError(t, err)
	require.NoError(t, certmanager.SaveCA(dir, ca))

	store := &fakeStore{userSupported: true}
	var out bytes.Buffer
	require.NoError(t, runCertInstall(dir, truststore.ScopeUser, true, store, &out))

	assert.True(t, store.uninstalled) // rotation uninstalls old first
	assert.True(t, store.installed)
}

func TestErrIfRunningUnderSudo(t *testing.T) {
	orig := geteuid
	t.Cleanup(func() { geteuid = orig })

	// root + SUDO_USER set → refused (sudo from a normal user).
	geteuid = func() int { return 0 }
	t.Setenv("SUDO_USER", "alice")
	assert.Error(t, errIfRunningUnderSudo())

	// root without SUDO_USER → genuine root, allowed.
	t.Setenv("SUDO_USER", "")
	assert.NoError(t, errIfRunningUnderSudo())

	// non-root → allowed even if SUDO_USER somehow set.
	geteuid = func() int { return 1000 }
	t.Setenv("SUDO_USER", "alice")
	assert.NoError(t, errIfRunningUnderSudo())
}

func TestCertInstallReplacesCorruptedCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := certmanager.GenerateCA(certmanager.PersistentCACertManagerConfig())
	require.NoError(t, err)
	require.NoError(t, certmanager.SaveCA(dir, ca))

	// Simulate a partial/corrupt state: cert still on disk (and possibly trusted)
	// but the private key is gone. Install must clean up the old root, not stack a
	// second one alongside a freshly generated keypair.
	require.NoError(t, os.Remove(certmanager.CAKeyPath(dir)))

	store := &fakeStore{userSupported: true}
	var out bytes.Buffer
	require.NoError(t, runCertInstall(dir, truststore.ScopeUser, false, store, &out))

	assert.True(t, store.uninstalled, "old trusted root should be cleaned up")
	assert.True(t, store.installed)
	_, err = certmanager.LoadCA(dir)
	require.NoError(t, err) // a complete keypair is regenerated
}

func TestCertUninstallPurgeDeletesFiles(t *testing.T) {
	dir := t.TempDir()
	ca, err := certmanager.GenerateCA(certmanager.PersistentCACertManagerConfig())
	require.NoError(t, err)
	require.NoError(t, certmanager.SaveCA(dir, ca))

	store := &fakeStore{}
	var out bytes.Buffer
	require.NoError(t, runCertUninstall(dir, truststore.ScopeUser, true, store, &out))

	assert.True(t, store.uninstalled)
	_, err = certmanager.LoadCA(dir)
	assert.Error(t, err) // files gone
	assert.NoFileExists(t, certmanager.CAKeyPath(dir))
}

func TestCertStatusReportsDrift(t *testing.T) {
	dir := t.TempDir()
	ca, err := certmanager.GenerateCA(certmanager.PersistentCACertManagerConfig())
	require.NoError(t, err)
	require.NoError(t, certmanager.SaveCA(dir, ca))
	// Simulate drift: remove the key, keep the cert.
	require.NoError(t, os.Remove(certmanager.CAKeyPath(dir)))

	store := &fakeStore{}
	var out bytes.Buffer
	require.NoError(t, runCertStatus(dir, store, &out))
	assert.Contains(t, out.String(), "drift")
}
