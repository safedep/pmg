package setup

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/safedep/pmg/internal/doctor"
	"github.com/safedep/pmg/internal/platform"
	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeStore struct {
	installErr    error
	user, system  bool
	userSupported bool
	calls         []string
}

func (f *fakeStore) Install(_ []byte, s platform.CAScope) error {
	f.calls = append(f.calls, "install "+s.String())
	return f.installErr
}
func (f *fakeStore) Uninstall(_ string, s platform.CAScope) error {
	f.calls = append(f.calls, "uninstall "+s.String())
	return nil
}

func (f *fakeStore) called(prefix string) bool {
	return slices.ContainsFunc(f.calls, func(c string) bool { return strings.HasPrefix(c, prefix) })
}
func (f *fakeStore) Status(_ string) (bool, bool, error) { return f.user, f.system, nil }
func (f *fakeStore) UserScopeSupported() bool            { return f.userSupported }

func TestCertInstallGeneratesSavesAndInstalls(t *testing.T) {
	dir := t.TempDir()
	store := &fakeStore{userSupported: true}
	var out bytes.Buffer

	require.NoError(t, runCertInstall(dir, platform.CAScopeUser, false, store, &out))

	assert.True(t, store.called("install"))
	_, err := certmanager.LoadCA(dir)
	require.NoError(t, err) // keypair persisted
}

func TestCertInstallRemovesSameNameCertsBeforeInstall(t *testing.T) {
	store := &fakeStore{userSupported: true}
	var out bytes.Buffer

	require.NoError(t, runCertInstall(t.TempDir(), platform.CAScopeSystem, false, store, &out))

	assert.Equal(t, []string{"uninstall system", "install system"}, store.calls,
		"a stale certificate with the PMG name must not stay trusted next to the new CA")
}

func TestCertInstallIdempotentWhenAlreadyTrusted(t *testing.T) {
	dir := t.TempDir()
	ca, err := certmanager.GenerateCA(certmanager.PersistentCACertManagerConfig())
	require.NoError(t, err)
	require.NoError(t, certmanager.SaveCA(dir, ca))

	store := &fakeStore{user: true, userSupported: true}
	var out bytes.Buffer
	require.NoError(t, runCertInstall(dir, platform.CAScopeUser, false, store, &out))

	assert.False(t, store.called("install")) // already trusted → no re-install
	assert.Contains(t, out.String(), "already installed")
}

func TestCertInstallLinuxUserNoopIsFriendly(t *testing.T) {
	dir := t.TempDir()
	store := &fakeStore{installErr: platform.ErrCAUserScopeUnsupported, userSupported: false}
	var out bytes.Buffer

	require.NoError(t, runCertInstall(dir, platform.CAScopeUser, false, store, &out))
	assert.Contains(t, out.String(), "--system")
}

func TestCertInstallForceRotates(t *testing.T) {
	dir := t.TempDir()
	ca, err := certmanager.GenerateCA(certmanager.PersistentCACertManagerConfig())
	require.NoError(t, err)
	require.NoError(t, certmanager.SaveCA(dir, ca))

	store := &fakeStore{userSupported: true}
	var out bytes.Buffer
	require.NoError(t, runCertInstall(dir, platform.CAScopeUser, true, store, &out))

	assert.True(t, store.called("uninstall")) // rotation uninstalls old first
	assert.True(t, store.called("install"))
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
	require.NoError(t, runCertInstall(dir, platform.CAScopeUser, false, store, &out))

	assert.True(t, store.called("uninstall"), "old trusted root should be cleaned up")
	assert.True(t, store.called("install"))
	_, err = certmanager.LoadCA(dir)
	require.NoError(t, err) // a complete keypair is regenerated
}

func TestCertUninstallPurgeDeletesEveryKeypair(t *testing.T) {
	tests := []struct {
		name  string
		dirs  int
		scope platform.CAScope
	}{
		{name: "the user keypair", dirs: 1, scope: platform.CAScopeUser},
		{name: "the user keypair and a legacy system keypair", dirs: 2, scope: platform.CAScopeSystem},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dirs []string
			for range tt.dirs {
				dir := t.TempDir()
				writeKeypair(t, dir)
				dirs = append(dirs, dir)
			}
			store := &fakeStore{}
			var out bytes.Buffer

			require.NoError(t, runCertUninstall(dirs, tt.scope, true, store, &out))

			assert.True(t, store.called("uninstall"))
			for _, dir := range dirs {
				assert.NoFileExists(t, certmanager.CACertPath(dir))
				assert.NoFileExists(t, certmanager.CAKeyPath(dir))
			}
		})
	}
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

func writeKeypair(t *testing.T, dir string) {
	t.Helper()
	ca, err := certmanager.GenerateCA(certmanager.PersistentCACertManagerConfig())
	require.NoError(t, err)
	require.NoError(t, certmanager.SaveCA(dir, ca))
}

func TestKeypairLayoutDirs(t *testing.T) {
	tests := []struct {
		name          string
		enforcing     bool
		privileged    bool
		scope         platform.CAScope
		wantInstall   string
		wantPurge     []string
		wantStatusDir string
	}{
		{name: "enforcing proxy, root, system scope", enforcing: true, privileged: true, scope: platform.CAScopeSystem,
			wantInstall: "system", wantPurge: []string{"system"}, wantStatusDir: "user"},
		{name: "enforcing proxy, user, system scope", enforcing: true, scope: platform.CAScopeSystem,
			wantInstall: "user", wantPurge: []string{"user"}, wantStatusDir: "user"},
		{name: "no enforcing proxy, administrator, system scope", privileged: true, scope: platform.CAScopeSystem,
			wantInstall: "user", wantPurge: []string{"user", "legacy"}, wantStatusDir: "user"},
		{name: "no enforcing proxy, administrator, user scope", privileged: true, scope: platform.CAScopeUser,
			wantInstall: "user", wantPurge: []string{"user"}, wantStatusDir: "user"},
		{name: "no enforcing proxy, user, system scope", scope: platform.CAScopeSystem,
			wantInstall: "user", wantPurge: []string{"user"}, wantStatusDir: "user"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dirs := map[string]string{"user": t.TempDir(), "system": t.TempDir(), "legacy": t.TempDir()}
			l := keypairLayout{user: dirs["user"], legacy: dirs["legacy"]}
			if tt.enforcing {
				l = keypairLayout{user: dirs["user"], system: dirs["system"]}
			}
			withPrivilege(t, tt.privileged)
			t.Setenv("SUDO_USER", "")

			dir, err := l.installDir(tt.scope)
			require.NoError(t, err)
			assert.Equal(t, dirs[tt.wantInstall], dir)

			purge, err := l.purgeDirs(tt.scope)
			require.NoError(t, err)
			var want []string
			for _, name := range tt.wantPurge {
				want = append(want, dirs[name])
			}
			assert.Equal(t, want, purge)

			dir, err = l.statusDir()
			require.NoError(t, err)
			assert.Equal(t, dirs[tt.wantStatusDir], dir, "with no keypair anywhere, status reads the user's")
		})
	}
}

func TestKeypairLayoutInspectsTheUsersKeypairFirst(t *testing.T) {
	l := keypairLayout{user: t.TempDir(), system: t.TempDir()}
	writeKeypair(t, l.system)

	dir, isSystem := l.inspectDir()
	assert.Equal(t, l.system, dir, "only the system keypair exists")
	assert.True(t, isSystem)

	writeKeypair(t, l.user)
	dir, isSystem = l.inspectDir()
	assert.Equal(t, l.user, dir)
	assert.False(t, isSystem)
}

func TestKeypairLayoutStatusReadsTheSystemKeypairAsRoot(t *testing.T) {
	l := keypairLayout{user: t.TempDir(), system: t.TempDir()}
	writeKeypair(t, l.system)
	withPrivilege(t, true)
	t.Setenv("SUDO_USER", "")

	dir, err := l.statusDir()
	require.NoError(t, err)
	assert.Equal(t, l.system, dir)
}

func TestKeypairLayoutFindsAnUnusedLegacyKeypair(t *testing.T) {
	l := keypairLayout{user: t.TempDir(), legacy: t.TempDir()}
	assert.Empty(t, l.unusedLegacyKeypair(), "no legacy keypair")

	writeKeypair(t, l.legacy)
	assert.Equal(t, l.legacy, l.unusedLegacyKeypair())

	writeKeypair(t, l.user)
	assert.Empty(t, l.unusedLegacyKeypair(), "the user's keypair is the one PMG reads")
}

func TestDoctorWarnsAboutAnUnusedLegacyKeypair(t *testing.T) {
	l := keypairLayout{user: t.TempDir(), legacy: t.TempDir()}
	writeKeypair(t, l.legacy)

	result := caCheck(l)
	assert.Equal(t, doctor.StatusWarn, result.Status)
	assert.Contains(t, result.Message, l.legacy)
	assert.Contains(t, result.Message, "pmg setup cert uninstall --system --purge")
}
