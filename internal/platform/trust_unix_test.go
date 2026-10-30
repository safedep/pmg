//go:build unix

package platform

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMkdirAllRootOwnedCreatesMissingChain(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "a", "b", "c")

	require.NoError(t, mkdirAllRootOwned(target, 0o755))

	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	require.NoError(t, mkdirAllRootOwned(target, 0o755), "idempotent on existing dir")
}

func TestMkdirAllRootOwnedRejectsFileCollision(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o644))

	assert.Error(t, mkdirAllRootOwned(blocker, 0o755))
	assert.Error(t, mkdirAllRootOwned(filepath.Join(blocker, "sub"), 0o755))
}

func TestMkdirAllRootOwnedLeavesExistingDirsAlone(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "existing")
	require.NoError(t, os.Mkdir(existing, 0o700))

	require.NoError(t, mkdirAllRootOwned(filepath.Join(existing, "created"), 0o755))

	info, err := os.Stat(existing)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(),
		"pre-existing directory permissions must not be changed")
}

func TestProtectSystemPathIsANoOpWithoutPrivilege(t *testing.T) {
	withPrivilege(t, false)
	file := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(file, []byte("paranoid: false\n"), 0o600))

	require.NoError(t, ProtectSystemPath(file, 0o644))

	info, err := os.Stat(file)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestRequireNotReparsePointRejectsASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(target, 0o755))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(target, link))

	assert.NoError(t, RequireNotReparsePoint(target))
	assert.NoError(t, RequireNotReparsePoint(filepath.Join(dir, "missing")))
	assert.ErrorContains(t, RequireNotReparsePoint(link), "is a link")
}

func TestValidateSystemControl(t *testing.T) {
	tests := []struct {
		name    string
		uid     uint32
		mode    os.FileMode
		wantErr string
	}{
		{name: "root file with mode 0644", uid: 0, mode: 0o644},
		{name: "root directory with mode 0755", uid: 0, mode: os.ModeDir | 0o755},
		{name: "root file with mode 0600", uid: 0, mode: 0o600},
		{name: "root file with mode 0444", uid: 0, mode: 0o444},
		{name: "root directory with the setgid bit", uid: 0, mode: os.ModeDir | os.ModeSetgid | 0o755},
		{name: "file of a user", uid: 1000, mode: 0o644, wantErr: "owned by uid 1000, not by root"},
		{name: "directory of a user", uid: 501, mode: os.ModeDir | 0o755, wantErr: "owned by uid 501, not by root"},
		{name: "root file the group may write", uid: 0, mode: 0o664, wantErr: "lets its group write it"},
		{name: "root directory the group may write", uid: 0, mode: os.ModeDir | 0o775, wantErr: "lets its group write it"},
		{name: "root file every user may write", uid: 0, mode: 0o646, wantErr: "lets every user write it"},
		{name: "root directory every user may write", uid: 0, mode: os.ModeDir | 0o757, wantErr: "lets every user write it"},
		{name: "root sticky directory every user may write", uid: 0, mode: os.ModeDir | os.ModeSticky | 0o757, wantErr: "lets every user write it"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSystemControl("/etc/safedep/pmg", tc.uid, tc.mode)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tc.wantErr)
			assert.ErrorContains(t, err, "/etc/safedep/pmg")
		})
	}
}

func TestRequireSystemControlledAcceptsRootPaths(t *testing.T) {
	for _, path := range []string{"/", "/usr"} {
		assert.NoError(t, RequireSystemControlled(path), path)
	}
}

func TestRequireSystemControlledRejectsAFileOfTheCurrentUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns each file it creates, so the test needs a non-root user")
	}
	file := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(file, []byte("paranoid: true\n"), 0o644))

	assert.ErrorContains(t, RequireSystemControlled(file), "not by root")
}

func TestRequireSystemControlledRejectsAFileOfAnotherAccount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("only root can give a file to another account")
	}
	file := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(file, []byte("paranoid: true\n"), 0o644))
	require.NoError(t, os.Chmod(file, 0o644))
	assert.NoError(t, RequireSystemControlled(file))

	require.NoError(t, os.Chown(file, 65534, 65534))
	assert.ErrorContains(t, RequireSystemControlled(file), "owned by uid 65534, not by root")
}

func TestRequireSystemControlledChecksTheOwnerAndMode(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(file, []byte("paranoid: true\n"), 0o644))
	require.NoError(t, os.Chmod(file, 0o644))

	trustOwner(t, uint32(os.Getuid()))
	assert.NoError(t, RequireSystemControlled(file))

	require.NoError(t, os.Chmod(file, 0o664))
	assert.ErrorContains(t, RequireSystemControlled(file), "lets its group write it")

	require.NoError(t, os.Chmod(file, 0o644))
	trustOwner(t, uint32(os.Getuid())+1)
	assert.ErrorContains(t, RequireSystemControlled(file), "not by root")
}

func TestRequireSystemControlledRejectsALink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink("/", link))

	assert.ErrorContains(t, RequireSystemControlled(link), "is a link")
	assert.ErrorContains(t, RequireSystemControlled(filepath.Join(dir, "missing")), "failed to inspect")
}

func trustOwner(t *testing.T, uid uint32) {
	t.Helper()
	orig := SystemOwnerUID
	SystemOwnerUID = uid
	t.Cleanup(func() { SystemOwnerUID = orig })
}
