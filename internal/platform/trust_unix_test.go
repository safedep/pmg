//go:build unix

package platform

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

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
		{name: "root file with mode 0444", uid: 0, mode: 0o444},
		{name: "root directory with the setgid bit", uid: 0, mode: os.ModeDir | os.ModeSetgid | 0o755},
		{name: "root sticky directory every user may write", uid: 0, mode: os.ModeDir | os.ModeSticky | 0o777},
		{name: "root link", uid: 0, mode: os.ModeSymlink | 0o777},
		{name: "file of a user", uid: 1000, mode: 0o644, wantErr: "owned by uid 1000, not by root"},
		{name: "link of a user", uid: 1000, mode: os.ModeSymlink | 0o777, wantErr: "owned by uid 1000, not by root"},
		{name: "sticky directory of a user", uid: 501, mode: os.ModeDir | os.ModeSticky | 0o777, wantErr: "owned by uid 501, not by root"},
		{name: "root file the group may write", uid: 0, mode: 0o664, wantErr: "lets its group write it"},
		{name: "root directory the group may write", uid: 0, mode: os.ModeDir | 0o775, wantErr: "lets its group write it"},
		{name: "root file every user may write", uid: 0, mode: 0o646, wantErr: "lets every user write it"},
		{name: "root directory every user may write", uid: 0, mode: os.ModeDir | 0o757, wantErr: "lets every user write it"},
		{name: "root socket", uid: 0, mode: os.ModeSocket | 0o600, wantErr: "not a directory or a regular file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSystemControl("/etc/safedep/pmg", tc.uid, tc.mode, false)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tc.wantErr)
			assert.ErrorContains(t, err, "/etc/safedep/pmg")
		})
	}
}

type fakeEntry struct {
	mode     os.FileMode
	uid      uint32
	target   string
	readOnly bool
}

type fakeInfo struct {
	name  string
	entry fakeEntry
}

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() os.FileMode  { return f.entry.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.entry.mode.IsDir() }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.entry.uid} }

// withFakeTree replaces the file system calls of the walk with a map from
// path to entry, so a test can describe a tree that only root can create.
func withFakeTree(t *testing.T, tree map[string]fakeEntry) {
	t.Helper()
	lstat, readlink, readOnly := lstatSystem, readlinkSystem, readOnlySystem
	readOnlySystem = func(path string) bool { return tree[path].readOnly }
	lstatSystem = func(path string) (os.FileInfo, error) {
		entry, ok := tree[path]
		if !ok {
			return nil, &os.PathError{Op: "lstat", Path: path, Err: os.ErrNotExist}
		}
		return fakeInfo{name: filepath.Base(path), entry: entry}, nil
	}
	readlinkSystem = func(path string) (string, error) {
		entry, ok := tree[path]
		if !ok || entry.mode&os.ModeSymlink == 0 {
			return "", &os.PathError{Op: "readlink", Path: path, Err: os.ErrInvalid}
		}
		return entry.target, nil
	}
	t.Cleanup(func() { lstatSystem, readlinkSystem, readOnlySystem = lstat, readlink, readOnly })
}

const (
	rootDir  = os.ModeDir | 0o755
	rootLink = os.ModeSymlink | 0o777
	managed  = "/etc/safedep/pmg/config.yml"
)

func rootTree() map[string]fakeEntry {
	return map[string]fakeEntry{
		"/":                {mode: rootDir},
		"/etc":             {mode: rootDir},
		"/etc/safedep":     {mode: rootDir},
		"/etc/safedep/pmg": {mode: rootDir},
		managed:            {mode: 0o644},
	}
}

func TestResolveSystemControlled(t *testing.T) {
	tests := []struct {
		name         string
		change       func(tree map[string]fakeEntry)
		wantResolved string
		wantErr      string
	}{
		{name: "root tree", change: func(map[string]fakeEntry) {}, wantResolved: managed},
		{
			name:    "group writable directory at the top",
			change:  func(tree map[string]fakeEntry) { tree["/etc"] = fakeEntry{mode: os.ModeDir | 0o775} },
			wantErr: "/etc lets its group write it",
		},
		{
			name:    "directory of a user",
			change:  func(tree map[string]fakeEntry) { tree["/etc/safedep"] = fakeEntry{mode: rootDir, uid: 1000} },
			wantErr: "/etc/safedep is owned by uid 1000, not by root",
		},
		{
			name:    "file every user may write",
			change:  func(tree map[string]fakeEntry) { tree[managed] = fakeEntry{mode: 0o666} },
			wantErr: managed + " lets its group write it",
		},
		{
			name:    "missing directory",
			change:  func(tree map[string]fakeEntry) { delete(tree, "/etc/safedep/pmg") },
			wantErr: "failed to inspect /etc/safedep/pmg",
		},
		{
			name: "sticky directory every user may write",
			change: func(tree map[string]fakeEntry) {
				tree["/etc/safedep"] = fakeEntry{mode: os.ModeDir | os.ModeSticky | 0o777}
			},
			wantResolved: managed,
		},
		{
			name: "directory every user may write on a mount that is not read-only",
			change: func(tree map[string]fakeEntry) {
				tree["/etc/safedep/pmg"] = fakeEntry{mode: os.ModeDir | 0o777}
			},
			wantErr: "/etc/safedep/pmg lets its group write it",
		},
		{
			name: "file every user may write on a read-only mount",
			change: func(tree map[string]fakeEntry) {
				tree[managed] = fakeEntry{mode: 0o666, readOnly: true}
			},
			wantErr: managed + " lets its group write it",
		},
		{
			name: "user file on a read-only mount",
			change: func(tree map[string]fakeEntry) {
				tree[managed] = fakeEntry{mode: 0o666, uid: 1000, readOnly: true}
			},
			wantErr: managed + " is owned by uid 1000, not by root",
		},
		{
			name: "directory in the chain is a link of a user",
			change: func(tree map[string]fakeEntry) {
				tree["/etc/safedep"] = fakeEntry{mode: rootLink, uid: 1000, target: "/opt/safedep"}
				tree["/opt"] = fakeEntry{mode: rootDir}
				tree["/opt/safedep"] = fakeEntry{mode: rootDir}
				tree["/opt/safedep/pmg"] = fakeEntry{mode: rootDir}
				tree["/opt/safedep/pmg/config.yml"] = fakeEntry{mode: 0o644}
			},
			wantErr: "/etc/safedep is owned by uid 1000, not by root",
		},
		{
			name: "file is a link of a user",
			change: func(tree map[string]fakeEntry) {
				tree[managed] = fakeEntry{mode: rootLink, uid: 1000, target: "/etc/safedep/pmg/real.yml"}
				tree["/etc/safedep/pmg/real.yml"] = fakeEntry{mode: 0o644}
			},
			wantErr: managed + " is owned by uid 1000, not by root",
		},
		{
			name: "root link at the top, relative, as /etc on macOS",
			change: func(tree map[string]fakeEntry) {
				tree["/etc"] = fakeEntry{mode: rootLink, target: "private/etc"}
				tree["/private"] = fakeEntry{mode: rootDir}
				tree["/private/etc"] = fakeEntry{mode: rootDir}
				tree["/private/etc/safedep"] = fakeEntry{mode: rootDir}
				tree["/private/etc/safedep/pmg"] = fakeEntry{mode: rootDir}
				tree["/private/etc/safedep/pmg/config.yml"] = fakeEntry{mode: 0o644}
			},
			wantResolved: "/private/etc/safedep/pmg/config.yml",
		},
		{
			name: "root link to the Nix store, as NixOS environment.etc",
			change: func(tree map[string]fakeEntry) {
				tree[managed] = fakeEntry{mode: rootLink, target: "/etc/static/safedep/pmg/config.yml"}
				tree["/etc/static"] = fakeEntry{mode: rootLink, target: "/nix/store/abc-etc/etc"}
				tree["/nix"] = fakeEntry{mode: rootDir}
				tree["/nix/store"] = fakeEntry{mode: os.ModeDir | os.ModeSticky | 0o775}
				tree["/nix/store/abc-etc"] = fakeEntry{mode: os.ModeDir | 0o555}
				tree["/nix/store/abc-etc/etc"] = fakeEntry{mode: os.ModeDir | 0o555}
				tree["/nix/store/abc-etc/etc/safedep"] = fakeEntry{mode: os.ModeDir | 0o555}
				tree["/nix/store/abc-etc/etc/safedep/pmg"] = fakeEntry{mode: rootLink, target: "/nix/store/def-pmg"}
				tree["/nix/store/def-pmg"] = fakeEntry{mode: os.ModeDir | 0o555}
				tree["/nix/store/def-pmg/config.yml"] = fakeEntry{mode: 0o444}
			},
			wantResolved: "/nix/store/def-pmg/config.yml",
		},
		{
			name: "root links of a Kubernetes ConfigMap volume on a read-only mount",
			change: func(tree map[string]fakeEntry) {
				tree["/etc/safedep/pmg"] = fakeEntry{mode: os.ModeDir | 0o777, readOnly: true}
				tree[managed] = fakeEntry{mode: rootLink, target: "..data/config.yml"}
				tree["/etc/safedep/pmg/..data"] = fakeEntry{mode: rootLink, target: "..2026_10_30_01_02_03.123"}
				tree["/etc/safedep/pmg/..2026_10_30_01_02_03.123"] = fakeEntry{mode: rootDir, readOnly: true}
				tree["/etc/safedep/pmg/..2026_10_30_01_02_03.123/config.yml"] = fakeEntry{mode: 0o644, readOnly: true}
			},
			wantResolved: "/etc/safedep/pmg/..2026_10_30_01_02_03.123/config.yml",
		},
		{
			name: "parent of a relative target is the parent of the resolved link",
			change: func(tree map[string]fakeEntry) {
				tree["/etc/safedep/pmg"] = fakeEntry{mode: rootLink, target: "/opt/pmg/conf"}
				tree[managed] = fakeEntry{mode: rootLink, target: "../real/config.yml"}
				tree["/opt"] = fakeEntry{mode: rootDir}
				tree["/opt/pmg"] = fakeEntry{mode: rootDir}
				tree["/opt/pmg/conf"] = fakeEntry{mode: rootDir}
				tree["/opt/pmg/conf/config.yml"] = fakeEntry{mode: rootLink, target: "../real/config.yml"}
				tree["/opt/pmg/real"] = fakeEntry{mode: rootDir}
				tree["/opt/pmg/real/config.yml"] = fakeEntry{mode: 0o644}
			},
			wantResolved: "/opt/pmg/real/config.yml",
		},
		{
			name: "root link to a target a user may write",
			change: func(tree map[string]fakeEntry) {
				tree["/etc/safedep"] = fakeEntry{mode: rootLink, target: "/opt/safedep"}
				tree["/opt"] = fakeEntry{mode: rootDir}
				tree["/opt/safedep"] = fakeEntry{mode: os.ModeDir | 0o777}
			},
			wantErr: "/opt/safedep lets its group write it",
		},
		{
			name: "root link to a target of a user",
			change: func(tree map[string]fakeEntry) {
				tree[managed] = fakeEntry{mode: rootLink, target: "/home/alice/config.yml"}
				tree["/home"] = fakeEntry{mode: rootDir}
				tree["/home/alice"] = fakeEntry{mode: rootDir, uid: 1000}
				tree["/home/alice/config.yml"] = fakeEntry{mode: 0o644, uid: 1000}
			},
			wantErr: "/home/alice is owned by uid 1000, not by root",
		},
		{
			name: "link loop",
			change: func(tree map[string]fakeEntry) {
				tree["/etc/safedep"] = fakeEntry{mode: rootLink, target: "/etc/safedep"}
			},
			wantErr: "too many links",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree := rootTree()
			tc.change(tree)
			withFakeTree(t, tree)

			resolved, err := resolveSystemControlled(managed, 0)
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				assert.ErrorContains(t, RequireSystemControlled(managed), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantResolved, resolved)
			assert.NoError(t, RequireSystemControlled(managed))
		})
	}
}

func TestRequireSystemControlledRefusesARelativePath(t *testing.T) {
	assert.ErrorContains(t, RequireSystemControlled("etc/safedep/pmg/config.yml"), "not an absolute path")
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

// The real tree under the temporary directory. The test owner stands in for
// root, which a normal user cannot be.
func TestRequireSystemControlledOnARealTree(t *testing.T) {
	t.Cleanup(TrustOwnerForTest(uint32(os.Getuid())))
	base := t.TempDir()
	dir := filepath.Join(base, "safedep", "pmg")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	file := filepath.Join(dir, "config.yml")
	require.NoError(t, os.WriteFile(file, []byte("paranoid: true\n"), 0o644))
	for _, p := range []string{filepath.Join(base, "safedep"), dir, file} {
		require.NoError(t, os.Chmod(p, 0o755))
	}

	require.NoError(t, RequireSystemControlled(file))

	require.NoError(t, os.Chmod(filepath.Join(base, "safedep"), 0o775))
	assert.ErrorContains(t, RequireSystemControlled(file), "safedep lets its group write it")
	require.NoError(t, os.Chmod(filepath.Join(base, "safedep"), 0o755))

	link := filepath.Join(base, "link")
	require.NoError(t, os.Symlink(filepath.Join(base, "safedep"), link))
	assert.NoError(t, RequireSystemControlled(filepath.Join(link, "pmg", "config.yml")), "a link of a trusted owner is followed")

	assert.NoError(t, RequireSystemControlled(filepath.Join(link, "..", "safedep", "pmg", "config.yml")))
}

func TestRequireSystemControlledRejectsEntriesOfAnotherAccount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("only root can give a file to another account")
	}
	base := t.TempDir()
	file := filepath.Join(base, "config.yml")
	require.NoError(t, os.WriteFile(file, []byte("paranoid: true\n"), 0o644))
	require.NoError(t, os.Chmod(file, 0o644))
	require.NoError(t, RequireSystemControlled(file))

	link := filepath.Join(base, "link.yml")
	require.NoError(t, os.Symlink(file, link))
	require.NoError(t, RequireSystemControlled(link), "a root link is followed")

	require.NoError(t, os.Lchown(link, 65534, 65534))
	assert.ErrorContains(t, RequireSystemControlled(link), "link.yml is owned by uid 65534, not by root")

	require.NoError(t, os.Chown(file, 65534, 65534))
	assert.ErrorContains(t, RequireSystemControlled(file), "owned by uid 65534, not by root")
}

func TestTrustOwnerForTestRestores(t *testing.T) {
	restore := TrustOwnerForTest(4242)
	assert.NoError(t, validateSystemControl("/x", 4242, 0o644, false))
	restore()
	assert.ErrorContains(t, validateSystemControl("/x", 4242, 0o644, false), "owned by uid 4242")
}

func TestMkdirAllRootOwnedRefusesAWritableParentWhenPrivileged(t *testing.T) {
	withPrivilege(t, true)
	t.Cleanup(TrustOwnerForTest(uint32(os.Getuid())))
	parent := filepath.Join(t.TempDir(), "safedep")
	require.NoError(t, os.Mkdir(parent, 0o755))
	require.NoError(t, os.Chmod(parent, 0o775))
	target := filepath.Join(parent, "pmg")

	err := mkdirAllRootOwned(target, 0o755)
	require.ErrorContains(t, err, "lets its group write it")
	assert.NoDirExists(t, target)
}
