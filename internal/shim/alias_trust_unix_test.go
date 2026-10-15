//go:build unix

package shim

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrustedAlias(t *testing.T) {
	writeFile := func(t *testing.T, path string) {
		t.Helper()
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755))
	}

	cases := []struct {
		name string
		// setup returns the alias to check.
		setup func(t *testing.T, root string) string
		want  bool
	}{
		{
			name: "a user-owned version manager alias",
			setup: func(t *testing.T, root string) string {
				writeFile(t, filepath.Join(root, "installs", "pmg", "0.31.0", "pmg"))
				require.NoError(t, os.Symlink("0.31.0", filepath.Join(root, "installs", "pmg", "latest")))
				return filepath.Join(root, "installs", "pmg", "latest", "pmg")
			},
			want: true,
		},
		{
			name: "a symlink chain with an absolute and a relative hop",
			setup: func(t *testing.T, root string) string {
				writeFile(t, filepath.Join(root, "store", "pmg-0.31.0", "bin", "pmg"))
				require.NoError(t, os.Symlink(filepath.Join(root, "store", "pmg-0.31.0"), filepath.Join(root, "profile")))
				require.NoError(t, os.MkdirAll(filepath.Join(root, "bin"), 0o755))
				require.NoError(t, os.Symlink("../profile/bin/pmg", filepath.Join(root, "bin", "pmg")))
				return filepath.Join(root, "bin", "pmg")
			},
			want: true,
		},
		{
			name: "an alias in a sticky world-writable directory",
			setup: func(t *testing.T, root string) string {
				writeFile(t, filepath.Join(root, "real", "pmg"))
				shared := filepath.Join(root, "shared")
				require.NoError(t, os.Mkdir(shared, 0o755))
				require.NoError(t, os.Chmod(shared, 0o777|os.ModeSticky))
				require.NoError(t, os.Symlink(filepath.Join(root, "real", "pmg"), filepath.Join(shared, "pmg")))
				return filepath.Join(shared, "pmg")
			},
			want: true,
		},
		{
			name: "an alias in a group-writable directory",
			setup: func(t *testing.T, root string) string {
				writeFile(t, filepath.Join(root, "real", "pmg"))
				bin := filepath.Join(root, "bin")
				require.NoError(t, os.Mkdir(bin, 0o755))
				require.NoError(t, os.Chmod(bin, 0o775))
				require.NoError(t, os.Symlink(filepath.Join(root, "real", "pmg"), filepath.Join(bin, "pmg")))
				return filepath.Join(bin, "pmg")
			},
			want: false,
		},
		{
			name: "an alias owned by another user",
			setup: func(t *testing.T, root string) string {
				writeFile(t, filepath.Join(root, "real", "pmg"))
				require.NoError(t, os.MkdirAll(filepath.Join(root, "bin"), 0o755))
				alias := filepath.Join(root, "bin", "pmg")
				require.NoError(t, os.Symlink(filepath.Join(root, "real", "pmg"), alias))
				ownAliasBy(t, alias, uint32(os.Geteuid())+1)
				return alias
			},
			want: false,
		},
		{
			name: "a chain that passes through a world-writable directory",
			setup: func(t *testing.T, root string) string {
				writeFile(t, filepath.Join(root, "real", "pmg"))
				open := filepath.Join(root, "open")
				require.NoError(t, os.Mkdir(open, 0o755))
				require.NoError(t, os.Chmod(open, 0o777))
				require.NoError(t, os.Symlink(filepath.Join(root, "real", "pmg"), filepath.Join(open, "pmg")))
				require.NoError(t, os.MkdirAll(filepath.Join(root, "bin"), 0o755))
				require.NoError(t, os.Symlink(filepath.Join(open, "pmg"), filepath.Join(root, "bin", "pmg")))
				return filepath.Join(root, "bin", "pmg")
			},
			want: false,
		},
		{
			name: "a symlink loop",
			setup: func(t *testing.T, root string) string {
				require.NoError(t, os.Symlink("b", filepath.Join(root, "a")))
				require.NoError(t, os.Symlink("a", filepath.Join(root, "b")))
				return filepath.Join(root, "a")
			},
			want: false,
		},
		{
			name: "a missing alias",
			setup: func(t *testing.T, root string) string {
				return filepath.Join(root, "missing", "pmg")
			},
			want: false,
		},
		{
			name: "a relative alias",
			setup: func(t *testing.T, root string) string {
				return filepath.Join("bin", "pmg")
			},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			alias := tc.setup(t, t.TempDir())
			assert.Equal(t, tc.want, trustedAlias(alias))
		})
	}
}

// ownAliasBy reports uid as the owner of path. Only root can chown, so the
// test replaces the owner lookup.
func ownAliasBy(t *testing.T, path string, uid uint32) {
	t.Helper()
	previous := aliasEntryOwner
	aliasEntryOwner = func(entry string, info os.FileInfo) (uint32, bool) {
		if entry == path {
			return uid, true
		}
		return previous(entry, info)
	}
	t.Cleanup(func() { aliasEntryOwner = previous })
}
