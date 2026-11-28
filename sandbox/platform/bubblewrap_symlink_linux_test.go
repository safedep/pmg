//go:build linux

package platform

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// symlinkFixture returns a directory with an absolute symlink to a file and
// one to a directory, as update-alternatives and a merged /usr create them.
func symlinkFixture(t *testing.T) (file, fileLink, dir, dirLink string) {
	t.Helper()

	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)

	file = filepath.Join(root, "python3")
	fileLink = filepath.Join(root, "python")
	dir = filepath.Join(root, "usrbin")
	dirLink = filepath.Join(root, "bin")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o755))
	require.NoError(t, os.Mkdir(dir, 0o755))
	require.NoError(t, os.Symlink(file, fileLink))
	require.NoError(t, os.Symlink(dir, dirLink))

	return file, fileLink, dir, dirLink
}

func TestBubblewrapMountsOnSymlinkTargets(t *testing.T) {
	file, fileLink, dir, dirLink := symlinkFixture(t)

	args := argSliceToString(translateForTest(t, &sandbox.SandboxPolicy{
		Name:            "test",
		PackageManagers: []string{"npm"},
		Filesystem: sandbox.FilesystemPolicy{
			AllowRead: []string{"/"},
			DenyWrite: []string{dirLink + "/**"},
		},
		Process: sandbox.ProcessPolicy{DenyExec: []string{fileLink}},
	}))

	assert.Contains(t, args, "--ro-bind /dev/null "+file+" ")
	assert.NotContains(t, args, " "+fileLink+" ")
	assert.Contains(t, args, "--ro-bind-try "+dir+" "+dir+" ")
	assert.NotContains(t, args, " "+dirLink+" ")
}

// A symlink that no earlier mount exposes does not exist in the sandbox:
// bwrap creates the mount point, and the path must stay as the policy has it.
func TestBubblewrapKeepsUnexposedSymlinkPath(t *testing.T) {
	_, _, dir, dirLink := symlinkFixture(t)

	got := resolveSymlinkMounts([]string{
		"--ro-bind-try", dirLink, dirLink,
		"--ro-bind-try", dirLink, dirLink,
	})

	assert.Equal(t, []string{
		"--ro-bind-try", dirLink, dirLink,
		"--ro-bind-try", dirLink, dirLink,
	}, got, "%s must not be rewritten to %s", dirLink, dir)
}

func TestBubblewrapStartsWithSymlinkDenies(t *testing.T) {
	requireBubblewrap(t)
	_, fileLink, _, dirLink := symlinkFixture(t)

	args := translateForTest(t, &sandbox.SandboxPolicy{
		Name:            "test",
		PackageManagers: []string{"npm"},
		Filesystem: sandbox.FilesystemPolicy{
			AllowRead: []string{"/"},
			DenyWrite: []string{dirLink + "/**"},
		},
		Process: sandbox.ProcessPolicy{DenyExec: []string{fileLink}},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The masked file reads as empty through the symlink.
	args = append(args, "--", "/bin/sh", "-c", `test ! -s "$1"`, "sh", fileLink)
	out, err := exec.CommandContext(ctx, "bwrap", args...).CombinedOutput()
	require.NoError(t, err, "bwrap: %s", out)
}
