//go:build darwin
// +build darwin

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/require"
)

func TestRenderSeatbeltKeychainSentinel(t *testing.T) {
	if out, err := exec.Command("/usr/bin/xcrun", "--sdk", "macosx", "--find", "clang").CombinedOutput(); err != nil {
		t.Skipf("Native compiler is unavailable: %s", out)
	}
	if out, err := exec.Command("/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path").CombinedOutput(); err != nil {
		t.Skipf("macOS SDK is unavailable: %s", out)
	}
	if out, err := exec.Command("/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", "/usr/bin/true").CombinedOutput(); err != nil {
		t.Skipf("Seatbelt cannot be applied in this environment: %s", out)
	}
	dir := t.TempDir()
	helper := filepath.Join(dir, "keychain-sentinel")
	out, err := exec.Command("/usr/bin/clang", "testdata/keychain_sentinel.c", "-o", helper).CombinedOutput()
	require.NoError(t, err, "%s", out)
	out, err = exec.Command(helper).CombinedOutput()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 2 {
			t.Skipf("Keychain sentinel is unavailable: %s", out)
		}
		require.NoError(t, err, "%s", out)
	}

	profile, err := RenderSeatbelt(&sandbox.SandboxPolicy{
		Name:       "keychain-sentinel",
		Filesystem: sandbox.FilesystemPolicy{AllowRead: []string{"/"}},
	})
	require.NoError(t, err)
	path := filepath.Join(dir, "profile.sb")
	require.NoError(t, os.WriteFile(path, profile, 0o600))
	out, err = exec.Command("/usr/bin/sandbox-exec", "-f", path, helper).CombinedOutput()
	require.NoError(t, err, "%s", out)

	profile = append(profile, []byte("\n(deny sysctl-read (sysctl-name \"security.mac.sandbox.sentinel\"))\n")...)
	require.NoError(t, os.WriteFile(path, profile, 0o600))
	out, err = exec.Command("/usr/bin/sandbox-exec", "-f", path, helper).CombinedOutput()
	require.Error(t, err, "%s", out)
	exit, ok := err.(*exec.ExitError)
	require.True(t, ok, "%s", out)
	require.Equal(t, 1, exit.ExitCode(), "%s", out)
}
