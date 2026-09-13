//go:build windows

package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/pmg/internal/platform"
)

// isolateUserPath points the user PATH scope at a throwaway registry key, so
// a test never edits the real HKCU\Environment. The scope lives in platform.
func isolateUserPath(t *testing.T) {
	t.Helper()
	restore, err := platform.RedirectUserPathForTest(`Software\pmg-shim-test-` + strings.ReplaceAll(t.Name(), "/", "_"))
	require.NoError(t, err)
	t.Cleanup(restore)
}

func isolateMachinePath(t *testing.T) {
	t.Helper()
	restore, err := platform.RedirectMachinePathForTest(`Software\pmg-shim-test-machine-` + strings.ReplaceAll(t.Name(), "/", "_"))
	require.NoError(t, err)
	t.Cleanup(restore)
}

func TestShimManagerInstallWritesCmdShims(t *testing.T) {
	isolateUserPath(t)
	homeDir := t.TempDir()
	binDir := filepath.Join(homeDir, "safedep", "pmg", "bin")
	// A percent sign in the binary path must not start a batch expansion. A
	// closing parenthesis must not end the if block, and an ampersand must
	// not start a second command.
	pmgBin := filepath.Join(homeDir, "100% (x86) & co", "pmg.exe")

	mgr := NewShimManager(ShimConfig{
		BinDir:          binDir,
		HomeDir:         homeDir,
		PMGBin:          pmgBin,
		PackageManagers: []string{"npm", "pip"},
	})
	require.NoError(t, mgr.Install())

	for _, pm := range []string{"npm", "pip"} {
		content, err := os.ReadFile(filepath.Join(binDir, pm+".cmd"))
		require.NoError(t, err, "shim %s.cmd should exist", pm)
		body := string(content)

		assert.True(t, strings.HasPrefix(body, "@echo off\r\n"))
		assert.Contains(t, body, "rem "+shimScriptMarker+"\r\n")
		assert.Contains(t, body, "setlocal DisableDelayedExpansion\r\n")
		assert.Contains(t, body, `set "PMG_SHIM_PATH=%~f0"`+"\r\n")
		assert.Contains(t, body, "set PMG_RAW_ARGS=%*\r\n")
		assert.Contains(t, body, fmt.Sprintf(`"%s" %s %%*`+"\r\n", strings.ReplaceAll(pmgBin, "%", "%%"), pm))
		assert.Contains(t, body, fmt.Sprintf(`if not exist "%s" (`+"\r\n", strings.ReplaceAll(pmgBin, "%", "%%")))
		assert.Contains(t, body, fmt.Sprintf(`PMG binary not found: "%s" 1>&2`+"\r\n", strings.ReplaceAll(pmgBin, "%", "%%")))
		assert.Contains(t, body, `or delete "%~dp0" to remove the shims 1>&2`+"\r\n")
		assert.Contains(t, body, "  exit /b 127\r\n")
		assert.True(t, strings.HasSuffix(body, "exit /b %ERRORLEVEL%\r\n"))
	}

	assert.True(t, shimsPresent(binDir), "shimsPresent must recognise a .cmd shim")

	installed, err := mgr.IsInstalled()
	require.NoError(t, err)
	assert.True(t, installed)
}

func TestShimManagerRemoveDeletesShimsAndPathEntry(t *testing.T) {
	isolateUserPath(t)
	homeDir := t.TempDir()
	binDir := filepath.Join(homeDir, "safedep", "pmg", "bin")

	mgr := NewShimManager(ShimConfig{
		BinDir:          binDir,
		HomeDir:         homeDir,
		PMGBin:          filepath.Join(homeDir, "pmg.exe"),
		PackageManagers: []string{"npm"},
	})
	require.NoError(t, mgr.Install())
	require.NoError(t, mgr.Remove())

	assert.NoDirExists(t, binDir)
	installed, err := mgr.IsInstalled()
	require.NoError(t, err)
	assert.False(t, installed)
}
