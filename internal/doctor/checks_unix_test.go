//go:build unix

package doctor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safedep/pmg/internal/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The pmg stub is a #!/bin/sh script and python3 is reached through a
// symlink. Neither runs on Windows.
func TestRunProtectionCheckUsesVenvPipWhenNoSystemPip(t *testing.T) {
	realPython, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}

	binDir := t.TempDir()
	require.NoError(t, os.Symlink(realPython, filepath.Join(binDir, "python3")))

	argvFile := filepath.Join(t.TempDir(), "argv.txt")
	pmgStub := filepath.Join(binDir, "pmg-stub")
	stub := fmt.Sprintf("#!/bin/sh\necho \"$@\" > %s\necho '%s'\nexit 1\n", argvFile, ui.MalwareBlockedHeadline)
	require.NoError(t, os.WriteFile(pmgStub, []byte(stub), 0o755))

	t.Setenv("PATH", binDir)

	var pipCase ProtectionTestCase
	for _, tc := range ProtectionTestCases() {
		if tc.PackageManager == "pip" {
			pipCase = tc
		}
	}
	require.True(t, pipCase.NeedsVenv)

	result := RunProtectionCheck(pipCase, pmgStub)
	assert.Equal(t, StatusPass, result.Status)

	argv, err := os.ReadFile(argvFile)
	require.NoError(t, err)
	assert.Equal(t, "pip install --no-cache-dir safedep-test-pkg==0.0.4", strings.TrimSpace(string(argv)))
}

// A Windows venv puts pip.exe under Scripts\, not bin/. setupVenv does not
// handle that layout, and the pip protection check on Windows is outside the
// Windows support spec.
func TestSetupVenv(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}

	tmpDir := t.TempDir()
	venvDir, err := setupVenv(tmpDir)
	require.NoError(t, err)

	pipPath := filepath.Join(venvDir, "bin", "pip")
	_, err = os.Stat(pipPath)
	assert.NoError(t, err)
}

// CheckShimScripts reads the executable bit, which Windows does not have.
// The Windows form of the shim-directory check owns that case.
func TestCheckShimScripts(t *testing.T) {
	tmpDir := t.TempDir()
	shimDir := filepath.Join(tmpDir, ".pmg", "bin")
	require.NoError(t, os.MkdirAll(shimDir, 0o755))

	shimPath := filepath.Join(shimDir, "npm")
	require.NoError(t, os.WriteFile(shimPath, []byte("#!/bin/sh\nexec pmg npm \"$@\""), 0o755))

	found, missing := CheckShimScripts(shimDir, []string{"npm", "pip"})
	assert.Equal(t, []string{"npm"}, found)
	assert.Equal(t, []string{"pip"}, missing)
}
