package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/safedep/pmg/internal/platform"
	"github.com/safedep/pmg/internal/shim"
	"github.com/safedep/pmg/internal/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storeAliasName is the name the test binary takes to act as the Windows
// Store alias. The alias prints an install hint and exits 9009.
const storeAliasName = "python3"

func TestMain(m *testing.M) {
	if strings.TrimSuffix(filepath.Base(os.Args[0]), exeSuffix()) == storeAliasName {
		if _, err := fmt.Fprintln(os.Stderr, "Python was not found; run without arguments to install from the Microsoft Store."); err != nil {
			os.Exit(2)
		}
		os.Exit(9009)
	}
	if os.Getenv("PMG_DOCTOR_TEST_HELPER") == "1" {
		path, err := shim.ResolveRealBinary(os.Args[1])
		if err == nil {
			err = os.WriteFile(os.Getenv("PMG_DOCTOR_TEST_RECEIPT"), []byte(path), 0o600)
		}
		if err == nil {
			_, err = fmt.Fprintln(os.Stdout, ui.MalwareBlockedHeadline)
		}
		if err != nil {
			os.Exit(2)
		}
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// requirePython runs each interpreter rather than only finding it. On
// Windows the Store alias is on PATH with no Python behind it.
func requirePython(t *testing.T) {
	t.Helper()
	for _, python := range platform.PythonCommands() {
		if err := python.Command("--version").Run(); err == nil {
			return
		}
	}
	t.Skip("python not available")
}

// installStoreAlias puts a copy of the test binary named like the Store
// alias into a new directory and returns its path.
func installStoreAlias(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	require.NoError(t, err)
	data, err := os.ReadFile(self)
	require.NoError(t, err)
	alias := filepath.Join(t.TempDir(), storeAliasName+exeSuffix())
	require.NoError(t, os.WriteFile(alias, data, 0o755))
	return alias
}

func TestSetupVenvSkipsFailingPython(t *testing.T) {
	requirePython(t)
	alias := installStoreAlias(t)

	venvDir, err := setupVenvWith(t.TempDir(), append([]platform.PythonCommand{{Name: alias}}, platform.PythonCommands()...))
	require.NoError(t, err)
	_, err = venvPipPath(venvDir)
	assert.NoError(t, err)
}

func TestSetupVenvReportsEveryFailure(t *testing.T) {
	alias := installStoreAlias(t)

	_, err := setupVenvWith(t.TempDir(), []platform.PythonCommand{{Name: alias}, {Name: alias, Args: []string{"-3"}}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), alias+":")
	assert.Contains(t, err.Error(), alias+" -3:")
	assert.Contains(t, err.Error(), "Microsoft Store")
}

func TestRunProtectionCheckUsesTemporaryPip(t *testing.T) {
	requirePython(t)
	self, err := os.Executable()
	require.NoError(t, err)
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "pip"+exeSuffix()), []byte("outside pip"), 0o755))
	t.Setenv("PATH", outside+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PMG_DOCTOR_TEST_HELPER", "1")
	receipt := filepath.Join(t.TempDir(), "pip-path")
	t.Setenv("PMG_DOCTOR_TEST_RECEIPT", receipt)

	result := RunProtectionCheck(ProtectionTestCase{
		PackageManager: "pip",
		Fallbacks:      []string{"pip3"},
		NeedsVenv:      true,
	}, self)
	require.Equal(t, StatusPass, result.Status, result.Message)
	data, err := os.ReadFile(receipt)
	require.NoError(t, err)
	binDir := "bin"
	if runtime.GOOS == "windows" {
		binDir = "Scripts"
	}
	assert.Contains(t, string(data), string(os.PathSeparator)+filepath.Join("venv", binDir, "pip"+exeSuffix()))
	assert.NotContains(t, string(data), outside)
}
