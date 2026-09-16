package doctor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/safedep/pmg/internal/shim"
	"github.com/safedep/pmg/internal/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
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

func TestRunProtectionCheckUsesTemporaryPip(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
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
