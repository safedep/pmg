package doctor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A python.org install has no python3.exe, so python3 resolves to the
// Microsoft Store alias. Doctor must still build the venv and run pip from it.
func TestRunProtectionCheckIgnoresStoreAlias(t *testing.T) {
	requirePython(t)
	alias := installStoreAlias(t)
	t.Setenv("PATH", filepath.Dir(alias)+string(os.PathListSeparator)+os.Getenv("PATH"))

	self, err := os.Executable()
	require.NoError(t, err)
	t.Setenv("PMG_DOCTOR_TEST_HELPER", "1")
	receipt := filepath.Join(t.TempDir(), "pip-path")
	t.Setenv("PMG_DOCTOR_TEST_RECEIPT", receipt)

	result := RunProtectionCheck(ProtectionTestCase{PackageManager: "pip", NeedsVenv: true}, self)
	require.Equal(t, StatusPass, result.Status, result.Message)
	data, err := os.ReadFile(receipt)
	require.NoError(t, err)
	assert.Contains(t, string(data), filepath.Join("venv", "Scripts", "pip.exe"))
}
