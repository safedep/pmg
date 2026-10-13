package platform

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFirstReadableFile(t *testing.T) {
	tempDir := t.TempDir()
	readable1 := filepath.Join(tempDir, "ca1.pem")
	readable2 := filepath.Join(tempDir, "ca2.pem")
	dir := filepath.Join(tempDir, "certs")
	missing := filepath.Join(tempDir, "missing.pem")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(readable1, []byte("CERT1"), 0o600))
	require.NoError(t, os.WriteFile(readable2, []byte("CERT2"), 0o600))

	assert.Equal(t, readable1, firstReadableFile("", dir, missing, readable1, readable2),
		"skips an empty path, a directory and a missing file")
	assert.Equal(t, "", firstReadableFile("", dir, missing))
}

func TestCABundlePathHonorsTheUserBundleAndSystemPathDoesNot(t *testing.T) {
	override := filepath.Join(t.TempDir(), "override.pem")
	require.NoError(t, os.WriteFile(override, []byte("not the system bundle"), 0o644))
	t.Setenv("SSL_CERT_FILE", override)
	t.Setenv("CURL_CA_BUNDLE", "")

	assert.Equal(t, override, CABundlePath(), "the merge for env-var trust honors the user's bundle")
	assert.NotEqual(t, override, SystemCABundlePath(), "the enforce trust bundle is the system bundle, never an inherited override")
}
