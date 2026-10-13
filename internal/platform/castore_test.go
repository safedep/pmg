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

	assert.Equal(t, readable1, FirstReadableFile("", dir, missing, readable1, readable2),
		"skips an empty path, a directory and a missing file")
	assert.Equal(t, "", FirstReadableFile("", dir, missing))
}

func TestSystemCABundlePathIsACandidate(t *testing.T) {
	path := SystemCABundlePath()
	if path == "" {
		t.Skip("this host has no CA bundle file")
	}
	assert.Contains(t, CABundleCandidates(), path)
}
