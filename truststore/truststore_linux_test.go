//go:build linux
// +build linux

package truststore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinuxUserScopeUnsupported(t *testing.T) {
	assert.False(t, UserScopeSupported())
	assert.ErrorIs(t, Install([]byte("PEM"), ScopeUser), ErrUserScopeUnsupported)
	assert.ErrorIs(t, Uninstall("Test CA", ScopeUser), ErrUserScopeUnsupported)
}

func TestLinuxSystemInstallWritesAnchorAndUpdates(t *testing.T) {
	dir := t.TempDir()
	origDetect := detectTrustTool
	detectTrustTool = func() (linuxTrustTool, error) {
		return linuxTrustTool{anchorDir: dir, updateCmd: "update-ca-certificates", anchorName: "pmg-proxy-ca.crt"}, nil
	}
	var ranUpdate string
	origRunner := commandRunner
	commandRunner = func(name string, _ ...string) ([]byte, error) {
		ranUpdate = name
		return nil, nil
	}
	t.Cleanup(func() { detectTrustTool = origDetect; commandRunner = origRunner })

	require.NoError(t, Install([]byte("PEM-BYTES"), ScopeSystem))

	got, err := os.ReadFile(filepath.Join(dir, "pmg-proxy-ca.crt"))
	require.NoError(t, err)
	assert.Equal(t, "PEM-BYTES", string(got))
	assert.Equal(t, "update-ca-certificates", ranUpdate)
}

func TestLinuxStatusReflectsAnchorFile(t *testing.T) {
	dir := t.TempDir()
	origDetect := detectTrustTool
	detectTrustTool = func() (linuxTrustTool, error) {
		return linuxTrustTool{anchorDir: dir, updateCmd: "update-ca-certificates", anchorName: "pmg-proxy-ca.crt"}, nil
	}
	t.Cleanup(func() { detectTrustTool = origDetect })

	_, system, err := Status("Test CA")
	require.NoError(t, err)
	assert.False(t, system)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "pmg-proxy-ca.crt"), []byte("x"), 0o644))
	_, system, err = Status("Test CA")
	require.NoError(t, err)
	assert.True(t, system)
}
