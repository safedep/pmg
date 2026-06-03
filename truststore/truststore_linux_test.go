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

func TestLinuxSystemInstallStagesAnchorAndUpdates(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "pmg-proxy-ca.crt")

	origDetect := detectTrustTool
	detectTrustTool = func() (linuxTrustTool, error) {
		return linuxTrustTool{anchorDir: dir, updateCmd: "update-ca-certificates", anchorName: "pmg-proxy-ca.crt"}, nil
	}
	origEUID := euid
	euid = func() int { return 0 } // run as root so no sudo prefix is added
	var calls [][]string
	origRunner := commandRunner
	commandRunner = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	t.Cleanup(func() { detectTrustTool = origDetect; euid = origEUID; commandRunner = origRunner })

	require.NoError(t, Install([]byte("PEM-BYTES"), ScopeSystem))

	require.Len(t, calls, 2)
	assert.Equal(t, "install", calls[0][0])
	assert.Contains(t, calls[0], dest)
	assert.Equal(t, "update-ca-certificates", calls[1][0])
}

func TestLinuxSystemInstallElevatesWhenNotRoot(t *testing.T) {
	dir := t.TempDir()
	origDetect := detectTrustTool
	detectTrustTool = func() (linuxTrustTool, error) {
		return linuxTrustTool{anchorDir: dir, updateCmd: "update-ca-certificates", anchorName: "pmg-proxy-ca.crt"}, nil
	}
	origEUID := euid
	euid = func() int { return 1000 }
	var firstName string
	origRunner := commandRunner
	commandRunner = func(name string, _ ...string) ([]byte, error) {
		if firstName == "" {
			firstName = name
		}
		return nil, nil
	}
	t.Cleanup(func() { detectTrustTool = origDetect; euid = origEUID; commandRunner = origRunner })

	require.NoError(t, Install([]byte("PEM"), ScopeSystem))
	assert.Equal(t, "sudo", firstName)
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
