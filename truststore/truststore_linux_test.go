//go:build linux
// +build linux

package truststore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/safedep/pmg/internal/platform"
	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// certPEM returns a self-signed certificate with the given common name.
func certPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// noBundle makes the install and status checks skip the bundle, as on a
// host whose bundle path is unknown.
func noBundle(t *testing.T) {
	t.Helper()
	orig := systemBundlePath
	systemBundlePath = func() string { return "" }
	t.Cleanup(func() { systemBundlePath = orig })
}

func TestLinuxDetectsTheAnchorDirOfUpdateCATrust(t *testing.T) {
	origLook, origPKI, origTrustSource := lookPath, pkiAnchorDir, trustSourceAnchorDir
	t.Cleanup(func() { lookPath, pkiAnchorDir, trustSourceAnchorDir = origLook, origPKI, origTrustSource })
	lookPath = func(name string) (string, error) {
		if name == "update-ca-trust" {
			return "/usr/bin/update-ca-trust", nil
		}
		return "", errors.New("not found")
	}
	pkiAnchorDir = filepath.Join(t.TempDir(), "pki")
	trustSourceAnchorDir = filepath.Join(t.TempDir(), "trust-source")

	tool, err := detectTrustTool()
	require.NoError(t, err)
	assert.Equal(t, pkiAnchorDir, tool.anchorDir, "Fedora layout when the Arch directory is absent")

	require.NoError(t, os.MkdirAll(trustSourceAnchorDir, 0o755))
	tool, err = detectTrustTool()
	require.NoError(t, err)
	assert.Equal(t, trustSourceAnchorDir, tool.anchorDir, "the Arch directory wins when it exists, even next to a stale pki one")
	assert.Equal(t, "update-ca-trust", tool.updateCmd)
}

func TestLinuxSystemInstallFailsWhenTheBundleMissesTheCert(t *testing.T) {
	dir := t.TempDir()
	origDetect := detectTrustTool
	detectTrustTool = func() (linuxTrustTool, error) {
		return linuxTrustTool{anchorDir: dir, updateCmd: "update-ca-trust", anchorName: "pmg-proxy-ca.crt"}, nil
	}
	origPrivileged := platform.IsPrivileged
	platform.IsPrivileged = func() bool { return true }
	origRunner := commandRunner
	commandRunner = func(string, ...string) ([]byte, error) { return nil, nil }
	bundle := filepath.Join(t.TempDir(), "ca-certificates.crt")
	origBundle := systemBundlePath
	systemBundlePath = func() string { return bundle }
	t.Cleanup(func() {
		detectTrustTool = origDetect
		platform.IsPrivileged = origPrivileged
		commandRunner = origRunner
		systemBundlePath = origBundle
	})

	ca := certPEM(t, "Test CA")
	require.NoError(t, os.WriteFile(bundle, certPEM(t, "Other CA"), 0o644))
	err := Install(ca, ScopeSystem)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not contain the certificate")

	require.NoError(t, os.WriteFile(bundle, append(certPEM(t, "Other CA"), ca...), 0o644))
	require.NoError(t, Install(ca, ScopeSystem))
}

func TestLinuxUserScopeUnsupported(t *testing.T) {
	assert.False(t, UserScopeSupported())
	assert.ErrorIs(t, Install([]byte("PEM"), ScopeUser), ErrUserScopeUnsupported)
	assert.ErrorIs(t, Uninstall("Test CA", ScopeUser), ErrUserScopeUnsupported)
}

func TestLinuxSystemInstallStagesAnchorAndUpdates(t *testing.T) {
	noBundle(t)
	dir := t.TempDir()
	dest := filepath.Join(dir, "pmg-proxy-ca.crt")

	origDetect := detectTrustTool
	detectTrustTool = func() (linuxTrustTool, error) {
		return linuxTrustTool{anchorDir: dir, updateCmd: "update-ca-certificates", anchorName: "pmg-proxy-ca.crt"}, nil
	}
	origPrivileged := platform.IsPrivileged
	platform.IsPrivileged = func() bool { return true } // run as root so no sudo prefix is added
	var calls [][]string
	origRunner := commandRunner
	commandRunner = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	t.Cleanup(func() {
		detectTrustTool = origDetect
		platform.IsPrivileged = origPrivileged
		commandRunner = origRunner
	})

	require.NoError(t, Install([]byte("PEM-BYTES"), ScopeSystem))

	require.Len(t, calls, 2)
	assert.Equal(t, "install", calls[0][0])
	assert.Contains(t, calls[0], dest)
	assert.Equal(t, "update-ca-certificates", calls[1][0])
}

func TestLinuxSystemInstallElevatesWhenNotRoot(t *testing.T) {
	noBundle(t)
	dir := t.TempDir()
	origDetect := detectTrustTool
	detectTrustTool = func() (linuxTrustTool, error) {
		return linuxTrustTool{anchorDir: dir, updateCmd: "update-ca-certificates", anchorName: "pmg-proxy-ca.crt"}, nil
	}
	origPrivileged := platform.IsPrivileged
	platform.IsPrivileged = func() bool { return false }
	var firstName string
	origRunner := commandRunner
	commandRunner = func(name string, _ ...string) ([]byte, error) {
		if firstName == "" {
			firstName = name
		}
		return nil, nil
	}
	t.Cleanup(func() {
		detectTrustTool = origDetect
		platform.IsPrivileged = origPrivileged
		commandRunner = origRunner
	})

	require.NoError(t, Install([]byte("PEM"), ScopeSystem))
	assert.Equal(t, "sudo", firstName)
}

// persistedCert writes a CA certificate to a temporary config directory and
// returns the directory and the PEM.
func persistedCert(t *testing.T) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	ca := certPEM(t, "Test CA")
	require.NoError(t, os.WriteFile(certmanager.CACertPath(dir), ca, 0o644))
	return dir, ca
}

func TestLinuxStatusChecksTheAnchorWithoutABundle(t *testing.T) {
	noBundle(t)
	anchorDir := t.TempDir()
	origDetect := detectTrustTool
	detectTrustTool = func() (linuxTrustTool, error) {
		return linuxTrustTool{anchorDir: anchorDir, updateCmd: "update-ca-certificates", anchorName: "pmg-proxy-ca.crt"}, nil
	}
	t.Cleanup(func() { detectTrustTool = origDetect })
	configDir, ca := persistedCert(t)
	anchor := filepath.Join(anchorDir, "pmg-proxy-ca.crt")

	tests := []struct {
		name   string
		anchor []byte
		want   bool
	}{
		{name: "no anchor"},
		{name: "the anchor holds another certificate with the same name", anchor: certPEM(t, "Test CA")},
		{name: "the anchor holds the CA", anchor: ca, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, os.RemoveAll(anchor))
			if tt.anchor != nil {
				require.NoError(t, os.WriteFile(anchor, tt.anchor, 0o644))
			}
			user, system, err := Status(configDir)
			require.NoError(t, err)
			assert.False(t, user)
			assert.Equal(t, tt.want, system)
		})
	}
}

func TestLinuxStatusTrustsOnlyWhatTheBundleHolds(t *testing.T) {
	anchorDir := t.TempDir()
	origDetect := detectTrustTool
	detectTrustTool = func() (linuxTrustTool, error) {
		return linuxTrustTool{anchorDir: anchorDir, updateCmd: "update-ca-trust", anchorName: "pmg-proxy-ca.crt"}, nil
	}
	bundle := filepath.Join(t.TempDir(), "ca-certificates.crt")
	origBundle := systemBundlePath
	systemBundlePath = func() string { return bundle }
	t.Cleanup(func() {
		detectTrustTool = origDetect
		systemBundlePath = origBundle
	})
	configDir, ca := persistedCert(t)
	anchor := filepath.Join(anchorDir, "pmg-proxy-ca.crt")

	tests := []struct {
		name     string
		bundle   []byte
		noAnchor bool
		want     bool
	}{
		{name: "an anchor the trust tool never read", bundle: certPEM(t, "Other CA")},
		{name: "another certificate with the same name", bundle: certPEM(t, "Test CA")},
		{name: "the bundle holds the CA", bundle: append(certPEM(t, "Other CA"), ca...), want: true},
		{name: "another path installed the CA, with no PMG anchor", bundle: ca, noAnchor: true, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, os.RemoveAll(anchor))
			if !tt.noAnchor {
				require.NoError(t, os.WriteFile(anchor, ca, 0o644))
			}
			require.NoError(t, os.WriteFile(bundle, tt.bundle, 0o644))
			_, system, err := Status(configDir)
			require.NoError(t, err)
			assert.Equal(t, tt.want, system)
		})
	}
}

func TestLinuxStatusWithoutAPersistedCA(t *testing.T) {
	user, system, err := Status(t.TempDir())
	require.NoError(t, err)
	assert.False(t, user)
	assert.False(t, system)
}
