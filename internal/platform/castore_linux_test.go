//go:build linux

package platform

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	origPrivileged := IsPrivileged
	IsPrivileged = func() bool { return true }
	origRunner := commandRunner
	commandRunner = func(string, ...string) ([]byte, error) { return nil, nil }
	bundle := filepath.Join(t.TempDir(), "ca-certificates.crt")
	origBundle := systemBundlePath
	systemBundlePath = func() string { return bundle }
	t.Cleanup(func() {
		detectTrustTool = origDetect
		IsPrivileged = origPrivileged
		commandRunner = origRunner
		systemBundlePath = origBundle
	})

	ca := certPEM(t, "Test CA")
	require.NoError(t, os.WriteFile(bundle, certPEM(t, "Other CA"), 0o644))
	err := installCA(parsePEM(t, ca), CAScopeSystem)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not contain the certificate")

	require.NoError(t, os.WriteFile(bundle, append(certPEM(t, "Other CA"), ca...), 0o644))
	require.NoError(t, installCA(parsePEM(t, ca), CAScopeSystem))
}

func TestLinuxUserScopeUnsupported(t *testing.T) {
	assert.False(t, caUserScopeSupported())
	assert.ErrorIs(t, installCA(testCert(t, "Test CA"), CAScopeUser), ErrCAUserScopeUnsupported)
	assert.ErrorIs(t, uninstallCA("Test CA", CAScopeUser), ErrCAUserScopeUnsupported)
}

func TestLinuxSystemInstallStagesAnchorAndUpdates(t *testing.T) {
	noBundle(t)
	dir := t.TempDir()
	dest := filepath.Join(dir, "pmg-proxy-ca.crt")

	origDetect := detectTrustTool
	detectTrustTool = func() (linuxTrustTool, error) {
		return linuxTrustTool{anchorDir: dir, updateCmd: "update-ca-certificates", anchorName: "pmg-proxy-ca.crt"}, nil
	}
	origPrivileged := IsPrivileged
	IsPrivileged = func() bool { return true } // run as root so no sudo prefix is added
	var calls [][]string
	origRunner := commandRunner
	commandRunner = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	t.Cleanup(func() {
		detectTrustTool = origDetect
		IsPrivileged = origPrivileged
		commandRunner = origRunner
	})

	require.NoError(t, installCA(testCert(t, "Test CA"), CAScopeSystem))

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
	origPrivileged := IsPrivileged
	IsPrivileged = func() bool { return false }
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
		IsPrivileged = origPrivileged
		commandRunner = origRunner
	})

	require.NoError(t, installCA(testCert(t, "Test CA"), CAScopeSystem))
	assert.Equal(t, "sudo", firstName)
}

func TestLinuxCAStoresChecksTheAnchorWithoutABundle(t *testing.T) {
	noBundle(t)
	anchorDir := t.TempDir()
	origDetect := detectTrustTool
	detectTrustTool = func() (linuxTrustTool, error) {
		return linuxTrustTool{anchorDir: anchorDir, updateCmd: "update-ca-certificates", anchorName: "pmg-proxy-ca.crt"}, nil
	}
	t.Cleanup(func() { detectTrustTool = origDetect })
	ca := certPEM(t, "Test CA")
	cert := parsePEM(t, ca)
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
			user, system, err := caStores(cert)
			require.NoError(t, err)
			assert.False(t, user)
			assert.Equal(t, tt.want, system)
		})
	}
}

func TestLinuxCAStoresTrustsOnlyWhatTheBundleHolds(t *testing.T) {
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
	ca := certPEM(t, "Test CA")
	cert := parsePEM(t, ca)
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
			_, system, err := caStores(cert)
			require.NoError(t, err)
			assert.Equal(t, tt.want, system)
		})
	}
}

func TestLinuxCABundleCandidates(t *testing.T) {
	candidates := caBundleCandidates()
	assert.Contains(t, candidates, "/etc/ssl/certs/ca-certificates.crt", "Debian and Ubuntu")
	assert.Contains(t, candidates, "/etc/pki/tls/certs/ca-bundle.crt", "Fedora and RHEL")
}

func TestLinuxCAStoresReadsTheBundleWhenTheAnchorCannotBeRead(t *testing.T) {
	// An anchor directory that is a regular file makes stat fail with an
	// error other than "not found".
	notADir := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(notADir, nil, 0o644))
	origDetect := detectTrustTool
	detectTrustTool = func() (linuxTrustTool, error) {
		return linuxTrustTool{anchorDir: notADir, updateCmd: "update-ca-certificates", anchorName: "pmg-proxy-ca.crt"}, nil
	}
	t.Cleanup(func() { detectTrustTool = origDetect })
	ca := certPEM(t, "Test CA")
	cert := parsePEM(t, ca)

	bundle := filepath.Join(t.TempDir(), "ca-certificates.crt")
	require.NoError(t, os.WriteFile(bundle, ca, 0o644))
	origBundle := systemBundlePath
	systemBundlePath = func() string { return bundle }
	t.Cleanup(func() { systemBundlePath = origBundle })

	_, system, err := caStores(cert)
	require.NoError(t, err)
	assert.True(t, system, "the bundle decides when there is one")

	systemBundlePath = func() string { return "" }
	_, _, err = caStores(cert)
	assert.Error(t, err, "without a bundle the anchor decides, so its error counts")
}
