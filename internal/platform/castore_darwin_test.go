//go:build darwin

package platform

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDarwinInstallUserArgs(t *testing.T) {
	var gotName string
	var gotArgs []string
	orig := commandRunner
	commandRunner = func(name string, args ...string) ([]byte, error) {
		gotName, gotArgs = name, args
		return nil, nil
	}
	t.Cleanup(func() { commandRunner = orig })

	require.NoError(t, installCA(testCert(t, "Test CA"), TrustScopeUser))
	assert.Equal(t, "security", gotName)
	assert.Equal(t, "add-trusted-cert", gotArgs[0])
	assert.NotContains(t, gotArgs, "-d") // user scope: no -d
	assert.Contains(t, gotArgs, "trustRoot")
}

func TestDarwinInstallSystemArgs(t *testing.T) {
	var gotArgs []string
	orig := commandRunner
	commandRunner = func(_ string, args ...string) ([]byte, error) {
		gotArgs = args
		return nil, nil
	}
	t.Cleanup(func() { commandRunner = orig })

	require.NoError(t, installCA(testCert(t, "Test CA"), TrustScopeSystem))
	assert.Contains(t, gotArgs, "-d") // system scope: -d
	assert.Contains(t, gotArgs, systemKeychainPath)
}

func TestDarwinUninstallStopsWhenNotFound(t *testing.T) {
	calls := 0
	orig := commandRunner
	commandRunner = func(_ string, _ ...string) ([]byte, error) {
		calls++
		return []byte(`Unable to delete certificate matching "Test CA"`), assert.AnError
	}
	t.Cleanup(func() { commandRunner = orig })

	require.NoError(t, uninstallCA("Test CA", TrustScopeUser))
	assert.Equal(t, 1, calls)
}

func TestDarwinUninstallStopsAfterDeletingMatches(t *testing.T) {
	calls := 0
	orig := commandRunner
	commandRunner = func(_ string, _ ...string) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, nil // first match deleted
		}
		return []byte(`Unable to delete certificate matching "Test CA"`), assert.AnError
	}
	t.Cleanup(func() { commandRunner = orig })

	require.NoError(t, uninstallCA("Test CA", TrustScopeUser))
	assert.Equal(t, 2, calls) // delete one, then terminal not-found
}

func TestDarwinUninstallSystemTargetsSystemKeychain(t *testing.T) {
	var gotArgs []string
	orig := commandRunner
	commandRunner = func(_ string, args ...string) ([]byte, error) {
		gotArgs = args
		return []byte("Could not find"), assert.AnError
	}
	t.Cleanup(func() { commandRunner = orig })

	require.NoError(t, uninstallCA("Test CA", TrustScopeSystem))
	assert.Contains(t, gotArgs, systemKeychainPath)
	assert.Contains(t, gotArgs, "-t")
}

func TestDarwinUserScopeSupported(t *testing.T) {
	assert.True(t, caUserScopeSupported())
}

func TestDarwinVerifyCATrustedRunsVerifyCert(t *testing.T) {
	cert := testCert(t, "Test CA")
	path := writeCertFile(t, cert)
	tests := []struct {
		name    string
		runErr  error
		wantErr error
	}{
		{name: "the OS trusts the CA"},
		{name: "the OS does not trust the CA", runErr: assert.AnError, wantErr: ErrCANotTrusted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotName string
			var gotArgs []string
			orig := commandRunner
			commandRunner = func(name string, args ...string) ([]byte, error) {
				gotName, gotArgs = name, args
				return nil, tt.runErr
			}
			t.Cleanup(func() { commandRunner = orig })

			err := verifyCATrusted(path, cert)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, "security", gotName)
			assert.Equal(t, []string{"verify-cert", "-p", "ssl", "-l", "-L", "-c", path}, gotArgs)
		})
	}
}

func TestDarwinCAStoresMatchesTheExactCertificateInEachKeychain(t *testing.T) {
	cert := testCert(t, "Test CA")
	sameName := "SHA-256 hash: 00\nSHA-1 hash: 0000000000000000000000000000000000000000\n"
	exact := "SHA-1 hash: " + thumbprint(cert) + "\n"
	tests := []struct {
		name              string
		system, login     string
		wantUser, wantSys bool
	}{
		{name: "exact CA in login, stale copy in System", login: exact, system: sameName, wantUser: true},
		{name: "exact CA in System, stale copy in login", login: sameName, system: exact, wantSys: true},
		{name: "only stale copies", login: sameName, system: sameName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := commandRunner
			commandRunner = func(_ string, args ...string) ([]byte, error) {
				if args[0] != "find-certificate" {
					return nil, assert.AnError
				}
				if args[len(args)-1] == systemKeychainPath {
					return []byte(tt.system), nil
				}
				return []byte(tt.login), nil
			}
			t.Cleanup(func() { commandRunner = orig })

			user, system, err := caStores(cert)
			require.NoError(t, err)
			assert.Equal(t, tt.wantUser, user)
			assert.Equal(t, tt.wantSys, system)
		})
	}
}

func TestDarwinCABundleCandidates(t *testing.T) {
	assert.Equal(t, []string{
		"/opt/homebrew/etc/openssl@3/cert.pem",
		"/usr/local/etc/openssl@3/cert.pem",
		"/etc/ssl/cert.pem",
	}, CABundleCandidates())
}

// writeCertFile writes cert as PEM to a temp file, as the persisted CA is
// stored, and returns its path.
func writeCertFile(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca-cert.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644))
	return path
}
