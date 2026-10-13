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

	require.NoError(t, installCA(testCert(t, "Test CA"), CAScopeUser))
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

	require.NoError(t, installCA(testCert(t, "Test CA"), CAScopeSystem))
	assert.Contains(t, gotArgs, "-d") // system scope: -d
	assert.Contains(t, gotArgs, systemKeychainPath)
}

func TestDarwinUserUninstallNamesTheLoginKeychain(t *testing.T) {
	var gotArgs [][]string
	orig := commandRunner
	commandRunner = func(_ string, args ...string) ([]byte, error) {
		gotArgs = append(gotArgs, args)
		return []byte(`Unable to delete certificate matching "Test CA"`), assert.AnError
	}
	t.Cleanup(func() { commandRunner = orig })

	require.NoError(t, uninstallCA("Test CA", CAScopeUser))
	require.Len(t, gotArgs, 1, "a not-found result ends the loop")
	login, err := loginKeychainPath()
	require.NoError(t, err)
	assert.Equal(t, []string{"delete-certificate", "-c", "Test CA", login}, gotArgs[0],
		"without a keychain, security also searches the System keychain and fails there without root")
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

	require.NoError(t, uninstallCA("Test CA", CAScopeUser))
	assert.Equal(t, 2, calls) // delete one, then terminal not-found
}

func TestDarwinUninstallSystemRemovesAdminTrustThenDeletes(t *testing.T) {
	cert := testCert(t, "Test CA")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	tests := []struct {
		name        string
		findOut     []byte
		findErr     error
		removeOut   []byte
		removeErr   error
		wantCalls   []string
		wantErr     bool
		wantRemoved []byte
	}{
		{
			name:        "trusted certificate",
			findOut:     certPEM,
			wantCalls:   []string{"find-certificate", "remove-trusted-cert", "delete-certificate"},
			wantRemoved: certPEM,
		},
		{
			name:      "no certificate with the name",
			findOut:   []byte(`security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.`),
			findErr:   assert.AnError,
			wantCalls: []string{"find-certificate", "delete-certificate"},
		},
		{
			name:        "certificate without admin trust settings",
			findOut:     certPEM,
			removeOut:   []byte(`SecTrustSettingsRemoveTrustSettings: The specified item could not be found in the keychain.`),
			removeErr:   assert.AnError,
			wantCalls:   []string{"find-certificate", "remove-trusted-cert", "delete-certificate"},
			wantRemoved: certPEM,
		},
		{
			name:        "trust removal fails",
			findOut:     certPEM,
			removeOut:   []byte(`SecTrustSettingsRemoveTrustSettings: The authorization was denied.`),
			removeErr:   assert.AnError,
			wantCalls:   []string{"find-certificate", "remove-trusted-cert"},
			wantErr:     true,
			wantRemoved: certPEM,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			var removed []byte
			orig := commandRunner
			commandRunner = func(name string, args ...string) ([]byte, error) {
				if name == "sudo" {
					args = args[1:]
				}
				calls = append(calls, args[0])
				switch args[0] {
				case "find-certificate":
					assert.Contains(t, args, systemKeychainPath)
					return tc.findOut, tc.findErr
				case "remove-trusted-cert":
					assert.Equal(t, "-d", args[1])
					b, err := os.ReadFile(args[2])
					require.NoError(t, err)
					removed = b
					return tc.removeOut, tc.removeErr
				default:
					assert.Contains(t, args, systemKeychainPath)
					assert.NotContains(t, args, "-t", "-t waits for a GUI prompt as root")
					return []byte("Could not find"), assert.AnError
				}
			}
			t.Cleanup(func() { commandRunner = orig })

			err := uninstallCA("Test CA", CAScopeSystem)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.wantCalls, calls)
			assert.Equal(t, tc.wantRemoved, removed)
		})
	}
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
	assert.Contains(t, caBundleCandidates(), "/etc/ssl/cert.pem")
	assert.Contains(t, caBundleCandidates(), "/opt/homebrew/etc/openssl@3/cert.pem")
}

// writeCertFile writes cert as PEM to a temp file, as the persisted CA is
// stored, and returns its path.
func writeCertFile(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca-cert.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644))
	return path
}
