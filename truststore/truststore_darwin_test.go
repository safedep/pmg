//go:build darwin
// +build darwin

package truststore

import (
	"testing"

	"github.com/safedep/pmg/proxy/certmanager"
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

	require.NoError(t, Install([]byte("PEM"), ScopeUser))
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

	require.NoError(t, Install([]byte("PEM"), ScopeSystem))
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

	require.NoError(t, Uninstall("Test CA", ScopeUser))
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

	require.NoError(t, Uninstall("Test CA", ScopeUser))
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

	require.NoError(t, Uninstall("Test CA", ScopeSystem))
	assert.Contains(t, gotArgs, systemKeychainPath)
	assert.Contains(t, gotArgs, "-t")
}

func TestDarwinUserScopeSupported(t *testing.T) {
	assert.True(t, UserScopeSupported())
}

func TestDarwinGoTrustsCAVerifiesThePersistedCertificate(t *testing.T) {
	dir, _ := persistedCA(t)
	tests := []struct {
		name    string
		runErr  error
		wantErr error
	}{
		{name: "the OS trusts the persisted CA"},
		{name: "the OS does not trust the persisted CA", runErr: assert.AnError, wantErr: ErrCANotTrusted},
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

			err := GoTrustsCA(dir)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, "security", gotName)
			assert.Equal(t, []string{"verify-cert", "-p", "ssl", "-l", "-L", "-c", certmanager.CACertPath(dir)}, gotArgs)
		})
	}
}

func TestDarwinStatusMatchesTheExactCertificateInEachKeychain(t *testing.T) {
	dir, ca := persistedCA(t)
	sameName := "SHA-256 hash: 00\nSHA-1 hash: 0000000000000000000000000000000000000000\n"
	exact := "SHA-1 hash: " + thumbprint(ca.X509Cert) + "\n"
	tests := []struct {
		name              string
		system, login     string
		verifyErr         error
		wantUser, wantSys bool
	}{
		{name: "exact CA in login, stale copy in System", login: exact, system: sameName, wantUser: true},
		{name: "exact CA in System, stale copy in login", login: sameName, system: exact, wantSys: true},
		{name: "exact CA in a keychain without trust settings", login: exact, verifyErr: assert.AnError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := commandRunner
			commandRunner = func(_ string, args ...string) ([]byte, error) {
				switch args[0] {
				case "verify-cert":
					return nil, tt.verifyErr
				case "find-certificate":
					if args[len(args)-1] == systemKeychainPath {
						return []byte(tt.system), nil
					}
					return []byte(tt.login), nil
				}
				return nil, assert.AnError
			}
			t.Cleanup(func() { commandRunner = orig })

			user, system, err := Status(dir)
			require.NoError(t, err)
			assert.Equal(t, tt.wantUser, user)
			assert.Equal(t, tt.wantSys, system)
		})
	}
}
