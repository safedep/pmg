//go:build windows
// +build windows

package truststore

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsInstallUserAddsUserFlag(t *testing.T) {
	var gotName string
	var gotArgs []string
	orig := commandRunner
	commandRunner = func(name string, args ...string) ([]byte, error) {
		gotName, gotArgs = name, args
		return nil, nil
	}
	t.Cleanup(func() { commandRunner = orig })

	require.NoError(t, Install([]byte("PEM"), ScopeUser))
	assert.Equal(t, "certutil", gotName)
	assert.Equal(t, "-user", gotArgs[0])
	assert.Contains(t, gotArgs, "-addstore")
	assert.Contains(t, gotArgs, "Root")
}

func TestWindowsInstallSystemHasNoUserFlag(t *testing.T) {
	var gotArgs []string
	orig := commandRunner
	commandRunner = func(_ string, args ...string) ([]byte, error) {
		gotArgs = args
		return nil, nil
	}
	t.Cleanup(func() { commandRunner = orig })

	require.NoError(t, Install([]byte("PEM"), ScopeSystem))
	assert.NotContains(t, gotArgs, "-user")
	assert.Equal(t, "-addstore", gotArgs[0])
}

func TestWindowsUninstallNotFoundIsOK(t *testing.T) {
	orig := commandRunner
	commandRunner = func(_ string, _ ...string) ([]byte, error) {
		return []byte("Cannot find the requested object"), assert.AnError
	}
	t.Cleanup(func() { commandRunner = orig })
	require.NoError(t, Uninstall("Test CA", ScopeUser))
}

func TestWindowsGoTrustsCALooksUpTheThumbprint(t *testing.T) {
	dir, ca := persistedCA(t)
	id := thumbprint(ca.X509Cert)
	tests := []struct {
		name        string
		trustedArgs []string
		wantErr     error
	}{
		{name: "user Root store holds the CA", trustedArgs: []string{"-user", "-store", "Root", id}},
		{name: "machine Root store holds the CA", trustedArgs: []string{"-store", "Root", id}},
		{name: "no Root store holds the CA", wantErr: ErrCANotTrusted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := commandRunner
			commandRunner = func(name string, args ...string) ([]byte, error) {
				assert.Equal(t, "certutil", name)
				assert.Contains(t, args, id, "the lookup uses the thumbprint, not the name")
				if slices.Equal(args, tt.trustedArgs) {
					return nil, nil
				}
				return []byte("CRYPT_E_NOT_FOUND 0x80092004"), assert.AnError
			}
			t.Cleanup(func() { commandRunner = orig })

			err := GoTrustsCA(dir)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestWindowsStatusMatchesTheExactCertificateInEachStore(t *testing.T) {
	dir, ca := persistedCA(t)
	id := thumbprint(ca.X509Cert)
	tests := []struct {
		name              string
		inUser, inMachine bool
	}{
		{name: "exact CA in the user store only", inUser: true},
		{name: "exact CA in the machine store only", inMachine: true},
		{name: "only a certificate with the same name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := commandRunner
			commandRunner = func(_ string, args ...string) ([]byte, error) {
				if !slices.Contains(args, id) {
					return nil, assert.AnError
				}
				userStore := slices.Contains(args, "-user")
				if userStore && tt.inUser || !userStore && tt.inMachine {
					return nil, nil
				}
				return []byte("CRYPT_E_NOT_FOUND 0x80092004"), assert.AnError
			}
			t.Cleanup(func() { commandRunner = orig })

			user, system, err := Status(dir)
			require.NoError(t, err)
			assert.Equal(t, tt.inUser, user)
			assert.Equal(t, tt.inMachine, system)
		})
	}
}
