//go:build windows
// +build windows

package truststore

import (
	"crypto/sha1"
	"fmt"
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
	thumbprint := fmt.Sprintf("%X", sha1.Sum(ca.X509Cert.Raw))
	tests := []struct {
		name        string
		trustedArgs []string
		wantErr     error
	}{
		{name: "user Root store holds the CA", trustedArgs: []string{"-user", "-store", "Root", thumbprint}},
		{name: "machine Root store holds the CA", trustedArgs: []string{"-store", "Root", thumbprint}},
		{name: "no Root store holds the CA", wantErr: ErrCANotTrusted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := commandRunner
			commandRunner = func(name string, args ...string) ([]byte, error) {
				assert.Equal(t, "certutil", name)
				assert.Contains(t, args, thumbprint, "the lookup uses the thumbprint, not the name")
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
