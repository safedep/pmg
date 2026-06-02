//go:build windows
// +build windows

package truststore

import (
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
