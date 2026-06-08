//go:build darwin
// +build darwin

package truststore

import (
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
