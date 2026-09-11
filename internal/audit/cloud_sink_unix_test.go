//go:build unix

package audit

import (
	"os/user"
	"testing"

	"github.com/safedep/pmg/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The sudo marker counts on Unix only, so attribution through it has no
// Windows case.
func TestInvokingUserIgnoresSudoUserWhenNotElevated(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)

	orig := platform.IsPrivileged
	t.Cleanup(func() { platform.IsPrivileged = orig })

	// Non-root process: SUDO_USER must be ignored, else attribution is spoofable.
	platform.IsPrivileged = func() bool { return false }
	t.Setenv("SUDO_USER", "root")
	got := invokingUser()
	require.NotNil(t, got)
	assert.Equal(t, current.Username, got.Username, "SUDO_USER must not override attribution when not elevated")

	// Privileged: SUDO_USER is trusted and used.
	platform.IsPrivileged = func() bool { return true }
	t.Setenv("SUDO_USER", current.Username)
	got = invokingUser()
	require.NotNil(t, got)
	assert.Equal(t, current.Username, got.Username)
}

func TestInvokingUserKeepsSudoAttributionWithoutPasswdEntry(t *testing.T) {
	orig := platform.IsPrivileged
	t.Cleanup(func() { platform.IsPrivileged = orig })

	platform.IsPrivileged = func() bool { return true }
	t.Setenv("SUDO_USER", "no-such-user-xyz")
	t.Setenv("SUDO_UID", "4242")

	got := invokingUser()
	require.NotNil(t, got)
	assert.Equal(t, "no-such-user-xyz", got.Username)
	assert.Equal(t, "4242", got.Uid)

	// Without SUDO_UID, fall back to the effective uid: a non-root username
	// with uid 0 correctly signals the command ran under sudo.
	t.Setenv("SUDO_UID", "")
	got = invokingUser()
	require.NotNil(t, got)
	assert.Equal(t, "no-such-user-xyz", got.Username)
	assert.Equal(t, "0", got.Uid)
}
