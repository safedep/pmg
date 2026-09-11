package platform

import (
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withPrivilege(t *testing.T, privileged bool) {
	t.Helper()
	orig := IsPrivileged
	IsPrivileged = func() bool { return privileged }
	t.Cleanup(func() { IsPrivileged = orig })
}

func TestIsSudoCountsTheMarkerOnlyWhenPrivileged(t *testing.T) {
	tests := []struct {
		name       string
		privileged bool
		sudoUser   string
		want       bool
	}{
		{name: "sudo from a person", privileged: true, sudoUser: "alice", want: true},
		{name: "root without sudo", privileged: true, sudoUser: "", want: false},
		{name: "a user who set the marker", privileged: false, sudoUser: "alice", want: false},
		{name: "a user", privileged: false, sudoUser: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withPrivilege(t, tt.privileged)
			t.Setenv("SUDO_USER", tt.sudoUser)
			assert.Equal(t, tt.want, IsSudo())
		})
	}
}

func TestRequirePrivilege(t *testing.T) {
	withPrivilege(t, true)
	assert.NoError(t, RequirePrivilege("pmg setup install --system"))

	withPrivilege(t, false)
	err := RequirePrivilege("pmg setup install --system")
	require.Error(t, err)
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.PermissionDenied, usefulErr.Code())
	assert.Contains(t, usefulErr.HumanError(), "`pmg setup install --system` requires "+privilegedRole)
	assert.Contains(t, usefulErr.Help(), privilegeRemedyWord)
	assert.ErrorIs(t, err, errNotPrivileged)
}
