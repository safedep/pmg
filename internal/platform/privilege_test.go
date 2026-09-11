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
