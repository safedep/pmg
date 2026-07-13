package setup

import (
	"runtime"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrIfSystemInstallAllowed(t *testing.T) {
	orig := setupGeteuid
	t.Cleanup(func() { setupGeteuid = orig })

	setupGeteuid = func() int { return 0 }
	err := requireSystemInstallSupported()
	if runtime.GOOS == "linux" {
		assert.NoError(t, err)
	} else {
		require.Error(t, err)
		usefulErr, ok := usefulerror.AsUsefulError(err)
		require.True(t, ok)
		assert.Equal(t, errcodes.UnsupportedPlatform, usefulErr.Code())
	}

	setupGeteuid = func() int { return 1000 }
	err = requireSystemInstallSupported()
	require.Error(t, err)
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	if runtime.GOOS == "linux" {
		assert.Equal(t, errcodes.PermissionDenied, usefulErr.Code())
	} else {
		assert.Equal(t, errcodes.UnsupportedPlatform, usefulErr.Code())
	}
}

func TestInstallSystemRequiresRoot(t *testing.T) {
	orig := setupGeteuid
	t.Cleanup(func() { setupGeteuid = orig })

	setupGeteuid = func() int { return 1000 }

	err := install(true)
	require.Error(t, err)
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	if runtime.GOOS == "linux" {
		assert.Equal(t, errcodes.PermissionDenied, usefulErr.Code())
	} else {
		assert.Equal(t, errcodes.UnsupportedPlatform, usefulErr.Code())
	}
}
