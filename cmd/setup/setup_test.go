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
	err := errIfSystemInstallAllowed()
	if runtime.GOOS == "linux" {
		assert.NoError(t, err)
	} else {
		require.Error(t, err)
		usefulErr, ok := usefulerror.AsUsefulError(err)
		require.True(t, ok)
		assert.Equal(t, errcodes.UnsupportedPlatform, usefulErr.Code())
	}

	setupGeteuid = func() int { return 1000 }
	err = errIfSystemInstallAllowed()
	require.Error(t, err)
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	if runtime.GOOS == "linux" {
		assert.Equal(t, errcodes.PermissionDenied, usefulErr.Code())
	} else {
		assert.Equal(t, errcodes.UnsupportedPlatform, usefulErr.Code())
	}
}

func TestInstallSystemRequiresLinuxAndRoot(t *testing.T) {
	orig := setupGeteuid
	t.Cleanup(func() {
		setupGeteuid = orig
		setupInstallSystem = false
	})

	setupInstallSystem = true
	setupGeteuid = func() int { return 0 }

	err := install()
	if runtime.GOOS == "linux" {
		if err != nil {
			usefulErr, ok := usefulerror.AsUsefulError(err)
			if ok {
				assert.NotEqual(t, errcodes.UnsupportedPlatform, usefulErr.Code())
				assert.NotEqual(t, errcodes.PermissionDenied, usefulErr.Code())
			}
		}
		return
	}

	require.Error(t, err)
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.UnsupportedPlatform, usefulErr.Code())
}
