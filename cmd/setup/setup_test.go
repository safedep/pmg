package setup

import (
	"runtime"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/winacl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Linux gates on root and Windows on UAC elevation, which a test cannot
// fake, so the Windows expectation follows the process. macOS is unsupported
// whoever runs it.
func TestRequireSystemInstallSupported(t *testing.T) {
	orig := setupGeteuid
	t.Cleanup(func() { setupGeteuid = orig })

	setupGeteuid = func() int { return 0 }
	err := requireSystemInstallSupported()
	switch {
	case runtime.GOOS == "linux", runtime.GOOS == "windows" && winacl.ProcessIsElevated():
		assert.NoError(t, err)
	case runtime.GOOS == "windows":
		assertUsefulCode(t, err, errcodes.PermissionDenied)
	default:
		assertUsefulCode(t, err, errcodes.UnsupportedPlatform)
	}

	setupGeteuid = func() int { return 1000 }
	err = requireSystemInstallSupported()
	switch {
	case runtime.GOOS == "linux":
		assertUsefulCode(t, err, errcodes.PermissionDenied)
	case runtime.GOOS == "windows" && winacl.ProcessIsElevated():
		assert.NoError(t, err, "Windows does not consult the uid")
	case runtime.GOOS == "windows":
		assertUsefulCode(t, err, errcodes.PermissionDenied)
	default:
		assertUsefulCode(t, err, errcodes.UnsupportedPlatform)
	}
}

func TestInstallSystemRequiresRoot(t *testing.T) {
	if runtime.GOOS == "windows" && winacl.ProcessIsElevated() {
		t.Skip("an elevated process would install for real")
	}
	orig := setupGeteuid
	t.Cleanup(func() { setupGeteuid = orig })

	setupGeteuid = func() int { return 1000 }

	err := install(true)
	switch runtime.GOOS {
	case "linux", "windows":
		assertUsefulCode(t, err, errcodes.PermissionDenied)
	default:
		assertUsefulCode(t, err, errcodes.UnsupportedPlatform)
	}
}

func assertUsefulCode(t *testing.T, err error, want string) {
	t.Helper()
	require.Error(t, err)
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, want, usefulErr.Code())
}
