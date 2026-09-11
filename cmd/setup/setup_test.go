package setup

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withPrivilege(t *testing.T, privileged bool) {
	t.Helper()
	orig := platform.IsPrivileged
	platform.IsPrivileged = func() bool { return privileged }
	t.Cleanup(func() { platform.IsPrivileged = orig })
}

// Linux and Windows gate on privilege, and macOS is unsupported whoever runs
// it. The privilege is injected, so every row runs on every platform and the
// process's own token never decides the result.
func TestRequireSystemInstallSupported(t *testing.T) {
	for _, privileged := range []bool{true, false} {
		t.Run(fmt.Sprintf("privileged=%t", privileged), func(t *testing.T) {
			withPrivilege(t, privileged)

			err := requireSystemInstallSupported()

			switch {
			case runtime.GOOS != "linux" && runtime.GOOS != "windows":
				assertUsefulCode(t, err, errcodes.UnsupportedPlatform)
			case privileged:
				assert.NoError(t, err)
			default:
				assertUsefulCode(t, err, errcodes.PermissionDenied)
			}
		})
	}
}

func TestInstallSystemRequiresPrivilege(t *testing.T) {
	withPrivilege(t, false)

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
