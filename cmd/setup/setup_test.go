package setup

import (
	"runtime"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Linux gates on root, Windows on UAC elevation, and macOS is unsupported
// whoever runs it. Both signals are injected, so every row runs on every
// platform and the process's own token never decides the result.
func TestRequireSystemInstallSupported(t *testing.T) {
	origUID, origElevated := setupGeteuid, setupIsElevated
	t.Cleanup(func() { setupGeteuid, setupIsElevated = origUID, origElevated })

	tests := []struct {
		name     string
		uid      int
		elevated bool
	}{
		{name: "root and elevated", uid: 0, elevated: true},
		{name: "root, not elevated", uid: 0, elevated: false},
		{name: "user, elevated", uid: 1000, elevated: true},
		{name: "user, not elevated", uid: 1000, elevated: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupGeteuid = func() int { return tt.uid }
			setupIsElevated = func() bool { return tt.elevated }

			err := requireSystemInstallSupported()

			switch {
			case runtime.GOOS == "linux" && tt.uid == 0, runtime.GOOS == "windows" && tt.elevated:
				assert.NoError(t, err)
			case runtime.GOOS == "linux", runtime.GOOS == "windows":
				assertUsefulCode(t, err, errcodes.PermissionDenied)
			default:
				assertUsefulCode(t, err, errcodes.UnsupportedPlatform)
			}
		})
	}
}

func TestInstallSystemRequiresRoot(t *testing.T) {
	if runtime.GOOS == "windows" && setupIsElevated() {
		t.Skip("an elevated process would install for real")
	}
	origUID, origElevated := setupGeteuid, setupIsElevated
	t.Cleanup(func() { setupGeteuid, setupIsElevated = origUID, origElevated })

	setupGeteuid = func() int { return 1000 }
	setupIsElevated = func() bool { return false }

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
