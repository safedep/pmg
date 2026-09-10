//go:build windows

package setup

import (
	"testing"

	"github.com/safedep/pmg/internal/shim"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The action depends on where the winning PATH entry came from, and for the
// machine PATH on whether an elevated install already registered the shims.
func TestShadowedAction(t *testing.T) {
	tests := []struct {
		name              string
		resolution        shim.ManagerResolution
		machineRegistered bool
		want              string
		notWant           string
	}{
		{
			name:       "a machine PATH entry needs an elevated install",
			resolution: shim.ManagerResolution{Name: "npm", Origin: shim.OriginMachine},
			want:       "Run `pmg setup install` from a terminal started as administrator",
			notWant:    "Open a new terminal",
		},
		{
			name:              "a machine PATH entry already behind the registered shims needs a new terminal",
			resolution:        shim.ManagerResolution{Name: "npm", Origin: shim.OriginMachine},
			machineRegistered: true,
			want:              "Open a new terminal.",
			notWant:           "administrator",
		},
		{
			name:       "a user PATH entry is one install can reorder",
			resolution: shim.ManagerResolution{Name: "pip", Origin: shim.OriginUser},
			want:       "Run `pmg setup install` again to move the shims ahead of it.",
			notWant:    "machine PATH",
		},
		{
			name:       "a profile entry needs the profile edited",
			resolution: shim.ManagerResolution{Name: "npm", Origin: shim.OriginProfile},
			want:       "A shell profile puts that directory on PATH",
			notWant:    "pmg setup install",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action := shadowedAction(tt.resolution, tt.machineRegistered)
			assert.Contains(t, action, tt.want)
			assert.NotContains(t, action, tt.notWant)
		})
	}

	// The earlier text told the user to install the manager for their user
	// only. The python.org installer prepends its own directory, so that
	// advice put pip ahead of the shims.
	for _, origin := range []shim.PathOrigin{shim.OriginMachine, shim.OriginUser, shim.OriginProfile} {
		assert.NotContains(t, shadowedAction(shim.ManagerResolution{Name: "pip", Origin: origin}, false),
			"for your user only")
	}
}

// The install warning and the doctor Fix column print the same lines from
// the same resolutions, so they cannot disagree on a path or an action.
func TestShadowedFixAndWarningShareTheResolvedPath(t *testing.T) {
	shadowed := []shim.ManagerResolution{
		{Name: "npm", Path: `C:\Program Files\nodejs\npm.cmd`, Origin: shim.OriginMachine},
		{Name: "pip", Path: `C:\Users\dev\Python\Scripts\pip.exe`, Origin: shim.OriginUser},
	}

	lines := shadowedLines(shadowed, false)
	fix := shadowedFix(t.TempDir(), shadowed)

	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], `npm is C:\Program Files\nodejs\npm.cmd.`)
	assert.Contains(t, lines[1], `pip is C:\Users\dev\Python\Scripts\pip.exe.`)
	for _, line := range lines {
		assert.Contains(t, fix, line)
	}
}
