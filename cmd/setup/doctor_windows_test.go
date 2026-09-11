//go:build windows

package setup

import (
	"testing"

	"github.com/safedep/pmg/internal/shim"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The action depends on where the winning PATH entry came from. Only the
// user half is one `pmg setup install` can reorder.
func TestShadowedAction(t *testing.T) {
	tests := []struct {
		name    string
		origin  shim.PathOrigin
		names   []string
		want    string
		notWant string
	}{
		{
			name:    "a machine PATH entry needs a system install",
			origin:  shim.OriginMachine,
			names:   []string{"npm"},
			want:    "Run `pmg setup install --system` from a terminal started as administrator, or run it as `pmg npm`.",
			notWant: "again",
		},
		{
			name:    "several machine PATH entries name every manager once",
			origin:  shim.OriginMachine,
			names:   []string{"npm", "pip", "pip3"},
			want:    "run them as `pmg npm`, `pmg pip`, `pmg pip3`.",
			notWant: "it as",
		},
		{
			name:    "a user PATH entry is one install can reorder",
			origin:  shim.OriginUser,
			names:   []string{"pip"},
			want:    "Run `pmg setup install` again to move the shims ahead.",
			notWant: "machine PATH",
		},
		{
			name:    "a profile entry needs the profile edited",
			origin:  shim.OriginProfile,
			names:   []string{"npm"},
			want:    "Run it as `pmg npm`, or drop that line from the profile.",
			notWant: "pmg setup install",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action := shadowedAction(tt.origin, tt.names)
			assert.Contains(t, action, tt.want)
			assert.NotContains(t, action, tt.notWant)
		})
	}

	// The earlier text told the user to install the manager for their user
	// only. The python.org installer prepends its own directory, so that
	// advice put pip ahead of the shims.
	for _, origin := range []shim.PathOrigin{shim.OriginMachine, shim.OriginUser, shim.OriginProfile} {
		assert.NotContains(t, shadowedAction(origin, []string{"pip"}), "for your user only")
	}
}

// Managers that share a PATH origin share one reason line and one action
// line. Two origins give four lines, not one pair per manager.
func TestShadowedLinesGroupByOrigin(t *testing.T) {
	shadowed := []shim.ManagerResolution{
		{Name: "npm", Path: `C:\Program Files\nodejs\npm.cmd`, Origin: shim.OriginMachine},
		{Name: "npx", Path: `C:\Program Files\nodejs\npx.cmd`, Origin: shim.OriginMachine},
		{Name: "pip", Path: `C:\Python314\Scripts\pip.exe`, Origin: shim.OriginMachine},
		{Name: "poetry", Path: `C:\Users\dev\poetry\poetry.exe`, Origin: shim.OriginUser},
	}

	lines := shadowedLines(shadowed)

	require.Len(t, lines, 4)
	assert.Equal(t, `On the machine PATH, ahead of the user PATH: npm (C:\Program Files\nodejs\npm.cmd), npx (C:\Program Files\nodejs\npx.cmd), pip (C:\Python314\Scripts\pip.exe)`, lines[0])
	assert.Equal(t, "Run `pmg setup install --system` from a terminal started as administrator, or run them as `pmg npm`, `pmg npx`, `pmg pip`.", lines[1])
	assert.Equal(t, `On the user PATH, ahead of the shims: poetry (C:\Users\dev\poetry\poetry.exe)`, lines[2])
	assert.Equal(t, "Run `pmg setup install` again to move the shims ahead.", lines[3])
}

// The install warning and the doctor Fix column print the same lines from
// the same resolutions, so they cannot disagree on a path or an action.
func TestShadowedFixAndWarningShareTheResolvedPath(t *testing.T) {
	shadowed := []shim.ManagerResolution{
		{Name: "npm", Path: `C:\Program Files\nodejs\npm.cmd`, Origin: shim.OriginMachine},
		{Name: "pip", Path: `C:\Users\dev\Python\Scripts\pip.exe`, Origin: shim.OriginUser},
	}

	lines := shadowedLines(shadowed)
	fix := shadowedFix(shadowed)

	require.Len(t, lines, 4)
	assert.Contains(t, lines[0], `npm (C:\Program Files\nodejs\npm.cmd)`)
	assert.Contains(t, lines[2], `pip (C:\Users\dev\Python\Scripts\pip.exe)`)
	for _, line := range lines {
		assert.Contains(t, fix, line)
	}
}
