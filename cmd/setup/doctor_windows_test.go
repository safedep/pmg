//go:build windows

package setup

import (
	"testing"

	"github.com/safedep/pmg/internal/shim"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The warning names every shadowed manager once and gives one action.
// A shell profile is the one case a system install cannot fix.
func TestShadowedLines(t *testing.T) {
	machine := []shim.ManagerResolution{
		{Name: "npm", Path: `C:\Program Files\nodejs\npm.cmd`, Origin: shim.OriginMachine},
		{Name: "npx", Path: `C:\Program Files\nodejs\npx.cmd`, Origin: shim.OriginMachine},
		{Name: "pip", Path: `C:\Python314\Scripts\pip.exe`, Origin: shim.OriginMachine},
	}
	lines := shadowedLines(machine)
	require.Len(t, lines, 2)
	assert.Equal(t, "PMG does not intercept npm, npx, pip. Another copy is ahead of the shims on PATH.", lines[0])
	assert.Equal(t, "Run `pmg setup install --system` from a terminal started as administrator, or prefix the command with `pmg`, as in `pmg npm install`.", lines[1])

	profile := []shim.ManagerResolution{{Name: "npm", Path: `C:\Users\dev\fnm\npm.cmd`, Origin: shim.OriginProfile}}
	lines = shadowedLines(profile)
	require.Len(t, lines, 2)
	assert.Equal(t, "PMG does not intercept npm. Another copy is ahead of the shims on PATH.", lines[0])
	assert.Contains(t, lines[1], "drop that line from the profile")
	assert.NotContains(t, lines[1], "--system")

	// The earlier text told the user to install the manager for their user
	// only. The python.org installer prepends its own directory, so that
	// advice put pip ahead of the shims.
	for _, line := range lines {
		assert.NotContains(t, line, "for your user only")
	}
}

// The install warning and the doctor Fix column print the same lines from
// the same resolutions, so they cannot disagree.
func TestShadowedFixAndWarningAgree(t *testing.T) {
	shadowed := []shim.ManagerResolution{
		{Name: "npm", Path: `C:\Program Files\nodejs\npm.cmd`, Origin: shim.OriginMachine},
		{Name: "pip", Path: `C:\Users\dev\Python\Scripts\pip.exe`, Origin: shim.OriginUser},
	}
	fix := shadowedFix(shadowed)
	for _, line := range shadowedLines(shadowed) {
		assert.Contains(t, fix, line)
	}
}
