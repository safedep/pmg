//go:build windows

package setup

import (
	"testing"

	"github.com/safedep/pmg/internal/shim"
	"github.com/stretchr/testify/assert"
)

// The install warning and the doctor Fix column print the same lines from
// the same resolutions, so they cannot disagree on a path. Neither tells the
// user to reorder PATH, which cannot put a user entry ahead of a machine
// entry.
func TestShadowedFixAndWarningShareTheResolvedPath(t *testing.T) {
	shadowed := []shim.ManagerResolution{
		{Name: "npm", Path: `C:\Program Files\nodejs\npm.cmd`},
		{Name: "npx", Path: `C:\Program Files\nodejs\npx.cmd`},
	}

	lines := shadowedLines(shadowed)
	fix := shadowedFix(shadowed)

	assert.Equal(t, []string{
		`npm is C:\Program Files\nodejs\npm.cmd.`,
		`npx is C:\Program Files\nodejs\npx.cmd.`,
	}, lines)
	for _, line := range lines {
		assert.Contains(t, fix, line)
	}
	assert.Contains(t, fix, "Run them as `pmg <manager>`")
	assert.NotContains(t, fix, "Move")
}
