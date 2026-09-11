//go:build windows

package alias

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The parent of a test binary is the go tool, so the image name resolves
// and no shell is claimed.
func TestParentShellNameNamesOnlyAShell(t *testing.T) {
	name, err := parentProcessName()
	require.NoError(t, err)
	assert.True(t, len(name) > 4 && name[len(name)-4:] == ".exe", name)

	assert.Empty(t, parentShellName())
}
