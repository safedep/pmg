package platform

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The parent of a test binary is the go tool, so the name resolves.
func TestParentProcessName(t *testing.T) {
	name, err := ParentProcessName()
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(strings.ToLower(name), ".exe"), name)
}
