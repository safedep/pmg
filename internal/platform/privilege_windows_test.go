package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const privilegeRemedyWord = "terminal started as administrator"

// Windows has no sudo. An elevated process with a stray SUDO_USER must not
// divert its directories or refuse `pmg setup cert`.
func TestIsSudoIsNeverTrueOnWindows(t *testing.T) {
	withPrivilege(t, true)
	t.Setenv("SUDO_USER", "alice")
	assert.False(t, IsSudo())
}
