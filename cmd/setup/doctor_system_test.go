package setup

import (
	"testing"

	"github.com/safedep/pmg/internal/doctor"
	"github.com/stretchr/testify/assert"
)

func TestPathContainsDir(t *testing.T) {
	assert.True(t, pathContainsDir([]string{"/usr/local/lib/pmg/bin/"}, "/usr/local/lib/pmg/bin"))
	assert.False(t, pathContainsDir([]string{"/usr/local/bin"}, "/usr/local/lib/pmg/bin"))
	assert.False(t, pathContainsDir([]string{"/usr/bin"}, ""))
}

func TestSystemShimsWithoutPathDoNotActivateInterception(t *testing.T) {
	results := []doctor.CheckResult{
		{Name: checkShellAliases, Status: doctor.StatusWarn},
		{Name: checkShimInPath, Status: doctor.StatusFail},
	}

	assert.False(t, isInterceptionActive(results))
}
