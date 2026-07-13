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

func TestSystemInstallAliasesPassDoesNotActivateInterception(t *testing.T) {
	results := []doctor.CheckResult{
		{Name: checkShellAliases, Status: doctor.StatusPass, Message: "No aliases (system install)"},
		{Name: checkShimInPath, Status: doctor.StatusFail},
	}

	assert.False(t, isInterceptionActive(results))
}

func TestAliasesInstalledActivatesInterception(t *testing.T) {
	results := []doctor.CheckResult{
		{Name: checkShellAliases, Status: doctor.StatusPass, Message: aliasesInstalledMessage},
		{Name: checkShimInPath, Status: doctor.StatusFail},
	}

	assert.True(t, isInterceptionActive(results))
}
