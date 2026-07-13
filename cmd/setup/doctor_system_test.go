package setup

import (
	"os/exec"
	"testing"

	"github.com/safedep/pmg/internal/doctor"
	"github.com/stretchr/testify/assert"
)

func TestPathContainsDir(t *testing.T) {
	assert.True(t, pathContainsDir([]string{"/usr/local/lib/pmg/bin/"}, "/usr/local/lib/pmg/bin"))
	assert.False(t, pathContainsDir([]string{"/usr/local/bin"}, "/usr/local/lib/pmg/bin"))
	assert.False(t, pathContainsDir([]string{"/usr/bin"}, ""))
}

func TestPathIsUnderDir(t *testing.T) {
	assert.True(t, pathIsUnderDir("/usr/local/lib/pmg/bin/npm", "/usr/local/lib/pmg/bin"))
	assert.False(t, pathIsUnderDir("/usr/local/bin/npm", "/usr/local/lib/pmg/bin"))
	assert.False(t, pathIsUnderDir("/usr/local/lib/pmg/bin-extra/npm", "/usr/local/lib/pmg/bin"))
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
		{
			Name:                checkShellAliases,
			Status:              doctor.StatusPass,
			Message:             aliasesInstalledMessage,
			ImpliesInterception: true,
		},
		{Name: checkShimInPath, Status: doctor.StatusFail},
	}

	assert.True(t, isInterceptionActive(results))
}

func TestShimInPathImpliesInterception(t *testing.T) {
	results := []doctor.CheckResult{
		{
			Name:                checkShimInPath,
			Status:              doctor.StatusPass,
			Message:             "Package managers resolve to System shim directory",
			ImpliesInterception: true,
		},
	}

	assert.True(t, isInterceptionActive(results))
}

func TestClassifyPackageManagerResolutions(t *testing.T) {
	shimDir := "/usr/local/lib/pmg/bin"
	lookPath := func(name string) (string, error) {
		switch name {
		case "npm":
			return shimDir + "/npm", nil
		case "pip":
			return "/usr/bin/pip", nil
		case "uv":
			return "", exec.ErrNotFound
		default:
			return "", exec.ErrNotFound
		}
	}

	under, shadowed := classifyPackageManagerResolutions(
		[]string{"npm", "pip", "uv"},
		shimDir,
		lookPath,
	)
	assert.Equal(t, []string{"npm"}, under)
	assert.Equal(t, []string{"pip"}, shadowed)
}
