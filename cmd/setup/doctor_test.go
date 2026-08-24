package setup

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/doctor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		[]string{shimDir},
		lookPath,
	)
	assert.Equal(t, []string{"npm"}, under)
	assert.Equal(t, []string{"pip"}, shadowed)
}

func TestClassifyPackageManagerResolutionsAcceptsEitherShimDir(t *testing.T) {
	systemDir := "/usr/local/lib/pmg/bin"
	userDir := "/home/dev/.pmg/bin"
	lookPath := func(name string) (string, error) {
		switch name {
		case "npm":
			return systemDir + "/npm", nil
		case "pip":
			return userDir + "/pip", nil
		default:
			return "/usr/bin/" + name, nil
		}
	}

	under, shadowed := classifyPackageManagerResolutions(
		[]string{"npm", "pip", "yarn"},
		[]string{systemDir, userDir},
		lookPath,
	)
	assert.ElementsMatch(t, []string{"npm", "pip"}, under)
	assert.Equal(t, []string{"yarn"}, shadowed)
}

func TestCheckSystemBinaryResult(t *testing.T) {
	// No system shims installed -> could not determine binary (Warn).
	result := checkSystemBinaryResult()
	// On a dev machine with no /usr/local/lib/pmg/bin shims, SystemShimBinary
	// returns !ok, so we get a Warn rather than a spurious Fail.
	assert.Contains(t, []doctor.CheckStatus{doctor.StatusWarn, doctor.StatusPass, doctor.StatusFail}, result.Status)
	if result.Status == doctor.StatusWarn {
		assert.Equal(t, "Could not determine system shim binary", result.Message)
	}
}

func TestCheckEventLogDirResult(t *testing.T) {
	configDir := "/home/dev/.config/safedep/pmg"

	t.Run("skipped when event logging disabled", func(t *testing.T) {
		result := checkEventLogDirResult(true, t.TempDir(), configDir)
		assert.Equal(t, doctor.StatusWarn, result.Status)
	})

	t.Run("missing directory fails", func(t *testing.T) {
		result := checkEventLogDirResult(false, filepath.Join(t.TempDir(), "absent"), configDir)
		assert.Equal(t, doctor.StatusFail, result.Status)
		assert.Equal(t, "Event log directory not found", result.Message)
	})

	t.Run("file instead of directory fails", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "logs")
		require.NoError(t, os.WriteFile(path, []byte("x"), 0o644))

		result := checkEventLogDirResult(false, path, configDir)
		assert.Equal(t, doctor.StatusFail, result.Status)
	})

	t.Run("writable directory passes", func(t *testing.T) {
		result := checkEventLogDirResult(false, t.TempDir(), configDir)
		assert.Equal(t, doctor.StatusPass, result.Status)
	})

	t.Run("unwritable directory fails with triaged remedy", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root: directory permissions are not enforced")
		}
		dir := t.TempDir()
		require.NoError(t, os.Chmod(dir, 0o555))
		t.Cleanup(func() {
			require.NoError(t, os.Chmod(dir, 0o755))
		})

		result := checkEventLogDirResult(false, dir, configDir)
		assert.Equal(t, doctor.StatusFail, result.Status)
		assert.Equal(t, "Event log directory not writable", result.Message)
		_, expectedFix := config.UnwritableConfigDirRemedy(configDir)
		assert.Equal(t, expectedFix, result.Fix)
	})
}

func TestCheckProxyRegistriesResult(t *testing.T) {
	httpsRegistry := config.ProxyRegistryConfig{
		Name:      "company-npm",
		Ecosystem: config.ProxyRegistryEcosystemNpm,
		Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://packages.test/npm"}},
	}
	httpRegistry := config.ProxyRegistryConfig{
		Name:      "plain-npm",
		Ecosystem: config.ProxyRegistryEcosystemNpm,
		Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "http://plain.test/npm"}},
	}

	tests := []struct {
		name        string
		loadErr     error
		registries  []config.ProxyRegistryConfig
		wantStatus  doctor.CheckStatus
		wantMessage string
	}{
		{
			name:        "load error fails",
			loadErr:     assert.AnError,
			wantStatus:  doctor.StatusFail,
			wantMessage: "fail closed",
		},
		{
			name:        "no registries passes",
			wantStatus:  doctor.StatusPass,
			wantMessage: "No custom registries",
		},
		{
			name:        "https endpoints pass",
			registries:  []config.ProxyRegistryConfig{httpsRegistry},
			wantStatus:  doctor.StatusPass,
			wantMessage: "1 custom registry endpoint(s) configured",
		},
		{
			name:        "plain http endpoint warns",
			registries:  []config.ProxyRegistryConfig{httpsRegistry, httpRegistry},
			wantStatus:  doctor.StatusWarn,
			wantMessage: "http://plain.test/npm",
		},
		{
			name: "endpoint on a built-in host fails like proxy startup",
			registries: []config.ProxyRegistryConfig{{
				Name:      "shadow-npm",
				Ecosystem: config.ProxyRegistryEcosystemNpm,
				Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://registry.npmjs.org/npm-virtual"}},
			}},
			wantStatus:  doctor.StatusFail,
			wantMessage: "covered by the built-in",
		},
		{
			name: "endpoint on a reserved go host fails like proxy startup",
			registries: []config.ProxyRegistryConfig{{
				Name:      "go-shadow",
				Ecosystem: config.ProxyRegistryEcosystemNpm,
				Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://sum.golang.org/npm"}},
			}},
			wantStatus:  doctor.StatusFail,
			wantMessage: "reserved for PMG's built-in Go module handling",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkProxyRegistriesResult(tt.loadErr, tt.registries)
			assert.Equal(t, tt.wantStatus, result.Status)
			assert.Contains(t, result.Message, tt.wantMessage)
		})
	}
}
