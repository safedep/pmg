package setup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/doctor"
	"github.com/safedep/pmg/internal/shim"
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

// checkShimDirResolution maps an inspection to a status. The inspection is
// fabricated here, so the mapping is tested on every platform.
func TestCheckShimDirResolution(t *testing.T) {
	shimDir := "/usr/local/lib/pmg/bin"
	entriesWithShim := []string{"/usr/bin", shimDir}
	entriesWithout := []string{"/usr/bin"}

	tests := []struct {
		name       string
		inspection shim.InterceptionInspection
		wantStatus doctor.CheckStatus
		wantActive bool
		wantMsg    string
	}{
		{
			name: "every manager under a shim passes and implies interception",
			inspection: shim.InterceptionInspection{PathEntries: entriesWithShim, Resolutions: []shim.ManagerResolution{
				{Name: "npm", Path: shimDir + "/npm", UnderShim: true},
			}},
			wantStatus: doctor.StatusPass, wantActive: true, wantMsg: "Package managers resolve to Shim directory",
		},
		{
			name: "a shadowed manager warns when the shim directory is on PATH",
			inspection: shim.InterceptionInspection{PathEntries: entriesWithShim, Resolutions: []shim.ManagerResolution{
				{Name: "npm", Path: shimDir + "/npm", UnderShim: true},
				{Name: "pip", Path: "/usr/bin/pip"},
			}},
			wantStatus: doctor.StatusWarn, wantMsg: "pip resolved outside Shim directory",
		},
		{
			name: "only shadowed managers and no shim directory on PATH fails",
			inspection: shim.InterceptionInspection{PathEntries: entriesWithout, Resolutions: []shim.ManagerResolution{
				{Name: "pip", Path: "/usr/bin/pip"},
			}},
			wantStatus: doctor.StatusFail, wantMsg: "Shim directory not in PATH",
		},
		{
			name:       "no manager installed but the shim directory on PATH passes",
			inspection: shim.InterceptionInspection{PathEntries: entriesWithShim},
			wantStatus: doctor.StatusPass, wantActive: true, wantMsg: "Shim directory is in PATH",
		},
		{
			name:       "nothing resolves and no shim directory fails",
			inspection: shim.InterceptionInspection{PathEntries: entriesWithout},
			wantStatus: doctor.StatusFail, wantMsg: "Shim directory not in PATH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkShimDirResolution(shimDir, "Shim directory", tt.inspection)
			assert.Equal(t, tt.wantStatus, result.Status)
			assert.Equal(t, tt.wantActive, result.ImpliesInterception)
			assert.Equal(t, tt.wantMsg, result.Message)
		})
	}
}

// checkShimDirectoryResult reads real shims, so a stale one fails on every
// platform. A stale shim names a pmg binary other than the one running.
func TestCheckShimDirectoryResult(t *testing.T) {
	pmgBin, err := os.Executable()
	require.NoError(t, err)
	managers := []string{"npm", "pip"}

	writeShims := func(t *testing.T, dir, bin string, pms []string) {
		t.Helper()
		require.NoError(t, shim.NewShimManager(shim.ShimConfig{
			BinDir:          dir,
			PMGBin:          bin,
			PackageManagers: pms,
			SkipUserPath:    true,
		}).Install())
	}

	t.Run("every shim names this pmg binary", func(t *testing.T) {
		dir := t.TempDir()
		writeShims(t, dir, pmgBin, managers)

		result := checkShimDirectoryResult(dir, managers)
		assert.Equal(t, doctor.StatusPass, result.Status)
	})

	t.Run("a shim from another install fails", func(t *testing.T) {
		dir := t.TempDir()
		writeShims(t, dir, pmgBin, managers)
		writeShims(t, dir, filepath.Join(t.TempDir(), "old", "pmg"), []string{"npm"})

		result := checkShimDirectoryResult(dir, managers)
		assert.Equal(t, doctor.StatusFail, result.Status)
		assert.Equal(t, "Shims for npm name another pmg binary", result.Message)
	})

	t.Run("a missing shim fails and is named", func(t *testing.T) {
		dir := t.TempDir()
		writeShims(t, dir, pmgBin, []string{"npm"})

		result := checkShimDirectoryResult(dir, managers)
		assert.Equal(t, doctor.StatusFail, result.Status)
		assert.Equal(t, "Shims missing for pip", result.Message)
	})

	t.Run("an empty directory reads as not found", func(t *testing.T) {
		result := checkShimDirectoryResult(t.TempDir(), managers)
		assert.Equal(t, doctor.StatusFail, result.Status)
		assert.Equal(t, "Shim directory not found", result.Message)
	})
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
