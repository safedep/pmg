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
			// A shadowed manager is worth a warning, and it must still imply
			// interception: npm here runs through the shim, and the
			// protection checks report a failure when nothing implies it.
			name: "a shadowed manager warns and still implies interception",
			inspection: shim.InterceptionInspection{PathEntries: entriesWithShim, Resolutions: []shim.ManagerResolution{
				{Name: "npm", Path: shimDir + "/npm", UnderShim: true},
				{Name: "pip", Path: "/usr/bin/pip"},
			}},
			wantStatus: doctor.StatusWarn, wantActive: true, wantMsg: "pip resolved outside Shim directory",
		},
		{
			// Every manager shadowed, but the shim directory is registered,
			// so a manager installed later is intercepted. The branch below
			// treats that as interception when no manager resolves at all,
			// so it does here too.
			name: "every manager shadowed warns and implies interception when the directory is on PATH",
			inspection: shim.InterceptionInspection{PathEntries: entriesWithShim, Resolutions: []shim.ManagerResolution{
				{Name: "npm", Path: "/usr/bin/npm"},
			}},
			wantStatus: doctor.StatusWarn, wantActive: true, wantMsg: "npm resolved outside Shim directory",
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

// checkShimDirectoryResult reads real shims, so it catches a shim that names
// a pmg binary other than the one running. A binary that is gone breaks the
// command and fails. One that still runs intercepts through it and warns.
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

	t.Run("a shim naming another binary that runs warns", func(t *testing.T) {
		dir := t.TempDir()
		writeShims(t, dir, pmgBin, managers)

		other := filepath.Join(t.TempDir(), "pmg")
		require.NoError(t, os.WriteFile(other, []byte("#!/bin/sh\n"), 0o755))
		writeShims(t, dir, other, []string{"npm"})

		result := checkShimDirectoryResult(dir, managers)
		assert.Equal(t, doctor.StatusWarn, result.Status, "that shim still intercepts, through the other binary")
		assert.Equal(t, "Shims for npm name another pmg binary", result.Message)
		assert.NotEmpty(t, result.Fix)
	})

	t.Run("a shim naming a binary that is gone fails", func(t *testing.T) {
		dir := t.TempDir()
		writeShims(t, dir, pmgBin, managers)
		writeShims(t, dir, filepath.Join(t.TempDir(), "removed", "pmg"), []string{"npm"})

		result := checkShimDirectoryResult(dir, managers)
		assert.Equal(t, doctor.StatusFail, result.Status)
		assert.Equal(t, "Shims missing or broken for npm", result.Message)
	})

	t.Run("a missing shim and a broken one report together", func(t *testing.T) {
		dir := t.TempDir()
		writeShims(t, dir, filepath.Join(t.TempDir(), "removed", "pmg"), []string{"npm"})

		result := checkShimDirectoryResult(dir, managers)
		assert.Equal(t, doctor.StatusFail, result.Status)
		assert.Equal(t, "Shims missing or broken for pip, npm", result.Message)
	})

	t.Run("an empty directory reads as no shims", func(t *testing.T) {
		result := checkShimDirectoryResult(t.TempDir(), managers)
		assert.Equal(t, doctor.StatusFail, result.Status)
		assert.Equal(t, "No shims found", result.Message)
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

// The Windows branches of the sandbox check. The OS has no sandbox, so a
// disabled sandbox passes with nothing to fix, and only a config that asks
// for one fails. The supported-OS branches are the ones the live check
// always ran.
func TestEvaluateSandboxCheckWithoutASandbox(t *testing.T) {
	got := evaluateSandboxCheck(nil, false, false)
	assert.Equal(t, doctor.StatusPass, got.Status)
	assert.Empty(t, got.Fix)

	got = evaluateSandboxCheck(nil, false, true)
	assert.Equal(t, doctor.StatusFail, got.Status)
	assert.Equal(t, "Set sandbox.enabled: false in config", got.Fix)
}
