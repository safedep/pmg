package config

import (
	"errors"
	"testing"

	"github.com/safedep/dry/usefulerror"
	appConfig "github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func asSudo(t *testing.T) {
	t.Helper()
	orig := platform.IsPrivileged
	platform.IsPrivileged = func() bool { return true }
	t.Cleanup(func() { platform.IsPrivileged = orig })
	t.Setenv("SUDO_USER", "alice")
}

func requirePermissionDenied(t *testing.T, err error) usefulerror.UsefulError {
	t.Helper()
	require.Error(t, err)
	var ue usefulerror.UsefulError
	require.True(t, errors.As(err, &ue), "%v", err)
	assert.Equal(t, errcodes.PermissionDenied, ue.Code())
	return ue
}

func TestSetUnderSudoWithoutSystemRefuses(t *testing.T) {
	asSudo(t)
	ue := requirePermissionDenied(t, setValue("paranoid", "true", false))
	assert.Contains(t, ue.HumanError(), "`pmg config set` would change root's per-user config")
	assert.Contains(t, ue.Help(), "--system")
}

func TestEditUnderSudoWithoutSystemRefuses(t *testing.T) {
	asSudo(t)
	_, err := editPath(false)
	ue := requirePermissionDenied(t, err)
	assert.Contains(t, ue.HumanError(), "`pmg config edit` would change root's per-user config")
	assert.Contains(t, ue.Help(), "without sudo for your own")
}

func TestSystemScopeNeedsRoot(t *testing.T) {
	orig := platform.IsPrivileged
	platform.IsPrivileged = func() bool { return false }
	t.Cleanup(func() { platform.IsPrivileged = orig })

	_, err := editPath(true)
	_ = requirePermissionDenied(t, err)
	_ = requirePermissionDenied(t, setValue("paranoid", "true", true))
}

func TestConfigPathTextExplainsTheUserFile(t *testing.T) {
	t.Setenv("PMG_CONFIG_DIR", t.TempDir())
	appConfig.Reload()
	cfg := appConfig.Get()

	out := configPathText(cfg, "/root/.config/safedep/pmg/config.yml", "/etc/safedep/pmg/config.yml")
	assert.Contains(t, out, cfg.ConfigFilePath()+" (PMG_CONFIG_DIR)")
	assert.NotContains(t, out, "ignored by a root daemon", "only a plain user file gets the hint")
}
