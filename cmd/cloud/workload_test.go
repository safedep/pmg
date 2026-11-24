package cloud

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/cloudauth"
	"github.com/safedep/pmg/internal/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialWriteHelp(t *testing.T) {
	expiresAt := time.Date(2026, 11, 23, 18, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "revoked",
			err:  &cloudauth.CredentialWriteError{Err: errors.New("disk full"), ExpiresAt: expiresAt},
			want: "pmg revoked the credential. Check the --output path",
		},
		{
			name: "not revoked",
			err:  &cloudauth.CredentialWriteError{Err: errors.New("disk full"), RevokeErr: errors.New("down"), ExpiresAt: expiresAt},
			want: "pmg could not revoke the credential. It stays valid until 2026-11-23T18:00:00Z. Check the --output path",
		},
		{
			name: "not revoked with no expiry",
			err:  &cloudauth.CredentialWriteError{Err: errors.New("disk full"), RevokeErr: errors.New("down")},
			want: "pmg could not revoke the credential. It stays valid until it expires. Check the --output path",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, credentialWriteHelp(tc.err))
		})
	}
}

// exchangeHelperDirEnv names the directory where TestWorkloadExchangeHelper
// writes its marks.
const exchangeHelperDirEnv = "PMG_TEST_EXCHANGE_HELPER_DIR"

// The exchange runs with the ID token request token in its environment. A
// detached sync child must not inherit it, also after an audit event. The
// failed exchange exits through ui, so the test runs it in a child process.
func TestWorkloadExchangeStartsNoBackgroundSync(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestWorkloadExchangeHelper$")
	cmd.Env = append(os.Environ(),
		exchangeHelperDirEnv+"="+dir,
		"PMG_CONFIG_DIR="+dir,
		"PMG_STATE_DIR="+dir,
		"ACTIONS_ID_TOKEN_REQUEST_URL=",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN=")
	out, err := cmd.CombinedOutput()

	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, string(out))
	assert.FileExists(t, filepath.Join(dir, "exit-hook"))
	assert.NoFileExists(t, filepath.Join(dir, "spawn"))
}

// TestWorkloadExchangeHelper is the child of
// TestWorkloadExchangeStartsNoBackgroundSync. It does nothing in a normal test
// run.
func TestWorkloadExchangeHelper(t *testing.T) {
	dir := os.Getenv(exchangeHelperDirEnv)
	if dir == "" {
		return
	}

	config.Reload()
	cfg := config.Get()
	cfg.Config.Cloud.Enabled = true
	cfg.Config.Cloud.AutoSync.Enabled = true
	cfg.Config.Cloud.AutoSync.MinInterval = time.Minute

	audit.UseSinksForTest()
	audit.UseSpawnerForTest(func(string, ...string) error {
		return os.WriteFile(filepath.Join(dir, "spawn"), nil, 0o600)
	})
	ui.SetExitHook(func() {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "exit-hook"), nil, 0o600))
		audit.MaybeSpawnBackgroundSync(cfg)
	})
	audit.LogInstallStarted("npm", []string{"install"})

	cmd := newWorkloadExchangeCommand()
	cmd.SetArgs([]string{"--tenant-id", "tenant", "--output", filepath.Join(dir, "credential")})
	err := cmd.Execute()
	require.Fail(t, "the exchange did not exit through ui", "error: %v", err)
}
