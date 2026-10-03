package proxy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartDaemonRejectsConfigLoadErrorBeforeLaunch(t *testing.T) {
	configDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "config.yml"), []byte(`
proxy:
  registries:
    - name: company-npm
      ecosystem: maven
      endpoints:
        - url: https://packages.example.test/npm
`), 0o644))
	t.Cleanup(config.Reload)
	t.Setenv("PMG_CONFIG_DIR", configDir)
	config.Reload()
	require.Error(t, config.LoadError())

	notDirectory := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(notDirectory, []byte("x"), 0o600))
	originalLogFileFlag := logFileFlag
	logFileFlag = filepath.Join(notDirectory, "proxy.log")
	t.Cleanup(func() { logFileFlag = originalLogFileFlag })

	err := startDaemon(&cobra.Command{}, config.Get(), proxyserver.RunOptions{StatePath: filepath.Join(configDir, "state.json"), Host: "127.0.0.1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid proxy registries")
}

func TestDaemonArgsPrependsChangedConfigFlags(t *testing.T) {
	root := &cobra.Command{Use: "pmg"}
	config.ApplyCobraFlags(root)

	var got []string
	start := &cobra.Command{
		Use: "start",
		Run: func(cmd *cobra.Command, _ []string) {
			got = daemonArgs(cmd, proxyserver.RunOptions{
				StatePath:         "/tmp/proxy-state.json",
				Host:              "127.0.0.1",
				Port:              9000,
				Enforce:           true,
				ExemptExecutables: []string{"/opt/runner/Runner.*"},
			})
		},
	}
	proxyCmd := &cobra.Command{Use: "proxy"}
	proxyCmd.AddCommand(start)
	root.AddCommand(proxyCmd)
	root.SetArgs([]string{
		"--paranoid",
		"--skip-dependency-cooldown",
		"proxy", "start",
	})

	require.NoError(t, root.Execute())
	assert.Equal(t, []string{
		"--paranoid=true",
		"--skip-dependency-cooldown=true",
		"proxy", "start", "--foreground-internal",
		"--state", "/tmp/proxy-state.json",
		"--host", "127.0.0.1",
		"--port", "9000",
		"--enforce=true",
		"--enforce-exempt-executable", "/opt/runner/Runner.*",
	}, got)
}
