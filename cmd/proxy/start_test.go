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

	t.Cleanup(config.Reload)
	t.Setenv("PMG_CONFIG_DIR", t.TempDir())
	config.Reload()

	var got []string
	start := &cobra.Command{
		Use: "start",
		Run: func(cmd *cobra.Command, _ []string) {
			got = daemonArgs(cmd, proxyserver.RunOptions{
				StatePath: "/tmp/proxy-state.json",
				Host:      "127.0.0.1",
				Port:      9000,
				Enforce:   true,
				Overrides: proxyserver.EnforceOverrides{
					Ports:             []int{8443},
					ExemptExecutables: []string{"/opt/agent/bin/agent"},
				},
			})
		},
	}
	addEnforceFlags(start, &config.Get().Config.Proxy.Server.Enforce)
	proxyCmd := &cobra.Command{Use: "proxy"}
	proxyCmd.AddCommand(start)
	root.AddCommand(proxyCmd)
	root.SetArgs([]string{
		"--paranoid",
		"--skip-dependency-cooldown",
		"proxy", "start", "--enforce-deny-udp=false", "--enforce-cgroup", "/sys/fs/cgroup/ci.slice", "--enforce-namespaces", "redirect",
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
		"--enforce-port", "8443",
		"--enforce-exempt-executable", "/opt/agent/bin/agent",
		"--enforce-cgroup", "/sys/fs/cgroup/ci.slice",
		"--enforce-deny-udp=false",
		"--enforce-namespaces", "redirect",
	}, got)
}

func TestWideningFlagsUnderLockdown(t *testing.T) {
	changed := func(set ...string) func(string) bool {
		return func(name string) bool {
			for _, s := range set {
				if s == name {
					return true
				}
			}
			return false
		}
	}

	on := config.ProxyEnforceConfig{Enabled: true, DenyUDP: true, Namespaces: config.ProxyEnforceNamespacesConfig{Mode: "redirect"}}
	assert.Empty(t, wideningFlags(changed("enforce-port", "enforce-cgroup"), on), "a port or a cgroup only narrows the scope")
	assert.Empty(t, wideningFlags(changed("enforce", "enforce-deny-udp", "enforce-namespaces"), on), "turning enforcement, the UDP denial or the redirect on is not a widening")
	assert.Equal(t, []string{"--enforce=false", "--enforce-exempt-user", "--enforce-skip-destination", "--enforce-deny-udp=false", "--enforce-namespaces=auto"},
		wideningFlags(changed("enforce", "enforce-exempt-user", "enforce-skip-destination", "enforce-deny-udp", "enforce-namespaces"),
			config.ProxyEnforceConfig{Namespaces: config.ProxyEnforceNamespacesConfig{Mode: "auto"}}))
}
