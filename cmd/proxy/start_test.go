package proxy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
				Network: proxyserver.NetworkOverrides{
					Allow: []string{"registry.npmjs.org:443"},
					Deny:  []string{"*:*"},
				},
			})
		},
	}
	addEnforceFlags(start, &config.Get().Config.Proxy.Server.Enforce)
	addNetworkFlags(start, &config.Get().Config.Proxy.Server)
	proxyCmd := &cobra.Command{Use: "proxy"}
	proxyCmd.AddCommand(start)
	root.AddCommand(proxyCmd)
	root.SetArgs([]string{
		"--paranoid",
		"--skip-dependency-cooldown",
		"proxy", "start", "--enforce-deny-udp=false", "--enforce-cgroup", "/sys/fs/cgroup/ci.slice", "--enforce-namespaces", "redirect",
		"--profile", "ci.yml", "--network-mode", "enforce",
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
		"--profile", "ci.yml",
		"--network-mode", "enforce",
		"--network-allow", "registry.npmjs.org:443",
		"--network-deny", "*:*",
	}, got)
}

func TestWideningNetworkFlagsUnderLockdown(t *testing.T) {
	parse := func(t *testing.T, fileMode string, args ...string) (*pflag.FlagSet, config.ProxyServerConfig) {
		t.Helper()
		srv := config.ProxyServerConfig{Profile: "npm-restrictive", NetworkMode: fileMode}
		cmd := &cobra.Command{Use: "start"}
		addNetworkFlags(cmd, &srv)
		require.NoError(t, cmd.Flags().Parse(args))
		return cmd.Flags(), srv
	}

	fs, srv := parse(t, "enforce", "--network-deny", "evil.example:443", "--network-mode", "enforce", "--profile", "ci.yml")
	assert.Empty(t, wideningNetworkFlags(fs, srv), "a deny rule, the file's mode and another profile narrow or are checked later")
	assert.Equal(t, "npm-restrictive", lockedProfile(fs), "the daemon checks the named profile against the file's")

	fs, srv = parse(t, "audit", "--network-mode", "enforce")
	assert.Empty(t, wideningNetworkFlags(fs, srv), "enforce over audit narrows")

	fs, srv = parse(t, "enforce", "--network-allow", "pastebin.com:443", "--network-mode", "audit")
	assert.Equal(t, []string{"--network-allow", "--network-mode=audit"}, wideningNetworkFlags(fs, srv))

	fs, srv = parse(t, "enforce", "--profile=", "--network-mode=")
	assert.Equal(t, []string{"--network-mode=", "--profile="}, wideningNetworkFlags(fs, srv), "an empty value unsets the file's profile and mode")
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

func TestAbsoluteProfileFlag(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ci.yml"), []byte("name: ci\n"), 0o600))
	cwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { require.NoError(t, os.Chdir(cwd)) })
	// The temp dir can be a symbolic link, as on macOS. Abs resolves it.
	dir, err = os.Getwd()
	require.NoError(t, err)

	parse := func(t *testing.T, args ...string) (*pflag.FlagSet, *config.ProxyServerConfig) {
		t.Helper()
		srv := &config.ProxyServerConfig{Profile: "profiles/ci.yml"}
		cmd := &cobra.Command{Use: "start"}
		addNetworkFlags(cmd, srv)
		require.NoError(t, cmd.Flags().Parse(args))
		absoluteProfileFlag(cmd.Flags(), srv)
		return cmd.Flags(), srv
	}

	_, srv := parse(t, "--profile", "ci.yml")
	assert.Equal(t, filepath.Join(dir, "ci.yml"), srv.Profile, "a file in the working directory is named by its absolute path")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "npm-restrictive"), []byte("name: open\n"), 0o600))
	_, srv = parse(t, "--profile", "npm-restrictive")
	assert.Equal(t, "npm-restrictive", srv.Profile, "a name stays a name, whatever file the working directory holds")

	_, srv = parse(t, "--profile", "missing/ci.yml")
	assert.Equal(t, filepath.Join(dir, "missing", "ci.yml"), srv.Profile, "a path that does not exist still names the working directory, never the config directory")

	_, srv = parse(t)
	assert.Equal(t, "profiles/ci.yml", srv.Profile, "the config value resolves next to the config file, not here")
}
