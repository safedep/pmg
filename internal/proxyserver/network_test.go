package proxyserver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy/netpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeProfile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}

func networkConfig(profile, mode string) *config.RuntimeConfig {
	rc := config.DefaultConfig()
	rc.Config.Proxy.Server.Profile = profile
	rc.Config.Proxy.Server.NetworkMode = mode
	return &rc
}

func TestResolveNetworkPolicy(t *testing.T) {
	dir := t.TempDir()
	child := writeProfile(t, dir, "ci.yml", `
name: ci
inherits: npm-restrictive
network:
  deny_outbound:
    - npm.pkg.github.com:443
`)
	noPM := writeProfile(t, dir, "net-only.yml", `
name: net-only
package_managers: [npm]
network:
  allow_outbound:
    - registry.npmjs.org:443
  deny_outbound:
    - "*:*"
`)

	tests := []struct {
		name      string
		cfg       *config.RuntimeConfig
		overrides NetworkOverrides
		allowed   []string
		denied    []string
		chain     []string
		mode      string
		warns     bool
		noPolicy  bool
		wantErr   string
	}{
		{
			name:     "no profile and no flag rule is no policy",
			cfg:      networkConfig("", ""),
			noPolicy: true,
		},
		{
			name:    "a built-in profile allows its registry and denies the rest",
			cfg:     networkConfig("npm-restrictive", ""),
			allowed: []string{"registry.npmjs.org:443"},
			denied:  []string{"evil.example:443"},
			chain:   []string{"npm-restrictive"},
			mode:    config.SandboxNetworkModeAudit,
			warns:   true,
		},
		{
			name:    "a child profile inherits the rules and adds a deny",
			cfg:     networkConfig(child, config.SandboxNetworkModeEnforce),
			allowed: []string{"registry.npmjs.org:443"},
			denied:  []string{"npm.pkg.github.com:443", "evil.example:443"},
			chain:   []string{"npm-restrictive", child},
			mode:    config.SandboxNetworkModeEnforce,
			warns:   true,
		},
		{
			name:      "a flag allow adds a rule and removes the equal deny",
			cfg:       networkConfig(child, ""),
			overrides: NetworkOverrides{Allow: []string{"npm.pkg.github.com:443"}},
			allowed:   []string{"npm.pkg.github.com:443"},
			denied:    []string{"evil.example:443"},
			warns:     true,
		},
		{
			name:      "a flag deny adds a rule",
			cfg:       networkConfig(noPM, ""),
			overrides: NetworkOverrides{Deny: []string{"registry.npmjs.org:443"}},
			denied:    []string{"registry.npmjs.org:443"},
			chain:     []string{noPM},
		},
		{
			name:      "flag rules alone are a policy",
			cfg:       networkConfig("", ""),
			overrides: NetworkOverrides{Deny: []string{"*:*"}, Allow: []string{"registry.npmjs.org:443"}},
			allowed:   []string{"registry.npmjs.org:443"},
			denied:    []string{"evil.example:443"},
		},
		{
			name:    "a profile with only network rules does not warn",
			cfg:     networkConfig(noPM, ""),
			allowed: []string{"registry.npmjs.org:443"},
			denied:  []string{"evil.example:443"},
			chain:   []string{noPM},
		},
		{
			name:      "a flag rule that does not parse names the flag",
			cfg:       networkConfig("", ""),
			overrides: NetworkOverrides{Allow: []string{"curl=evil.example:443"}},
			wantErr:   "--network-allow",
		},
		{
			name:    "a missing profile names the reference",
			cfg:     networkConfig("no-such-profile", ""),
			wantErr: "no-such-profile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveNetworkPolicy(tt.cfg, tt.overrides)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			if tt.noPolicy {
				assert.Nil(t, got.policy)
				assert.Nil(t, got.state)
				return
			}

			require.NotNil(t, got.policy)
			for _, dest := range tt.allowed {
				assert.True(t, got.policy.Decide(hostOf(dest), 443).Allowed, dest)
			}
			for _, dest := range tt.denied {
				assert.False(t, got.policy.Decide(hostOf(dest), 443).Allowed, dest)
			}
			if tt.chain != nil {
				assert.Equal(t, tt.chain, got.state.Chain)
			}
			if tt.mode != "" {
				assert.Equal(t, tt.mode, got.state.Mode)
			}
			assert.Equal(t, tt.warns, len(got.warnings) > 0, "%v", got.warnings)
		})
	}
}

func hostOf(dest string) string {
	return dest[:len(dest)-len(":443")]
}

func TestResolveNetworkPolicyRelativePathFromConfigDir(t *testing.T) {
	configDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "profiles"), 0o755))
	writeProfile(t, filepath.Join(configDir, "profiles"), "ci.yml", "name: ci\ninherits: npm-restrictive\n")

	t.Setenv("PMG_CONFIG_DIR", configDir)
	t.Cleanup(config.Reload)
	config.Reload()
	cfg := config.Get()
	cfg.Config.Proxy.Server.Profile = "profiles/ci.yml"

	got, err := resolveNetworkPolicy(cfg, NetworkOverrides{})
	require.NoError(t, err)
	assert.Equal(t, []string{"npm-restrictive", filepath.Join(configDir, "profiles", "ci.yml")}, got.state.Chain)
}

func TestResolveNetworkPolicyUnderLockdown(t *testing.T) {
	dir := t.TempDir()
	narrower := writeProfile(t, dir, "narrower.yml", `
name: narrower
inherits: npm-restrictive
network:
  deny_outbound:
    - npm.pkg.github.com:443
`)
	wider := writeProfile(t, dir, "wider.yml", `
name: wider
inherits: npm-restrictive
network:
  allow_outbound:
    - pastebin.com:443
`)
	unrelated := writeProfile(t, dir, "unrelated.yml", `
name: unrelated
package_managers: [npm]
network:
  allow_outbound:
    - registry.npmjs.org:443
`)

	locked := NetworkOverrides{LockedProfile: "npm-restrictive"}

	got, err := resolveNetworkPolicy(networkConfig("npm-restrictive", ""), locked)
	require.NoError(t, err, "the locked profile itself loads")
	assert.Equal(t, []string{"npm-restrictive"}, got.state.Chain)

	_, err = resolveNetworkPolicy(networkConfig(narrower, ""), locked)
	assert.NoError(t, err, "a child that only adds a deny rule narrows")

	err = resolveNetworkPolicyErr(networkConfig(wider, ""), locked)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allows pastebin.com:443")
	assert.Contains(t, err.Error(), "globally managed profile npm-restrictive")

	err = resolveNetworkPolicyErr(networkConfig(unrelated, ""), locked)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "drops the deny rule *:*")

	err = resolveNetworkPolicyErr(networkConfig("", ""), locked)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be unset")
}

func resolveNetworkPolicyErr(cfg *config.RuntimeConfig, o NetworkOverrides) error {
	_, err := resolveNetworkPolicy(cfg, o)
	return err
}

// A locked config's profile must not resolve through a directory the user
// writes: the working directory or the user profile directory.
func TestResolveNetworkPolicyLoadsTheLockedProfileFromManagedLocations(t *testing.T) {
	open := "name: open\npackage_managers: [npm]\nnetwork:\n  allow_outbound: ['*:*']\n"

	// The config directory stands in for the managed one. The config file
	// path is what the loader resolves a relative reference against.
	configDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "profiles"), 0o755))
	writeProfile(t, filepath.Join(configDir, "profiles"), "ci.yml", "name: managed-ci\ninherits: npm-restrictive\n")
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "sandbox", "profiles"), 0o755))
	writeProfile(t, filepath.Join(configDir, "sandbox", "profiles"), "open.yml", open)

	workDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(workDir, "profiles"), 0o755))
	writeProfile(t, filepath.Join(workDir, "profiles"), "ci.yml", open)

	t.Setenv("PMG_CONFIG_DIR", configDir)
	t.Cleanup(config.Reload)
	config.Reload()
	cfg := config.Get()
	require.Equal(t, filepath.Join(configDir, "config.yml"), cfg.ConfigFilePath())

	cwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(workDir))
	t.Cleanup(func() { require.NoError(t, os.Chdir(cwd)) })

	cfg.Config.Proxy.Server.Profile = "profiles/ci.yml"
	got, err := resolveNetworkPolicy(cfg, NetworkOverrides{LockedProfile: "profiles/ci.yml"})
	require.NoError(t, err)
	assert.Equal(t, []string{"npm-restrictive", filepath.Join(configDir, "profiles", "ci.yml")}, got.state.Chain, "the file next to the config, not the one in the working directory")

	cfg.Config.Proxy.Server.Profile = filepath.Join(workDir, "profiles", "ci.yml")
	err = resolveNetworkPolicyErr(cfg, NetworkOverrides{LockedProfile: "profiles/ci.yml"})
	require.Error(t, err, "a --profile that drops the inherited deny rule widens")
	assert.Contains(t, err.Error(), "drops the deny rule *:*")

	cfg.Config.Proxy.Server.Profile = "open"
	err = resolveNetworkPolicyErr(cfg, NetworkOverrides{LockedProfile: "open"})
	require.Error(t, err, "a user profile name is not a managed location")
	assert.Contains(t, err.Error(), "not a built-in profile, a policy template or a path")
}

func TestNetworkPolicyLine(t *testing.T) {
	assert.Equal(t, "Network policy: none. No profile is set, so every destination is allowed.\n", NetworkPolicyLine(nil, false))

	chained := &NetworkState{Chain: []string{"npm-restrictive", "/srv/ci.yml"}, Mode: "enforce"}
	assert.Equal(t, "Network policy: enforce, profile npm-restrictive < /srv/ci.yml, enforce: off, policy advisory\n", NetworkPolicyLine(chained, false))
	assert.Equal(t, "Network policy: enforce, profile npm-restrictive < /srv/ci.yml\n", NetworkPolicyLine(chained, true))
	assert.Equal(t, "Network policy: audit, profile flags\n", NetworkPolicyLine(&NetworkState{Mode: "audit"}, true))
}

func TestNetworkStateDeniedCount(t *testing.T) {
	denials := []netpolicy.Denial{{Destination: "a:443", Count: 2}, {Destination: "b:443", Count: 1}}
	assert.Equal(t, 0, (*NetworkState)(nil).DeniedCount())
	assert.Equal(t, 0, (&NetworkState{Mode: "audit", Denials: denials}).DeniedCount(), "audit refuses nothing")
	assert.Equal(t, 3, (&NetworkState{Mode: "enforce", Denials: denials}).DeniedCount())
}

func TestStateRoundTripsNetworkBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-state.json")
	in := State{PID: 7, Addr: "127.0.0.1:7777", Network: &NetworkState{
		Chain:   []string{"npm-restrictive", "/srv/ci.yml"},
		Mode:    "enforce",
		Denials: []netpolicy.Denial{{Destination: "evil.example:443", Rule: "*:*", Client: "/usr/bin/curl", PID: 4132, Count: 2}},
	}}
	require.NoError(t, writeState(path, in))

	out, err := readState(path)
	require.NoError(t, err)
	assert.Equal(t, in.Network, out.Network)
	assert.Equal(t, in.Network, GetStatus(path).Network)
}
