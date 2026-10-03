package proxyserver

import (
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/netenforce"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func enforceConfig(mutate func(*config.ProxyEnforceConfig)) *config.RuntimeConfig {
	rc := config.DefaultConfig()
	mutate(&rc.Config.Proxy.Server.Enforce)
	return &rc
}

func TestEnforcePolicyFromConfig(t *testing.T) {
	cfg := enforceConfig(func(ec *config.ProxyEnforceConfig) {
		ec.Ports = []int{443, 80}
		ec.EligibleUsers = []string{"1000"}
		ec.ExemptUsers = []string{"0"}
		ec.ExemptExecutables = []string{"/opt/agent/bin/agent"}
		ec.SkipDestinations = []string{"10.20.0.0/16"}
		ec.Cgroup = "/sys/fs/cgroup/system.slice"
		ec.DenyUDP = false
	})
	cfg.Config.Proxy.Registries = []config.ProxyRegistryConfig{{
		Name: "corp", Ecosystem: "npm",
		Endpoints: []config.ProxyRegistryEndpointConfig{
			{URL: "https://packages.example.com:8443/npm"},
			{URL: "https://registry.example.com/npm"},
			{URL: "http://mirror.example.com/npm"},
		},
	}}

	p, err := enforcePolicy(cfg, EnforceOverrides{
		Ports:             []int{9443},
		EligibleUsers:     []string{"1001"},
		ExemptUsers:       []string{"65534"},
		ExemptExecutables: []string{"/home/runner/actions-runner/bin/Runner.*"},
		SkipDestinations:  []string{"10.30.0.0/16"},
	})
	require.NoError(t, err)
	assert.Equal(t, []uint16{80, 443, 8443, 9443}, p.Ports, "registry and flag ports are added and the list is sorted and unique")
	assert.Equal(t, []string{"1000", "1001"}, p.EligibleUsers, "a flag adds to the file")
	assert.Equal(t, []string{"0", "65534"}, p.ExemptUsers)
	assert.Equal(t, []string{"/opt/agent/bin/agent", "/home/runner/actions-runner/bin/Runner.*"}, p.ExemptExecutables)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("10.30.0.0/16")}, p.SkipDestinations)
	assert.Equal(t, "/sys/fs/cgroup/system.slice", p.CgroupPath)
	assert.False(t, p.DenyUDP)
}

func TestEnforcePolicyRejectsBadInput(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*config.ProxyEnforceConfig)
		wantErr string
	}{
		{"port out of range", func(ec *config.ProxyEnforceConfig) { ec.Ports = []int{70000} }, "not a valid port"},
		{"bad prefix", func(ec *config.ProxyEnforceConfig) { ec.SkipDestinations = []string{"10.20.0.0"} }, "not a CIDR prefix"},
		{"unknown user", func(ec *config.ProxyEnforceConfig) { ec.ExemptUsers = []string{"pmg-no-such-user-0b1"} }, "pmg-no-such-user-0b1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := enforcePolicy(enforceConfig(tc.mutate), EnforceOverrides{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestEndpointPort(t *testing.T) {
	cases := map[string]uint16{
		"https://packages.example.com/npm":      443,
		"http://packages.example.com/npm":       80,
		"https://packages.example.com:8443/npm": 8443,
	}
	for raw, want := range cases {
		got, err := endpointPort(raw)
		require.NoError(t, err, raw)
		assert.Equal(t, want, got, raw)
	}
}

func TestEnvVarsInEnforceModeAreTrustOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-state.json")
	require.NoError(t, writeState(path, State{
		PID: 1, Addr: "127.0.0.1:7777", CACertPath: "/etc/safedep/pmg/ca-cert.pem",
		Enforce: &EnforceState{Status: netenforce.Status{Ports: []uint16{80, 443}}},
	}))

	vars, err := EnvVars(path)
	require.NoError(t, err)
	assert.Contains(t, vars, "NODE_USE_SYSTEM_CA=1")
	assert.Contains(t, vars, "UV_NATIVE_TLS=1")
	for _, v := range vars {
		assert.NotContains(t, v, "PROXY", "no proxy variable in enforce mode")
		assert.NotContains(t, v, "NODE_EXTRA_CA_CERTS", "trust comes from the system store")
	}
}

func TestStateRoundTripsEnforceBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-state.json")
	in := State{PID: 7, Addr: "127.0.0.1:7777", Enforce: &EnforceState{
		Status: netenforce.Status{
			CgroupPath:        "/sys/fs/cgroup",
			Ports:             []uint16{80, 443},
			NetnsCookie:       42,
			ExemptExecutables: []netenforce.ExemptedFile{{Path: "/opt/Runner.Worker", Dev: 1, Inode: 2}},
			SkipDestinations:  []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
			DenyUDP:           true,
			KernelVersion:     "6.8.0",
		},
		Addr6:    "[::1]:7777",
		Warnings: []string{"Docker is running."},
	}}
	require.NoError(t, writeState(path, in))

	out, err := readState(path)
	require.NoError(t, err)
	assert.Equal(t, in.Enforce, out.Enforce)
}

func TestStartupMessage(t *testing.T) {
	plain := startupMessage(State{Addr: "127.0.0.1:7777"})
	assert.Contains(t, plain, "pmg proxy env")
	assert.NotContains(t, plain, "enforcement")
	assert.NotContains(t, plain, "config:", "an older state file has no path")

	sourced := startupMessage(State{Addr: "127.0.0.1:7777", ConfigPath: "/etc/safedep/pmg/config.yml", ConfigSource: "managed"})
	assert.Contains(t, sourced, "config: /etc/safedep/pmg/config.yml (managed)")

	enforced := startupMessage(State{Addr: "127.0.0.1:7777", Enforce: &EnforceState{
		Status:   netenforce.Status{CgroupPath: "/sys/fs/cgroup", Ports: []uint16{80, 443}},
		Warnings: []string{"Docker is running."},
	}})
	assert.Contains(t, enforced, "kernel enforcement (cgroup /sys/fs/cgroup, ports 80,443)")
	assert.Contains(t, enforced, "Docker is running.")
}

func TestRootPerUserConfigWarningNamesBothFiles(t *testing.T) {
	w := rootPerUserConfigWarning("/root/.config/safedep/pmg/config.yml")
	assert.Contains(t, w, "/root/.config/safedep/pmg/config.yml")
	if system := config.SystemConfigFilePath(); system != "" {
		assert.Contains(t, w, system)
		assert.Contains(t, w, "pmg config edit --system")
	}
}

func TestDestinationResolverBeforeAttach(t *testing.T) {
	var r destinationResolver
	_, ok := r.OriginalDestination(netip.MustParseAddrPort("127.0.0.1:40000"))
	assert.False(t, ok)
}
