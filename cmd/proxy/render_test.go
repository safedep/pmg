package proxy

import (
	"testing"

	"github.com/safedep/pmg/internal/netenforce"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/stretchr/testify/assert"
)

func TestStartupMessage(t *testing.T) {
	plain := startupMessage(proxyserver.State{Addr: "127.0.0.1:7777"})
	assert.Contains(t, plain, "pmg proxy env")
	assert.NotContains(t, plain, "enforcement")
	assert.Contains(t, plain, "Network policy: none.")
	assert.NotContains(t, plain, "config:", "an older state file has no path")

	policed := startupMessage(proxyserver.State{Addr: "127.0.0.1:7777", Network: &proxyserver.NetworkState{Chain: []string{"npm-restrictive"}, Mode: "audit"}})
	assert.Contains(t, policed, "Network policy: audit, profile npm-restrictive, enforce: off, policy advisory")

	noticed := startupMessage(proxyserver.State{Addr: "127.0.0.1:7777", Warnings: []string{"Go module downloads are not analyzed."}})
	assert.Contains(t, noticed, "Go module downloads are not analyzed.", "a daemon notice shows without enforcement")

	sourced := startupMessage(proxyserver.State{Addr: "127.0.0.1:7777", ConfigPath: "/etc/safedep/pmg/config.yml", ConfigSource: "managed"})
	assert.Contains(t, sourced, "config: /etc/safedep/pmg/config.yml (managed)")

	enforced := startupMessage(proxyserver.State{Addr: "127.0.0.1:7777", Enforce: &proxyserver.EnforceState{
		Status:   netenforce.Status{CgroupPath: "/sys/fs/cgroup", Ports: []uint16{80, 443}},
		Warnings: []string{"Docker is running."},
	}, Warnings: []string{"Go module downloads are not analyzed."}})
	assert.Contains(t, enforced, "kernel enforcement (cgroup /sys/fs/cgroup, ports 80,443)")
	assert.Contains(t, enforced, "Network policy: none.")
	assert.Contains(t, enforced, "Docker is running.")
	assert.Contains(t, enforced, "Go module downloads are not analyzed.")
}

func TestNetworkPolicyLine(t *testing.T) {
	assert.Equal(t, "Network policy: none. No profile is set, so every destination is allowed.\n", networkPolicyLine(nil, false))

	chained := &proxyserver.NetworkState{Chain: []string{"npm-restrictive", "/srv/ci.yml"}, Mode: "enforce"}
	assert.Equal(t, "Network policy: enforce, profile npm-restrictive < /srv/ci.yml, enforce: off, policy advisory\n", networkPolicyLine(chained, false))
	assert.Equal(t, "Network policy: enforce, profile npm-restrictive < /srv/ci.yml\n", networkPolicyLine(chained, true))
	assert.Equal(t, "Network policy: audit, profile flags\n", networkPolicyLine(&proxyserver.NetworkState{Mode: "audit"}, true))
}

func TestNamespaceStatusLine(t *testing.T) {
	tests := []struct {
		name string
		ns   *proxyserver.NamespaceState
		want string
	}{
		{name: "older state file", ns: nil, want: ""},
		{name: "ignore", ns: &proxyserver.NamespaceState{Mode: "ignore", Effective: "ignore"}, want: "namespaces: ignore"},
		{name: "auto fell back", ns: &proxyserver.NamespaceState{Mode: "auto", Effective: "ignore", Reason: "nf_tables is not available"}, want: "namespaces: ignore (auto: nf_tables is not available)"},
		{
			name: "redirect",
			ns: &proxyserver.NamespaceState{Mode: "redirect", Effective: "redirect", Table: &netenforce.NamespaceStatus{
				Address: "169.254.200.1", Port: 7777, Ingress: []string{"docker0", "br-*"},
			}},
			want: "namespaces: redirect (169.254.200.1:7777 from docker0, br-*)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, namespaceStatusLine(tc.ns))
		})
	}
}
