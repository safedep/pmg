package proxy

import (
	"net/netip"
	"testing"

	"github.com/safedep/pmg/internal/netenforce"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStopExitError(t *testing.T) {
	t.Run("no flag, blocks present -> nil", func(t *testing.T) {
		err := stopExitError(proxyserver.StopResult{BlockedCount: 3, StateVerified: true}, false)
		assert.NoError(t, err)
	})

	t.Run("flag, no blocks -> nil", func(t *testing.T) {
		err := stopExitError(proxyserver.StopResult{BlockedCount: 0, StateVerified: true}, true)
		assert.NoError(t, err)
	})

	t.Run("flag, blocks present -> error", func(t *testing.T) {
		err := stopExitError(proxyserver.StopResult{BlockedCount: 2, StateVerified: true}, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "2 package")
	})

	t.Run("flag, crash (unverified state) -> fail closed", func(t *testing.T) {
		err := stopExitError(proxyserver.StopResult{StateVerified: false}, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not be verified")
	})

	t.Run("no flag, crash -> nil", func(t *testing.T) {
		err := stopExitError(proxyserver.StopResult{StateVerified: false}, false)
		assert.NoError(t, err)
	})
}

func TestStatusTextShowsEnforcement(t *testing.T) {
	assert.Contains(t, statusText(proxyserver.StatusInfo{}), "not running")
	assert.Contains(t, statusText(proxyserver.StatusInfo{Found: true, PID: 9}), "stale state for pid 9")
	assert.Contains(t, statusText(proxyserver.StatusInfo{Found: true, Unreadable: true}), "re-run with sudo")

	plain := statusText(proxyserver.StatusInfo{Found: true, Running: true, PID: 9, Addr: "127.0.0.1:7777", CACert: "/tmp/ca.pem"})
	assert.Contains(t, plain, "running (pid 9, addr 127.0.0.1:7777, ca /tmp/ca.pem)")
	assert.NotContains(t, plain, "enforcement")
	assert.NotContains(t, plain, "config:", "an older state file has no path")

	sourced := statusText(proxyserver.StatusInfo{Found: true, Running: true, PID: 9, Addr: "127.0.0.1:7777",
		ConfigPath: "/root/.config/safedep/pmg/config.yml", ConfigSource: "root per-user"})
	assert.Contains(t, sourced, "config: /root/.config/safedep/pmg/config.yml (root per-user)")

	enforced := statusText(proxyserver.StatusInfo{Found: true, Running: true, PID: 9, Addr: "127.0.0.1:7777", Enforce: &proxyserver.EnforceState{
		Status: netenforce.Status{
			CgroupPath:        "/sys/fs/cgroup",
			Ports:             []uint16{80, 443},
			KernelVersion:     "6.8.0",
			ExemptExecutables: []netenforce.ExemptedFile{{Path: "/opt/Runner.Worker"}},
			SkipDestinations:  []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
			DenyUDP:           true,
		},
		Namespaces: &proxyserver.NamespaceState{Mode: "redirect", Effective: "redirect", Table: &netenforce.NamespaceStatus{
			Address: "169.254.200.1", Port: 7777, Ingress: []string{"docker0", "br-*"},
		}},
		Warnings: []string{"Docker is running."},
	}})
	assert.Contains(t, enforced, "Kernel enforcement: active (cgroup /sys/fs/cgroup, ports 80,443, kernel 6.8.0)")
	assert.Contains(t, enforced, "  namespaces: redirect (169.254.200.1:7777 from docker0, br-*)")
	assert.Contains(t, enforced, "exempt executable: /opt/Runner.Worker")
	assert.Contains(t, enforced, "udp to enforced ports: denied")
	assert.Contains(t, enforced, "skip destination: 10.20.0.0/16")
	assert.Contains(t, enforced, "Docker is running.")
}
