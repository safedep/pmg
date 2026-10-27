package proxy

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/internal/netenforce"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/safedep/pmg/proxy/netpolicy"
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

	t.Run("flag, denied connection -> error", func(t *testing.T) {
		err := stopExitError(proxyserver.StopResult{StateVerified: true, BlockedCount: 1, Network: &proxyserver.NetworkState{
			Mode: "enforce", Denials: []netpolicy.Denial{{Destination: "evil.example:443", Count: 2}},
		}}, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "1 package(s) were blocked by the proxy and 2 connection(s) were denied by the network policy")
	})

	t.Run("flag, audit decision -> nil", func(t *testing.T) {
		err := stopExitError(proxyserver.StopResult{StateVerified: true, Network: &proxyserver.NetworkState{
			Mode: "audit", Denials: []netpolicy.Denial{{Destination: "evil.example:443", Count: 2}},
		}}, true)
		assert.NoError(t, err)
	})
}

func TestNetworkReport(t *testing.T) {
	assert.Empty(t, networkReport(proxyserver.StopResult{}), "no policy, no block")

	denials := []netpolicy.Denial{
		{Destination: "193.32.204.199:80", Rule: "*:*", Client: "/usr/bin/curl", PID: 4132, Count: 1},
		{Destination: "pastebin.com:443", Rule: "*:*", Client: "172.17.0.2", Count: 3},
	}
	enforced := networkReport(proxyserver.StopResult{
		Network: &proxyserver.NetworkState{Chain: []string{"pypi-restrictive", "/etc/pmg/profiles/runner.yml"}, Mode: "enforce", Denials: denials},
		Enforce: &proxyserver.EnforceState{Status: netenforce.Status{Ports: []uint16{80, 443}}},
	})
	assert.Equal(t, "Network policy: enforce, 4 denied, 0 would deny\n"+
		"  denied  193.32.204.199:80  rule *:*  /usr/bin/curl pid 4132\n"+
		"  denied  pastebin.com:443   rule *:*  172.17.0.2 (3)\n"+
		"Profile: pypi-restrictive < /etc/pmg/profiles/runner.yml  ports 80,443\n", enforced)

	audited := networkReport(proxyserver.StopResult{Network: &proxyserver.NetworkState{Chain: []string{"npm-restrictive"}, Mode: "audit", Denials: denials[:1]}})
	assert.Equal(t, "Network policy: audit, 0 denied, 1 would deny\n"+
		"  would deny  193.32.204.199:80  rule *:*  /usr/bin/curl pid 4132\n"+
		"Profile: npm-restrictive\n", audited)

	clean := networkReport(proxyserver.StopResult{Network: &proxyserver.NetworkState{Mode: "enforce"}})
	assert.Equal(t, "Network policy: enforce, 0 denied, 0 would deny\nProfile: flags\n", clean)

	unnamed := networkReport(proxyserver.StopResult{Network: &proxyserver.NetworkState{Mode: "enforce",
		Denials: []netpolicy.Denial{{Destination: "pastebin.com:443", Rule: "pastebin.com:443", Count: 1}}}})
	assert.Equal(t, "Network policy: enforce, 1 denied, 0 would deny\n"+
		"  denied  pastebin.com:443  rule pastebin.com:443\n"+
		"Profile: flags\n", unnamed, "a proxy-aware client has no name and no trailing padding")
}

func TestStatusTextShowsEnforcement(t *testing.T) {
	assert.Contains(t, statusText(proxyserver.StatusInfo{}), "not running")
	assert.Contains(t, statusText(proxyserver.StatusInfo{Found: true, PID: 9}), "stale state for pid 9")
	assert.Contains(t, statusText(proxyserver.StatusInfo{Found: true, Unreadable: true}), "re-run with sudo")

	plain := statusText(proxyserver.StatusInfo{Found: true, Running: true, PID: 9, Addr: "127.0.0.1:7777", CACert: "/tmp/ca.pem"})
	assert.Contains(t, plain, "running (pid 9, addr 127.0.0.1:7777, ca /tmp/ca.pem)")
	assert.NotContains(t, plain, "enforcement")
	assert.NotContains(t, plain, "config:", "an older state file has no path")

	warned := statusText(proxyserver.StatusInfo{Found: true, Running: true, PID: 9, Addr: "127.0.0.1:7777",
		Warnings: []string{"Go module downloads are not analyzed."}})
	assert.Contains(t, warned, "Go module downloads are not analyzed.", "a daemon notice shows without enforcement")

	sourced := statusText(proxyserver.StatusInfo{Found: true, Running: true, PID: 9, Addr: "127.0.0.1:7777",
		ConfigPath: "/root/.config/safedep/pmg/config.yml", ConfigSource: "root per-user"})
	assert.Contains(t, sourced, "config: /root/.config/safedep/pmg/config.yml (root per-user)")
	assert.Contains(t, sourced, "Network policy: none.")

	policed := statusText(proxyserver.StatusInfo{Found: true, Running: true, PID: 9, Addr: "127.0.0.1:7777",
		Network: &proxyserver.NetworkState{Chain: []string{"npm-restrictive", "/srv/ci.yml"}, Mode: "enforce"}})
	assert.Contains(t, policed, "Network policy: enforce, profile npm-restrictive < /srv/ci.yml, enforce: off, policy advisory")

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
	}, Warnings: []string{"Docker is running."}})
	assert.Contains(t, enforced, "Kernel enforcement: active (cgroup /sys/fs/cgroup, ports 80,443, kernel 6.8.0)")
	assert.Contains(t, enforced, "  namespaces: redirect (169.254.200.1:7777 from docker0, br-*)")
	assert.Contains(t, enforced, "exempt executable: /opt/Runner.Worker")
	assert.Contains(t, enforced, "udp to enforced ports: denied")
	assert.Contains(t, enforced, "skip destination: 10.20.0.0/16")
	assert.Contains(t, enforced, "Docker is running.")
}

func TestObservationLine(t *testing.T) {
	assert.Equal(t, "", observationLine(proxyserver.StopResult{RunID: "abc", Observed: 0}))
	assert.Equal(t, "", observationLine(proxyserver.StopResult{Observed: 3}), "a daemon that predates the run id prints nothing")
	assert.Equal(t, "Destinations: 3 observed. Propose a profile with: pmg sandbox profile propose --run abc\n",
		observationLine(proxyserver.StopResult{RunID: "abc", Observed: 3}))
}

func TestStopReport(t *testing.T) {
	cases := []struct {
		name      string
		res       proxyserver.StopResult
		violation string
	}{
		{
			name: "clean run",
			res:  proxyserver.StopResult{PID: 7, StateVerified: true, RunID: "run-1", Observed: 3},
		},
		{
			name:      "block is a violation without the flag",
			res:       proxyserver.StopResult{PID: 7, StateVerified: true, BlockedCount: 2},
			violation: "2 package(s) were blocked by the proxy",
		},
		{
			name:      "unverified state is a violation",
			res:       proxyserver.StopResult{PID: 7},
			violation: "Proxy shut down but the blocked-package count could not be verified",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.json")
			require.NoError(t, writeStopReport(path, tc.res.Report(stopViolation(tc.res))))

			data, err := os.ReadFile(path)
			require.NoError(t, err)
			var got proxyserver.StopReport
			require.NoError(t, json.Unmarshal(data, &got))

			assert.True(t, got.Stopped)
			assert.Equal(t, tc.res.PID, got.PID)
			assert.Equal(t, tc.res.BlockedCount, got.BlockedCount)
			assert.Equal(t, tc.res.RunID, got.RunID)
			assert.Equal(t, tc.res.Observed, got.Observed)
			if tc.violation == "" {
				assert.Empty(t, got.Violation)
			} else {
				assert.Equal(t, tc.violation, got.Violation)
			}
		})
	}
}
