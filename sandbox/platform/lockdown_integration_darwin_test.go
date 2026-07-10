//go:build darwin

package platform

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	lockdownHelperEnv       = "PMG_LOCKDOWN_HELPER"
	lockdownSandboxExecPath = "/usr/bin/sandbox-exec"
)

// TestLockdownHelperProcess is not a test: it is the child process re-executed
// under sandbox-exec by the lockdown integration test below. It performs the
// network checks described by its environment and exits 0 only when every
// check agrees with its expectation.
func TestLockdownHelperProcess(t *testing.T) {
	if os.Getenv(lockdownHelperEnv) != "1" {
		t.Skip("helper process only")
	}

	failed := false
	report := func(name string, ok bool, err error) {
		fmt.Printf("check %s: ok=%v err=%v\n", name, ok, err)
		if !ok {
			failed = true
		}
	}

	if addr := os.Getenv("PMG_DIAL_MUST_PASS"); addr != "" {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		report("dial-must-pass "+addr, err == nil, err)
		if conn != nil {
			_ = conn.Close()
		}
	}

	if addr := os.Getenv("PMG_DIAL_MUST_FAIL"); addr != "" {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		report("dial-must-fail "+addr, err != nil, err)
		if conn != nil {
			_ = conn.Close()
		}
	}

	if host := os.Getenv("PMG_RESOLVE"); host != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := net.DefaultResolver.LookupHost(ctx, host)
		wantPass := os.Getenv("PMG_RESOLVE_MUST_PASS") == "1"
		report(fmt.Sprintf("resolve %s (wantPass=%v)", host, wantPass), (err == nil) == wantPass, err)

		// Informational probes to localize where resolution is blocked; they
		// do not affect the pass/fail outcome.
		goResolver := &net.Resolver{PreferGo: true}
		_, goErr := goResolver.LookupHost(ctx, host)
		fmt.Printf("probe prefergo-resolve %s: err=%v\n", host, goErr)

		conn, dialErr := net.DialTimeout("udp", "1.1.1.1:53", 2*time.Second)
		if dialErr != nil {
			fmt.Printf("probe udp53-dial: err=%v\n", dialErr)
		} else {
			_, writeErr := conn.Write([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01})
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 512)
			_, readErr := conn.Read(buf)
			fmt.Printf("probe udp53 write err=%v read err=%v\n", writeErr, readErr)
			_ = conn.Close()
		}
	}

	if os.Getenv("PMG_SELF_DIAL") == "1" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			report("self-dial listen", false, err)
		} else {
			go func() {
				conn, aerr := ln.Accept()
				if aerr == nil {
					_ = conn.Close()
				}
			}()
			conn, derr := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
			report("self-dial "+ln.Addr().String(), derr == nil, derr)
			if conn != nil {
				_ = conn.Close()
			}
			_ = ln.Close()
		}
	}

	if failed {
		t.Fatal("one or more sandboxed checks disagreed with expectations")
	}
}

func requireSandboxExec(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(lockdownSandboxExecPath); err != nil {
		// Skips must not hide security tests in CI (see ci.yml).
		if os.Getenv("CI") != "" {
			t.Fatal("sandbox-exec required in CI")
		}
		t.Skip("sandbox-exec not available")
	}
}

func mustListenLoopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return ln
}

// lockdownTestPolicy mirrors the shipped profiles' filesystem posture
// (broad read like go.yml, temp-only writes): filesystem breadth is not
// under test here, network confinement is.
func lockdownTestPolicy(t *testing.T) *sandbox.SandboxPolicy {
	t.Helper()

	return &sandbox.SandboxPolicy{
		Name:            "lockdown-e2e",
		PackageManagers: []string{"npm"},
		Filesystem: sandbox.FilesystemPolicy{
			AllowRead: []string{"/"},
			AllowWrite: []string{
				os.TempDir() + "/**",
				"/tmp/**",
				"/private/tmp/**",
				"/dev/null",
			},
		},
		NetworkViaProxyOnly: utils.PtrTo(true),
	}
}

func writeTempProfile(t *testing.T, policy *sandbox.SandboxPolicy, proxyAddr string) string {
	t.Helper()
	profile, err := newSeatbeltPolicyTranslator().translate(policy,
		&sandbox.ExecutionContext{ProxyAddr: proxyAddr})
	require.NoError(t, err)

	f, err := os.CreateTemp("", "pmg-lockdown-e2e-*.sb")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	_, err = f.WriteString(profile)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func runSandboxedHelper(t *testing.T, profilePath string, env map[string]string) error {
	t.Helper()
	cmd := exec.Command(lockdownSandboxExecPath, "-f", profilePath,
		os.Args[0], "-test.run", "^TestLockdownHelperProcess$", "-test.v")
	cmd.Env = append(os.Environ(), lockdownHelperEnv+"=1")
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	out, err := cmd.CombinedOutput()
	t.Logf("sandboxed helper output:\n%s", out)
	return err
}

func TestLockdownEnforcementDarwin(t *testing.T) {
	requireSandboxExec(t)

	proxyLn := mustListenLoopback(t)
	otherLn := mustListenLoopback(t)

	t.Run("base lockdown", func(t *testing.T) {
		profile := writeTempProfile(t, lockdownTestPolicy(t), proxyLn.Addr().String())
		err := runSandboxedHelper(t, profile, map[string]string{
			"PMG_DIAL_MUST_PASS": proxyLn.Addr().String(),
			"PMG_DIAL_MUST_FAIL": otherLn.Addr().String(),
			"PMG_RESOLVE":        "example.com",
		})
		assert.NoError(t, err, "proxy dial must pass, direct dial and DNS must fail")
	})

	t.Run("allow_direct_dns re-opens DNS", func(t *testing.T) {
		policy := lockdownTestPolicy(t)
		policy.AllowDirectDNS = utils.PtrTo(true)
		profile := writeTempProfile(t, policy, proxyLn.Addr().String())
		err := runSandboxedHelper(t, profile, map[string]string{
			"PMG_DIAL_MUST_PASS":    proxyLn.Addr().String(),
			"PMG_RESOLVE":           "example.com",
			"PMG_RESOLVE_MUST_PASS": "1",
		})
		assert.NoError(t, err, "DNS must pass with allow_direct_dns")
	})

	t.Run("allow_direct_dns with network bind (diagnostic)", func(t *testing.T) {
		policy := lockdownTestPolicy(t)
		policy.AllowDirectDNS = utils.PtrTo(true)
		policy.AllowNetworkBind = utils.PtrTo(true)
		profile := writeTempProfile(t, policy, proxyLn.Addr().String())
		err := runSandboxedHelper(t, profile, map[string]string{
			"PMG_RESOLVE":           "example.com",
			"PMG_RESOLVE_MUST_PASS": "1",
		})
		assert.NoError(t, err, "DNS with allow_direct_dns and allow_network_bind")
	})

	// Gating check for the milestone: allow_network_bind's
	// (allow network* (local ip "localhost:*")) rules are emitted after the
	// lockdown deny and are expected to keep loopback->loopback connects
	// working. If this sub-test fails, the committed fallback is to emit
	// (allow network-outbound (remote ip "localhost:*")) under lockdown when
	// AllowNetworkBind is set.
	t.Run("allow_network_bind keeps loopback self-dial working", func(t *testing.T) {
		policy := lockdownTestPolicy(t)
		policy.AllowNetworkBind = utils.PtrTo(true)
		profile := writeTempProfile(t, policy, proxyLn.Addr().String())
		err := runSandboxedHelper(t, profile, map[string]string{
			"PMG_DIAL_MUST_PASS": proxyLn.Addr().String(),
			"PMG_SELF_DIAL":      "1",
		})
		assert.NoError(t, err, "loopback self-dial must pass under lockdown with allow_network_bind")
	})
}
