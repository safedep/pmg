package proxyserver

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientAddr(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{"ipv4 loopback", "127.0.0.1:7777", "127.0.0.1:7777"},
		{"specific ipv4", "172.18.0.2:7777", "172.18.0.2:7777"},
		{"specific ipv6", "[fd00::2]:7777", "[fd00::2]:7777"},
		{"ipv4 wildcard", "0.0.0.0:7777", "127.0.0.1:7777"},
		{"ipv6 wildcard, as Go reports a 0.0.0.0 bind", "[::]:7777", "127.0.0.1:7777"},
		{"empty host", ":7777", "127.0.0.1:7777"},
		{"hostname", "proxy.internal:7777", "proxy.internal:7777"},
		{"no port", "garbage", "garbage"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, clientAddr(tt.addr))
		})
	}
}

func TestEnvVarsWildcardBindExportsLoopback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-state.json")
	require.NoError(t, writeState(path, State{PID: 1, Addr: "[::]:7777", CACertPath: "/tmp/ca.pem"}))

	vars, err := EnvVars(path)
	require.NoError(t, err)
	assert.Contains(t, vars, "HTTPS_PROXY=http://127.0.0.1:7777")
	assert.Contains(t, vars, "HTTP_PROXY=http://127.0.0.1:7777")
}

func TestEnvVarsKeepGoOnTheOSTrustStore(t *testing.T) {
	t.Setenv("GODEBUG", "")
	path := filepath.Join(t.TempDir(), "proxy-state.json")
	require.NoError(t, writeState(path, State{PID: 1, Addr: "127.0.0.1:7777", CACertPath: "/tmp/ca.pem"}))

	vars, err := EnvVars(path)
	require.NoError(t, err)
	assert.Contains(t, vars, "GODEBUG=x509sslcertoverrideplatform=0",
		"a Go 1.27 client of the daemon keeps the OS trust store on macOS and Windows")
}

func TestEnvVarsNameTheRun(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.json")
	require.NoError(t, writeState(plain, State{PID: 1, Addr: "127.0.0.1:7777", CACertPath: "/tmp/ca.pem", RunID: "3f2a9c1d7e4b"}))
	enforced := filepath.Join(dir, "enforced.json")
	require.NoError(t, writeState(enforced, State{PID: 1, Addr: "127.0.0.1:7777", RunID: "3f2a9c1d7e4b", Enforce: &EnforceState{}}))
	older := filepath.Join(dir, "older.json")
	require.NoError(t, writeState(older, State{PID: 1, Addr: "127.0.0.1:7777", CACertPath: "/tmp/ca.pem"}))

	vars, err := EnvVars(plain)
	require.NoError(t, err)
	assert.Contains(t, vars, "PMG_PROXY_RUN=3f2a9c1d7e4b")

	vars, err = EnvVars(enforced)
	require.NoError(t, err)
	assert.Contains(t, vars, "PMG_PROXY_RUN=3f2a9c1d7e4b", "the run id is not a proxy variable, so enforcement keeps it")

	vars, err = EnvVars(older)
	require.NoError(t, err)
	for _, v := range vars {
		assert.NotContains(t, v, "PMG_PROXY_RUN", "a state file from an older daemon has no run")
	}
}
