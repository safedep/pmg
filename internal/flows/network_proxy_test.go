package flows

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy/netpolicy"
	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/executor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func connectStatus(t *testing.T, proxyAddr, target string) int {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	require.NoError(t, err)
	return resp.StatusCode
}

func TestNetworkProxyAppliesTheResolutionAndReportsTheRun(t *testing.T) {
	network, err := sandbox.NetworkPolicy{DenyOutbound: []string{"*:*"}}.Compile()
	require.NoError(t, err)
	res := &executor.Resolution{
		PackageManager: sandbox.WorkloadExec,
		Policy:         &sandbox.SandboxPolicy{Name: "exec-strict"},
		NetworkMode:    config.SandboxNetworkModeEnforce,
		Network:        network,
	}

	p, err := StartNetworkProxy(res)
	require.NoError(t, err)
	assert.NotEmpty(t, p.Addr())
	assert.Contains(t, p.Env(), "HTTPS_PROXY=http://"+p.Addr())
	assert.NotContains(t, fmt.Sprint(p.Env()), "SSL_CERT_FILE", "a proxy that does not terminate TLS hands out no CA")

	assert.Equal(t, http.StatusForbidden, connectStatus(t, p.Addr(), "pastebin.com:443"))
	assert.Equal(t, http.StatusForbidden, connectStatus(t, p.Addr(), "pastebin.com:443"))

	outcome := p.Stop()
	require.NotNil(t, outcome.Report)
	assert.True(t, outcome.Report.Enforced)
	require.Len(t, outcome.Report.Denials, 1)
	assert.Equal(t, netpolicy.Denial{Destination: "pastebin.com:443", Rule: "*:*", Count: 2}, outcome.Report.Denials[0])
	assert.Equal(t, 1, outcome.Observed)

	_, err = net.DialTimeout("tcp", p.Addr(), time.Second)
	assert.Error(t, err, "the proxy is down after Stop")
	assert.Equal(t, outcome, p.Stop(), "a second Stop returns the same outcome")
}
