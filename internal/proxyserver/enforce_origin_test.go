package proxyserver

import (
	"net/netip"
	"testing"

	"github.com/safedep/pmg/internal/netenforce"
	pmgproxy "github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
)

func TestOriginFromKernel(t *testing.T) {
	dst := netip.MustParseAddrPort("203.0.113.9:443")
	proxyAddr := netip.MustParseAddrPort("127.0.0.1:7777")

	redirected := originFromKernel(netenforce.Origin{Dst: dst, PID: 42, Comm: "curl", Exe: "/usr/bin/curl"})
	assert.Equal(t, pmgproxy.Origin{Dst: dst, PID: 42, Comm: "curl", Exe: "/usr/bin/curl"}, redirected)

	explicit := originFromKernel(netenforce.Origin{Dst: proxyAddr, PID: 7, Comm: "npm", Exe: "/usr/bin/node", ToProxy: true})
	assert.Equal(t, pmgproxy.Origin{PID: 7, Comm: "npm", Exe: "/usr/bin/node"}, explicit)
	assert.False(t, explicit.IsValid(), "a client of the proxy itself is not a redirect")
}
