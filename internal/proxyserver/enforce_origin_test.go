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

func TestRecordIsOfThisConnection(t *testing.T) {
	listener := netip.MustParseAddrPort("127.0.0.1:7777")
	cases := map[string]struct {
		rec  netenforce.Origin
		want bool
	}{
		"a redirect record is always of its connection":          {netenforce.Origin{Dst: netip.MustParseAddrPort("203.0.113.9:443")}, true},
		"a client of this listener":                              {netenforce.Origin{Dst: listener, ToProxy: true}, true},
		"a client of this listener over a mapped address":        {netenforce.Origin{Dst: netip.MustParseAddrPort("[::ffff:127.0.0.1]:7777"), ToProxy: true}, true},
		"a refused connect to another loopback address is stale": {netenforce.Origin{Dst: netip.MustParseAddrPort("127.0.0.2:7777"), ToProxy: true}, false},
		"a refused connect to another port is stale":             {netenforce.Origin{Dst: netip.MustParseAddrPort("127.0.0.1:7778"), ToProxy: true}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, recordIsOfThisConnection(tc.rec, listener))
		})
	}
}
