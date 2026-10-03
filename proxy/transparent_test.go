package proxy

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTransparentTarget(t *testing.T) {
	ps := &proxyServer{config: DefaultProxyConfig()}
	orig := netip.MustParseAddrPort("203.0.113.9:8443")

	cases := []struct {
		name     string
		sni      string
		orig     netip.AddrPort
		wantHost string
		wantPort uint16
	}{
		{"name and destination keep the name and the real port", "registry.npmjs.org", orig, "registry.npmjs.org", 8443},
		{"name without destination uses the default port", "registry.npmjs.org", netip.AddrPort{}, "registry.npmjs.org", 443},
		{"destination without name uses the address", "", orig, "203.0.113.9", 8443},
		{"nothing known leaves the host empty", "", netip.AddrPort{}, "", 443},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port := ps.transparentTarget(tc.sni, tc.orig, 443)
			assert.Equal(t, tc.wantHost, host)
			assert.Equal(t, tc.wantPort, port)
		})
	}
}
