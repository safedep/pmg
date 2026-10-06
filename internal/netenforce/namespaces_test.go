package netenforce

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseNamespaceMode(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want NamespaceMode
		ok   bool
	}{
		{"", NamespaceIgnore, true},
		{"ignore", NamespaceIgnore, true},
		{" Redirect ", NamespaceRedirect, true},
		{"auto", NamespaceAuto, true},
		{"on", "", false},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseNamespaceMode(tc.in)
			if !tc.ok {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestNamespacePolicyValidate(t *testing.T) {
	good := NamespacePolicy{Ingress: []string{"docker0", "br-*"}, Address: netip.MustParseAddr("169.254.200.1"), Ports: []uint16{80, 443}}
	require.NoError(t, good.Validate())
	require.NoError(t, NamespacePolicy{}.WithDefaults().Validate(), "the defaults are valid")
	require.Error(t, NamespacePolicy{}.Validate(), "an empty policy is not")

	for name, mutate := range map[string]func(*NamespacePolicy){
		"empty ingress name":  func(p *NamespacePolicy) { p.Ingress = []string{""} },
		"wildcard inside":     func(p *NamespacePolicy) { p.Ingress = []string{"br*0"} },
		"bare wildcard":       func(p *NamespacePolicy) { p.Ingress = []string{"*"} },
		"name too long":       func(p *NamespacePolicy) { p.Ingress = []string{"abcdefghijklmnop"} },
		"loopback address":    func(p *NamespacePolicy) { p.Address = netip.MustParseAddr("127.0.0.2") },
		"ipv6 address":        func(p *NamespacePolicy) { p.Address = netip.MustParseAddr("fe80::1") },
		"unspecified address": func(p *NamespacePolicy) { p.Address = netip.MustParseAddr("0.0.0.0") },
		"port zero":           func(p *NamespacePolicy) { p.Ports = []uint16{0} },
	} {
		t.Run(name, func(t *testing.T) {
			p := good
			mutate(&p)
			assert.Error(t, p.Validate())
		})
	}
}

func TestInputDropChainAcceptRule(t *testing.T) {
	addr := netip.MustParseAddr("169.254.200.1")
	assert.Equal(t, "iptables -I INPUT -i docker0 -d 169.254.200.1 -j ACCEPT",
		InputDropChain{Family: "ip", Table: "filter", Chain: "INPUT"}.AcceptRule("docker0", addr))
	assert.Equal(t, `nft insert rule inet firewall input iifname "docker0" ip daddr 169.254.200.1 accept`,
		InputDropChain{Family: "inet", Table: "firewall", Chain: "input"}.AcceptRule("docker0", addr))
}

func TestNamespaceStatusTarget(t *testing.T) {
	assert.Equal(t, "169.254.200.1:18443", NamespaceStatus{Address: "169.254.200.1", Port: 18443}.Target())
}
