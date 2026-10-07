package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOutboundMatcherAllows(t *testing.T) {
	tests := []struct {
		name  string
		allow []string
		deny  []string
		host  string
		port  uint16
		want  bool
	}{
		{"no rules allows all", nil, nil, "example.com", 443, true},
		{"exact allow", []string{"registry.npmjs.org:443"}, []string{"*:*"}, "registry.npmjs.org", 443, true},
		{"wrong port denied", []string{"registry.npmjs.org:443"}, []string{"*:*"}, "registry.npmjs.org", 80, false},
		{"unlisted host denied", []string{"registry.npmjs.org:443"}, []string{"*:*"}, "evil.example", 443, false},
		{"allow list alone denies by default", []string{"registry.npmjs.org:443"}, nil, "evil.example", 443, false},
		{"deny all alone denies", nil, []string{"*:*"}, "registry.npmjs.org", 443, false},
		{"wildcard subdomain", []string{"*.mycorp.example:443"}, nil, "a.b.mycorp.example", 443, true},
		{"wildcard does not match apex", []string{"*.mycorp.example:443"}, nil, "mycorp.example", 443, false},
		{"wildcard does not match a suffix without a dot", []string{"*.mycorp.example:443"}, nil, "evilmycorp.example", 443, false},
		{"wildcard port", []string{"registry.npmjs.org:*"}, nil, "registry.npmjs.org", 8443, true},
		{"star host", []string{"*:443"}, nil, "anything.example", 443, true},
		{"specific deny beats inherited allow", []string{"github.com:443", "registry.npmjs.org:443"}, []string{"*:*", "github.com:443"}, "github.com", 443, false},
		{"specific deny keeps other allows", []string{"github.com:443", "registry.npmjs.org:443"}, []string{"*:*", "github.com:443"}, "registry.npmjs.org", 443, true},
		{"specific deny with star port", []string{"*:*"}, []string{"evil.example:*"}, "evil.example", 443, false},
		{"case and trailing dot", []string{"registry.npmjs.org:443"}, []string{"*:*"}, "Registry.NPMJS.org.", 443, true},
		{"rule case and trailing dot", []string{"Registry.NPMJS.org.:443"}, []string{"*:*"}, "registry.npmjs.org", 443, true},
		{"ip literal not matched by name", []string{"registry.npmjs.org:443"}, []string{"*:*"}, "104.16.0.35", 443, false},
		{"ipv4 rule", []string{"10.0.0.5:5000"}, nil, "10.0.0.5", 5000, true},
		{"ipv6 rule canonical form", []string{"[2001:db8::1]:443"}, nil, "2001:DB8:0::1", 443, true},
		{"ipv4-mapped ipv6 host matches ipv4 rule", []string{"10.0.0.5:443"}, nil, "::ffff:10.0.0.5", 443, true},
		{"empty host denied by allow list", []string{"registry.npmjs.org:443"}, nil, "", 443, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NewOutboundMatcher(NetworkPolicy{AllowOutbound: tc.allow, DenyOutbound: tc.deny})
			require.NoError(t, err)
			assert.Equal(t, tc.want, m.Allows(tc.host, tc.port))
		})
	}
}

func TestNewOutboundMatcherRejectsInvalidRules(t *testing.T) {
	for _, rule := range []string{
		"registry.npmjs.org",
		"registry.npmjs.org:",
		"registry.npmjs.org:0",
		"registry.npmjs.org:70000",
		"registry.npmjs.org:https",
		":443",
		"reg*stry.npmjs.org:443",
		"*.:443",
		"*.*.example:443",
		"*..example:443",
	} {
		t.Run(rule, func(t *testing.T) {
			_, err := NewOutboundMatcher(NetworkPolicy{AllowOutbound: []string{rule}})
			require.Error(t, err)
			assert.Contains(t, err.Error(), rule)
			assert.Contains(t, err.Error(), "network.allow_outbound")
		})
	}

	_, err := NewOutboundMatcher(NetworkPolicy{DenyOutbound: []string{"evil.example"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "network.deny_outbound")
}

func TestBuiltinProfilesHaveValidOutboundRules(t *testing.T) {
	registry, err := NewProfileRegistry()
	require.NoError(t, err)

	profiles, err := registry.ListProfiles()
	require.NoError(t, err)
	require.NotEmpty(t, profiles)

	for _, summary := range profiles {
		if summary.Source != ProfileSourceBuiltin {
			continue
		}
		t.Run(summary.Name, func(t *testing.T) {
			p, err := registry.GetProfile(summary.Name)
			require.NoError(t, err)
			_, err = NewOutboundMatcher(p.Network)
			require.NoError(t, err)
		})
	}
}
