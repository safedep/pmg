package netpolicy

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecide(t *testing.T) {
	tests := []struct {
		name     string
		allow    []string
		deny     []string
		host     string
		port     uint16
		allowed  bool
		rule     string
		noRuleOK bool
	}{
		{name: "no rules allow", host: "example.com", port: 443, allowed: true, noRuleOK: true},
		{name: "nil lists allow", allow: nil, deny: nil, host: "example.com", port: 443, allowed: true, noRuleOK: true},
		{name: "allow list without deny all allows an unlisted host", allow: []string{"registry.npmjs.org:443"}, host: "evil.example", port: 443, allowed: true, noRuleOK: true},

		{name: "exact allow over deny all", allow: []string{"registry.npmjs.org:443"}, deny: []string{"*:*"}, host: "registry.npmjs.org", port: 443, allowed: true, rule: "registry.npmjs.org:443"},
		{name: "deny all catches an unlisted host", allow: []string{"registry.npmjs.org:443"}, deny: []string{"*:*"}, host: "cdn.example.com", port: 443, allowed: false, rule: "*:*"},
		{name: "deny all catches another port", allow: []string{"registry.npmjs.org:443"}, deny: []string{"*:*"}, host: "registry.npmjs.org", port: 80, allowed: false, rule: "*:*"},

		{name: "wildcard allow matches a subdomain", allow: []string{"*.github.com:443"}, deny: []string{"api.github.com:*"}, host: "registry.github.com", port: 443, allowed: true, rule: "*.github.com:443"},
		{name: "wildcard allow matches two labels", allow: []string{"*.github.com:443"}, deny: []string{"*:*"}, host: "a.b.github.com", port: 443, allowed: true, rule: "*.github.com:443"},
		{name: "wildcard does not match the apex", allow: []string{"*.github.com:443"}, deny: []string{"*:*"}, host: "github.com", port: 443, allowed: false, rule: "*:*"},
		{name: "wildcard does not match a longer label", allow: []string{"*.github.com:443"}, deny: []string{"*:*"}, host: "evilgithub.com", port: 443, allowed: false, rule: "*:*"},
		{name: "exact deny beats wildcard allow", allow: []string{"*.github.com:443"}, deny: []string{"api.github.com:*"}, host: "api.github.com", port: 443, allowed: false, rule: "api.github.com:*"},
		{name: "longer wildcard beats shorter wildcard", allow: []string{"*.api.github.com:443"}, deny: []string{"*.github.com:443"}, host: "x.api.github.com", port: 443, allowed: true, rule: "*.api.github.com:443"},
		{name: "wildcard beats star", allow: []string{"*.github.com:443"}, deny: []string{"*:443"}, host: "x.github.com", port: 443, allowed: true, rule: "*.github.com:443"},

		{name: "deny port only", deny: []string{"*:80"}, host: "registry.npmjs.org", port: 443, allowed: true, noRuleOK: true},
		{name: "deny port only hits", deny: []string{"*:80"}, host: "cdn.example.com", port: 80, allowed: false, rule: "*:80"},
		{name: "exact port beats star port on the same host", allow: []string{"registry.npmjs.org:443"}, deny: []string{"registry.npmjs.org:*"}, host: "registry.npmjs.org", port: 443, allowed: true, rule: "registry.npmjs.org:443"},
		{name: "star port rule still denies another port", allow: []string{"registry.npmjs.org:443"}, deny: []string{"registry.npmjs.org:*"}, host: "registry.npmjs.org", port: 8443, allowed: false, rule: "registry.npmjs.org:*"},

		{name: "deny wins on a tie", allow: []string{"github.com:443"}, deny: []string{"github.com:443"}, host: "github.com", port: 443, allowed: false, rule: "github.com:443"},
		{name: "deny wins on a wildcard tie", allow: []string{"*.example.com:443"}, deny: []string{"*.example.com:443"}, host: "a.example.com", port: 443, allowed: false, rule: "*.example.com:443"},
		{name: "deny wins on a star tie", allow: []string{"*:*"}, deny: []string{"*:*"}, host: "a.example.com", port: 443, allowed: false, rule: "*:*"},

		{name: "connection host case and trailing dot", allow: []string{"registry.npmjs.org:443"}, deny: []string{"*:*"}, host: "Registry.NPMJS.org.", port: 443, allowed: true, rule: "registry.npmjs.org:443"},
		{name: "rule host case and trailing dot", allow: []string{"Registry.NPMJS.org.:443"}, deny: []string{"*:*"}, host: "registry.npmjs.org", port: 443, allowed: true, rule: "Registry.NPMJS.org.:443"},

		{name: "ip literal is not matched by a name", allow: []string{"registry.npmjs.org:443"}, deny: []string{"*:*"}, host: "104.16.0.35", port: 443, allowed: false, rule: "*:*"},
		{name: "ipv4 rule", allow: []string{"10.0.0.5:5000"}, deny: []string{"*:*"}, host: "10.0.0.5", port: 5000, allowed: true, rule: "10.0.0.5:5000"},
		{name: "ipv6 rule in brackets against canonical form", allow: []string{"[2001:db8::1]:443"}, deny: []string{"*:*"}, host: "2001:DB8:0::1", port: 443, allowed: true, rule: "[2001:db8::1]:443"},
		{name: "ipv6 connection in brackets", allow: []string{"[2001:db8::1]:443"}, deny: []string{"*:*"}, host: "[2001:db8::1]", port: 443, allowed: true, rule: "[2001:db8::1]:443"},
		{name: "ipv4 mapped ipv6 matches the ipv4 rule", allow: []string{"10.0.0.5:443"}, deny: []string{"*:*"}, host: "::ffff:10.0.0.5", port: 443, allowed: true, rule: "10.0.0.5:443"},
		{name: "wildcard does not match an ip literal", allow: []string{"*.example.com:443"}, deny: []string{"*:*"}, host: "10.0.0.5", port: 443, allowed: false, rule: "*:*"},
		{name: "numeric wildcard does not match an ip literal", allow: []string{"*.0.5:443"}, deny: []string{"*:*"}, host: "10.0.0.5", port: 443, allowed: false, rule: "*:*"},
		{name: "numeric wildcard matches a numeric name", allow: []string{"*.0.5:443"}, deny: []string{"*:*"}, host: "x.0.5", port: 443, allowed: true, rule: "*.0.5:443"},

		{name: "empty host is denied by deny all", allow: []string{"registry.npmjs.org:443"}, deny: []string{"*:*"}, host: "", port: 443, allowed: false, rule: "(unreadable host)"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := New(tc.allow, tc.deny)
			require.NoError(t, err)

			decision := policy.Decide(tc.host, tc.port)
			assert.Equal(t, tc.allowed, decision.Allowed)
			if tc.noRuleOK {
				assert.Nil(t, decision.Rule)
				return
			}
			require.NotNil(t, decision.Rule)
			assert.Equal(t, tc.rule, decision.Rule.Raw)
		})
	}
}

func TestDecideNilPolicyAllows(t *testing.T) {
	var policy *Policy
	decision := policy.Decide("example.com", 443)
	assert.True(t, decision.Allowed)
	assert.Nil(t, decision.Rule)
}

func TestDecideFirstRuleWinsAmongEquals(t *testing.T) {
	policy, err := New([]string{"github.com:443", "github.com:443"}, nil)
	require.NoError(t, err)

	rules := policy.Rules()
	require.Len(t, rules, 2)

	decision := policy.Decide("github.com", 443)
	require.NotNil(t, decision.Rule)
	assert.Same(t, &policy.rules[0], decision.Rule)
}

func TestParseRule(t *testing.T) {
	tests := []struct {
		raw    string
		client string
		host   string
		port   uint16
	}{
		{raw: "registry.npmjs.org:443", host: "registry.npmjs.org", port: 443},
		{raw: "Registry.NPMJS.org.:443", host: "registry.npmjs.org", port: 443},
		{raw: "*.example.com:443", host: "*.example.com", port: 443},
		{raw: "*.Example.COM.:*", host: "*.example.com", port: 0},
		{raw: "*:*", host: "*", port: 0},
		{raw: "*:443", host: "*", port: 443},
		{raw: "10.0.0.5:5000", host: "10.0.0.5", port: 5000},
		{raw: "[2001:DB8::1]:443", host: "2001:db8::1", port: 443},
		{raw: "[::ffff:10.0.0.5]:443", host: "10.0.0.5", port: 443},
		{raw: "git=github.com:443", client: "git", host: "github.com", port: 443},
		{raw: "/usr/bin/git=*.github.com:443", client: "/usr/bin/git", host: "*.github.com", port: 443},
		{raw: "curl=*:*", client: "curl", host: "*", port: 0},
		{raw: "my_host.internal:8080", host: "my_host.internal", port: 8080},
		{raw: "/opt/my tools/git=github.com:443", client: "/opt/my tools/git", host: "github.com", port: 443},
		{raw: `C:\tools\git.exe=github.com:443`, client: `C:\tools\git.exe`, host: "github.com", port: 443},
		{raw: "D:/tools/git.exe=github.com:443", client: "D:/tools/git.exe", host: "github.com", port: 443},
		{raw: "git =github.com:443", client: "git", host: "github.com", port: 443},
	}

	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			rule, err := parseRule(tc.raw)
			require.NoError(t, err)
			assert.Equal(t, tc.raw, rule.Raw)
			assert.Equal(t, tc.client, rule.Client)
			assert.Equal(t, tc.host, rule.Host)
			assert.Equal(t, tc.port, rule.Port)
			assert.False(t, rule.Deny)
		})
	}
}

func TestParseRuleRejectsAClientRule(t *testing.T) {
	_, err := ParseRule("git=github.com:443")
	var ruleErr *RuleError
	require.ErrorAs(t, err, &ruleErr)
	assert.Equal(t, "names a client, which the proxy cannot match yet", ruleErr.Reason)

	_, err = New(nil, []string{"curl=*:*"})
	require.ErrorAs(t, err, &ruleErr)
	assert.Equal(t, "network.deny_outbound", ruleErr.List)
}

func TestParseRuleRejects(t *testing.T) {
	for _, raw := range []string{
		"",
		"registry.npmjs.org",
		"registry.npmjs.org:",
		":443",
		"registry.npmjs.org:0",
		"registry.npmjs.org:70000",
		"registry.npmjs.org:https",
		"registry.npmjs.org:-1",
		"reg*stry.npmjs.org:443",
		"*.:443",
		"*.*.example:443",
		"*..example:443",
		"**:443",
		"exa mple.com:443",
		"example.com/path:443",
		"=github.com:443",
		"cu\trl=github.com:443",
		"bin/git=github.com:443",
		"./git=github.com:443",
		`tools\git.exe=github.com:443`,
		"git=github.com",
		"2001:db8::1:443",
		"[fe80::1%eth0]:443",
		"-example.com:443",
		"example-.com:443",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := ParseRule(raw)
			require.Error(t, err)

			var ruleErr *RuleError
			require.True(t, errors.As(err, &ruleErr))
			assert.Equal(t, raw, ruleErr.Rule)
			assert.Empty(t, ruleErr.List)
		})
	}
}

func TestNewNamesTheList(t *testing.T) {
	_, err := New([]string{"github.com:443"}, []string{"evil.example"})
	require.Error(t, err)

	var ruleErr *RuleError
	require.True(t, errors.As(err, &ruleErr))
	assert.Equal(t, "network.deny_outbound", ruleErr.List)
	assert.Equal(t, "evil.example", ruleErr.Rule)
	assert.Contains(t, err.Error(), `network.deny_outbound: rule "evil.example" is not host:port`)

	_, err = New([]string{"github.com"}, nil)
	require.Error(t, err)
	require.True(t, errors.As(err, &ruleErr))
	assert.Equal(t, "network.allow_outbound", ruleErr.List)
}

func TestRulesKeepsOrderAndDenyFlag(t *testing.T) {
	policy, err := New([]string{"a.example.com:443", "b.example.com:443"}, []string{"*:*"})
	require.NoError(t, err)

	rules := policy.Rules()
	require.Len(t, rules, 3)
	assert.Equal(t, "a.example.com:443", rules[0].Raw)
	assert.False(t, rules[0].Deny)
	assert.Equal(t, "*:*", rules[2].Raw)
	assert.True(t, rules[2].Deny)

	rules[0].Raw = "changed"
	assert.Equal(t, "a.example.com:443", policy.Rules()[0].Raw)
}

func TestNormalizeHost(t *testing.T) {
	tests := map[string]string{
		"Example.COM.":       "example.com",
		" example.com ":      "example.com",
		"[2001:DB8::1]":      "2001:db8::1",
		"::ffff:10.0.0.5":    "10.0.0.5",
		"10.0.0.5":           "10.0.0.5",
		"*.Example.com":      "*.example.com",
		"":                   "",
		"registry.npmjs.org": "registry.npmjs.org",

		// The transport maps a name with IDNA before it dials, so the
		// policy must read the same name.
		"\uff4cocalhost":            "localhost",
		"local\u00adhost":           "localhost",
		"b\u00fccher.example":       "xn--bcher-kva.example",
		"[fe80::1%eth0]":            "fe80::1",
		"127.1":                     "127.0.0.1",
		"0x7f000001":                "127.0.0.1",
		"2130706433":                "127.0.0.1",
		"0177.0.0.1":                "127.0.0.1",
		"0177.0000.0.01":            "127.0.0.1",
		"\uff11\uff12\uff17.\uff11": "127.0.0.1",
		"*.b\u00fccher.example":     "*.xn--bcher-kva.example",
	}
	for in, want := range tests {
		got := NormalizeHost(in)
		assert.Equal(t, want, got, in)
		assert.Equal(t, got, NormalizeHost(got), "normalization is idempotent for %q", in)
	}
}

func TestWildcardRuleWithAnInternationalizedSuffix(t *testing.T) {
	rule, err := ParseRule("*.b\u00fccher.example:443")
	require.NoError(t, err)
	assert.Equal(t, "*.xn--bcher-kva.example", rule.Host)

	p, err := New(nil, []string{"*.b\u00fccher.example:443"})
	require.NoError(t, err)
	assert.False(t, p.Decide("shop.b\u00fccher.example", 443).Allowed)
	assert.False(t, p.Decide("shop.xn--bcher-kva.example", 443).Allowed)
	assert.True(t, p.Decide("b\u00fccher.example", 443).Allowed, "a wildcard does not match its own suffix")
}

// A host the policy cannot read as a name or an address is denied, because
// the transport may still reach something by it.
func TestDecideDeniesAnUnreadableHost(t *testing.T) {
	p, err := New([]string{"*:*"}, nil)
	require.NoError(t, err)
	for _, host := range []string{"exa mple.com", "evil.example\x00", "-evil.example", "evil..example", "*"} {
		d := p.Decide(host, 443)
		assert.False(t, d.Allowed, host)
		require.NotNil(t, d.Rule, host)
		assert.True(t, d.Rule.Deny, host)
	}
	assert.True(t, (*Policy)(nil).Decide("exa mple.com", 443).Allowed, "no policy decides nothing")
}

func TestRuleCovers(t *testing.T) {
	cases := []struct {
		deny, allow string
		want        bool
	}{
		{"api.anthropic.com:*", "api.anthropic.com:443", true},
		{"api.anthropic.com:443", "api.anthropic.com:443", true},
		{"api.anthropic.com:443", "api.anthropic.com:*", false},
		{"api.anthropic.com:443", "api.anthropic.com:8443", false},
		{"*.anthropic.com:443", "api.anthropic.com:443", true},
		{"*.anthropic.com:*", "*.api.anthropic.com:443", true},
		{"*.anthropic.com:*", "*.anthropic.com:443", true},
		{"*.anthropic.com:443", "*.anthropic.com:*", false},
		{"*.anthropic.com:*", "anthropic.com:443", false},
		{"*.anthropic.com:*", "evilanthropic.com:443", false},
		{"*:*", "api.anthropic.com:443", true},
		{"*:443", "api.anthropic.com:443", true},
		{"*:443", "api.anthropic.com:80", false},
	}
	for _, tc := range cases {
		t.Run(tc.deny+" covers "+tc.allow, func(t *testing.T) {
			deny, err := ParseRule(tc.deny)
			require.NoError(t, err)
			allow, err := ParseRule(tc.allow)
			require.NoError(t, err)
			assert.Equal(t, tc.want, deny.Covers(allow))
		})
	}
}

func TestDecideDeniesIPLiterals(t *testing.T) {
	tests := []struct {
		name    string
		allow   []string
		deny    []string
		host    string
		port    uint16
		allowed bool
		rule    string
	}{
		{name: "an address no rule names is denied", host: "193.32.204.199", port: 80, allowed: false, rule: IPLiteralRule},
		{name: "a wildcard allow does not name an address", allow: []string{"*:*"}, host: "193.32.204.199", port: 80, allowed: false, rule: IPLiteralRule},
		{name: "a port allow does not name an address", allow: []string{"*:80"}, host: "193.32.204.199", port: 80, allowed: false, rule: IPLiteralRule},
		{name: "an exact address allow wins", allow: []string{"10.0.0.5:5000"}, deny: []string{"*:*"}, host: "10.0.0.5", port: 5000, allowed: true, rule: "10.0.0.5:5000"},
		{name: "an exact address allow on another port does not name this one", allow: []string{"10.0.0.5:5000"}, host: "10.0.0.5", port: 443, allowed: false, rule: IPLiteralRule},
		{name: "an exact address allow with any port names the address", allow: []string{"10.0.0.5:*"}, host: "10.0.0.5", port: 443, allowed: true, rule: "10.0.0.5:*"},
		{name: "an exact address deny keeps its own name", deny: []string{"10.0.0.5:*"}, host: "10.0.0.5", port: 443, allowed: false, rule: "10.0.0.5:*"},
		{name: "a catch-all deny names the address denial", deny: []string{"*:*"}, host: "10.0.0.5", port: 443, allowed: false, rule: IPLiteralRule},
		{name: "an ipv6 address is denied", host: "2001:db8::1", port: 443, allowed: false, rule: IPLiteralRule},
		{name: "an ipv6 exact allow wins", allow: []string{"[2001:db8::1]:443"}, host: "2001:DB8::1", port: 443, allowed: true, rule: "[2001:db8::1]:443"},
		{name: "a mapped ipv4 is the ipv4 address", allow: []string{"10.0.0.5:443"}, host: "::ffff:10.0.0.5", port: 443, allowed: true, rule: "10.0.0.5:443"},
		{name: "a bracketed ipv6 is the address", allow: []string{"*:*"}, host: "[2001:db8::1]", port: 443, allowed: false, rule: IPLiteralRule},
		{name: "an ipv6 address with a zone is the address", allow: []string{"*:*"}, host: "fe80::1%eth0", port: 443, allowed: false, rule: IPLiteralRule},
		{name: "a mapped loopback stays with the rules", host: "::ffff:127.0.0.1", port: 8080, allowed: true},
		{name: "a legacy ipv4 spelling is the address", host: "0xa.1.2", port: 80, allowed: false, rule: IPLiteralRule},
		{name: "a bare 0x part is zero, as inet_aton reads it", allow: []string{"*:*"}, host: "0x.1.2", port: 80, allowed: false, rule: IPLiteralRule},
		{name: "loopback stays with the rules", host: "127.0.0.1", port: 8080, allowed: true},
		{name: "loopback ipv6 stays with the rules", host: "::1", port: 8080, allowed: true},
		{name: "loopback is still denied by a rule", deny: []string{"*:*"}, host: "127.0.0.1", port: 8080, allowed: false, rule: "*:*"},
		{name: "a name is decided by the rules", allow: []string{"registry.npmjs.org:443"}, deny: []string{"*:*"}, host: "registry.npmjs.org", port: 443, allowed: true, rule: "registry.npmjs.org:443"},
		{name: "a name no rule names is allowed", host: "example.com", port: 443, allowed: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(tt.allow, tt.deny, DenyIPLiterals())
			require.NoError(t, err)
			require.True(t, p.DeniesIPLiterals())

			d := p.Decide(tt.host, tt.port)
			assert.Equal(t, tt.allowed, d.Allowed)
			if tt.rule == "" {
				assert.Nil(t, d.Rule)
				return
			}
			require.NotNil(t, d.Rule)
			assert.Equal(t, tt.rule, d.Rule.Raw)
		})
	}
}

func TestDeniesIPLiteralsIsOffByDefault(t *testing.T) {
	p, err := New(nil, nil)
	require.NoError(t, err)
	assert.False(t, p.DeniesIPLiterals())
	assert.True(t, p.Decide("193.32.204.199", 80).Allowed)

	var nilPolicy *Policy
	assert.False(t, nilPolicy.DeniesIPLiterals())
}
