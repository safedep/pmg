package propose

import (
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/proxy/netpolicy"
	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func dest(host string, port uint16) netpolicy.Destination {
	return netpolicy.Destination{Host: host, Port: port, Count: 1, Allowed: true}
}

func TestNetworkProposesOneRulePerDestinationAndTheCatchAllDeny(t *testing.T) {
	res, err := Network(Input{Destinations: []netpolicy.Destination{
		dest("registry.npmjs.org", 443),
		dest("github.com", 443),
		{Host: "github.com", Port: 443, Client: "/usr/bin/git", Count: 3, Allowed: true},
		dest("api.example", 80),
	}})
	require.NoError(t, err)
	assert.Equal(t, []string{"api.example:80", "github.com:443", "registry.npmjs.org:443"}, res.Added)
	assert.Equal(t, res.Added, res.Network.AllowOutbound)
	assert.Equal(t, []string{CatchAllDeny}, res.Network.DenyOutbound)
	require.Len(t, res.Rows, 4)
	for _, row := range res.Rows {
		assert.Equal(t, VerdictAdd, row.Verdict)
	}
}

func TestNetworkLeavesTheParentsHostsToTheParent(t *testing.T) {
	parent := &sandbox.SandboxPolicy{Name: "npm-restrictive", Network: sandbox.NetworkPolicy{
		AllowOutbound: []string{"registry.npmjs.org:443"},
		DenyOutbound:  []string{"*:*"},
	}}
	res, err := Network(Input{Parent: parent, Destinations: []netpolicy.Destination{
		dest("registry.npmjs.org", 443),
		dest("github.com", 443),
	}})
	require.NoError(t, err)
	assert.Equal(t, []string{"github.com:443"}, res.Added)
	assert.Empty(t, res.Network.DenyOutbound, "the parent denies everything else")
	assert.Equal(t, VerdictParentAllows, res.Rows[0].Verdict)
	assert.Equal(t, "registry.npmjs.org:443", res.Rows[0].Rule)
	assert.Equal(t, VerdictAdd, res.Rows[1].Verdict)
}

func TestNetworkAppendsToAnExistingBlockAndRemovesNothing(t *testing.T) {
	existing := &sandbox.NetworkPolicy{
		AllowOutbound: []string{"github.com:443", "old.example:443"},
		DenyOutbound:  []string{"pastebin.com:443", "*:*"},
	}
	res, err := Network(Input{Existing: existing, Destinations: []netpolicy.Destination{
		dest("github.com", 443),
		dest("new.example", 443),
		{Host: "pastebin.com", Port: 443, Count: 1, Allowed: false, Rule: "pastebin.com:443", Enforced: true},
	}})
	require.NoError(t, err)
	assert.Equal(t, []string{"new.example:443"}, res.Added)
	assert.Equal(t, []string{"github.com:443", "old.example:443", "new.example:443"}, res.Network.AllowOutbound)
	assert.Equal(t, []string{"pastebin.com:443", "*:*"}, res.Network.DenyOutbound)
	assert.Equal(t, VerdictAlreadyAllowed, res.Rows[0].Verdict)
	assert.Equal(t, VerdictAdd, res.Rows[1].Verdict)
	assert.Equal(t, VerdictKeptDenied, res.Rows[2].Verdict)
	assert.Equal(t, "pastebin.com:443", res.Rows[2].Rule)
}

func TestNetworkProposesADestinationTheCatchAllDenied(t *testing.T) {
	existing := &sandbox.NetworkPolicy{DenyOutbound: []string{"*:*"}}
	res, err := Network(Input{Existing: existing, Destinations: []netpolicy.Destination{
		{Host: "cdn.example", Port: 443, Count: 2, Allowed: false, Rule: "*:*"},
	}})
	require.NoError(t, err)
	assert.Equal(t, []string{"cdn.example:443"}, res.Added, "the catch-all is the baseline's own deny, not a decision about the host")
}

func TestNetworkNamesEveryHostUnderAParentThatAllowsAll(t *testing.T) {
	parent := &sandbox.SandboxPolicy{Name: "exec", Network: sandbox.NetworkPolicy{AllowOutbound: []string{"*:*"}}}
	res, err := Network(Input{Parent: parent, Destinations: []netpolicy.Destination{dest("github.com", 443)}})
	require.NoError(t, err)
	assert.Equal(t, []string{"github.com:443"}, res.Added)
	assert.Equal(t, []string{CatchAllDeny}, res.Network.DenyOutbound)
}

func TestNetworkRejectsAnUnparsableRule(t *testing.T) {
	_, err := Network(Input{Existing: &sandbox.NetworkPolicy{AllowOutbound: []string{"not a rule"}}})
	require.Error(t, err)
}

func TestNetworkWritesAnIPv6DestinationAsARule(t *testing.T) {
	res, err := Network(Input{Destinations: []netpolicy.Destination{dest("2606:4700::1", 443)}})
	require.NoError(t, err)
	assert.Equal(t, []string{"[2606:4700::1]:443"}, res.Added)
	_, err = netpolicy.New(res.Network.AllowOutbound, res.Network.DenyOutbound)
	require.NoError(t, err, "the proposal parses as a policy")
}

func TestNetworkSkipsAHostNoRuleCanName(t *testing.T) {
	res, err := Network(Input{Destinations: []netpolicy.Destination{dest("foo!bar", 443), dest("ok.example", 443)}})
	require.NoError(t, err)
	assert.Equal(t, []string{"ok.example:443"}, res.Added)
	assert.Equal(t, VerdictInvalid, res.Rows[0].Verdict)
}

func TestNetworkKeepsAParentsSpecificDeny(t *testing.T) {
	parent := &sandbox.SandboxPolicy{Name: "base", Network: sandbox.NetworkPolicy{DenyOutbound: []string{"pastebin.com:443", "*:*"}}}
	res, err := Network(Input{Parent: parent, Destinations: []netpolicy.Destination{
		{Host: "pastebin.com", Port: 443, Count: 1, Rule: "pastebin.com:443", Enforced: true},
	}})
	require.NoError(t, err)
	assert.Empty(t, res.Added)
	assert.Equal(t, VerdictKeptDenied, res.Rows[0].Verdict)
}

func TestSetBlockGivesASkeletonNetworkKeyAMapping(t *testing.T) {
	out, err := SetBlock([]byte("name: x\n# the rules\nnetwork:\n"), sandbox.NetworkPolicy{AllowOutbound: []string{"a.example:443"}, DenyOutbound: []string{"*:*"}})
	require.NoError(t, err)
	assert.Equal(t, "name: x\n# the rules\nnetwork:\n  allow_outbound:\n    - a.example:443\n  deny_outbound:\n    - '*:*'\n", string(out))
}

func TestSetBlockKeepsAnAnchor(t *testing.T) {
	doc := "name: x\nnetwork:\n  allow_outbound: &hosts\n    - a.example:443\nprocess:\n  allow_exec: *hosts\n"
	out, err := SetBlock([]byte(doc), sandbox.NetworkPolicy{AllowOutbound: []string{"a.example:443", "b.example:443"}})
	require.NoError(t, err)
	assert.Contains(t, string(out), "allow_outbound: &hosts")
	var parsed map[string]any
	require.NoError(t, yaml.Unmarshal(out, &parsed), "the alias still resolves")
}

func TestSetBlockRefusesADocumentThatIsNotAMapping(t *testing.T) {
	_, err := SetBlock([]byte("- a\n- b\n"), sandbox.NetworkPolicy{})
	require.Error(t, err)
}

func TestSetBlockEditsTheMappingAnAliasPointsAt(t *testing.T) {
	doc := "name: x\ndefaults: &net\n  allow_bind: true\nnetwork: *net\n"
	out, err := SetBlock([]byte(doc), sandbox.NetworkPolicy{AllowOutbound: []string{"a.example:443"}})
	require.NoError(t, err)
	var parsed struct {
		Network struct {
			AllowBind     bool     `yaml:"allow_bind"`
			AllowOutbound []string `yaml:"allow_outbound"`
		} `yaml:"network"`
	}
	require.NoError(t, yaml.Unmarshal(out, &parsed))
	assert.True(t, parsed.Network.AllowBind, "the other fields of the aliased mapping stay")
	assert.Equal(t, []string{"a.example:443"}, parsed.Network.AllowOutbound)
}

func TestNetworkDecidesOnTheUnionOfParentAndTarget(t *testing.T) {
	parent := &sandbox.SandboxPolicy{Name: "base", Network: sandbox.NetworkPolicy{DenyOutbound: []string{"blocked.example.com:443", "*:*"}}}
	existing := &sandbox.NetworkPolicy{AllowOutbound: []string{"*.example.com:443"}}
	res, err := Network(Input{Parent: parent, Existing: existing, Destinations: []netpolicy.Destination{
		{Host: "blocked.example.com", Port: 443, Count: 1, Rule: "blocked.example.com:443", Enforced: true},
		dest("cdn.example.com", 443),
	}})
	require.NoError(t, err)
	assert.Empty(t, res.Added)
	assert.Equal(t, VerdictKeptDenied, res.Rows[0].Verdict, "the parent's exact deny beats the target's wildcard allow, as enforcement decides")
	assert.Equal(t, "blocked.example.com:443", res.Rows[0].Rule)
	assert.Equal(t, VerdictAlreadyAllowed, res.Rows[1].Verdict)
	assert.Equal(t, "*.example.com:443", res.Rows[1].Rule)
}

func TestNetworkTurnsOnDenyIPLiteralsUnlessTheTargetDecided(t *testing.T) {
	fresh, err := Network(Input{Destinations: []netpolicy.Destination{dest("github.com", 443)}})
	require.NoError(t, err)
	require.NotNil(t, fresh.Network.DenyIPLiterals)
	assert.True(t, *fresh.Network.DenyIPLiterals, "a new block denies addresses")

	kept, err := Network(Input{
		Destinations: []netpolicy.Destination{dest("github.com", 443)},
		Existing:     &sandbox.NetworkPolicy{DenyIPLiterals: utils.PtrTo(false)},
	})
	require.NoError(t, err)
	require.NotNil(t, kept.Network.DenyIPLiterals)
	assert.False(t, *kept.Network.DenyIPLiterals, "an explicit false is a decision the proposal keeps")
}

func TestNetworkProposesAnAddressTheKeyWillDeny(t *testing.T) {
	res, err := Network(Input{Destinations: []netpolicy.Destination{dest("10.0.0.5", 5000)}})
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.5:5000"}, res.Added, "the exact address rule is what deny_ip_literals needs to allow the address")

	compiled, err := res.Network.Compile()
	require.NoError(t, err)
	assert.True(t, compiled.Decide("10.0.0.5", 5000).Allowed)
	assert.Equal(t, netpolicy.IPLiteralRule, compiled.Decide("10.0.0.6", 5000).Rule.Raw)
}

func TestNetworkAddsAnAddressAPortWideAllowCoversWhenTheKeyDeniesIt(t *testing.T) {
	parent := &sandbox.SandboxPolicy{Name: "parent", Network: sandbox.NetworkPolicy{AllowOutbound: []string{"*:443"}}}

	res, err := Network(Input{Parent: parent, Destinations: []netpolicy.Destination{dest("10.0.0.5", 443), dest("github.com", 443)}})
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.5:443"}, res.Added, "the key the proposal writes denies the address, so it needs an exact rule")
	assert.Equal(t, VerdictAdd, res.Rows[0].Verdict)
	assert.Equal(t, VerdictParentAllows, res.Rows[1].Verdict)

	off, err := Network(Input{
		Parent:       parent,
		Existing:     &sandbox.NetworkPolicy{DenyIPLiterals: utils.PtrTo(false)},
		Destinations: []netpolicy.Destination{dest("10.0.0.5", 443)},
	})
	require.NoError(t, err)
	assert.Empty(t, off.Added, "with the key off the port-wide allow covers the address")
	assert.Equal(t, VerdictParentAllows, off.Rows[0].Verdict)
}

func TestRenderBlockWritesDenyIPLiteralsFirst(t *testing.T) {
	out := RenderBlock(sandbox.NetworkPolicy{
		DenyIPLiterals: utils.PtrTo(true),
		AllowOutbound:  []string{"a.example:443"},
		DenyOutbound:   []string{"*:*"},
	})
	assert.Equal(t, "network:\n  deny_ip_literals: true\n  allow_outbound:\n    - a.example:443\n  deny_outbound:\n    - \"*:*\"\n", string(out))

	plain := RenderBlock(sandbox.NetworkPolicy{AllowOutbound: []string{"a.example:443"}})
	assert.NotContains(t, string(plain), "deny_ip_literals", "an unset key is not written")
}

func TestSetBlockWritesAndReplacesDenyIPLiterals(t *testing.T) {
	out, err := SetBlock([]byte("name: x\nnetwork:\n  allow_outbound: []\n"), sandbox.NetworkPolicy{DenyIPLiterals: utils.PtrTo(true)})
	require.NoError(t, err)
	assert.Equal(t, "name: x\nnetwork:\n  deny_ip_literals: true\n  allow_outbound: []\n  deny_outbound: []\n", string(out))

	out, err = SetBlock([]byte("name: x\nnetwork:\n  # keep me\n  deny_ip_literals: true\n"), sandbox.NetworkPolicy{DenyIPLiterals: utils.PtrTo(false)})
	require.NoError(t, err)
	assert.Contains(t, string(out), "# keep me\n  deny_ip_literals: false\n")

	out, err = SetBlock([]byte("name: x\nnetwork:\n  deny_ip_literals: true\n"), sandbox.NetworkPolicy{})
	require.NoError(t, err)
	assert.Contains(t, string(out), "deny_ip_literals: true", "an unset key leaves the file's value")
}
