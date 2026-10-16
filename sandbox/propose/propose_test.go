package propose

import (
	"testing"

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
