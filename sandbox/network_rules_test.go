package sandbox

import (
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/proxy/netpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkPolicyAllowRemovesTheEqualDeny(t *testing.T) {
	n := NetworkPolicy{DenyOutbound: []string{"Example.com.:443", "*:*", "evil.example:443"}}
	n.Allow("example.com:443")

	assert.Equal(t, []string{"example.com:443"}, n.AllowOutbound)
	assert.Equal(t, []string{"*:*", "evil.example:443"}, n.DenyOutbound, "the deny is removed as the matcher reads it, whatever its case or trailing dot")

	n.Deny("pastebin.com:443")
	assert.Equal(t, []string{"*:*", "evil.example:443", "pastebin.com:443"}, n.DenyOutbound)
}

func TestNetworkPolicyCompileCarriesDenyIPLiterals(t *testing.T) {
	rules := NetworkPolicy{AllowOutbound: []string{"registry.npmjs.org:443"}, DenyOutbound: []string{"*:*"}}

	open, err := rules.Compile()
	require.NoError(t, err)
	assert.False(t, open.DeniesIPLiterals())
	assert.Equal(t, "*:*", open.Decide("10.0.0.5", 443).Rule.Raw)

	rules.DenyIPLiterals = utils.PtrTo(true)
	closed, err := rules.Compile()
	require.NoError(t, err)
	assert.True(t, closed.DeniesIPLiterals())
	assert.Equal(t, netpolicy.IPLiteralRule, closed.Decide("10.0.0.5", 443).Rule.Raw)
	assert.True(t, closed.Decide("registry.npmjs.org", 443).Allowed)

	rules.AllowOutbound = append(rules.AllowOutbound, "registry.npmjs.org")
	_, err = rules.Compile()
	require.Error(t, err, "an invalid rule still fails the compile")
}
