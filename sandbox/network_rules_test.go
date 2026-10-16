package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNetworkPolicyAllowRemovesTheEqualDeny(t *testing.T) {
	n := NetworkPolicy{DenyOutbound: []string{"Example.com.:443", "*:*", "evil.example:443"}}
	n.Allow("example.com:443")

	assert.Equal(t, []string{"example.com:443"}, n.AllowOutbound)
	assert.Equal(t, []string{"*:*", "evil.example:443"}, n.DenyOutbound, "the deny is removed as the matcher reads it, whatever its case or trailing dot")

	n.Deny("pastebin.com:443")
	assert.Equal(t, []string{"*:*", "evil.example:443", "pastebin.com:443"}, n.DenyOutbound)
}
