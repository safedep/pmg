package flows

import (
	"sync"
	"testing"

	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/executor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEgressRecorderRecordsUniqueDenials(t *testing.T) {
	m, err := sandbox.NewOutboundMatcher(sandbox.NetworkPolicy{
		AllowOutbound: []string{"registry.npmjs.org:443"},
	})
	require.NoError(t, err)

	r := newEgressRecorder(m)
	assert.True(t, r.Allows("registry.npmjs.org", 443))
	assert.False(t, r.Allows("b.example", 443))
	assert.False(t, r.Allows("a.example", 443))
	assert.False(t, r.Allows("b.example", 443))
	assert.False(t, r.Allows("2001:db8::1", 443))

	assert.Equal(t, []string{"[2001:db8::1]:443", "a.example:443", "b.example:443"}, r.Denied())
}

func TestEgressPolicyFor(t *testing.T) {
	m, err := sandbox.NewOutboundMatcher(sandbox.NetworkPolicy{DenyOutbound: []string{"*:*"}})
	require.NoError(t, err)

	t.Run("no outbound rules gives a nil interface", func(t *testing.T) {
		recorder, policy := egressPolicyFor(&executor.Resolution{PackageManager: "npm"})
		assert.Nil(t, recorder)
		// A typed nil in the interface would make the proxy enforce rules.
		assert.True(t, policy == nil)
	})

	t.Run("outbound rules give a recorder", func(t *testing.T) {
		recorder, policy := egressPolicyFor(&executor.Resolution{PackageManager: "npm", Outbound: m})
		require.NotNil(t, recorder)
		require.NotNil(t, policy)
		assert.False(t, policy.Allows("evil.example", 443))
		assert.Equal(t, []string{"evil.example:443"}, recorder.Denied())
	})
}

func TestEgressRecorderIsSafeForConcurrentUse(t *testing.T) {
	m, err := sandbox.NewOutboundMatcher(sandbox.NetworkPolicy{DenyOutbound: []string{"*:*"}})
	require.NoError(t, err)

	r := newEgressRecorder(m)

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Allows("evil.example", 443)
		}()
	}
	wg.Wait()

	assert.Equal(t, []string{"evil.example:443"}, r.Denied())
}
