package netenforce

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveUIDs(t *testing.T) {
	uids, err := resolveUIDs([]string{"0", "65534"})
	require.NoError(t, err)
	assert.Equal(t, []uint32{0, 65534}, uids)

	_, err = resolveUIDs([]string{"pmg-no-such-user-0b1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pmg-no-such-user-0b1")
}

func TestPolicyValidateResolvesUsers(t *testing.T) {
	p := DefaultPolicy()
	p.EligibleUsers = []string{"0"}
	p.ExemptUsers = []string{"65534"}
	require.NoError(t, p.Validate())

	p.ExemptUsers = []string{"pmg-no-such-user-0b1"}
	err := p.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pmg-no-such-user-0b1")
}
