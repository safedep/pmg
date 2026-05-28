package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCloudSinkCIResolverReturnsNilWhenNoCI(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")

	resolver := newCloudSinkCIResolver()
	assert.Nil(t, resolver)
}

func TestNewCloudSinkCIResolverReturnsNilWhenPartialEnv(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_RUN_ID", "")

	resolver := newCloudSinkCIResolver()
	assert.Nil(t, resolver)
}

func TestNewCloudSinkCIResolverReturnsGitHub(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_RUN_ID", "12345")
	t.Setenv("GITHUB_REPOSITORY", "safedep/pmg")
	t.Setenv("GITHUB_REF_NAME", "main")
	t.Setenv("GITHUB_SHA", "abc123")
	t.Setenv("GITHUB_ACTOR", "dependabot[bot]")

	resolver := newCloudSinkCIResolver()
	require.NotNil(t, resolver)
	assert.Equal(t, "safedep/pmg", resolver.Repository())
}
