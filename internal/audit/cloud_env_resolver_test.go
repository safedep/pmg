package audit

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultCloudSinkEnvResolver(t *testing.T) {
	resolver := DefaultCloudSinkEnvResolver()
	ctx := resolver.Resolve("npm install express", "/home/user/project")

	require.NotNil(t, ctx)
	assert.Equal(t, "npm install express", ctx.GetCommand())
	assert.Equal(t, "/home/user/project", ctx.GetWorkingDirectory())
	assert.False(t, ctx.HasCi())
}

func TestNewCloudSinkEnvResolverReturnsDefault(t *testing.T) {
	os.Unsetenv("GITHUB_ACTIONS")

	resolver := NewCloudSinkEnvResolver()
	ctx := resolver.Resolve("pip install requests", "/tmp")

	require.NotNil(t, ctx)
	assert.False(t, ctx.HasCi())
}

func TestNewCloudSinkEnvResolverReturnsGitHub(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_RUN_ID", "12345")
	t.Setenv("GITHUB_REPOSITORY", "safedep/pmg")
	t.Setenv("GITHUB_REF_NAME", "main")
	t.Setenv("GITHUB_SHA", "abc123")
	t.Setenv("GITHUB_ACTOR", "dependabot[bot]")

	resolver := NewCloudSinkEnvResolver()
	ctx := resolver.Resolve("npm install", "/workspace")

	require.NotNil(t, ctx)
	assert.True(t, ctx.HasCi())
	assert.Equal(t, "safedep/pmg", ctx.GetCi().GetRepository())
}
