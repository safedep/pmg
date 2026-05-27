package audit

import (
	"testing"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGithubActionsResolverBasicFields(t *testing.T) {
	t.Setenv("GITHUB_RUN_ID", "9876543210")
	t.Setenv("GITHUB_REPOSITORY", "safedep/pmg")
	t.Setenv("GITHUB_REF_NAME", "feature/cool")
	t.Setenv("GITHUB_HEAD_REF", "")
	t.Setenv("GITHUB_SHA", "deadbeef1234567890")
	t.Setenv("GITHUB_ACTOR", "octocat")
	t.Setenv("GITHUB_REF", "refs/heads/feature/cool")

	resolver := GithubActionsCloudSinkEnvResolver()
	ctx := resolver.Resolve("npm install express", "/home/runner/work/pmg/pmg")

	require.NotNil(t, ctx)
	assert.Equal(t, "npm install express", ctx.GetCommand())
	assert.Equal(t, "/home/runner/work/pmg/pmg", ctx.GetWorkingDirectory())

	ci := ctx.GetCi()
	require.NotNil(t, ci)
	assert.Equal(t, controltowerv1.EndpointCIProvider_ENDPOINT_CI_PROVIDER_GITHUB_ACTIONS, ci.GetProvider())
	assert.Equal(t, "9876543210", ci.GetRunId())
	assert.Equal(t, "safedep/pmg", ci.GetRepository())
	assert.Equal(t, "feature/cool", ci.GetBranch())
	assert.Equal(t, "deadbeef1234567890", ci.GetCommitSha())
	assert.Equal(t, "octocat", ci.GetActor())
	assert.Equal(t, "", ci.GetPrNumber())
}

func TestGithubActionsResolverPRBranch(t *testing.T) {
	t.Setenv("GITHUB_HEAD_REF", "fix/security-patch")
	t.Setenv("GITHUB_REF_NAME", "123/merge")
	t.Setenv("GITHUB_REF", "refs/pull/42/merge")
	t.Setenv("GITHUB_RUN_ID", "111")
	t.Setenv("GITHUB_REPOSITORY", "safedep/pmg")
	t.Setenv("GITHUB_SHA", "abc")
	t.Setenv("GITHUB_ACTOR", "user")

	resolver := GithubActionsCloudSinkEnvResolver()
	ctx := resolver.Resolve("pip install requests", "/workspace")

	ci := ctx.GetCi()
	require.NotNil(t, ci)
	assert.Equal(t, "fix/security-patch", ci.GetBranch(), "should prefer GITHUB_HEAD_REF for PRs")
	assert.Equal(t, "42", ci.GetPrNumber(), "should extract PR number from GITHUB_REF")
}

func TestGithubActionsResolverNonPRRef(t *testing.T) {
	t.Setenv("GITHUB_HEAD_REF", "")
	t.Setenv("GITHUB_REF_NAME", "main")
	t.Setenv("GITHUB_REF", "refs/heads/main")
	t.Setenv("GITHUB_RUN_ID", "222")
	t.Setenv("GITHUB_REPOSITORY", "safedep/pmg")
	t.Setenv("GITHUB_SHA", "def")
	t.Setenv("GITHUB_ACTOR", "bot")

	resolver := GithubActionsCloudSinkEnvResolver()
	ctx := resolver.Resolve("yarn add lodash", "/app")

	ci := ctx.GetCi()
	require.NotNil(t, ci)
	assert.Equal(t, "main", ci.GetBranch(), "should use GITHUB_REF_NAME when GITHUB_HEAD_REF is empty")
	assert.Equal(t, "", ci.GetPrNumber(), "should be empty for non-PR ref")
}
