package audit

import (
	"testing"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	"github.com/stretchr/testify/assert"
)

func TestGithubActionsResolverBasicFields(t *testing.T) {
	t.Setenv("GITHUB_RUN_ID", "9876543210")
	t.Setenv("GITHUB_REPOSITORY", "safedep/pmg")
	t.Setenv("GITHUB_REF_NAME", "feature/cool")
	t.Setenv("GITHUB_HEAD_REF", "")
	t.Setenv("GITHUB_SHA", "deadbeef1234567890")
	t.Setenv("GITHUB_ACTOR", "octocat")
	t.Setenv("GITHUB_REF", "refs/heads/feature/cool")

	resolver := newGithubActionsCIResolver()

	assert.Equal(t, controltowerv1.EndpointCIProvider_ENDPOINT_CI_PROVIDER_GITHUB_ACTIONS, resolver.Provider())
	assert.Equal(t, "9876543210", resolver.RunId())
	assert.Equal(t, "safedep/pmg", resolver.Repository())
	assert.Equal(t, "feature/cool", resolver.Branch())
	assert.Equal(t, "deadbeef1234567890", resolver.CommitSha())
	assert.Equal(t, "octocat", resolver.Actor())
	assert.Equal(t, "", resolver.PrNumber())
}

func TestGithubActionsResolverPRBranch(t *testing.T) {
	t.Setenv("GITHUB_HEAD_REF", "fix/security-patch")
	t.Setenv("GITHUB_REF_NAME", "123/merge")
	t.Setenv("GITHUB_REF", "refs/pull/42/merge")
	t.Setenv("GITHUB_RUN_ID", "111")
	t.Setenv("GITHUB_REPOSITORY", "safedep/pmg")
	t.Setenv("GITHUB_SHA", "abc")
	t.Setenv("GITHUB_ACTOR", "user")

	resolver := newGithubActionsCIResolver()

	assert.Equal(t, "fix/security-patch", resolver.Branch(), "should prefer GITHUB_HEAD_REF for PRs")
	assert.Equal(t, "42", resolver.PrNumber(), "should extract PR number from GITHUB_REF")
}

func TestGithubActionsResolverMetadata(t *testing.T) {
	t.Setenv("GITHUB_WORKFLOW", "CI")
	t.Setenv("GITHUB_JOB", "build")
	t.Setenv("GITHUB_RUN_ATTEMPT", "1")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")

	resolver := newGithubActionsCIResolver()
	metadata := resolver.Metadata()

	assert.Equal(t, "CI", metadata["workflow"])
	assert.Equal(t, "build", metadata["job"])
	assert.Equal(t, "1", metadata["run_attempt"])
	assert.Equal(t, "https://github.com", metadata["server_url"])
}

func TestGithubActionsResolverMetadataEmpty(t *testing.T) {
	t.Setenv("GITHUB_WORKFLOW", "")
	t.Setenv("GITHUB_JOB", "")
	t.Setenv("GITHUB_RUN_ATTEMPT", "")
	t.Setenv("GITHUB_SERVER_URL", "")

	resolver := newGithubActionsCIResolver()
	assert.Nil(t, resolver.Metadata())
}

func TestGithubActionsResolverNonPRRef(t *testing.T) {
	t.Setenv("GITHUB_HEAD_REF", "")
	t.Setenv("GITHUB_REF_NAME", "main")
	t.Setenv("GITHUB_REF", "refs/heads/main")
	t.Setenv("GITHUB_RUN_ID", "222")
	t.Setenv("GITHUB_REPOSITORY", "safedep/pmg")
	t.Setenv("GITHUB_SHA", "def")
	t.Setenv("GITHUB_ACTOR", "bot")

	resolver := newGithubActionsCIResolver()

	assert.Equal(t, "main", resolver.Branch(), "should use GITHUB_REF_NAME when GITHUB_HEAD_REF is empty")
	assert.Equal(t, "", resolver.PrNumber(), "should be empty for non-PR ref")
}
