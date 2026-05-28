package audit

import (
	"os"
	"regexp"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
)

var prRefPattern = regexp.MustCompile(`^refs/pull/(\d+)/merge$`)

type githubActionsEnvResolver struct{}

func newGithubActionsCIResolver() CloudSinkCIResolver {
	return &githubActionsEnvResolver{}
}

func (r *githubActionsEnvResolver) Provider() controltowerv1.EndpointCIProvider {
	return controltowerv1.EndpointCIProvider_ENDPOINT_CI_PROVIDER_GITHUB_ACTIONS
}

func (r *githubActionsEnvResolver) RunId() string      { return os.Getenv("GITHUB_RUN_ID") }
func (r *githubActionsEnvResolver) Repository() string  { return os.Getenv("GITHUB_REPOSITORY") }
func (r *githubActionsEnvResolver) CommitSha() string   { return os.Getenv("GITHUB_SHA") }
func (r *githubActionsEnvResolver) Actor() string       { return os.Getenv("GITHUB_ACTOR") }

func (r *githubActionsEnvResolver) Branch() string {
	if headRef := os.Getenv("GITHUB_HEAD_REF"); headRef != "" {
		return headRef
	}
	return os.Getenv("GITHUB_REF_NAME")
}

func (r *githubActionsEnvResolver) PrNumber() string {
	matches := prRefPattern.FindStringSubmatch(os.Getenv("GITHUB_REF"))
	if len(matches) == 2 {
		return matches[1]
	}
	return ""
}

func (r *githubActionsEnvResolver) Metadata() map[string]string {
	entries := []struct {
		key    string
		envVar string
	}{
		{"workflow", "GITHUB_WORKFLOW"},
		{"job", "GITHUB_JOB"},
		{"run_attempt", "GITHUB_RUN_ATTEMPT"},
		{"server_url", "GITHUB_SERVER_URL"},
	}

	metadata := make(map[string]string)
	for _, e := range entries {
		if val := os.Getenv(e.envVar); val != "" {
			metadata[e.key] = val
		}
	}

	if len(metadata) == 0 {
		return nil
	}
	return metadata
}
