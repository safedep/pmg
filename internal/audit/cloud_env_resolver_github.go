package audit

import (
	"os"
	"regexp"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
)

var prRefPattern = regexp.MustCompile(`^refs/pull/(\d+)/merge$`)

type githubActionsEnvResolver struct{}

func GithubActionsCloudSinkEnvResolver() CloudSinkEnvResolver {
	return &githubActionsEnvResolver{}
}

func (r *githubActionsEnvResolver) Resolve(command string, workingDirectory string) *controltowerv1.EndpointInvocationContext {
	ci := &controltowerv1.EndpointCIContext{}
	ci.SetProvider(controltowerv1.EndpointCIProvider_ENDPOINT_CI_PROVIDER_GITHUB_ACTIONS)
	ci.SetRunId(os.Getenv("GITHUB_RUN_ID"))
	ci.SetRepository(os.Getenv("GITHUB_REPOSITORY"))
	ci.SetBranch(r.resolveBranch())
	ci.SetCommitSha(os.Getenv("GITHUB_SHA"))
	ci.SetActor(os.Getenv("GITHUB_ACTOR"))
	ci.SetPrNumber(r.extractPRNumber())

	ctx := &controltowerv1.EndpointInvocationContext{}
	ctx.SetCommand(command)
	ctx.SetWorkingDirectory(workingDirectory)
	ctx.SetCi(ci)
	return ctx
}

func (r *githubActionsEnvResolver) resolveBranch() string {
	if headRef := os.Getenv("GITHUB_HEAD_REF"); headRef != "" {
		return headRef
	}
	return os.Getenv("GITHUB_REF_NAME")
}

func (r *githubActionsEnvResolver) extractPRNumber() string {
	matches := prRefPattern.FindStringSubmatch(os.Getenv("GITHUB_REF"))
	if len(matches) == 2 {
		return matches[1]
	}
	return ""
}
