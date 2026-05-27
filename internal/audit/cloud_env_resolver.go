package audit

import (
	"os"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
)

// CloudSinkEnvResolver resolves the runtime environment into an
// EndpointInvocationContext for the cloud sink. Implementations detect
// CI providers, AI agents, or other runtime context from environment
// variables and build the appropriate proto message.
type CloudSinkEnvResolver interface {
	Resolve(command string, workingDirectory string) *controltowerv1.EndpointInvocationContext
}

type defaultEnvResolver struct{}

func DefaultCloudSinkEnvResolver() CloudSinkEnvResolver {
	return &defaultEnvResolver{}
}

func (r *defaultEnvResolver) Resolve(command string, workingDirectory string) *controltowerv1.EndpointInvocationContext {
	ctx := &controltowerv1.EndpointInvocationContext{}
	ctx.SetCommand(command)
	ctx.SetWorkingDirectory(workingDirectory)
	return ctx
}

// GithubActionsCloudSinkEnvResolver returns a resolver that populates
// CI context from GitHub Actions environment variables.
// TODO: Replace stub with full implementation (Task 3).
func GithubActionsCloudSinkEnvResolver() CloudSinkEnvResolver {
	return &githubActionsEnvResolver{}
}

type githubActionsEnvResolver struct{}

func (r *githubActionsEnvResolver) Resolve(command string, workingDirectory string) *controltowerv1.EndpointInvocationContext {
	ctx := &controltowerv1.EndpointInvocationContext{}
	ctx.SetCommand(command)
	ctx.SetWorkingDirectory(workingDirectory)

	ci := &controltowerv1.EndpointCIContext{}
	ci.SetProvider(controltowerv1.EndpointCIProvider_ENDPOINT_CI_PROVIDER_GITHUB_ACTIONS)
	ci.SetRunId(os.Getenv("GITHUB_RUN_ID"))
	ci.SetRepository(os.Getenv("GITHUB_REPOSITORY"))
	ci.SetBranch(os.Getenv("GITHUB_REF_NAME"))
	ci.SetCommitSha(os.Getenv("GITHUB_SHA"))
	ci.SetActor(os.Getenv("GITHUB_ACTOR"))
	ctx.SetCi(ci)

	return ctx
}

// NewCloudSinkEnvResolver detects the runtime environment and returns
// the appropriate resolver. Falls back to the default resolver when
// no CI provider is detected.
func NewCloudSinkEnvResolver() CloudSinkEnvResolver {
	if os.Getenv("GITHUB_ACTIONS") != "" {
		return GithubActionsCloudSinkEnvResolver()
	}
	return DefaultCloudSinkEnvResolver()
}
