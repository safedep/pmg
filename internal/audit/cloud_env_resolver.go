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

// NewCloudSinkEnvResolver detects the runtime environment and returns
// the appropriate resolver. Falls back to the default resolver when
// no CI provider is detected.
func NewCloudSinkEnvResolver() CloudSinkEnvResolver {
	if os.Getenv("GITHUB_ACTIONS") != "" {
		return GithubActionsCloudSinkEnvResolver()
	}
	return DefaultCloudSinkEnvResolver()
}
