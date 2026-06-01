package audit

import (
	"os"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
)

// CloudSinkCIResolver resolves CI/CD environment context for the cloud
// sink. Implementations detect CI providers from environment variables
// and expose individual fields. The cloudSink assembles the
// EndpointCIContext proto from these.
type CloudSinkCIResolver interface {
	// Provider returns the detected CI provider.
	Provider() controltowerv1.EndpointCIProvider

	// RunId returns the CI run identifier.
	RunId() string

	// Repository returns the repository being built.
	Repository() string

	// Branch returns the branch being built.
	Branch() string

	// CommitSha returns the commit SHA being built.
	CommitSha() string

	// Actor returns the user or bot that triggered the build.
	Actor() string

	// PrNumber returns the pull request number, if applicable.
	PrNumber() string

	// Metadata returns provider-specific key-value pairs.
	Metadata() map[string]string
}

// newCloudSinkCIResolver detects the CI environment and returns the
// appropriate resolver. Returns nil when no CI provider is detected.
func newCloudSinkCIResolver() CloudSinkCIResolver {
	if os.Getenv("GITHUB_ACTIONS") != "" && os.Getenv("GITHUB_RUN_ID") != "" {
		return newGithubActionsCIResolver()
	}
	return nil
}
