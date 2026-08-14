package audit

import (
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
)

// defaultCIEndpointID derives a stable endpoint identity for an unconfigured
// run on hosted CI. A hosted runner's machine ID churns per job, so without a
// stable identity every job would register a fresh endpoint. The derived
// identity is provider-prefixed and repository-scoped (for example
// "gh:safedep/pmg"), so all jobs of a repository sync as one endpoint. A
// configured cloud.endpoint_id always overrides this for finer segmentation.
// Returns empty when no CI is detected or the provider exposes no repository.
func defaultCIEndpointID() string {
	resolver := newCloudSinkCIResolver()
	if resolver == nil {
		return ""
	}

	prefix := ciProviderIDPrefix(resolver.Provider())
	repository := resolver.Repository()
	if prefix == "" || repository == "" {
		return ""
	}

	return prefix + ":" + repository
}

func ciProviderIDPrefix(provider controltowerv1.EndpointCIProvider) string {
	switch provider {
	case controltowerv1.EndpointCIProvider_ENDPOINT_CI_PROVIDER_GITHUB_ACTIONS:
		return "gh"
	default:
		return ""
	}
}
