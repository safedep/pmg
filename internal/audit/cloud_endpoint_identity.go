package audit

import (
	"fmt"
	"strings"

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

	// Only a hosted, ephemeral runner gets the repository-scoped default. A
	// self-hosted runner is a persistent machine with a stable machine id,
	// and its sync WAL is shared across the repositories it builds: a
	// sync-time repository label could misattribute another repository's
	// queued events. An ephemeral self-hosted fleet configures
	// cloud.endpoint_id explicitly.
	if !resolver.HostedRunner() {
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

// kubernetesEndpointID formats a stable endpoint identity for a Kubernetes
// workload. All replicas of one workload share this identity. It returns empty
// when namespace or workload name is absent, so the caller keeps the existing
// machine identity. It adds the cluster prefix only when the platform provides
// one.
func kubernetesEndpointID(ctx *cloudSinkKubernetesContext) string {
	if ctx == nil || ctx.Namespace == "" || ctx.WorkloadName == "" {
		return ""
	}
	if ctx.Cluster != "" {
		// KUBE_CLUSTER_NAME is free-form operator env. A "/" would make the ID
		// ambiguous against the 3-part form, so replace it. Namespace and
		// workload cannot hold a "/".
		cluster := strings.ReplaceAll(ctx.Cluster, "/", "_")
		return fmt.Sprintf("k8s:%s/%s/%s", cluster, ctx.Namespace, ctx.WorkloadName)
	}
	return fmt.Sprintf("k8s:%s/%s", ctx.Namespace, ctx.WorkloadName)
}

// defaultKubernetesEndpointID resolves the process Kubernetes context and
// formats its endpoint identity. It returns empty outside Kubernetes or when
// required fields are absent.
func defaultKubernetesEndpointID() string {
	return kubernetesEndpointID(newCloudSinkKubernetesContext())
}

// resolveCloudEndpointID selects the endpoint identity in priority order. A
// configured value wins first. A hosted CI identity wins next. A Kubernetes
// identity wins next. It returns empty when none applies, so the caller keeps
// DRY's existing machine identity.
func resolveCloudEndpointID(configured string) string {
	if configured != "" {
		return configured
	}
	if id := defaultCIEndpointID(); id != "" {
		return id
	}
	return defaultKubernetesEndpointID()
}
