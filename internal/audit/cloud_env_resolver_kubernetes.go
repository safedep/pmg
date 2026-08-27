package audit

import (
	"os"
	"regexp"
	"strings"

	"github.com/safedep/dry/log"
)

// Kubernetes runtime seams. Production uses the real calls. Tests override
// these package vars, following the auditGeteuid pattern in cloud_sink.go.
// os.Getenv needs no seam because tests use t.Setenv, and log.Warnf needs
// none because tests use drylog.SwapGlobalForTest.
var (
	kubernetesNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	kubernetesHostname      = os.Hostname
)

// Kubernetes generated-name patterns. The pod-template hash uses the reduced
// alphabet that Kubernetes applies to avoid vowels. The five-character suffix
// is the random tail on ReplicaSet, Job, and DaemonSet Pods.
var (
	kubernetesOrdinalPattern     = regexp.MustCompile(`^\d+$`)
	kubernetesPodTemplateHash    = regexp.MustCompile(`^[bcdfghjklmnpqrstvwxz2456789]{6,10}$`)
	kubernetesGeneratedPodSuffix = regexp.MustCompile(`^[a-z0-9]{5}$`)
)

type cloudSinkKubernetesContext struct {
	Cluster      string
	Namespace    string
	WorkloadName string
	WorkloadKind string
	PodName      string
	PodUID       string
}

func newCloudSinkKubernetesContext() *cloudSinkKubernetesContext {
	return resolveKubernetesContext()
}

func resolveKubernetesContext() *cloudSinkKubernetesContext {
	env := func(key string) string {
		return strings.TrimSpace(os.Getenv(key))
	}

	fileNamespace := ""
	if data, err := os.ReadFile(kubernetesNamespacePath); err == nil {
		fileNamespace = strings.TrimSpace(string(data))
	}

	namespace := fileNamespace
	if namespace == "" {
		namespace = env("KUBE_NAMESPACE")
	}

	explicitContext := namespace != "" &&
		(env("KUBE_POD_NAME") != "" || env("KUBE_WORKLOAD_NAME") != "")
	if env("KUBERNETES_SERVICE_HOST") == "" && fileNamespace == "" && !explicitContext {
		return nil
	}

	podName := env("KUBE_POD_NAME")
	if podName == "" {
		if hostname, err := kubernetesHostname(); err == nil {
			podName = strings.TrimSpace(hostname)
		}
	}

	workloadName := env("KUBE_WORKLOAD_NAME")
	if workloadName == "" {
		derived, stable := kubernetesWorkloadName(podName)
		workloadName = derived
		if !stable {
			log.Warnf("PMG cannot derive a stable Kubernetes workload name from Pod %q. Set KUBE_WORKLOAD_NAME.", podName)
		}
	}

	return &cloudSinkKubernetesContext{
		Cluster:      env("KUBE_CLUSTER_NAME"),
		Namespace:    namespace,
		WorkloadName: workloadName,
		WorkloadKind: env("KUBE_WORKLOAD_KIND"),
		PodName:      podName,
		PodUID:       env("KUBE_POD_UID"),
	}
}

// kubernetesWorkloadName derives a stable workload name from a Pod name. It
// removes generated controller suffixes in a fixed order. The second result
// reports whether a known suffix was recognized. It returns the full Pod name
// with false when no rule matches, so the caller can warn and still produce an
// endpoint ID. It does not infer the workload kind.
//
// The two-segment strippers run before the single ordinal rule. A Deployment
// Pod is <workload>-<pod-template-hash>-<random5>, and the random suffix can be
// all digits. If the ordinal rule ran first, it would strip only that suffix
// and keep the hash, which churns on every rollout.
func kubernetesWorkloadName(podName string) (string, bool) {
	segments := strings.Split(podName, "-")
	last := len(segments) - 1

	switch {
	case len(segments) >= 3 && kubernetesPodTemplateHash.MatchString(segments[last-1]):
		return strings.Join(segments[:last-1], "-"), true
	case len(segments) >= 3 && kubernetesOrdinalPattern.MatchString(segments[last-1]) && kubernetesGeneratedPodSuffix.MatchString(segments[last]):
		return strings.Join(segments[:last-1], "-"), true
	case len(segments) >= 2 && kubernetesOrdinalPattern.MatchString(segments[last]):
		return strings.Join(segments[:last], "-"), true
	case len(segments) >= 2 && kubernetesGeneratedPodSuffix.MatchString(segments[last]):
		return strings.Join(segments[:last], "-"), true
	default:
		return podName, false
	}
}
