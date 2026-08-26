package audit

import (
	"os"
	"regexp"
	"strings"

	"github.com/safedep/dry/log"
)

const kubernetesServiceAccountNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

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

type kubernetesResolverDeps struct {
	getenv   func(string) string
	readFile func(string) ([]byte, error)
	hostname func() (string, error)
	warnf    func(string, ...any)
}

func newCloudSinkKubernetesContext() *cloudSinkKubernetesContext {
	return resolveKubernetesContext(kubernetesResolverDeps{
		getenv:   os.Getenv,
		readFile: os.ReadFile,
		hostname: os.Hostname,
		warnf:    log.Warnf,
	})
}

func resolveKubernetesContext(deps kubernetesResolverDeps) *cloudSinkKubernetesContext {
	env := func(key string) string {
		return strings.TrimSpace(deps.getenv(key))
	}

	namespaceBytes, namespaceErr := deps.readFile(kubernetesServiceAccountNamespacePath)
	fileNamespace := ""
	if namespaceErr == nil {
		fileNamespace = strings.TrimSpace(string(namespaceBytes))
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
		if hostname, err := deps.hostname(); err == nil {
			podName = strings.TrimSpace(hostname)
		}
	}

	workloadName := env("KUBE_WORKLOAD_NAME")
	if workloadName == "" {
		derived, stable := kubernetesWorkloadName(podName)
		workloadName = derived
		if !stable {
			deps.warnf("PMG cannot derive a stable Kubernetes workload name from Pod %q. Set KUBE_WORKLOAD_NAME.", podName)
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
func kubernetesWorkloadName(podName string) (string, bool) {
	segments := strings.Split(podName, "-")
	last := len(segments) - 1

	switch {
	case len(segments) >= 2 && kubernetesOrdinalPattern.MatchString(segments[last]):
		return strings.Join(segments[:last], "-"), true
	case len(segments) >= 3 && kubernetesPodTemplateHash.MatchString(segments[last-1]):
		return strings.Join(segments[:last-1], "-"), true
	case len(segments) >= 3 && kubernetesOrdinalPattern.MatchString(segments[last-1]) && kubernetesGeneratedPodSuffix.MatchString(segments[last]):
		return strings.Join(segments[:last-1], "-"), true
	case len(segments) >= 2 && kubernetesGeneratedPodSuffix.MatchString(segments[last]):
		return strings.Join(segments[:last], "-"), true
	default:
		return podName, false
	}
}
