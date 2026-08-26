package audit

import (
	"os"
	"strings"

	"github.com/safedep/dry/log"
)

const kubernetesServiceAccountNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

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

	return &cloudSinkKubernetesContext{
		Cluster:      env("KUBE_CLUSTER_NAME"),
		Namespace:    namespace,
		WorkloadName: env("KUBE_WORKLOAD_NAME"),
		WorkloadKind: env("KUBE_WORKLOAD_KIND"),
		PodName:      podName,
		PodUID:       env("KUBE_POD_UID"),
	}
}
