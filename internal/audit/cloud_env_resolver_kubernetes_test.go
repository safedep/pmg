package audit

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveKubernetesContextDetection(t *testing.T) {
	cases := []struct {
		name      string
		env       map[string]string
		namespace string
		wantNil   bool
	}{
		{
			name: "service host detects Kubernetes",
			env: map[string]string{
				"KUBERNETES_SERVICE_HOST": "10.0.0.1",
			},
		},
		{
			name:      "namespace file detects Kubernetes",
			namespace: "payments",
		},
		{
			name: "explicit namespace and pod detect Kubernetes",
			env: map[string]string{
				"KUBE_NAMESPACE": "payments",
				"KUBE_POD_NAME":  "api-0",
			},
		},
		{
			name: "explicit namespace and workload detect Kubernetes",
			env: map[string]string{
				"KUBE_NAMESPACE":     "payments",
				"KUBE_WORKLOAD_NAME": "api",
			},
		},
		{
			name: "namespace alone is not an explicit signal",
			env: map[string]string{
				"KUBE_NAMESPACE": "payments",
			},
			wantNil: true,
		},
		{
			name:    "no signal stays outside Kubernetes",
			wantNil: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := resolveKubernetesContext(kubernetesTestResolverDeps(tc.env, tc.namespace, nil, "host-pod", nil, nil))
			if tc.wantNil {
				assert.Nil(t, ctx)
				return
			}
			require.NotNil(t, ctx)
		})
	}
}

func TestResolveKubernetesContextSourcePrecedence(t *testing.T) {
	env := map[string]string{
		"KUBERNETES_SERVICE_HOST": " 10.0.0.1 ",
		"KUBE_CLUSTER_NAME":       " prod-eu ",
		"KUBE_NAMESPACE":          " env-namespace ",
		"KUBE_WORKLOAD_NAME":      " checkout ",
		"KUBE_WORKLOAD_KIND":      " Deployment ",
		"KUBE_POD_NAME":           " checkout-explicit ",
		"KUBE_POD_UID":            " pod-uid ",
	}

	ctx := resolveKubernetesContext(kubernetesTestResolverDeps(env, " file-namespace\n", nil, "hostname-pod", nil, nil))
	require.NotNil(t, ctx)
	assert.Equal(t, "prod-eu", ctx.Cluster)
	assert.Equal(t, "file-namespace", ctx.Namespace)
	assert.Equal(t, "checkout", ctx.WorkloadName)
	assert.Equal(t, "Deployment", ctx.WorkloadKind)
	assert.Equal(t, "checkout-explicit", ctx.PodName)
	assert.Equal(t, "pod-uid", ctx.PodUID)
}

func TestResolveKubernetesContextUsesFallbacks(t *testing.T) {
	t.Run("namespace file error uses explicit namespace", func(t *testing.T) {
		env := map[string]string{
			"KUBERNETES_SERVICE_HOST": "10.0.0.1",
			"KUBE_NAMESPACE":          "payments",
			"KUBE_WORKLOAD_NAME":      "api",
		}
		ctx := resolveKubernetesContext(kubernetesTestResolverDeps(env, "", errors.New("not mounted"), "api-host", nil, nil))
		require.NotNil(t, ctx)
		assert.Equal(t, "payments", ctx.Namespace)
	})

	t.Run("missing pod environment uses hostname", func(t *testing.T) {
		env := map[string]string{
			"KUBERNETES_SERVICE_HOST": "10.0.0.1",
			"KUBE_WORKLOAD_NAME":      "api",
		}
		ctx := resolveKubernetesContext(kubernetesTestResolverDeps(env, "payments", nil, "api-host", nil, nil))
		require.NotNil(t, ctx)
		assert.Equal(t, "api-host", ctx.PodName)
	})

	t.Run("hostname error leaves pod empty", func(t *testing.T) {
		env := map[string]string{
			"KUBERNETES_SERVICE_HOST": "10.0.0.1",
			"KUBE_WORKLOAD_NAME":      "api",
		}
		ctx := resolveKubernetesContext(kubernetesTestResolverDeps(env, "payments", nil, "", errors.New("hostname unavailable"), nil))
		require.NotNil(t, ctx)
		assert.Empty(t, ctx.PodName)
	})
}

func kubernetesTestResolverDeps(env map[string]string, namespace string, namespaceErr error, hostname string, hostnameErr error, warnings *[]string) kubernetesResolverDeps {
	return kubernetesResolverDeps{
		getenv: func(key string) string {
			return env[key]
		},
		readFile: func(path string) ([]byte, error) {
			if path != kubernetesServiceAccountNamespacePath {
				return nil, fmt.Errorf("unexpected path: %s", path)
			}
			return []byte(namespace), namespaceErr
		},
		hostname: func() (string, error) {
			return hostname, hostnameErr
		},
		warnf: func(format string, args ...any) {
			if warnings != nil {
				*warnings = append(*warnings, fmt.Sprintf(format, args...))
			}
		},
	}
}
