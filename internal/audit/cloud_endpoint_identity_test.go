package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultCIEndpointID(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "no CI detected returns empty",
			env: map[string]string{
				"GITHUB_ACTIONS": "",
			},
			want: "",
		},
		{
			name: "hosted github actions derives repository-scoped identity",
			env: map[string]string{
				"GITHUB_ACTIONS":     "true",
				"GITHUB_RUN_ID":      "12345",
				"GITHUB_REPOSITORY":  "safedep/pmg",
				"RUNNER_ENVIRONMENT": "github-hosted",
			},
			want: "gh:safedep/pmg",
		},
		{
			name: "self-hosted runner keeps the host identity",
			env: map[string]string{
				"GITHUB_ACTIONS":     "true",
				"GITHUB_RUN_ID":      "12345",
				"GITHUB_REPOSITORY":  "safedep/pmg",
				"RUNNER_ENVIRONMENT": "self-hosted",
			},
			want: "",
		},
		{
			name: "hosted github actions without repository returns empty",
			env: map[string]string{
				"GITHUB_ACTIONS":     "true",
				"GITHUB_RUN_ID":      "12345",
				"GITHUB_REPOSITORY":  "",
				"RUNNER_ENVIRONMENT": "github-hosted",
			},
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for key, value := range tc.env {
				t.Setenv(key, value)
			}

			assert.Equal(t, tc.want, defaultCIEndpointID())
		})
	}
}

func TestKubernetesEndpointID(t *testing.T) {
	assert.Equal(t, "k8s:payments/checkout",
		kubernetesEndpointID(&cloudSinkKubernetesContext{Namespace: "payments", WorkloadName: "checkout"}))
	assert.Equal(t, "k8s:prod-eu/payments/checkout",
		kubernetesEndpointID(&cloudSinkKubernetesContext{Cluster: "prod-eu", Namespace: "payments", WorkloadName: "checkout"}))
	assert.Empty(t, kubernetesEndpointID(&cloudSinkKubernetesContext{Namespace: "payments"}))
	assert.Empty(t, kubernetesEndpointID(&cloudSinkKubernetesContext{WorkloadName: "checkout"}))
	assert.Empty(t, kubernetesEndpointID(nil))
}

func TestResolveCloudEndpointID(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		env        map[string]string
		want       string
	}{
		{
			name:       "configured endpoint wins over hosted CI and Kubernetes",
			configured: "team/service",
			env: map[string]string{
				"GITHUB_ACTIONS":     "true",
				"GITHUB_RUN_ID":      "12345",
				"GITHUB_REPOSITORY":  "safedep/pmg",
				"RUNNER_ENVIRONMENT": "github-hosted",
				"KUBE_NAMESPACE":     "payments",
				"KUBE_WORKLOAD_NAME": "checkout",
			},
			want: "team/service",
		},
		{
			name: "hosted github actions wins over Kubernetes",
			env: map[string]string{
				"GITHUB_ACTIONS":          "true",
				"GITHUB_RUN_ID":           "12345",
				"GITHUB_REPOSITORY":       "safedep/pmg",
				"RUNNER_ENVIRONMENT":      "github-hosted",
				"KUBERNETES_SERVICE_HOST": "10.0.0.1",
				"KUBE_NAMESPACE":          "payments",
				"KUBE_WORKLOAD_NAME":      "checkout",
			},
			want: "gh:safedep/pmg",
		},
		{
			name: "kubernetes wins without configured or hosted CI",
			env: map[string]string{
				"GITHUB_ACTIONS":     "",
				"GITHUB_RUN_ID":      "",
				"KUBE_NAMESPACE":     "payments",
				"KUBE_WORKLOAD_NAME": "checkout",
				"KUBE_CLUSTER_NAME":  "prod-eu",
			},
			want: "k8s:prod-eu/payments/checkout",
		},
		{
			name: "no automatic context returns empty",
			env: map[string]string{
				"GITHUB_ACTIONS":          "",
				"GITHUB_RUN_ID":           "",
				"KUBERNETES_SERVICE_HOST": "",
				"KUBE_NAMESPACE":          "",
				"KUBE_POD_NAME":           "",
				"KUBE_WORKLOAD_NAME":      "",
			},
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for key, value := range tc.env {
				t.Setenv(key, value)
			}

			assert.Equal(t, tc.want, resolveCloudEndpointID(tc.configured))
		})
	}
}
