package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clearKubernetesEnv clears every environment variable the resolver reads, so
// ambient values on a Kubernetes host do not leak into a test.
func clearKubernetesEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"KUBERNETES_SERVICE_HOST", "KUBE_NAMESPACE", "KUBE_POD_NAME",
		"KUBE_WORKLOAD_NAME", "KUBE_CLUSTER_NAME", "KUBE_WORKLOAD_KIND", "KUBE_POD_UID",
	} {
		t.Setenv(key, "")
	}
}

// setKubernetesNamespaceFile points the resolver at a temp namespace file, or
// at an absent path when present is false. This keeps the test independent of
// the host service-account mount.
func setKubernetesNamespaceFile(t *testing.T, present bool, content string) {
	t.Helper()
	orig := kubernetesNamespacePath
	t.Cleanup(func() { kubernetesNamespacePath = orig })
	if !present {
		kubernetesNamespacePath = filepath.Join(t.TempDir(), "absent")
		return
	}
	path := filepath.Join(t.TempDir(), "namespace")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	kubernetesNamespacePath = path
}

func setKubernetesHostname(t *testing.T, name string, err error) {
	t.Helper()
	orig := kubernetesHostname
	t.Cleanup(func() { kubernetesHostname = orig })
	kubernetesHostname = func() (string, error) { return name, err }
}

func captureKubernetesWarnings(t *testing.T) *[]string {
	t.Helper()
	orig := kubernetesWarnf
	t.Cleanup(func() { kubernetesWarnf = orig })
	var warnings []string
	kubernetesWarnf = func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	}
	return &warnings
}

func TestResolveKubernetesContextDetection(t *testing.T) {
	cases := []struct {
		name      string
		env       map[string]string
		hasNSFile bool
		nsFile    string
		wantNil   bool
	}{
		{
			name: "service host detects Kubernetes",
			env:  map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1"},
		},
		{
			name:      "namespace file detects Kubernetes",
			hasNSFile: true,
			nsFile:    "payments",
		},
		{
			name: "explicit namespace and pod detect Kubernetes",
			env:  map[string]string{"KUBE_NAMESPACE": "payments", "KUBE_POD_NAME": "api-0"},
		},
		{
			name: "explicit namespace and workload detect Kubernetes",
			env:  map[string]string{"KUBE_NAMESPACE": "payments", "KUBE_WORKLOAD_NAME": "api"},
		},
		{
			name:    "namespace alone is not an explicit signal",
			env:     map[string]string{"KUBE_NAMESPACE": "payments"},
			wantNil: true,
		},
		{
			name:    "no signal stays outside Kubernetes",
			wantNil: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearKubernetesEnv(t)
			for key, value := range tc.env {
				t.Setenv(key, value)
			}
			setKubernetesNamespaceFile(t, tc.hasNSFile, tc.nsFile)
			setKubernetesHostname(t, "host-pod", nil)
			captureKubernetesWarnings(t)

			ctx := resolveKubernetesContext()
			if tc.wantNil {
				assert.Nil(t, ctx)
				return
			}
			require.NotNil(t, ctx)
		})
	}
}

func TestResolveKubernetesContextSourcePrecedence(t *testing.T) {
	clearKubernetesEnv(t)
	t.Setenv("KUBERNETES_SERVICE_HOST", " 10.0.0.1 ")
	t.Setenv("KUBE_CLUSTER_NAME", " prod-eu ")
	t.Setenv("KUBE_NAMESPACE", " env-namespace ")
	t.Setenv("KUBE_WORKLOAD_NAME", " checkout ")
	t.Setenv("KUBE_WORKLOAD_KIND", " Deployment ")
	t.Setenv("KUBE_POD_NAME", " checkout-explicit ")
	t.Setenv("KUBE_POD_UID", " pod-uid ")
	setKubernetesNamespaceFile(t, true, " file-namespace\n")
	setKubernetesHostname(t, "hostname-pod", nil)
	captureKubernetesWarnings(t)

	ctx := resolveKubernetesContext()
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
		clearKubernetesEnv(t)
		t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
		t.Setenv("KUBE_NAMESPACE", "payments")
		t.Setenv("KUBE_WORKLOAD_NAME", "api")
		setKubernetesNamespaceFile(t, false, "")
		setKubernetesHostname(t, "api-host", nil)
		captureKubernetesWarnings(t)

		ctx := resolveKubernetesContext()
		require.NotNil(t, ctx)
		assert.Equal(t, "payments", ctx.Namespace)
	})

	t.Run("missing pod environment uses hostname", func(t *testing.T) {
		clearKubernetesEnv(t)
		t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
		t.Setenv("KUBE_WORKLOAD_NAME", "api")
		setKubernetesNamespaceFile(t, true, "payments")
		setKubernetesHostname(t, "api-host", nil)
		captureKubernetesWarnings(t)

		ctx := resolveKubernetesContext()
		require.NotNil(t, ctx)
		assert.Equal(t, "api-host", ctx.PodName)
	})

	t.Run("hostname error leaves pod empty", func(t *testing.T) {
		clearKubernetesEnv(t)
		t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
		t.Setenv("KUBE_WORKLOAD_NAME", "api")
		setKubernetesNamespaceFile(t, true, "payments")
		setKubernetesHostname(t, "", errors.New("hostname unavailable"))
		captureKubernetesWarnings(t)

		ctx := resolveKubernetesContext()
		require.NotNil(t, ctx)
		assert.Empty(t, ctx.PodName)
	})
}

func TestKubernetesWorkloadName(t *testing.T) {
	cases := []struct {
		name       string
		podName    string
		want       string
		wantStable bool
	}{
		{name: "Deployment", podName: "checkout-75d84f5bdf-abc12", want: "checkout", wantStable: true},
		{name: "Deployment all-numeric suffix", podName: "checkout-75d84f5bdf-24567", want: "checkout", wantStable: true},
		{name: "StatefulSet", podName: "database-2", want: "database", wantStable: true},
		{name: "StatefulSet hyphenated", podName: "user-db-2", want: "user-db", wantStable: true},
		{name: "CronJob", podName: "cleanup-4111706356-x7p9q", want: "cleanup", wantStable: true},
		{name: "indexed Job", podName: "worker-12-x7p9q", want: "worker", wantStable: true},
		{name: "DaemonSet", podName: "scanner-x7p9q", want: "scanner", wantStable: true},
		{name: "bare name", podName: "unusualpod", want: "unusualpod", wantStable: false},
		{name: "unrecognized suffix", podName: "my-pod", want: "my-pod", wantStable: false},
		{name: "empty", podName: "", want: "", wantStable: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, stable := kubernetesWorkloadName(tc.podName)
			assert.Equal(t, tc.want, name)
			assert.Equal(t, tc.wantStable, stable)
		})
	}
}

func TestResolveKubernetesContextWarns(t *testing.T) {
	t.Run("full pod-name fallback warns and recommends KUBE_WORKLOAD_NAME", func(t *testing.T) {
		clearKubernetesEnv(t)
		t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
		t.Setenv("KUBE_POD_NAME", "my-pod")
		setKubernetesNamespaceFile(t, true, "payments")
		setKubernetesHostname(t, "", nil)
		warnings := captureKubernetesWarnings(t)

		ctx := resolveKubernetesContext()
		require.NotNil(t, ctx)
		assert.Equal(t, "my-pod", ctx.WorkloadName)
		require.Len(t, *warnings, 1)
		assert.Contains(t, (*warnings)[0], "KUBE_WORKLOAD_NAME")
	})

	t.Run("recognized suffix does not warn", func(t *testing.T) {
		clearKubernetesEnv(t)
		t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
		t.Setenv("KUBE_POD_NAME", "checkout-75d84f5bdf-abc12")
		setKubernetesNamespaceFile(t, true, "payments")
		setKubernetesHostname(t, "", nil)
		warnings := captureKubernetesWarnings(t)

		ctx := resolveKubernetesContext()
		require.NotNil(t, ctx)
		assert.Equal(t, "checkout", ctx.WorkloadName)
		assert.Empty(t, *warnings)
	})

	t.Run("explicit workload does not warn", func(t *testing.T) {
		clearKubernetesEnv(t)
		t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
		t.Setenv("KUBE_POD_NAME", "my-pod")
		t.Setenv("KUBE_WORKLOAD_NAME", "checkout")
		setKubernetesNamespaceFile(t, true, "payments")
		setKubernetesHostname(t, "", nil)
		warnings := captureKubernetesWarnings(t)

		ctx := resolveKubernetesContext()
		require.NotNil(t, ctx)
		assert.Equal(t, "checkout", ctx.WorkloadName)
		assert.Empty(t, *warnings)
	})
}
