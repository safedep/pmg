package container

import (
	"context"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectSkipsAMissingSocketAndNamesTheRuntime(t *testing.T) {
	socket := fakeEngine(t, map[string]http.HandlerFunc{
		"/version":         reply(t, podmanVersion),
		"/containers/json": reply(t, containerList),
	})
	missing := filepath.Join(filepath.Dir(socket), "missing.sock")

	ins := detect(context.Background(), []string{missing, socket})
	require.NotNil(t, ins)
	assert.Equal(t, RuntimePodman, ins.Runtime())

	c, found, err := ins.ContainerByAddress(context.Background(), netip.MustParseAddr("172.17.0.2"))
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, "web", c.Name)
	assert.Equal(t, RuntimePodman, c.Runtime)
}

func TestDetectReturnsNilWhenNoRuntimeAnswers(t *testing.T) {
	broken := fakeEngine(t, map[string]http.HandlerFunc{})
	assert.Nil(t, detect(context.Background(), []string{broken, filepath.Join(filepath.Dir(broken), "missing.sock")}))
}

func TestDetectDoesNotWaitForeverOnAHungSocket(t *testing.T) {
	hung := fakeEngine(t, map[string]http.HandlerFunc{
		"/version": func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() },
	})
	docker := fakeEngine(t, map[string]http.HandlerFunc{"/version": reply(t, dockerVersion)})

	ins := detect(context.Background(), []string{hung, docker})
	require.NotNil(t, ins)
	assert.Equal(t, RuntimeDocker, ins.Runtime())
}

func TestCandidateSocketsAddsAUnixHostAfterTheDefaults(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want []string
	}{
		{"no variable", nil, engineSockets},
		{"a Docker socket of its own", map[string]string{"DOCKER_HOST": "unix:///srv/docker.sock"}, append(slices.Clone(engineSockets), "/srv/docker.sock")},
		{"a Podman socket of its own", map[string]string{"CONTAINER_HOST": "unix:///srv/podman.sock"}, append(slices.Clone(engineSockets), "/srv/podman.sock")},
		{"a default path is not tried twice", map[string]string{"DOCKER_HOST": "unix:///var/run/docker.sock"}, engineSockets},
		{"a TCP host is not used", map[string]string{"DOCKER_HOST": "tcp://10.0.0.5:2375"}, engineSockets},
		{"an SSH host is not used", map[string]string{"CONTAINER_HOST": "ssh://core@10.0.0.5/run/podman/podman.sock"}, engineSockets},
		{"a relative path is not used", map[string]string{"DOCKER_HOST": "unix://docker.sock"}, engineSockets},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := candidateSockets(func(name string) string { return tc.env[name] })
			assert.Equal(t, tc.want, got)
		})
	}
}
