package container

import (
	"context"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCandidateSockets(t *testing.T) {
	defaults := []string{"/var/run/docker.sock"}
	cases := []struct {
		name       string
		dockerHost string
		want       []string
	}{
		{"unset", "", defaults},
		{"unix socket first", "unix:///run/user/docker.sock", []string{"/run/user/docker.sock", "/var/run/docker.sock"}},
		{"tcp is not a socket", "tcp://127.0.0.1:2375", defaults},
		{"empty unix path", "unix://", defaults},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, candidateSockets(tc.dockerHost, defaults))
		})
	}
}

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
