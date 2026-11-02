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
