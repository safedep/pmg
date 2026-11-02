package container

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const dockerVersion = `{"Platform":{"Name":"Docker Engine - Community"},"Components":[{"Name":"Engine"},{"Name":"containerd"}]}`

const podmanVersion = `{"Platform":{"Name":"linux/amd64/ubuntu-24.04"},"Components":[{"Name":"Podman Engine"}]}`

const containerList = `[
  {"Id":"aaaa","Names":["/web"],"Image":"node:22","ImageID":"sha256:1111",
   "NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.2","GlobalIPv6Address":"fd00::2"}}}},
  {"Id":"bbbb","Names":["/buildx_buildkit_builder0"],"Image":"moby/buildkit:buildx-stable-1","ImageID":"sha256:2222",
   "NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.3"},"other":{"IPAddress":"172.20.0.5"}}}},
  {"Id":"cccc","Names":["/host-net"],"Image":"alpine",
   "NetworkSettings":{"Networks":{"host":{"IPAddress":""}}}}
]`

// fakeEngine serves the Docker Engine API on a Unix socket and returns its
// path. A path without a route answers 404.
func fakeEngine(t *testing.T, routes map[string]http.HandlerFunc) string {
	t.Helper()
	// A Unix socket path has a short length limit, so the directory is not
	// t.TempDir, which can be long.
	dir, err := os.MkdirTemp("", "pmgc")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })
	socket := filepath.Join(dir, "engine.sock")

	l, err := net.Listen("unix", socket)
	require.NoError(t, err)
	mux := http.NewServeMux()
	for path, h := range routes {
		mux.HandleFunc(path, h)
	}
	srv := &http.Server{Handler: mux}
	go func() {
		if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
			assert.NoError(t, err)
		}
	}()
	t.Cleanup(func() { assert.NoError(t, srv.Close()) })
	return socket
}

func reply(t *testing.T, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(body))
		assert.NoError(t, err)
	}
}

func TestEngineRuntime(t *testing.T) {
	cases := []struct {
		name    string
		version string
		want    Runtime
	}{
		{"docker", dockerVersion, RuntimeDocker},
		{"podman", podmanVersion, RuntimePodman},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			socket := fakeEngine(t, map[string]http.HandlerFunc{"/version": reply(t, tc.version)})
			got, err := newEngineClient(socket).runtime(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestEngineContainersByAddress(t *testing.T) {
	socket := fakeEngine(t, map[string]http.HandlerFunc{"/containers/json": reply(t, containerList)})
	byAddr, err := newEngineClient(socket).containers(context.Background(), RuntimeDocker)
	require.NoError(t, err)

	web := Container{Runtime: RuntimeDocker, ID: "aaaa", Name: "web", Image: "node:22", ImageID: "sha256:1111"}
	builder := Container{Runtime: RuntimeDocker, ID: "bbbb", Name: "buildx_buildkit_builder0", Image: "moby/buildkit:buildx-stable-1", ImageID: "sha256:2222"}
	assert.Equal(t, map[netip.Addr]Container{
		netip.MustParseAddr("172.17.0.2"): web,
		netip.MustParseAddr("fd00::2"):    web,
		netip.MustParseAddr("172.17.0.3"): builder,
		netip.MustParseAddr("172.20.0.5"): builder,
	}, byAddr)
}

func TestEngineErrorStatus(t *testing.T) {
	socket := fakeEngine(t, map[string]http.HandlerFunc{
		"/containers/json": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		},
	})
	_, err := newEngineClient(socket).containers(context.Background(), RuntimeDocker)
	assert.ErrorContains(t, err, "500")
}
