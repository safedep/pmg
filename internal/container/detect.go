package container

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/safedep/dry/log"
)

// engineSockets are the sockets where a rootful runtime serves the Docker
// Engine API, in the order Detect tries them. Only a rootful runtime puts
// its containers on a bridge of the host, where the namespace redirect sees
// them. A rootless runtime keeps them behind its own user-space network.
var engineSockets = []string{
	"/var/run/docker.sock",
	"/run/podman/podman.sock",
}

// engineHostVars name the variables that point a client of each runtime at
// its socket. A runtime started with its own socket path needs one of them.
// Detect tries a unix:// value after engineSockets. sudo drops both unless
// the user keeps them, as with sudo -E.
var engineHostVars = []string{"DOCKER_HOST", "CONTAINER_HOST"}

// probeTimeout bounds the wait for each socket, so a runtime that hangs does
// not hide the next one.
const probeTimeout = time.Second

// Detect returns an Introspector for the first runtime that answers on a
// known socket, or nil when none does.
func Detect(ctx context.Context) Introspector {
	return detect(ctx, candidateSockets(os.Getenv))
}

func candidateSockets(getenv func(string) string) []string {
	sockets := slices.Clone(engineSockets)
	for _, name := range engineHostVars {
		value := getenv(name)
		if value == "" {
			continue
		}
		path, ok := strings.CutPrefix(value, "unix://")
		if !ok || !filepath.IsAbs(path) {
			log.Debugf("container: %s=%s is not a unix:// socket path, so it is not used", name, value)
			continue
		}
		if !slices.Contains(sockets, path) {
			sockets = append(sockets, path)
		}
	}
	return sockets
}

func detect(ctx context.Context, sockets []string) Introspector {
	for _, socket := range sockets {
		if _, err := os.Stat(socket); err != nil {
			continue
		}
		client := newEngineClient(socket)
		runtime, err := probe(ctx, client)
		if err != nil {
			log.Debugf("container: no runtime answers on %s: %v", socket, err)
			continue
		}
		log.Debugf("container: %s answers on %s", runtime, socket)
		return newSnapshot(runtime, func(ctx context.Context) (map[netip.Addr]Container, error) {
			return client.containers(ctx, runtime)
		})
	}
	return nil
}

func probe(ctx context.Context, client *engineClient) (Runtime, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	return client.runtime(ctx)
}
