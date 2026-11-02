package container

import (
	"context"
	"net/netip"
	"os"
	"strings"

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

// Detect returns an Introspector for the first runtime that answers on a
// known socket, or nil when none does. A unix:// address in DOCKER_HOST
// comes first.
func Detect(ctx context.Context) Introspector {
	return detect(ctx, candidateSockets(os.Getenv("DOCKER_HOST"), engineSockets))
}

func detect(ctx context.Context, sockets []string) Introspector {
	for _, socket := range sockets {
		if _, err := os.Stat(socket); err != nil {
			continue
		}
		client := newEngineClient(socket)
		runtime, err := client.runtime(ctx)
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

func candidateSockets(dockerHost string, defaults []string) []string {
	if socket, ok := strings.CutPrefix(dockerHost, "unix://"); ok && socket != "" {
		return append([]string{socket}, defaults...)
	}
	return defaults
}
