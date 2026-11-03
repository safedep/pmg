package container

import (
	"context"
	"net/netip"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/platform"
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
		// A socket path is a Unix path on each OS, so path, not filepath,
		// checks it. filepath.IsAbs refuses /srv/docker.sock on Windows.
		socket, ok := strings.CutPrefix(value, "unix://")
		if !ok || !path.IsAbs(socket) {
			log.Debugf("container: %s=%s is not a unix:// socket path, so it is not used", name, value)
			continue
		}
		if !slices.Contains(sockets, socket) {
			sockets = append(sockets, socket)
		}
	}
	return sockets
}

func detect(ctx context.Context, sockets []string) Introspector {
	for _, socket := range sockets {
		info, err := os.Stat(socket)
		if err != nil {
			continue
		}
		if !trustedOwner(info, os.Geteuid()) {
			log.Debugf("container: %s is not owned by root, so it is not used", socket)
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

// trustedOwner reports whether root, or the account that runs the daemon,
// owns a socket. The root daemon writes the names a runtime gives into audit
// events, so a socket that another account owns, such as a rootless Docker
// socket in DOCKER_HOST, could feed it false names. A rootless runtime keeps
// its containers off the bridges of the host, so it names none anyway. ok is
// false where the OS has no uid, and there the check does not apply.
func trustedOwner(info os.FileInfo, euid int) bool {
	uid, ok := platform.FileOwnerUID(info)
	return !ok || uid == 0 || int64(uid) == int64(euid)
}

func probe(ctx context.Context, client *engineClient) (Runtime, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	return client.runtime(ctx)
}
