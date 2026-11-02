// Package container names the container that owns a network address on this
// host. A connection that the namespace redirect brings from a container
// carries only the container's address. The proxy asks an Introspector which
// container owns it, so a report can name the container instead of an IP.
package container

import (
	"context"
	"net/netip"
)

// Runtime is the container runtime that reported a container. A container ID
// is unique only within its runtime.
type Runtime string

const (
	RuntimeDocker Runtime = "docker"
	RuntimePodman Runtime = "podman"
)

// Container is a container as its runtime reported it. A field the runtime
// did not report is empty.
type Container struct {
	Runtime Runtime
	ID      string
	Name    string
	Image   string
	ImageID string
}

// IsZero reports whether no container is named.
func (c Container) IsZero() bool { return c == Container{} }

// Label names the container for a person, as in "container web (node:22)".
// A container without a name shows its short ID.
func (c Container) Label() string {
	name := c.Name
	if name == "" {
		name = shortID(c.ID)
	}
	label := "container " + name
	if c.Image != "" {
		label += " (" + c.Image + ")"
	}
	return label
}

func shortID(id string) string {
	const n = 12
	if len(id) > n {
		return id[:n]
	}
	return id
}

// Introspector names the container that owns an address on this host. found
// is false when no running container of the runtime has the address. An
// error means the runtime did not answer.
type Introspector interface {
	Runtime() Runtime
	ContainerByAddress(ctx context.Context, addr netip.Addr) (c Container, found bool, err error)
}
