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

// Ref names the container: its name, or its short ID when it has no name.
func (c Container) Ref() string {
	if c.Name != "" {
		return c.Name
	}
	return c.ID[:min(len(c.ID), shortIDLen)]
}

// shortIDLen is the length of the short ID that Docker shows.
const shortIDLen = 12

// Label names the container for a person, as in "container web (node:22)".
func (c Container) Label() string {
	label := "container " + c.Ref()
	if c.Image != "" {
		label += " (" + c.Image + ")"
	}
	return label
}

// Introspector names the container that owns an address on this host. found
// is false, and c is zero, when no running container of the runtime has the
// address. An error means the runtime did not answer. An IPv4-mapped address
// names the same container as its IPv4 form.
type Introspector interface {
	Runtime() Runtime
	ContainerByAddress(ctx context.Context, addr netip.Addr) (c Container, found bool, err error)
}
