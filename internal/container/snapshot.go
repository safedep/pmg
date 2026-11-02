package container

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

const (
	// hitMaxAge is how long a listed address is trusted. A runtime gives the
	// address of an exited container to the next one, so an old list can
	// name the wrong container.
	hitMaxAge = 2 * time.Second

	// missMaxAge is how long an address that no container had stays a miss.
	// A container that just started is not in an older list.
	missMaxAge = 250 * time.Millisecond

	// failureBackoff is how long the runtime is not asked after it failed to
	// answer. The proxy asks on each new connection from a container, and a
	// hung runtime must not slow every one of them.
	failureBackoff = 10 * time.Second
)

// snapshot is an Introspector that answers from the last list of running
// containers and lists again when the list is too old to trust. One list
// answers many connections, so a busy container costs one call to the
// runtime per hitMaxAge, not one per connection.
type snapshot struct {
	runtime Runtime
	list    func(context.Context) (map[netip.Addr]Container, error)
	now     func() time.Time

	// mu also makes concurrent lookups share one list call.
	mu       sync.Mutex
	byAddr   map[netip.Addr]Container
	listedAt time.Time
	failedAt time.Time
}

func newSnapshot(runtime Runtime, list func(context.Context) (map[netip.Addr]Container, error)) *snapshot {
	return &snapshot{runtime: runtime, list: list, now: time.Now}
}

func (s *snapshot) Runtime() Runtime { return s.runtime }

// ContainerByAddress answers from the list while it is fresh. During the
// backoff after a failure it reports a miss without an error, because the
// failure was already reported.
func (s *snapshot) ContainerByAddress(ctx context.Context, addr netip.Addr) (Container, bool, error) {
	addr = addr.Unmap()
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	c, found := s.byAddr[addr]
	age := now.Sub(s.listedAt)
	if (found && age < hitMaxAge) || (!found && age < missMaxAge) {
		return c, found, nil
	}
	if now.Sub(s.failedAt) < failureBackoff {
		return Container{}, false, nil
	}

	byAddr, err := s.list(ctx)
	if err != nil {
		s.failedAt = now
		return Container{}, false, err
	}
	s.byAddr, s.listedAt = byAddr, now
	c, found = byAddr[addr]
	return c, found, nil
}
