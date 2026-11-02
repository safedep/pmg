package container

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

const (
	// listMaxAge is how long a list of containers is trusted, for a hit and
	// for a miss. A runtime gives the address of an exited container to the
	// next one, so an older list can name the wrong container. A container
	// that just started is not in an older list. The proxy asks on each new
	// connection from a container, so the runtime gets at most one list call
	// per listMaxAge.
	listMaxAge = 250 * time.Millisecond

	// failureBackoff is how long the runtime is not asked after it failed to
	// answer, so a hung runtime does not slow every connection.
	failureBackoff = 10 * time.Second
)

// snapshot is an Introspector that answers from the last list of running
// containers and lists again when the list is too old to trust.
type snapshot struct {
	runtime Runtime
	list    func(context.Context) (map[netip.Addr]Container, error)
	now     func() time.Time

	// mu also makes concurrent lookups share one list call. A caller waits
	// for at most one list call, because a failed call starts the backoff.
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
	if now.Sub(s.listedAt) < listMaxAge {
		c, found := s.byAddr[addr]
		return c, found, nil
	}
	if now.Sub(s.failedAt) < failureBackoff {
		return Container{}, false, nil
	}

	// The list call can take up to a second, so both windows start when it
	// returns. A window that starts before the call can end before the
	// lookups that waited on mu read the list.
	byAddr, err := s.list(ctx)
	if err != nil {
		s.failedAt = s.now()
		return Container{}, false, err
	}
	s.byAddr, s.listedAt = byAddr, s.now()
	c, found := byAddr[addr]
	return c, found, nil
}
