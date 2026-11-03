package container

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeLister struct {
	byAddr map[netip.Addr]Container
	err    error
	calls  int
}

func (f *fakeLister) list(context.Context) (map[netip.Addr]Container, error) {
	f.calls++
	return f.byAddr, f.err
}

var (
	webAddr = netip.MustParseAddr("172.17.0.2")
	web     = Container{Runtime: RuntimeDocker, ID: "aaaa", Name: "web"}
)

func newTestSnapshot(l *fakeLister, clock *time.Time) *snapshot {
	s := newSnapshot(RuntimeDocker, l.list)
	s.now = func() time.Time { return *clock }
	return s
}

func TestSnapshotReusesAFreshList(t *testing.T) {
	clock := time.Unix(1000, 0)
	l := &fakeLister{byAddr: map[netip.Addr]Container{webAddr: web}}
	s := newTestSnapshot(l, &clock)
	ctx := context.Background()

	c, found, err := s.ContainerByAddress(ctx, webAddr)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, web, c)

	clock = clock.Add(listMaxAge - time.Millisecond)
	_, found, err = s.ContainerByAddress(ctx, webAddr)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, 1, l.calls, "a fresh list answers without the runtime")
}

func TestSnapshotListsAgainWhenTheListIsOld(t *testing.T) {
	db := Container{Runtime: RuntimeDocker, ID: "bbbb", Name: "db"}
	cases := []struct {
		name  string
		first map[netip.Addr]Container
		later map[netip.Addr]Container
		want  Container
		found bool
	}{
		{"a container that started after the list is found", map[netip.Addr]Container{}, map[netip.Addr]Container{webAddr: web}, web, true},
		{"a new container on a reused address gets its own name", map[netip.Addr]Container{webAddr: web}, map[netip.Addr]Container{webAddr: db}, db, true},
		{"an exited container is not named", map[netip.Addr]Container{webAddr: web}, map[netip.Addr]Container{}, Container{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := time.Unix(1000, 0)
			l := &fakeLister{byAddr: tc.first}
			s := newTestSnapshot(l, &clock)
			ctx := context.Background()

			_, _, err := s.ContainerByAddress(ctx, webAddr)
			require.NoError(t, err)

			l.byAddr = tc.later
			clock = clock.Add(listMaxAge)
			c, found, err := s.ContainerByAddress(ctx, webAddr)
			require.NoError(t, err)
			assert.Equal(t, tc.found, found)
			assert.Equal(t, tc.want, c)
			assert.Equal(t, 2, l.calls)
		})
	}
}

func TestSnapshotTrustsAMissForLessTimeThanAHit(t *testing.T) {
	db := Container{Runtime: RuntimeDocker, ID: "bbbb", Name: "db"}
	dbAddr := netip.MustParseAddr("172.17.0.3")
	cases := []struct {
		name      string
		addr      netip.Addr
		after     time.Duration
		wantFound bool
		wantCalls int
	}{
		{"a hit reuses the list after missMaxAge", webAddr, missMaxAge, true, 1},
		{"a miss reuses a list younger than missMaxAge", dbAddr, missMaxAge - time.Millisecond, false, 1},
		{"a miss lists again after missMaxAge and finds a new container", dbAddr, missMaxAge, true, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := time.Unix(1000, 0)
			l := &fakeLister{byAddr: map[netip.Addr]Container{webAddr: web}}
			s := newTestSnapshot(l, &clock)
			ctx := context.Background()

			_, _, err := s.ContainerByAddress(ctx, webAddr)
			require.NoError(t, err)

			l.byAddr = map[netip.Addr]Container{webAddr: web, dbAddr: db}
			clock = clock.Add(tc.after)
			_, found, err := s.ContainerByAddress(ctx, tc.addr)
			require.NoError(t, err)
			assert.Equal(t, tc.wantFound, found)
			assert.Equal(t, tc.wantCalls, l.calls)
		})
	}
}

func TestSnapshotBacksOffAfterAFailure(t *testing.T) {
	clock := time.Unix(1000, 0)
	l := &fakeLister{err: errors.New("engine hung")}
	s := newTestSnapshot(l, &clock)
	ctx := context.Background()

	_, found, err := s.ContainerByAddress(ctx, webAddr)
	assert.ErrorContains(t, err, "engine hung")
	assert.False(t, found)

	clock = clock.Add(failureBackoff - time.Millisecond)
	_, found, err = s.ContainerByAddress(ctx, webAddr)
	require.NoError(t, err, "the failure was already reported")
	assert.False(t, found)
	assert.Equal(t, 1, l.calls, "the runtime is not asked during the backoff")

	l.err = nil
	l.byAddr = map[netip.Addr]Container{webAddr: web}
	clock = clock.Add(time.Millisecond)
	_, found, err = s.ContainerByAddress(ctx, webAddr)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, 2, l.calls)
}

// slowLister moves the clock forward during each list call, like a runtime
// that takes time to answer.
type slowLister struct {
	fakeLister
	clock *time.Time
	took  time.Duration
}

func (l *slowLister) list(ctx context.Context) (map[netip.Addr]Container, error) {
	*l.clock = l.clock.Add(l.took)
	return l.fakeLister.list(ctx)
}

func TestSnapshotWindowsStartWhenTheListCallReturns(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		window time.Duration
	}{
		{"a slow list is fresh when it returns", nil, listMaxAge},
		{"the backoff starts when a slow list fails", errors.New("engine hung"), failureBackoff},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := time.Unix(1000, 0)
			l := &slowLister{
				fakeLister: fakeLister{byAddr: map[netip.Addr]Container{webAddr: web}, err: tc.err},
				clock:      &clock,
				took:       time.Second,
			}
			s := newSnapshot(RuntimeDocker, l.list)
			s.now = func() time.Time { return clock }
			ctx := context.Background()

			_, _, err := s.ContainerByAddress(ctx, webAddr)
			if tc.err != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			clock = clock.Add(tc.window - time.Millisecond)
			_, _, err = s.ContainerByAddress(ctx, webAddr)
			require.NoError(t, err)
			assert.Equal(t, 1, l.calls, "the runtime is not asked inside the window")
		})
	}
}

func TestSnapshotUnmapsAnIPv4MappedAddress(t *testing.T) {
	clock := time.Unix(1000, 0)
	l := &fakeLister{byAddr: map[netip.Addr]Container{webAddr: web}}
	s := newTestSnapshot(l, &clock)

	_, found, err := s.ContainerByAddress(context.Background(), netip.MustParseAddr("::ffff:172.17.0.2"))
	require.NoError(t, err)
	assert.True(t, found)
}

// blockingLister holds every list call until release is closed.
type blockingLister struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (b *blockingLister) list(context.Context) (map[netip.Addr]Container, error) {
	if b.calls.Add(1) == 1 {
		close(b.started)
	}
	<-b.release
	return map[netip.Addr]Container{webAddr: web}, nil
}

// While the first list call is held, the other lookups must wait for it. A
// lookup that does not wait would start a list call of its own.
func TestSnapshotConcurrentLookupsShareOneList(t *testing.T) {
	clock := time.Unix(1000, 0)
	b := &blockingLister{started: make(chan struct{}), release: make(chan struct{})}
	s := newSnapshot(RuntimeDocker, b.list)
	s.now = func() time.Time { return clock }

	const lookups = 8
	var wg sync.WaitGroup
	found := make(chan bool, lookups)
	lookup := func() {
		defer wg.Done()
		_, ok, err := s.ContainerByAddress(context.Background(), webAddr)
		assert.NoError(t, err)
		found <- ok
	}
	wg.Add(1)
	go lookup()
	<-b.started
	for range lookups - 1 {
		wg.Add(1)
		go lookup()
	}

	assert.Never(t, func() bool { return b.calls.Load() > 1 }, 200*time.Millisecond, 5*time.Millisecond,
		"a lookup started a second list call while the first was held")
	close(b.release)
	wg.Wait()
	close(found)

	for ok := range found {
		assert.True(t, ok)
	}
	assert.Equal(t, int32(1), b.calls.Load())
}
