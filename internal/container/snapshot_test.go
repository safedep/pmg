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

	clock = clock.Add(hitMaxAge - time.Millisecond)
	_, found, err = s.ContainerByAddress(ctx, webAddr)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, 1, l.calls, "a fresh hit does not ask the runtime")

	clock = clock.Add(time.Millisecond)
	_, _, err = s.ContainerByAddress(ctx, webAddr)
	require.NoError(t, err)
	assert.Equal(t, 2, l.calls, "an old hit asks the runtime again")
}

func TestSnapshotListsAgainSoonAfterAMiss(t *testing.T) {
	clock := time.Unix(1000, 0)
	l := &fakeLister{byAddr: map[netip.Addr]Container{}}
	s := newTestSnapshot(l, &clock)
	ctx := context.Background()

	_, found, err := s.ContainerByAddress(ctx, webAddr)
	require.NoError(t, err)
	assert.False(t, found)

	_, found, err = s.ContainerByAddress(ctx, webAddr)
	require.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, 1, l.calls, "a fresh miss does not ask the runtime")

	// The container starts after the first list.
	l.byAddr = map[netip.Addr]Container{webAddr: web}
	clock = clock.Add(missMaxAge)
	c, found, err := s.ContainerByAddress(ctx, webAddr)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, web, c)
	assert.Equal(t, 2, l.calls)
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

func TestSnapshotUnmapsAnIPv4MappedAddress(t *testing.T) {
	clock := time.Unix(1000, 0)
	l := &fakeLister{byAddr: map[netip.Addr]Container{webAddr: web}}
	s := newTestSnapshot(l, &clock)

	_, found, err := s.ContainerByAddress(context.Background(), netip.MustParseAddr("::ffff:172.17.0.2"))
	require.NoError(t, err)
	assert.True(t, found)
}

// blockingLister holds its first list call until release is closed.
type blockingLister struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (b *blockingLister) list(context.Context) (map[netip.Addr]Container, error) {
	if b.calls.Add(1) == 1 {
		close(b.started)
		<-b.release
	}
	return map[netip.Addr]Container{webAddr: web}, nil
}

func TestSnapshotConcurrentLookupsShareOneList(t *testing.T) {
	b := &blockingLister{started: make(chan struct{}), release: make(chan struct{})}
	s := newSnapshot(RuntimeDocker, b.list)

	const lookups = 8
	var wg sync.WaitGroup
	found := make(chan bool, lookups)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, ok, err := s.ContainerByAddress(context.Background(), webAddr)
		assert.NoError(t, err)
		found <- ok
	}()
	<-b.started
	for range lookups - 1 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := s.ContainerByAddress(context.Background(), webAddr)
			assert.NoError(t, err)
			found <- ok
		}()
	}
	close(b.release)
	wg.Wait()
	close(found)

	for ok := range found {
		assert.True(t, ok)
	}
	assert.Equal(t, int32(1), b.calls.Load())
}
