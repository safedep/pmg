package container

import (
	"context"
	"errors"
	"net/netip"
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
