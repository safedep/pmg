package proxyserver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/safedep/pmg/internal/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeIntrospector struct {
	byAddr map[netip.Addr]container.Container
	err    error
	asked  []netip.Addr
}

func (f *fakeIntrospector) Runtime() container.Runtime { return container.RuntimeDocker }

func (f *fakeIntrospector) ContainerByAddress(_ context.Context, addr netip.Addr) (container.Container, bool, error) {
	f.asked = append(f.asked, addr)
	if f.err != nil {
		return container.Container{}, false, f.err
	}
	c, ok := f.byAddr[addr]
	return c, ok, nil
}

// peerConn is a connection whose only use here is its remote address.
type peerConn struct {
	net.Conn
	remote net.Addr
}

func (c peerConn) RemoteAddr() net.Addr { return c.remote }

func connFrom(t *testing.T, addrPort string) net.Conn {
	t.Helper()
	return peerConn{remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(addrPort))}
}

func TestDestinationResolverNamesTheContainer(t *testing.T) {
	web := container.Container{Runtime: container.RuntimeDocker, ID: "aaaa", Name: "web", Image: "node:22"}
	cases := []struct {
		name string
		ins  *fakeIntrospector
		peer string
		want container.Container
	}{
		{"a known address names the container", &fakeIntrospector{byAddr: map[netip.Addr]container.Container{netip.MustParseAddr("172.17.0.2"): web}}, "172.17.0.2:40000", web},
		{"an unknown address names none", &fakeIntrospector{byAddr: map[netip.Addr]container.Container{}}, "172.17.0.9:40000", container.Container{}},
		{"a runtime error names none", &fakeIntrospector{err: errors.New("engine hung")}, "172.17.0.2:40000", container.Container{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r destinationResolver
			r.useContainers(tc.ins)
			assert.Equal(t, tc.want, r.containerOf(connFrom(t, tc.peer)))
			require.Len(t, tc.ins.asked, 1)
			assert.Equal(t, netip.MustParseAddrPort(tc.peer).Addr(), tc.ins.asked[0])
		})
	}
}

func TestDestinationResolverWithoutARuntimeNamesNoContainer(t *testing.T) {
	var r destinationResolver
	assert.True(t, r.containerOf(connFrom(t, "172.17.0.2:40000")).IsZero())

	r.useContainers(nil)
	assert.True(t, r.containerOf(connFrom(t, "172.17.0.2:40000")).IsZero())
}

func TestWatchContainerRuntimeLooksAgainUntilARuntimeAnswers(t *testing.T) {
	ins := &fakeIntrospector{}
	var calls atomic.Int32
	detect := func(context.Context) container.Introspector {
		if calls.Add(1) < 3 {
			return nil
		}
		return ins
	}
	used := make(chan container.Introspector, 1)

	watchContainerRuntime(t.Context(), detect, time.Millisecond, func(found container.Introspector) { used <- found })

	select {
	case found := <-used:
		assert.Same(t, ins, found)
	case <-time.After(5 * time.Second):
		require.Fail(t, "the watch never gave the runtime to use")
	}
	assert.Never(t, func() bool { return calls.Load() > 3 }, 50*time.Millisecond, 5*time.Millisecond,
		"the watch kept looking after a runtime answered")
}

func TestWatchContainerRuntimeStopsWithItsContext(t *testing.T) {
	var calls atomic.Int32
	detect := func(context.Context) container.Introspector {
		calls.Add(1)
		return nil
	}
	ctx, cancel := context.WithCancel(t.Context())

	watchContainerRuntime(ctx, detect, time.Millisecond, func(container.Introspector) {
		assert.Fail(t, "no runtime answers, so nothing is used")
	})
	require.Eventually(t, func() bool { return calls.Load() > 1 }, 5*time.Second, time.Millisecond)
	cancel()

	// One look can be in flight when the context ends.
	stopped := calls.Load() + 1
	assert.Never(t, func() bool { return calls.Load() > stopped }, 50*time.Millisecond, 5*time.Millisecond,
		"the watch kept looking after its context ended")
}
