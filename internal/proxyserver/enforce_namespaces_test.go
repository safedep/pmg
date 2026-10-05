package proxyserver

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/netenforce"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRedirector stands in for the host. It records what the daemon asked
// for and fails where the test says.
type fakeRedirector struct {
	missing    []string
	addressErr error
	attachErr  error

	addresses []netip.Addr
	removed   []netip.Addr
	attached  *netenforce.NamespacePolicy
	port      uint16
	handle    *fakeHandle
}

type fakeHandle struct {
	status netenforce.NamespaceStatus
	closed bool
}

func (h *fakeHandle) Status() netenforce.NamespaceStatus { return h.status }
func (h *fakeHandle) Close() error                       { h.closed = true; return nil }

func (f *fakeRedirector) Probe() netenforce.ProbeResult {
	return netenforce.ProbeResult{Supported: len(f.missing) == 0, Missing: f.missing}
}

func (f *fakeRedirector) EnsureAddress(addr netip.Addr) error {
	f.addresses = append(f.addresses, addr)
	return f.addressErr
}

func (f *fakeRedirector) RemoveAddress(addr netip.Addr) error {
	f.removed = append(f.removed, addr)
	return nil
}

func (f *fakeRedirector) Attach(_ context.Context, port uint16, p netenforce.NamespacePolicy) (netenforce.NamespaceHandle, error) {
	if f.attachErr != nil {
		return nil, f.attachErr
	}
	f.attached, f.port = &p, port
	f.handle = &fakeHandle{status: netenforce.NamespaceStatus{Address: p.Address.String(), Port: port, Ingress: p.Ingress, Ports: p.Ports}}
	return f.handle, nil
}

func useFakeRedirector(t *testing.T, f *fakeRedirector, err error) {
	t.Helper()
	orig := newNamespaceRedirector
	newNamespaceRedirector = func() (netenforce.NamespaceRedirector, error) { return f, err }
	t.Cleanup(func() { newNamespaceRedirector = orig })
}

func nsConfig(mode string) config.ProxyEnforceNamespacesConfig {
	return config.ProxyEnforceNamespacesConfig{Mode: mode, Ingress: []string{"docker0", "br-*"}, Address: "169.254.200.1"}
}

var basePolicy = netenforce.Policy{Ports: []uint16{80, 443}, DenyUDP: true}

func TestNamespaceRedirectIgnoreTouchesNothing(t *testing.T) {
	f := &fakeRedirector{}
	useFakeRedirector(t, f, nil)

	n, err := newNamespaceRedirect(nsConfig("ignore"), basePolicy)
	require.NoError(t, err)
	assert.False(t, n.active())
	assert.Empty(t, n.listenAddr())
	require.NoError(t, n.prepare())
	require.NoError(t, n.attach(context.Background(), nil))
	assert.Empty(t, f.addresses)
	assert.Nil(t, f.attached)
	assert.Equal(t, "namespaces: ignore", NamespaceStatusLine(n.state()))
	assert.Empty(t, n.warnings())
}

func TestNamespaceRedirectLoadsTableOnTheBoundPort(t *testing.T) {
	f := &fakeRedirector{}
	useFakeRedirector(t, f, nil)

	n, err := newNamespaceRedirect(nsConfig("redirect"), basePolicy)
	require.NoError(t, err)
	assert.True(t, n.active())
	assert.Equal(t, "169.254.200.1:0", n.listenAddr())
	require.NoError(t, n.prepare())
	require.NoError(t, n.attach(context.Background(), []string{"[::1]:7777", "169.254.200.1:7777"}))

	require.NotNil(t, f.attached)
	assert.Equal(t, uint16(7777), f.port)
	assert.Equal(t, []uint16{80, 443}, f.attached.Ports)
	assert.True(t, f.attached.DenyUDP)
	assert.Equal(t, "namespaces: redirect (169.254.200.1:7777 from docker0, br-*)", NamespaceStatusLine(n.state()))
	assert.Contains(t, n.warnings()[0], "PMG_CA_BUNDLE")

	require.NoError(t, n.detach())
	assert.True(t, f.handle.closed)
	require.NoError(t, n.releaseAddress())
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("169.254.200.1")}, f.removed)
}

func TestNamespaceRedirectFailsFastWhereAutoFallsBack(t *testing.T) {
	cases := []struct {
		name string
		fake *fakeRedirector
		ctor error
		want string
	}{
		{"unsupported platform", &fakeRedirector{}, netenforce.ErrNamespaceUnsupported, "only supported on Linux"},
		{"probe fails", &fakeRedirector{missing: []string{"nf_tables is not available"}}, nil, "nf_tables is not available"},
		{"address conflict", &fakeRedirector{addressErr: errors.New("address is on eth0")}, nil, "address is on eth0"},
		{"table fails", &fakeRedirector{attachErr: errors.New("EPERM")}, nil, "EPERM"},
	}
	for _, tc := range cases {
		t.Run(tc.name+" under redirect", func(t *testing.T) {
			useFakeRedirector(t, tc.fake, tc.ctor)
			n, err := newNamespaceRedirect(nsConfig("redirect"), basePolicy)
			if err == nil {
				err = n.prepare()
			}
			if err == nil {
				err = n.attach(context.Background(), []string{"169.254.200.1:7777"})
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
		t.Run(tc.name+" under auto", func(t *testing.T) {
			useFakeRedirector(t, tc.fake, tc.ctor)
			n, err := newNamespaceRedirect(nsConfig("auto"), basePolicy)
			require.NoError(t, err)
			require.NoError(t, n.prepare())
			require.NoError(t, n.attach(context.Background(), []string{"169.254.200.1:7777"}))
			assert.False(t, n.active())
			assert.Equal(t, "auto", n.state().Mode)
			assert.Equal(t, "ignore", n.state().Effective)
			assert.Contains(t, n.state().Reason, tc.want)
			assert.Contains(t, NamespaceStatusLine(n.state()), "namespaces: ignore (auto: ")
			assert.Nil(t, tc.fake.attached, "no table under a fallback")
			if tc.fake.addressErr == nil && len(tc.fake.addresses) > 0 {
				assert.Equal(t, tc.fake.addresses, tc.fake.removed, "an address that went on comes off")
			}
			assert.Contains(t, n.warnings()[0], "not redirected")
		})
	}
}

func TestNamespaceRedirectRejectsBadConfig(t *testing.T) {
	useFakeRedirector(t, &fakeRedirector{}, nil)
	for name, nc := range map[string]config.ProxyEnforceNamespacesConfig{
		"mode":    {Mode: "on"},
		"address": {Mode: "redirect", Address: "not-an-ip"},
		"ingress": {Mode: "redirect", Ingress: []string{"a*b"}},
	} {
		_, err := newNamespaceRedirect(nc, basePolicy)
		assert.Error(t, err, name)
	}
}

func TestNamespacesNeedEnforce(t *testing.T) {
	cfg := enforceConfig(func(ec *config.ProxyEnforceConfig) { ec.Namespaces.Mode = "redirect" })
	assert.NoError(t, NamespacesNeedEnforce(cfg, true))
	err := NamespacesNeedEnforce(cfg, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "without enforcement")

	for _, mode := range []string{"ignore", "auto"} {
		cfg = enforceConfig(func(ec *config.ProxyEnforceConfig) { ec.Namespaces.Mode = mode })
		assert.NoError(t, NamespacesNeedEnforce(cfg, false), mode)
	}
}

func TestNilNamespaceRedirectIsInert(t *testing.T) {
	var n *namespaceRedirect
	assert.False(t, n.active())
	assert.NoError(t, n.detachAll())
	assert.Nil(t, n.state())
	assert.Empty(t, n.warnings())
}

func TestStateRoundTripsNamespaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-state.json")
	in := State{PID: 7, Addr: "127.0.0.1:7777", Enforce: &EnforceState{
		Namespaces: &NamespaceState{Mode: "auto", Effective: "redirect", Table: &netenforce.NamespaceStatus{
			Address: "169.254.200.1", Port: 7777, Ingress: []string{"docker0"}, Ports: []uint16{443}, DenyUDP: true,
		}},
	}}
	require.NoError(t, writeState(path, in))
	out, err := readState(path)
	require.NoError(t, err)
	assert.Equal(t, in.Enforce.Namespaces, out.Enforce.Namespaces)
}
