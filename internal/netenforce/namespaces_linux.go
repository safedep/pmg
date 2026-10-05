//go:build linux

package netenforce

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	// Owned tables, which the kernel deletes with their netlink socket,
	// arrived in 5.13.
	minOwnerKernelMajor = 5
	minOwnerKernelMinor = 13

	// conntrackMaxPath appears once nf_conntrack is loaded, which a nat
	// chain does. Without conntrack there is no original destination.
	conntrackMaxPath = "/proc/sys/net/netfilter/nf_conntrack_max"

	chainIngress = "ingress"
	chainSteer   = "steer"
	chainGuard   = "guard"
	chainQUIC    = "quic"
	setPorts     = "ports"
)

type linuxNamespaceRedirector struct{}

func newPlatformNamespaceRedirector() (NamespaceRedirector, error) {
	return linuxNamespaceRedirector{}, nil
}

func (linuxNamespaceRedirector) Probe() ProbeResult { return probeNamespaces() }

func (linuxNamespaceRedirector) EnsureAddress(addr netip.Addr) error { return ensureAddress(addr) }

func (linuxNamespaceRedirector) RemoveAddress(addr netip.Addr) error { return removeAddress(addr) }

// probeNamespaces checks what the redirect needs: a kernel with owned
// tables, CAP_NET_ADMIN, and nf_tables that answers over netlink.
func probeNamespaces() ProbeResult {
	r := ProbeResult{Subject: "redirect other network namespaces"}

	if version, err := kernelVersion(); err != nil {
		r.Missing = append(r.Missing, fmt.Sprintf("the kernel version is unknown: %v", err))
	} else {
		r.KernelVersion = version.String()
		if !version.atLeast(minOwnerKernelMajor, minOwnerKernelMinor) {
			r.Missing = append(r.Missing, fmt.Sprintf("kernel %s is older than %d.%d, which added owned nftables tables", version, minOwnerKernelMajor, minOwnerKernelMinor))
		}
	}

	for _, missing := range missingCapabilities(capability{"CAP_NET_ADMIN", unix.CAP_NET_ADMIN}) {
		r.Missing = append(r.Missing, missing+" is not in the effective capability set (run as root)")
	}

	if cc, err := nftables.New(); err != nil {
		r.Missing = append(r.Missing, fmt.Sprintf("nf_tables netlink is not available: %v", err))
	} else if _, err := cc.ListTablesOfFamily(nftables.TableFamilyINet); err != nil {
		r.Missing = append(r.Missing, fmt.Sprintf("nf_tables is not available (CONFIG_NF_TABLES): %v", err))
	}

	r.Supported = len(r.Missing) == 0
	return r
}

// Attach loads the table over one lasting netlink connection. The table
// carries the owner flag, so the kernel deletes it when the connection
// closes, on a clean stop and on a crash alike.
func (linuxNamespaceRedirector) Attach(_ context.Context, port uint16, p NamespacePolicy) (NamespaceHandle, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if port == 0 {
		return nil, errors.New("enforce: namespaces listener port is 0")
	}
	if err := probeNamespaces().Err(); err != nil {
		return nil, err
	}

	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, fmt.Errorf("enforce: open nftables: %w", err)
	}
	h := &namespaceHandle{
		conn: conn,
		status: NamespaceStatus{
			Address: p.Address.String(),
			Port:    port,
			Ingress: slices.Clone(p.Ingress),
			Ports:   slices.Clone(p.Ports),
			DenyUDP: p.DenyUDP,
		},
	}
	if err := h.load(port, p); err != nil {
		return nil, errors.Join(err, h.Close())
	}
	return h, nil
}

// NamespaceTableLoaded reports whether a pmg table exists, from any daemon.
func NamespaceTableLoaded() (bool, error) {
	conn, err := nftables.New()
	if err != nil {
		return false, fmt.Errorf("enforce: open nftables: %w", err)
	}
	return tableExists(conn)
}

func tableExists(conn *nftables.Conn) (bool, error) {
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, fmt.Errorf("enforce: list nftables tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == NamespaceTable {
			return true, nil
		}
	}
	return false, nil
}

type namespaceHandle struct {
	conn      *nftables.Conn
	table     *nftables.Table
	status    NamespaceStatus
	closeOnce sync.Once
	closeErr  error
}

func (h *namespaceHandle) Status() NamespaceStatus { return h.status }

// Close deletes the table and closes the connection. Either alone would
// do, and the explicit delete keeps a clean stop free of a window where
// rules point at a closed listener.
func (h *namespaceHandle) Close() error {
	h.closeOnce.Do(func() {
		var errs []error
		if h.table != nil {
			h.conn.DelTable(h.table)
			if err := h.flush("delete table"); err != nil {
				errs = append(errs, err)
			}
		}
		if err := h.conn.CloseLasting(); err != nil {
			errs = append(errs, fmt.Errorf("enforce: close nftables: %w", err))
		}
		h.closeErr = errors.Join(errs...)
	})
	return h.closeErr
}

// load builds the whole table in one batch, so no packet ever meets a
// half-built ruleset.
func (h *namespaceHandle) load(port uint16, p NamespacePolicy) error {
	if err := h.claimTable(); err != nil {
		return err
	}
	t := h.conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: NamespaceTable, Flags: nftables.TableFlagOwner})
	h.table = t

	ports := &nftables.Set{Table: t, Name: setPorts, KeyType: nftables.TypeInetService}
	elems := make([]nftables.SetElement, len(p.Ports))
	for i, v := range p.Ports {
		elems[i] = nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(v)}
	}
	if err := h.conn.AddSet(ports, elems); err != nil {
		return fmt.Errorf("enforce: add port set: %w", err)
	}

	accept := nftables.ChainPolicyAccept
	ingress := h.conn.AddChain(&nftables.Chain{
		Name: chainIngress, Table: t, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest, Policy: &accept,
	})
	steer := h.conn.AddChain(&nftables.Chain{Name: chainSteer, Table: t})
	guard := h.conn.AddChain(&nftables.Chain{
		Name: chainGuard, Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &accept,
	})

	for _, name := range p.Ingress {
		h.rule(ingress, meta(expr.MetaKeyIIFNAME), ifnameCmp(name), verdict(expr.VerdictJump, chainSteer))
	}

	h.rule(steer, &expr.Fib{Register: 1, FlagDADDR: true, ResultADDRTYPE: true},
		cmp(binaryutil.NativeEndian.PutUint32(unix.RTN_LOCAL)), verdict(expr.VerdictReturn, ""))
	for _, name := range p.Ingress {
		h.rule(steer, &expr.Fib{Register: 1, FlagDADDR: true, ResultOIFNAME: true}, ifnameCmp(name), verdict(expr.VerdictReturn, ""))
	}
	addr := p.Address.As4()
	h.rule(steer,
		meta(expr.MetaKeyNFPROTO), cmp([]byte{unix.NFPROTO_IPV4}),
		meta(expr.MetaKeyL4PROTO), cmp([]byte{unix.IPPROTO_TCP}),
		transportDestPort(), lookup(ports),
		&expr.Immediate{Register: 1, Data: addr[:]},
		&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(port)},
		&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1, RegProtoMin: 2},
	)

	for _, name := range append([]string{loopbackName}, p.Ingress...) {
		h.rule(guard, ipv4Daddr(addr, meta(expr.MetaKeyIIFNAME), ifnameCmp(name), verdict(expr.VerdictAccept, ""))...)
	}
	h.rule(guard, ipv4Daddr(addr, verdict(expr.VerdictDrop, ""))...)

	if p.DenyUDP {
		quic := h.conn.AddChain(&nftables.Chain{
			Name: chainQUIC, Table: t, Type: nftables.ChainTypeFilter,
			Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &accept,
		})
		for _, name := range p.Ingress {
			h.rule(quic, meta(expr.MetaKeyIIFNAME), ifnameCmp(name),
				meta(expr.MetaKeyL4PROTO), cmp([]byte{unix.IPPROTO_UDP}),
				transportDestPort(), lookup(ports),
				&expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_PORT_UNREACH})
		}
	}

	if err := h.flush("load table"); err != nil {
		return err
	}
	if _, err := os.Stat(conntrackMaxPath); err != nil {
		return errors.New("enforce: conntrack is not available (CONFIG_NF_CONNTRACK), so a redirected connection has no original destination")
	}
	return nil
}

// claimTable removes a table left by a daemon that could not use the owner
// flag. A table another live daemon owns cannot be removed, and that is
// the second-daemon case.
func (h *namespaceHandle) claimTable() error {
	exists, err := tableExists(h.conn)
	if err != nil || !exists {
		return err
	}
	h.conn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: NamespaceTable})
	return h.flush("remove stale table")
}

// flush sends the batch. The kernel answers EPERM for a table another
// socket owns, which is the second-daemon case.
func (h *namespaceHandle) flush(action string) error {
	err := h.conn.Flush()
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EPERM):
		return ErrNamespaceTableOwned
	default:
		return fmt.Errorf("enforce: %s %s: %w", action, NamespaceTable, err)
	}
}

func (h *namespaceHandle) rule(c *nftables.Chain, exprs ...expr.Any) {
	h.conn.AddRule(&nftables.Rule{Table: h.table, Chain: c, Exprs: exprs})
}

func meta(key expr.MetaKey) *expr.Meta { return &expr.Meta{Key: key, Register: 1} }

func cmp(data []byte) *expr.Cmp { return &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data} }

func verdict(kind expr.VerdictKind, chain string) *expr.Verdict {
	return &expr.Verdict{Kind: kind, Chain: chain}
}

// ifnameCmp matches an interface name in register 1. A trailing * compares
// the prefix only, which is how nft compiles a wildcard. An exact name is
// compared as the full IFNAMSIZ field, NUL padded.
func ifnameCmp(name string) *expr.Cmp {
	if prefix, ok := strings.CutSuffix(name, "*"); ok {
		return cmp([]byte(prefix))
	}
	data := make([]byte, unix.IFNAMSIZ)
	copy(data, name)
	return cmp(data)
}

func transportDestPort() *expr.Payload {
	return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}
}

// ipv4Daddr prefixes an IPv4 destination match to rest. The nfproto check
// comes first, because an inet chain sees IPv6 too and offset 16 is inside
// the IPv6 source address.
func ipv4Daddr(addr [4]byte, rest ...expr.Any) []expr.Any {
	exprs := []expr.Any{
		meta(expr.MetaKeyNFPROTO), cmp([]byte{unix.NFPROTO_IPV4}),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}, cmp(addr[:]),
	}
	return append(exprs, rest...)
}

func lookup(s *nftables.Set) *expr.Lookup {
	return &expr.Lookup{SourceRegister: 1, SetName: s.Name, SetID: s.ID}
}
