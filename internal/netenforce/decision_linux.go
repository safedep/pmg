//go:build linux

package netenforce

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/safedep/pmg/internal/netenforce/bpf"
	"golang.org/x/sys/unix"
)

// Decision is one kernel verdict on a connect or a UDP send, as the trace
// ring buffer reports it.
type Decision struct {
	Action      string
	PID         uint32 // in the daemon's PID namespace, 0 for a process outside it
	UID         uint32
	Protocol    string
	Destination netip.AddrPort
	Comm        string
	ExeDev      uint64
	ExeInode    uint64
}

const (
	ActionOtherNetns     = "other-netns"
	ActionSkipDst        = "skip-destination"
	ActionExemptDaemon   = "exempt-daemon"
	ActionExemptUID      = "exempt-uid"
	ActionNotEligibleUID = "not-eligible-uid"
	ActionExemptExe      = "exempt-executable"
	ActionRedirect       = "redirect"
	ActionDenyUDP        = "deny-udp"
	ActionDenyIPv6       = "deny-ipv6"
	ActionToProxy        = "to-proxy"

	actionMax = 16
)

var actionNames = map[uint8]string{
	1:  ActionOtherNetns,
	2:  ActionSkipDst,
	3:  ActionExemptDaemon,
	4:  ActionExemptUID,
	5:  ActionNotEligibleUID,
	6:  ActionExemptExe,
	7:  ActionRedirect,
	8:  ActionDenyUDP,
	9:  ActionDenyIPv6,
	10: ActionToProxy,
}

func actionName(code uint8) string {
	if name, ok := actionNames[code]; ok {
		return name
	}
	return fmt.Sprintf("action-%d", code)
}

func decodeDecision(raw []byte) (Decision, error) {
	var e bpf.EnforceEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return Decision{}, err
	}

	var dst netip.Addr
	if e.Family == unix.AF_INET {
		dst = netip.AddrFrom4([4]byte(e.Dst[:4]))
	} else {
		dst = netip.AddrFrom16(e.Dst)
	}

	proto := "tcp"
	if e.Proto == unix.IPPROTO_UDP {
		proto = "udp"
	}

	comm := make([]byte, 0, len(e.Comm))
	for _, c := range e.Comm {
		if c == 0 {
			break
		}
		comm = append(comm, byte(c))
	}

	return Decision{
		Action:      actionName(e.Action),
		PID:         e.Tgid,
		UID:         e.Uid,
		Protocol:    proto,
		Destination: netip.AddrPortFrom(dst, e.Dport),
		Comm:        string(comm),
		ExeDev:      e.ExeDev,
		ExeInode:    e.ExeIno,
	}, nil
}
