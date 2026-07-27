//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -type target bpf connect.c -- -I/usr/include/aarch64-linux-gnu

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Mirrors the ACTION_* constants in connect.c.
var actionNames = map[uint8]string{
	0: "REDIRECT",
	1: "skip/proto",
	2: "skip/loopback",
	3: "skip/exempt",
	4: "skip/dport",
	5: "skip/no-target",
}

func main() {
	proxyFlag := flag.String("proxy", "", "redirect target as host:port, e.g. 127.0.0.1:8443")
	exemptFlag := flag.String("exempt-uid", "", "comma separated uids that are never redirected")
	tcpOnlyFlag := flag.Bool("tcp-only", false, "only print TCP events, hiding DNS and route probe noise")
	flag.Parse()

	if err := run(*proxyFlag, *exemptFlag, *tcpOnlyFlag); err != nil {
		fmt.Fprintf(os.Stderr, "pmgwatch: %v\n", err)
		os.Exit(1)
	}
}

func run(proxyAddr, exemptUIDs string, tcpOnly bool) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer objs.Close()

	if err := configureTarget(&objs, proxyAddr); err != nil {
		return err
	}

	if err := configureExempt(&objs, exemptUIDs); err != nil {
		return err
	}

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.Connect4,
	})
	if err != nil {
		return fmt.Errorf("attach cgroup: %w", err)
	}
	defer l.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("open ringbuf: %w", err)
	}
	defer rd.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		fmt.Println("\nSignal received, detaching and cleaning up...")
		rd.Close()
	}()

	fmt.Println("Attached to /sys/fs/cgroup. Ctrl+C to exit.")
	fmt.Printf("%-15s %-17s %-7s %-8s %-22s %s\n", "ACTION", "COMMAND", "UID", "PID", "DESTINATION", "PROTO")

	return drain(rd, tcpOnly)
}

func drain(rd *ringbuf.Reader, tcpOnly bool) error {
	var e bpfEvent

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}

			fmt.Fprintf(os.Stderr, "read event: %v\n", err)
			continue
		}

		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			fmt.Fprintf(os.Stderr, "decode event: %v\n", err)
			continue
		}

		if tcpOnly && e.Proto != syscall.IPPROTO_TCP {
			continue
		}

		printEvent(&e)
	}
}

func printEvent(e *bpfEvent) {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, e.Daddr)

	action, ok := actionNames[e.Action]
	if !ok {
		action = fmt.Sprintf("action/%d", e.Action)
	}

	fmt.Printf("%-15s %-17s %-7d %-8d %-22s %s\n",
		action, comm(e.Comm[:]), e.Uid, e.Pid,
		net.JoinHostPort(ip.String(), strconv.Itoa(int(e.Dport))), proto(e.Proto))
}

// comm is a fixed 16 byte buffer, NUL terminated when the name is shorter.
func comm(raw []byte) string {
	if i := bytes.IndexByte(raw, 0); i != -1 {
		raw = raw[:i]
	}

	return string(raw)
}

func proto(p uint8) string {
	switch p {
	case syscall.IPPROTO_TCP:
		return "TCP"
	case syscall.IPPROTO_UDP:
		return "UDP"
	default:
		return strconv.Itoa(int(p))
	}
}

// configureTarget writes the redirect destination the hook will use. Leaving it
// unset is valid: every otherwise eligible connection then reports
// skip/no-target, which is how shadow mode runs before a proxy exists.
func configureTarget(objs *bpfObjects, addr string) error {
	if addr == "" {
		fmt.Println("No redirect target set, eligible connections will report skip/no-target")
		return nil
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parse proxy address %q: %w", addr, err)
	}

	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("proxy address %q must be an IPv4 address", addr)
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("parse proxy port %q: %w", portStr, err)
	}

	// The kernel holds the address in network byte order, which is what reading
	// the four octets little endian reproduces.
	target := bpfTarget{
		Ip:   binary.LittleEndian.Uint32(ip.To4()),
		Port: uint16(port),
	}

	if err := objs.TargetMap.Put(uint32(0), target); err != nil {
		return fmt.Errorf("write redirect target: %w", err)
	}

	fmt.Printf("Redirect target: %s\n", addr)

	return nil
}

func configureExempt(objs *bpfObjects, list string) error {
	if list == "" {
		fmt.Println("No exempt uids set, nothing bypasses the ladder")
		return nil
	}

	var applied []string
	for _, field := range strings.Split(list, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}

		uid, err := strconv.ParseUint(field, 10, 32)
		if err != nil {
			return fmt.Errorf("parse exempt uid %q: %w", field, err)
		}

		if err := objs.ExemptMap.Put(uint32(uid), uint8(1)); err != nil {
			return fmt.Errorf("write exempt uid %d: %w", uid, err)
		}

		applied = append(applied, field)
	}

	fmt.Printf("Exempt uids: %s\n", strings.Join(applied, ", "))

	return nil
}
