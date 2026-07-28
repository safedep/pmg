//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -type target bpf connect.c -- -I/usr/include/aarch64-linux-gnu

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
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

type options struct {
	proxyAddr string
	stateFile string
	exempt    string
	tcpOnly   bool
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "ca" {
		if err := runCACommand(os.Args[2:], os.Stdout); err != nil {
			exitWithError("pmgwatch ca", err)
		}
		return
	}

	var opts options
	flag.StringVar(&opts.proxyAddr, "proxy", "", "redirect target as host:port, e.g. 127.0.0.1:8443")
	flag.StringVar(&opts.stateFile, "proxy-state", "",
		"PMG proxy state file, used to derive both the redirect target and the uid to exempt")
	flag.StringVar(&opts.exempt, "exempt-uid", "", "comma separated uids or usernames that are never redirected")
	flag.BoolVar(&opts.tcpOnly, "tcp-only", false, "only print TCP events, hiding DNS and route probe noise")
	flag.Parse()

	if err := run(opts); err != nil {
		exitWithError("pmgwatch", err)
	}
}

func exitWithError(name string, err error) {
	if _, writeErr := fmt.Fprintf(os.Stderr, "%s: %v\n", name, err); writeErr != nil {
		os.Exit(1)
	}
	os.Exit(1)
}

func run(opts options) error {
	target, exempt, err := resolve(opts)
	if err != nil {
		return err
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer objs.Close()

	if err := configureTarget(&objs, target); err != nil {
		return err
	}

	if err := configureExempt(&objs, exempt); err != nil {
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

	return drain(rd, opts.tcpOnly)
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

func configureExempt(objs *bpfObjects, uids []uint32) error {
	if len(uids) == 0 {
		fmt.Println("No exempt uids set, nothing bypasses the ladder")
		return nil
	}

	var applied []string
	for _, uid := range uids {
		if err := objs.ExemptMap.Put(uid, uint8(1)); err != nil {
			return fmt.Errorf("write exempt uid %d: %w", uid, err)
		}

		applied = append(applied, strconv.FormatUint(uint64(uid), 10))
	}

	fmt.Printf("Exempt uids: %s\n", strings.Join(applied, ", "))

	return nil
}

// proxyState is the subset of PMG's proxy state file this tool needs.
type proxyState struct {
	PID  int    `json:"pid"`
	Addr string `json:"addr"`
}

// resolve works out the redirect target and the uids to exempt. Deriving both
// from the proxy's own state file is the safe path: an exempt uid that does not
// match the running daemon sends the proxy's upstream fetches back into itself.
func resolve(opts options) (string, []uint32, error) {
	target := opts.proxyAddr

	exempt, err := parseUIDs(opts.exempt)
	if err != nil {
		return "", nil, err
	}

	if opts.stateFile == "" {
		return target, exempt, nil
	}

	state, err := readProxyState(opts.stateFile)
	if err != nil {
		return "", nil, err
	}

	if target == "" {
		target = state.Addr
	}

	uid, err := uidOfPID(state.PID)
	if err != nil {
		return "", nil, fmt.Errorf("resolve uid of proxy pid %d: %w", state.PID, err)
	}

	fmt.Printf("Proxy daemon: pid %d, addr %s, uid %d\n", state.PID, state.Addr, uid)

	return target, append(exempt, uid), nil
}

func readProxyState(path string) (*proxyState, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read proxy state %q: %w", path, err)
	}

	var state proxyState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("parse proxy state %q: %w", path, err)
	}

	if state.Addr == "" || state.PID == 0 {
		return nil, fmt.Errorf("proxy state %q has no addr or pid, is the daemon running", path)
	}

	return &state, nil
}

// uidOfPID reads the owner of /proc/<pid>, which is the uid the process runs as.
func uidOfPID(pid int) (uint32, error) {
	info, err := os.Stat("/proc/" + strconv.Itoa(pid))
	if err != nil {
		return 0, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("unexpected stat type")
	}

	return stat.Uid, nil
}

// parseUIDs accepts numeric uids or usernames, since a dedicated service
// account is easier to name than to remember the number of.
func parseUIDs(list string) ([]uint32, error) {
	var uids []uint32

	for _, field := range strings.Split(list, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}

		if uid, err := strconv.ParseUint(field, 10, 32); err == nil {
			uids = append(uids, uint32(uid))
			continue
		}

		account, err := user.Lookup(field)
		if err != nil {
			return nil, fmt.Errorf("resolve exempt user %q: %w", field, err)
		}

		uid, err := strconv.ParseUint(account.Uid, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parse uid of user %q: %w", field, err)
		}

		uids = append(uids, uint32(uid))
	}

	return uids, nil
}
