//go:build linux

package netenforce

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/netenforce/bpf"
	"golang.org/x/sys/unix"
)

const (
	cfgTrace        = 1 << 0
	cfgHasProxy6    = 1 << 1
	cfgDenyUDP      = 1 << 2
	cfgEligibleUIDs = 1 << 3
)

type linuxEnforcer struct{}

func newPlatformEnforcer() (Enforcer, error) {
	return linuxEnforcer{}, nil
}

func (linuxEnforcer) Probe() ProbeResult { return probe() }

func (linuxEnforcer) Attached(cgroupPath string) (bool, error) { return attached(cgroupPath) }

// attached looks for pmg_connect4 among the connect4 programs on the
// cgroup. Link attachments are multi-attach, so the kernel would accept a
// second set without complaint.
func attached(cgroupPath string) (bool, error) {
	if cgroupPath == "" {
		root, err := cgroup2Root()
		if err != nil {
			return false, err
		}
		cgroupPath = root
	}
	dir, err := os.Open(cgroupPath)
	if err != nil {
		return false, fmt.Errorf("enforce: open cgroup %s: %w", cgroupPath, err)
	}
	defer func() { _ = dir.Close() }()

	result, err := link.QueryPrograms(link.QueryOptions{Target: int(dir.Fd()), Attach: ebpf.AttachCGroupInet4Connect})
	if err != nil {
		return false, fmt.Errorf("enforce: query programs on %s: %w", cgroupPath, err)
	}
	for _, p := range result.Programs {
		name, err := programName(p.ID)
		if err != nil {
			return false, err
		}
		if name == bpf.EnforceProgPmgConnect4 {
			return true, nil
		}
	}
	return false, nil
}

func programName(id ebpf.ProgramID) (string, error) {
	prog, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return "", fmt.Errorf("enforce: open program %d: %w", id, err)
	}
	defer func() { _ = prog.Close() }()
	info, err := prog.Info()
	if err != nil {
		return "", fmt.Errorf("enforce: read program %d: %w", id, err)
	}
	return info.Name, nil
}

// Attach fills every map before it attaches a program, so no connection
// ever meets a half-configured policy. The links detach when the owner
// closes the handle or the process exits. Nothing else detaches them.
func (linuxEnforcer) Attach(_ context.Context, t Target, p Policy) (Handle, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if !t.Addr.IsValid() || !t.Addr.Addr().Unmap().Is4() {
		return nil, fmt.Errorf("enforce: target %q is not an IPv4 address and port", t.Addr)
	}

	pr := probe()
	if err := pr.Err(); err != nil {
		return nil, err
	}

	cgroupPath := p.CgroupPath
	if cgroupPath == "" {
		cgroupPath = pr.CgroupPath
	}
	lock, err := lockCgroup(cgroupPath)
	if err != nil {
		return nil, err
	}
	if on, err := attached(cgroupPath); err != nil {
		return nil, errors.Join(err, lock.Close())
	} else if on {
		return nil, errors.Join(ErrAlreadyEnforced, lock.Close())
	}
	ports := p.Ports
	if len(ports) == 0 {
		ports = slices.Clone(DefaultPorts)
	}

	// Kernels before 5.11 charge BPF memory to RLIMIT_MEMLOCK. Newer
	// kernels use memcg, and the call is a no-op there.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Debugf("enforce: remove memlock limit: %v", err)
	}

	h := &linuxHandle{
		lock:       lock,
		policy:     p,
		trace:      p.TraceDecisions,
		decisions:  make(chan Decision, 1024),
		exemptKeys: map[bpf.EnforceExeKey]struct{}{},
	}
	h.status = Status{
		CgroupPath:       cgroupPath,
		Ports:            ports,
		SkipDestinations: skipList(p.SkipDestinations),
		DenyUDP:          p.DenyUDP,
		KernelVersion:    pr.KernelVersion,
		LoaderVersion:    loaderVersion(),
	}

	if err := bpf.LoadEnforceObjects(&h.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			err = fmt.Errorf("enforce: the kernel rejected a program: %+v", ve)
		} else {
			err = fmt.Errorf("enforce: load programs: %w", err)
		}
		return nil, errors.Join(err, lock.Close())
	}

	if err := h.fillMaps(t); err != nil {
		return nil, errors.Join(err, h.Close())
	}
	if err := h.attach(cgroupPath); err != nil {
		return nil, errors.Join(err, h.Close())
	}
	h.startReaders()
	return h, nil
}

// lockCgroup takes an exclusive flock on the cgroup directory. The query
// for an attached program and the attach are two steps, so two daemons
// that start together would both pass the query and both attach. The lock
// lives as long as the handle, and the kernel drops it with the process,
// the same as the links.
func lockCgroup(cgroupPath string) (*os.File, error) {
	dir, err := os.Open(cgroupPath)
	if err != nil {
		return nil, fmt.Errorf("enforce: open cgroup %s: %w", cgroupPath, err)
	}
	if err := unix.Flock(int(dir.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.Join(ErrAlreadyEnforced, dir.Close())
		}
		return nil, errors.Join(fmt.Errorf("enforce: lock cgroup %s: %w", cgroupPath, err), dir.Close())
	}
	return dir, nil
}

type linuxHandle struct {
	lock   *os.File
	objs   bpf.EnforceObjects
	links  []link.Link
	policy Policy

	mu         sync.Mutex
	status     Status
	exemptKeys map[bpf.EnforceExeKey]struct{}

	trace     bool
	decisions chan Decision
	readers   sync.WaitGroup
	execRd    *ringbuf.Reader
	traceRd   *ringbuf.Reader
	closeOnce sync.Once
	closeErr  error
}

func (h *linuxHandle) fillMaps(t Target) error {
	eligible, err := resolveUIDs(h.policy.EligibleUsers)
	if err != nil {
		return err
	}
	exempt, err := resolveUIDs(h.policy.ExemptUsers)
	if err != nil {
		return err
	}
	for _, uid := range eligible {
		if err := h.objs.EligibleUid.Put(uid, uint8(1)); err != nil {
			return fmt.Errorf("enforce: add eligible uid %d: %w", uid, err)
		}
	}
	for _, uid := range exempt {
		if err := h.objs.ExemptUid.Put(uid, uint8(1)); err != nil {
			return fmt.Errorf("enforce: add exempt uid %d: %w", uid, err)
		}
	}
	h.status.EligibleUIDs = eligible
	h.status.ExemptUIDs = exempt

	for _, port := range h.status.Ports {
		if err := h.objs.Ports.Put(port, uint8(1)); err != nil {
			return fmt.Errorf("enforce: add port %d: %w", port, err)
		}
	}

	for _, prefix := range h.status.SkipDestinations {
		if err := h.addSkip(prefix); err != nil {
			return err
		}
	}

	if err := h.refreshExempt(nil); err != nil {
		return err
	}

	cookie, err := netnsCookie()
	if err != nil {
		return err
	}
	h.status.NetnsCookie = cookie

	pidns, err := pidNamespace()
	if err != nil {
		return err
	}
	cfg := bpf.EnforceCfg{
		ProxyIp4:    ipv4Word(t.Addr.Addr().Unmap().As4()),
		ProxyPort:   portWord(t.Addr.Port()),
		DaemonTgid:  uint32(os.Getpid()),
		PidnsInum:   pidns,
		NetnsCookie: cookie,
	}
	if h.trace {
		cfg.Flags |= cfgTrace
	}
	if h.policy.DenyUDP {
		cfg.Flags |= cfgDenyUDP
	}
	if len(eligible) > 0 {
		cfg.Flags |= cfgEligibleUIDs
	}
	if t.Addr6.IsValid() && t.Addr6.Addr().Is6() && !t.Addr6.Addr().Is4In6() {
		cfg.Flags |= cfgHasProxy6
		a := t.Addr6.Addr().As16()
		for i := range cfg.ProxyIp6 {
			cfg.ProxyIp6[i] = ipv4Word([4]byte(a[i*4 : i*4+4]))
		}
	}
	if err := h.objs.PmgCfg.Put(uint32(0), cfg); err != nil {
		return fmt.Errorf("enforce: write config: %w", err)
	}
	return nil
}

func (h *linuxHandle) addSkip(prefix netip.Prefix) error {
	addr := prefix.Addr()
	if addr.Is4() {
		key := bpf.EnforceSkip4Key{Prefixlen: uint32(prefix.Bits()), Addr: ipv4Word(addr.As4())}
		if err := h.objs.Skip4.Put(key, uint8(1)); err != nil {
			return fmt.Errorf("enforce: add skip destination %s: %w", prefix, err)
		}
		return nil
	}
	key := bpf.EnforceSkip6Key{Prefixlen: uint32(prefix.Bits()), Addr: addr.As16()}
	if err := h.objs.Skip6.Put(key, uint8(1)); err != nil {
		return fmt.Errorf("enforce: add skip destination %s: %w", prefix, err)
	}
	return nil
}

// refreshExempt expands the executable globs and adds every new file to the
// kernel map. It runs at attach and again when the kernel reports an
// executable it has not seen, so a binary that appears later is covered.
//
// stat reports a device number that can differ from the one the kernel
// compares: btrfs gives each subvolume its own, and overlayfs reports a
// layer's. The exec event carries the kernel's pair and the process, so a
// match on the inode number also exempts the kernel's (dev, inode) once
// /proc/<tgid>/exe confirms that the process runs the matched file. Inode
// numbers repeat across filesystems, so the inode alone proves nothing.
// The programs report the tgid in this process's PID namespace, the one
// /proc shows, and 0 for a process outside it.
func (h *linuxHandle) refreshExempt(exec *bpf.EnforceExecEvent) error {
	files, err := expandExecutables(h.policy.ExemptExecutables)
	if err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	for _, f := range files {
		if err := h.exempt(f); err != nil {
			return err
		}
		if exec != nil && exec.Ino == f.Inode && exec.Dev != f.Dev && processRunsFile(exec.Tgid, f.Path) {
			if err := h.exempt(ExemptedFile{Path: f.Path, Dev: exec.Dev, Inode: exec.Ino}); err != nil {
				return err
			}
		}
	}
	return nil
}

// processRunsFile reports whether the process executes path. A process that
// exited, or any lookup failure, counts as no. The next exec reports again.
func processRunsFile(tgid uint32, path string) bool {
	if tgid == 0 {
		return false
	}
	exe, err := os.Readlink(filepath.Join("/proc", strconv.FormatUint(uint64(tgid), 10), "exe"))
	if err != nil {
		return false
	}
	want, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	return exe == want
}

func (h *linuxHandle) exempt(f ExemptedFile) error {
	key := bpf.EnforceExeKey{Dev: f.Dev, Ino: f.Inode}
	if _, seen := h.exemptKeys[key]; seen {
		return nil
	}
	if err := h.objs.ExemptExe.Put(key, uint8(1)); err != nil {
		return fmt.Errorf("enforce: exempt %s: %w", f.Path, err)
	}
	h.exemptKeys[key] = struct{}{}
	h.status.ExemptExecutables = append(h.status.ExemptExecutables, f)
	log.Debugf("enforce: exempt executable %s (dev %d, inode %d)", f.Path, f.Dev, f.Inode)
	return nil
}

func (h *linuxHandle) attach(cgroupPath string) error {
	cgroupProgs := []struct {
		name   string
		attach ebpf.AttachType
		prog   *ebpf.Program
	}{
		{"sendmsg4", ebpf.AttachCGroupUDP4Sendmsg, h.objs.PmgSendmsg4},
		{"sendmsg6", ebpf.AttachCGroupUDP6Sendmsg, h.objs.PmgSendmsg6},
		{"connect4", ebpf.AttachCGroupInet4Connect, h.objs.PmgConnect4},
		{"connect6", ebpf.AttachCGroupInet6Connect, h.objs.PmgConnect6},
		{"sockops", ebpf.AttachCGroupSockOps, h.objs.PmgSockops},
	}
	for _, p := range cgroupProgs {
		l, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Attach: p.attach, Program: p.prog})
		if err != nil {
			return fmt.Errorf("enforce: attach %s to %s: %w", p.name, cgroupPath, err)
		}
		h.links = append(h.links, l)
	}

	// The exec hook only matters when there are globs to match.
	if len(h.policy.ExemptExecutables) > 0 {
		l, err := link.AttachTracing(link.TracingOptions{Program: h.objs.PmgExec, AttachType: ebpf.AttachTraceRawTp})
		if err != nil {
			return fmt.Errorf("enforce: attach the exec tracepoint: %w", err)
		}
		h.links = append(h.links, l)
	}
	return nil
}

func (h *linuxHandle) startReaders() {
	if len(h.policy.ExemptExecutables) > 0 {
		rd, err := ringbuf.NewReader(h.objs.ExecEvents)
		if err != nil {
			log.Warnf("enforce: exec events unavailable, new runner binaries are not exempted: %v", err)
		} else {
			h.execRd = rd
			h.readers.Add(1)
			go h.readExecEvents(rd)
		}
	}
	if h.trace {
		rd, err := ringbuf.NewReader(h.objs.Events)
		if err != nil {
			log.Warnf("enforce: decision trace unavailable: %v", err)
		} else {
			h.traceRd = rd
			h.readers.Add(1)
			go h.readDecisions(rd)
		}
	}
}

func (h *linuxHandle) readExecEvents(rd *ringbuf.Reader) {
	defer h.readers.Done()
	var rec ringbuf.Record
	for {
		if err := rd.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Debugf("enforce: read exec event: %v", err)
			continue
		}
		var exec bpf.EnforceExecEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &exec); err != nil {
			log.Debugf("enforce: decode exec event: %v", err)
			continue
		}
		if err := h.refreshExempt(&exec); err != nil {
			log.Warnf("enforce: refresh exempt executables: %v", err)
		}
	}
}

func (h *linuxHandle) readDecisions(rd *ringbuf.Reader) {
	defer h.readers.Done()
	var rec ringbuf.Record
	for {
		if err := rd.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Debugf("enforce: read decision: %v", err)
			continue
		}
		d, err := decodeDecision(rec.RawSample)
		if err != nil {
			log.Debugf("enforce: decode decision: %v", err)
			continue
		}
		log.Debugf("enforce: %s pid=%d uid=%d comm=%s exe=%s dst=%s", d.Action, d.PID, d.UID, d.Comm, exePath(d.PID, d.ExeDev, d.ExeInode), d.Destination)
		select {
		case h.decisions <- d:
		default:
		}
	}
}

// OriginalDestination reads and removes the kernel's record for the client.
// The key family is the destination's: an IPv4-mapped destination on an
// IPv6 socket is stored as IPv4, which is the family the proxy sees too.
func (h *linuxHandle) OriginalDestination(client netip.AddrPort) (Origin, bool) {
	key := bpf.EnforceDstKey{Family: unix.AF_INET6, Sport: client.Port()}
	if addr := client.Addr().Unmap(); addr.Is4() {
		key.Family = unix.AF_INET
		a4 := addr.As4()
		copy(key.Saddr[:], a4[:])
	} else {
		key.Saddr = addr.As16()
	}

	var d bpf.EnforceDst
	if err := h.objs.OrigDst.Lookup(key, &d); err != nil {
		return Origin{}, false
	}
	if err := h.objs.OrigDst.Delete(key); err != nil {
		log.Debugf("enforce: delete original destination for %s: %v", client, err)
	}
	return Origin{
		Dst:     decodeDst(d),
		PID:     d.Tgid,
		Comm:    commString(d.Comm),
		Exe:     exePath(d.Tgid, d.ExeDev, d.ExeIno),
		ToProxy: d.ToProxy != 0,
	}, true
}

// commString reads the NUL-terminated task name the kernel wrote.
func commString(comm [16]int8) string {
	b := make([]byte, 0, len(comm))
	for _, c := range comm {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

// exePath names the executable of a process, when it is still the file
// the kernel saw at connect. A process can exec another binary after it
// connected, or exit and leave its pid to another process, so the path
// counts only when the file's device and inode match the kernel's record.
// It is "" for a process outside the daemon's PID namespace. The comm
// still names it then.
func exePath(tgid uint32, dev, ino uint64) string {
	if tgid == 0 || ino == 0 {
		return ""
	}
	link := filepath.Join("/proc", strconv.FormatUint(uint64(tgid), 10), "exe")
	var st unix.Stat_t
	if err := unix.Stat(link, &st); err != nil {
		return ""
	}
	if kernelDev(st.Dev) != dev || st.Ino != ino {
		return ""
	}
	exe, err := os.Readlink(link)
	if err != nil {
		return ""
	}
	return exe
}

func (h *linuxHandle) Status() Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.status
	s.ExemptExecutables = slices.Clone(s.ExemptExecutables)
	return s
}

// Close detaches every program. The kernel does the same when the process
// exits, so a crash never leaves enforcement on.
func (h *linuxHandle) Close() error {
	h.closeOnce.Do(func() {
		var errs []error
		for _, l := range h.links {
			if err := l.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if h.execRd != nil {
			errs = append(errs, h.execRd.Close())
		}
		if h.traceRd != nil {
			errs = append(errs, h.traceRd.Close())
		}
		h.readers.Wait()
		errs = append(errs, h.objs.Close(), h.lock.Close())
		h.closeErr = errors.Join(errs...)
	})
	return h.closeErr
}

// Decisions streams the kernel's per-connection decisions when
// Policy.TraceDecisions is set. Tests and debugging read it.
func (h *linuxHandle) Decisions() <-chan Decision { return h.decisions }

// Counters returns how many connections met each decision since attach,
// summed over CPUs.
func (h *linuxHandle) Counters() (map[string]uint64, error) {
	out := map[string]uint64{}
	for action := uint32(1); action < actionMax; action++ {
		var perCPU []uint64
		if err := h.objs.Stats.Lookup(action, &perCPU); err != nil {
			return nil, fmt.Errorf("enforce: read counter %d: %w", action, err)
		}
		var sum uint64
		for _, n := range perCPU {
			sum += n
		}
		if sum > 0 {
			out[actionName(uint8(action))] = sum
		}
	}
	return out, nil
}

func decodeDst(d bpf.EnforceDst) netip.AddrPort {
	port := bits.ReverseBytes16(d.Port)
	if d.Family == unix.AF_INET {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(d.Addr[:4])), port)
	}
	return netip.AddrPortFrom(netip.AddrFrom16(d.Addr), port)
}

// ipv4Word returns the address as the kernel stores user_ip4: the four
// network-order bytes read as one native integer.
func ipv4Word(b [4]byte) uint32 { return binary.NativeEndian.Uint32(b[:]) }

// portWord returns the port as the kernel stores user_port: the two
// network-order bytes read as one native integer.
func portWord(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// netnsCookie identifies the network namespace of this process. A socket
// in another namespace has another cookie, and the programs leave it alone.
func netnsCookie() (uint64, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("enforce: open a socket for the namespace cookie: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil {
		return 0, fmt.Errorf("enforce: read the network namespace cookie: %w", err)
	}
	return cookie, nil
}

// pidNamespace returns the inode of this process's PID namespace. The
// programs translate every thread group id into that namespace before they
// compare it with os.Getpid or hand it to the daemon, because the kernel's
// own ids belong to the initial namespace and differ in a container. The
// daemon reads /proc/<tgid> for those ids, so /proc must belong to the same
// namespace, which it does not after an unshare without a new mount.
func pidNamespace() (uint32, error) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &st); err != nil {
		return 0, fmt.Errorf("enforce: read the PID namespace: %w", err)
	}
	self, err := os.Readlink("/proc/self")
	if err != nil {
		return 0, fmt.Errorf("enforce: read /proc/self: %w", err)
	}
	if self != strconv.Itoa(os.Getpid()) {
		return 0, fmt.Errorf("enforce: /proc belongs to another PID namespace: it shows this process as pid %s, not %d", self, os.Getpid())
	}
	return uint32(st.Ino), nil
}

func loaderVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "cilium/ebpf"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/cilium/ebpf" {
			return "cilium/ebpf " + dep.Version
		}
	}
	return "cilium/ebpf"
}
