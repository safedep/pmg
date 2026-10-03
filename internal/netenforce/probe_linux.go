//go:build linux

package netenforce

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

const (
	btfPath = "/sys/kernel/btf/vmlinux"

	// minKernel is 5.15: the first long-term kernel with every helper the
	// programs use. SO_NETNS_COOKIE needs 5.14, and the rest is older.
	minKernelMajor = 5
	minKernelMinor = 15
)

var requiredCapabilities = []struct {
	name string
	bit  uint
}{
	{"CAP_BPF", unix.CAP_BPF},
	{"CAP_NET_ADMIN", unix.CAP_NET_ADMIN},
	{"CAP_PERFMON", unix.CAP_PERFMON},
}

// probe checks every host requirement at once, so one error can name them
// all. Missing is empty when the host can enforce.
func probe() ProbeResult {
	var r ProbeResult

	if version, err := kernelVersion(); err != nil {
		r.Missing = append(r.Missing, fmt.Sprintf("the kernel version is unknown: %v", err))
	} else {
		r.KernelVersion = version.String()
		if !version.atLeast(minKernelMajor, minKernelMinor) {
			r.Missing = append(r.Missing, fmt.Sprintf("kernel %s is older than %d.%d", version, minKernelMajor, minKernelMinor))
		}
	}

	if _, err := os.Stat(btfPath); err != nil {
		r.Missing = append(r.Missing, "the kernel has no BTF at "+btfPath+" (CONFIG_DEBUG_INFO_BTF)")
	}

	if path, err := cgroup2Root(); err != nil {
		r.Missing = append(r.Missing, err.Error())
	} else {
		r.CgroupPath = path
	}

	for _, missing := range missingCapabilities() {
		r.Missing = append(r.Missing, missing+" is not in the effective capability set (run as root)")
	}

	r.Supported = len(r.Missing) == 0
	return r
}

type kernelRelease struct {
	major, minor, patch int
}

func (k kernelRelease) String() string {
	return fmt.Sprintf("%d.%d.%d", k.major, k.minor, k.patch)
}

func (k kernelRelease) atLeast(major, minor int) bool {
	return k.major > major || k.major == major && k.minor >= minor
}

func kernelVersion() (kernelRelease, error) {
	code, err := features.LinuxVersionCode()
	if err != nil {
		return kernelRelease{}, err
	}
	return kernelRelease{
		major: int(code >> 16),
		minor: int(code >> 8 & 0xff),
		patch: int(code & 0xff),
	}, nil
}

// cgroup2Root finds the cgroup v2 mount. A pure v2 host mounts it at
// /sys/fs/cgroup. A hybrid host mounts it at /sys/fs/cgroup/unified. Any
// other layout is read from mountinfo.
func cgroup2Root() (string, error) {
	for _, candidate := range []string{"/sys/fs/cgroup", "/sys/fs/cgroup/unified"} {
		if isCgroup2(candidate) {
			return candidate, nil
		}
	}

	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", fmt.Errorf("no cgroup v2 mount found: %w", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// The filesystem type follows the " - " separator.
		for i, field := range fields {
			if field == "-" && i+1 < len(fields) && fields[i+1] == "cgroup2" && len(fields) > 4 {
				return fields[4], nil
			}
		}
	}
	return "", fmt.Errorf("no cgroup v2 mount found")
}

func isCgroup2(path string) bool {
	_, err := os.Stat(path + "/cgroup.controllers")
	return err == nil
}

// missingCapabilities returns the names of the required capabilities the
// process lacks. The effective set is what the bpf syscall checks.
func missingCapabilities() []string {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		names := make([]string, 0, len(requiredCapabilities))
		for _, c := range requiredCapabilities {
			names = append(names, c.name)
		}
		return names
	}

	effective := uint64(data[0].Effective) | uint64(data[1].Effective)<<32
	var missing []string
	for _, c := range requiredCapabilities {
		if effective&(1<<c.bit) == 0 {
			missing = append(missing, c.name)
		}
	}
	return missing
}
