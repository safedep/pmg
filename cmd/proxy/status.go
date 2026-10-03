package proxy

import (
	"fmt"
	"os"
	"strings"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/safedep/pmg/internal/ui"
	"github.com/spf13/cobra"
)

func newStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the status of the persistent PMG proxy server",
		RunE:  runStatus,
	}
}

func runStatus(_ *cobra.Command, _ []string) error {
	cfg := config.Get()
	statePath := proxyserver.ResolveStatePath(stateFlag, cfg.CacheDir())

	st := proxyserver.GetStatus(statePath)

	if _, err := fmt.Fprint(os.Stdout, statusText(st)); err != nil {
		ui.ErrorExit(err)
	}

	return nil
}

func statusText(st proxyserver.StatusInfo) string {
	switch {
	case !st.Found:
		return "PMG proxy: not running (no state file)\n"
	case st.Unreadable:
		return "PMG proxy: state file is not readable by this user (an enforcing proxy runs as root, re-run with sudo)\n"
	case !st.Running:
		return fmt.Sprintf("PMG proxy: stopped (stale state for pid %d — run 'pmg proxy stop' to clean up)\n", st.PID)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "PMG proxy: running (pid %d, addr %s, ca %s)\n", st.PID, st.Addr, st.CACert)
	if st.ConfigPath != "" {
		fmt.Fprintf(&b, "  config: %s (%s)\n", st.ConfigPath, st.ConfigSource)
	}
	if st.Enforce == nil {
		return b.String()
	}

	e := st.Enforce
	fmt.Fprintf(&b, "Kernel enforcement: active (cgroup %s, ports %s, kernel %s)\n",
		e.CgroupPath, e.PortList(), e.KernelVersion)
	if e.DenyUDP {
		b.WriteString("  udp to enforced ports: denied\n")
	} else {
		b.WriteString("  udp to enforced ports: allowed\n")
	}
	for _, prefix := range e.SkipDestinations {
		fmt.Fprintf(&b, "  skip destination: %s\n", prefix)
	}
	if len(e.EligibleUIDs) > 0 {
		fmt.Fprintf(&b, "  eligible uids: %v\n", e.EligibleUIDs)
	}
	if len(e.ExemptUIDs) > 0 {
		fmt.Fprintf(&b, "  exempt uids: %v\n", e.ExemptUIDs)
	}
	for _, f := range e.ExemptExecutables {
		fmt.Fprintf(&b, "  exempt executable: %s\n", f.Path)
	}
	for _, w := range e.Warnings {
		fmt.Fprintf(&b, "%s %s\n", ui.Colors.Yellow("⚠"), w)
	}
	return b.String()
}
