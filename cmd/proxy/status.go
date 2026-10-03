package proxy

import (
	"fmt"
	"os"
	"strconv"
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
	case !st.Running:
		return fmt.Sprintf("PMG proxy: stopped (stale state for pid %d — run 'pmg proxy stop' to clean up)\n", st.PID)
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("PMG proxy: running (pid %d, addr %s, ca %s)\n", st.PID, st.Addr, st.CACert))
	if st.Enforce == nil {
		return b.String()
	}

	e := st.Enforce
	b.WriteString(fmt.Sprintf("Kernel enforcement: active (cgroup %s, ports %s, kernel %s)\n",
		e.CgroupPath, joinPorts(e.Ports), e.KernelVersion))
	if len(e.EligibleUIDs) > 0 {
		b.WriteString(fmt.Sprintf("  eligible uids: %v\n", e.EligibleUIDs))
	}
	if len(e.ExemptUIDs) > 0 {
		b.WriteString(fmt.Sprintf("  exempt uids: %v\n", e.ExemptUIDs))
	}
	for _, f := range e.ExemptExecutables {
		b.WriteString(fmt.Sprintf("  exempt executable: %s\n", f.Path))
	}
	for _, w := range e.Warnings {
		b.WriteString(fmt.Sprintf("%s %s\n", ui.Colors.Yellow("⚠"), w))
	}
	return b.String()
}

func joinPorts(ports []uint16) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	return strings.Join(parts, ",")
}
