//go:build windows

package setup

import (
	"fmt"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/shim"
	"github.com/safedep/pmg/internal/ui"
)

// warnShadowedManagers reports the package managers a new shell would still
// resolve outside the shim directory. Windows builds PATH as the machine
// value, then the user value, so a manager installed for the machine (the
// Node.js MSI puts npm under C:\Program Files\nodejs) sits ahead of a user
// PATH entry, and install alone cannot change that.
func warnShadowedManagers(binDir string) {
	inspection, err := shim.InspectInterception(alias.DefaultConfig().PackageManagers, []string{binDir})
	if err != nil {
		log.Warnf("failed to check which managers the shims intercept: %v", err)
		return
	}
	_, shadowed := inspection.Partition()
	if len(shadowed) == 0 {
		return
	}

	fmt.Printf("\n%s A new shell resolves these managers ahead of the shims, so PMG does not intercept them:\n",
		ui.Colors.Yellow("⚠"))
	for _, line := range shadowedLines(shadowed) {
		fmt.Printf("   %s\n", line)
	}
	fmt.Printf("   %s\n", shadowedActions)
}

// shadowedActions names what a user can do today. A user PATH entry can
// never move ahead of a machine PATH entry, so "reorder PATH" is not an
// option for a manager that a machine-wide installer put there.
const shadowedActions = "Run them as `pmg <manager>`, or install that manager for your user only, so it lands on the user PATH behind the shims."

// shadowedFix fills the doctor Fix column with the same lines the install
// warning prints, joined with the actions.
func shadowedFix(shadowed []shim.ManagerResolution) string {
	return strings.Join(append(shadowedLines(shadowed), shadowedActions), " ")
}

func shadowedLines(shadowed []shim.ManagerResolution) []string {
	lines := make([]string, 0, len(shadowed))
	for _, r := range shadowed {
		lines = append(lines, fmt.Sprintf("%s is %s.", r.Name, r.Path))
	}
	return lines
}
