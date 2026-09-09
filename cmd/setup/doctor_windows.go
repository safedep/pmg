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

// warnShadowedManagers reports the package managers a shell resolves outside
// the shim directory, and what to do about each. Windows builds PATH as the
// machine value then the user value, and a shell profile can prepend more,
// so `pmg setup install` alone cannot always win.
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

	fmt.Printf("\n%s A shell resolves these managers ahead of the shims, so PMG does not intercept them:\n",
		ui.Colors.Yellow("⚠"))
	for _, line := range shadowedLines(shadowed) {
		fmt.Printf("   %s\n", line)
	}
}

// shadowedFix fills the doctor Fix column with the same lines the install
// warning prints, so the two cannot disagree.
func shadowedFix(shadowed []shim.ManagerResolution) string {
	return strings.Join(shadowedLines(shadowed), " ")
}

func shadowedLines(shadowed []shim.ManagerResolution) []string {
	lines := make([]string, 0, len(shadowed))
	for _, r := range shadowed {
		lines = append(lines, fmt.Sprintf("%s is %s. %s", r.Name, r.Path, shadowedAction(r)))
	}
	return lines
}

// shadowedAction names what the user can do, which depends on where the
// winning PATH entry came from. Only the user PATH is one PMG can reorder.
func shadowedAction(r shim.ManagerResolution) string {
	switch r.Origin {
	case shim.OriginUser:
		return "Run `pmg setup install` again to move the shims ahead of it."
	case shim.OriginProfile:
		return fmt.Sprintf("A shell profile puts that directory on PATH, where PMG cannot reorder it. Run it as `pmg %s`, or drop that line from the profile.", r.Name)
	default:
		return fmt.Sprintf("It is on the machine PATH, which no per-user install can move behind the shims. Run it as `pmg %s`.", r.Name)
	}
}
