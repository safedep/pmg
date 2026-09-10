//go:build !windows

package setup

import "github.com/safedep/pmg/internal/shim"

// warnShadowedManagers is Windows only. On Unix the rc file prepends the
// shim directory to PATH, so no machine-wide entry sits ahead of it.
func warnShadowedManagers(string) {}

// shadowedFix is empty on Unix, so the doctor table keeps its usual hint.
func shadowedFix([]shim.ManagerResolution) string { return "" }
