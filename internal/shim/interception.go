package shim

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/safedep/pmg/internal/fsutil"
)

// PathOrigin is where the PATH entry that won a lookup came from. The remedy
// for a shadowed manager depends on it, because PMG can reorder the user PATH
// and nothing else.
type PathOrigin int

const (
	// OriginUnknown is every platform that has one PATH and no way to say
	// where an entry came from.
	OriginUnknown PathOrigin = iota
	// OriginMachine is the Windows machine PATH, which a machine-wide
	// installer writes. Windows puts it ahead of the user PATH, so no
	// user-scope write can move the shims in front of it.
	OriginMachine
	// OriginUser is the Windows user PATH. `pmg setup install` moves the shim
	// directory to the front of it.
	OriginUser
	// OriginProfile is a directory that only this process has, so a shell
	// profile added it. It never reaches the registry, and PMG cannot reorder
	// it.
	OriginProfile
)

// ManagerResolution is where one package manager resolves on the PATH a new
// shell gets. UnderShim means the command runs through a pmg shim. Otherwise
// a real npm or pip sits ahead of the shims and PMG does not see it.
type ManagerResolution struct {
	Name      string
	Path      string
	UnderShim bool
	Origin    PathOrigin
}

// InterceptionInspection is the PATH a new shell gets and where each
// configured package manager resolves. On Windows a resolution can come from
// the process PATH instead, when a shell profile put a directory there that
// the registry cannot show.
type InterceptionInspection struct {
	PathEntries []string
	Resolutions []ManagerResolution
}

// Partition splits the resolutions into the managers a shim intercepts and
// the managers that resolve elsewhere.
func (i InterceptionInspection) Partition() (underShim, shadowed []ManagerResolution) {
	for _, r := range i.Resolutions {
		if r.UnderShim {
			underShim = append(underShim, r)
		} else {
			shadowed = append(shadowed, r)
		}
	}
	return underShim, shadowed
}

// ShimInspection groups the package managers whose shim needs attention.
// Missing has no shim file. BinaryMissing names a pmg binary that is gone, so
// the shim fails with exit 127. BinaryDiffers names another pmg binary that
// still runs, so the manager is intercepted by that one.
type ShimInspection struct {
	Missing       []string
	BinaryMissing []string
	BinaryDiffers []string
}

// resolveManagers looks each manager up once against entries, in the order
// given, and omits one that does not resolve.
func resolveManagers(packageManagers, shimDirs, entries []string, lookPath lookupFunc) []ManagerResolution {
	resolutions := make([]ManagerResolution, 0, len(packageManagers))
	for _, pm := range packageManagers {
		resolved, err := lookPath(pm, entries)
		if err != nil {
			continue
		}
		resolutions = append(resolutions, ManagerResolution{
			Name:      pm,
			Path:      resolved,
			UnderShim: PathUnderAnyDir(resolved, shimDirs),
		})
	}
	return resolutions
}

// lookupFunc resolves a command name against the given PATH entries.
type lookupFunc func(name string, entries []string) (string, error)

// PathUnderAnyDir reports whether path sits inside one of dirs.
func PathUnderAnyDir(path string, dirs []string) bool {
	for _, dir := range dirs {
		if fsutil.PathWithinDir(path, dir) {
			return true
		}
	}
	return false
}

// InspectShimFiles reads the shim of each package manager in shimDir and
// groups the ones that need attention. A shim names the pmg binary by
// absolute path at install time and nothing updates it later, so a second
// install, a moved binary or a package upgrade to a versioned directory
// leaves the shim naming a binary that is not this one.
func InspectShimFiles(shimDir string, packageManagers []string) (ShimInspection, error) {
	pmgBin, err := currentExecutable()
	if err != nil {
		return ShimInspection{}, err
	}

	var inspection ShimInspection
	for _, pm := range packageManagers {
		content, err := os.ReadFile(filepath.Join(shimDir, shimFileName(pm)))
		if errors.Is(err, os.ErrNotExist) {
			inspection.Missing = append(inspection.Missing, pm)
			continue
		}
		if err != nil {
			return ShimInspection{}, fmt.Errorf("failed to read the %s shim: %w", pm, err)
		}

		named, ok := parseShimBinary(string(content))
		if !ok {
			// A file with no pmg path in it is not a shim PMG wrote.
			inspection.Missing = append(inspection.Missing, pm)
			continue
		}
		if fsutil.SamePath(named, pmgBin) {
			continue
		}
		if _, err := os.Stat(named); err != nil {
			inspection.BinaryMissing = append(inspection.BinaryMissing, pm)
			continue
		}
		inspection.BinaryDiffers = append(inspection.BinaryDiffers, pm)
	}
	return inspection, nil
}
