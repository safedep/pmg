package shim

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/safedep/pmg/internal/fsutil"
)

// ManagerResolution is where one package manager resolves on the PATH a new
// shell gets. UnderShim means the command runs through a pmg shim. Otherwise
// a real npm or pip sits ahead of the shims and PMG does not see it.
type ManagerResolution struct {
	Name      string
	Path      string
	UnderShim bool
}

// InterceptionInspection is the PATH a new shell gets and where each
// configured package manager resolves on it.
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

// ShimInspection names the managers whose shim file is absent, and the
// managers whose shim names a pmg binary other than the one asked about.
type ShimInspection struct {
	Missing []string
	Stale   []string
}

// InspectInterception resolves each package manager once against the PATH a
// new shell gets, in the order given. A manager that does not resolve is
// omitted. On Windows the PATH comes from the registry, because the shell
// that ran `pmg setup install` still carries the PATH from before it.
func InspectInterception(packageManagers []string, shimDirs []string) (InterceptionInspection, error) {
	entries, err := interceptionPathEntries()
	if err != nil {
		return InterceptionInspection{}, err
	}
	return inspectInterception(packageManagers, shimDirs, entries, interceptionLookPath(entries)), nil
}

func inspectInterception(packageManagers, shimDirs, pathEntries []string, lookPath func(string) (string, error)) InterceptionInspection {
	inspection := InterceptionInspection{PathEntries: pathEntries}
	for _, pm := range packageManagers {
		resolved, err := lookPath(pm)
		if err != nil {
			continue
		}
		inspection.Resolutions = append(inspection.Resolutions, ManagerResolution{
			Name:      pm,
			Path:      resolved,
			UnderShim: PathUnderAnyDir(resolved, shimDirs),
		})
	}
	return inspection
}

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
// reports the ones that are absent and the ones that name a pmg binary other
// than pmgBin. A shim from an older install can point at a binary that moved
// or is gone.
func InspectShimFiles(shimDir string, packageManagers []string, pmgBin string) (ShimInspection, error) {
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
		if !shimNamesBinary(string(content), pmgBin) {
			inspection.Stale = append(inspection.Stale, pm)
		}
	}
	return inspection, nil
}
