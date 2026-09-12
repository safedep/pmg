package shim

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/safedep/pmg/internal/fsutil"
	"github.com/safedep/pmg/internal/platform"
)

// ManagerResolution is where one package manager resolves on the PATH a new
// shell gets. UnderShim means the command runs through a pmg shim. Otherwise
// a real npm or pip sits ahead of the shims and PMG does not see it.
type ManagerResolution struct {
	Name      string
	Path      string
	UnderShim bool
	Origin    platform.PathOrigin
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

// InspectInterception resolves each configured package manager over the PATH
// a new shell gets, and reports where each one wins. It builds on
// platform.NewShellPath, so the install warning and doctor read one PATH.
func InspectInterception(packageManagers, shimDirs []string) (InterceptionInspection, error) {
	shell, err := platform.NewShellPath()
	if err != nil {
		return InterceptionInspection{}, err
	}

	inspection := InterceptionInspection{PathEntries: shell.Entries}
	for _, pm := range packageManagers {
		resolved, origin, err := shell.LookPath(pm)
		if err != nil {
			continue
		}
		inspection.Resolutions = append(inspection.Resolutions, ManagerResolution{
			Name:      pm,
			Path:      resolved,
			UnderShim: fsutil.PathWithinAny(resolved, shimDirs),
			Origin:    origin,
		})
	}
	return inspection, nil
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
