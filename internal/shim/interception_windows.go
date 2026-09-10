//go:build windows

package shim

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// InspectInterception reports where a package manager runs from when the
// developer types its name.
//
// It reads two PATHs, because neither answers the question alone. The
// registry PATH is what a shell started from Explorer gets, and doctor often
// runs in the shell that ran `pmg setup install`, whose process PATH predates
// the new entry. The process PATH is what this shell has, and it is the only
// one that shows a directory a shell profile added: `fnm env |
// Invoke-Expression` in $PROFILE prepends a multishell directory that holds
// npm, and the registry never sees it.
//
// A manager that the process PATH resolves outside the shims, from a
// directory the registry does not hold, is shadowed by the profile. Anything
// else takes the registry answer, so a stale shell does not report a
// registered shim directory as absent.
func InspectInterception(packageManagers []string, shimDirs []string) (InterceptionInspection, error) {
	machine, user, err := registryPathHalves()
	if err != nil {
		return InterceptionInspection{}, err
	}
	registryEntries := append(append([]string{}, machine...), user...)
	process := filepath.SplitList(os.Getenv("PATH"))

	inspection := InterceptionInspection{PathEntries: registryEntries}
	for _, pm := range packageManagers {
		if r, ok := profileShadowed(pm, shimDirs, registryEntries, process); ok {
			inspection.Resolutions = append(inspection.Resolutions, r)
			continue
		}

		resolved, err := lookPathIn(pm, registryEntries)
		if err != nil {
			continue
		}
		inspection.Resolutions = append(inspection.Resolutions, ManagerResolution{
			Name:      pm,
			Path:      resolved,
			UnderShim: PathUnderAnyDir(resolved, shimDirs),
			Origin:    originOf(resolved, machine, user),
		})
	}
	return inspection, nil
}

// profileShadowed reports a manager that this shell resolves outside the
// shims from a directory no registry PATH entry names.
func profileShadowed(pm string, shimDirs, registryEntries, process []string) (ManagerResolution, bool) {
	resolved, err := lookPathIn(pm, process)
	if err != nil || PathUnderAnyDir(resolved, shimDirs) {
		return ManagerResolution{}, false
	}
	if PathUnderAnyDir(resolved, registryEntries) {
		return ManagerResolution{}, false
	}
	return ManagerResolution{Name: pm, Path: resolved, Origin: OriginProfile}, true
}

// originOf names the PATH half that holds the directory of path. Windows
// searches the machine half first, so it wins a directory that is in both.
func originOf(path string, machine, user []string) PathOrigin {
	if PathUnderAnyDir(path, machine) {
		return OriginMachine
	}
	if PathUnderAnyDir(path, user) {
		return OriginUser
	}
	return OriginUnknown
}

// lookPathIn resolves a name over the given PATH entries with the PATHEXT
// rule, so the answer matches what a shell would run.
func lookPathIn(name string, entries []string) (string, error) {
	exts := pathExtensions()
	for _, dir := range entries {
		for _, ext := range exts {
			// The extension is lower-cased as exec.LookPath does, so a
			// resolved path reads `npm.cmd` rather than `npm.CMD`.
			candidate := filepath.Join(dir, name+strings.ToLower(ext))
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, nil
			}
		}
	}
	return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
}

// pathExtensions drops an empty entry, which a trailing semicolon in PATHEXT
// leaves behind. An empty extension would match a file with no extension,
// such as the sh script npm ships next to npm.cmd, which cmd.exe cannot run.
func pathExtensions() []string {
	value := os.Getenv("PATHEXT")
	if value == "" {
		value = ".COM;.EXE;.BAT;.CMD"
	}

	exts := make([]string, 0, 4)
	for _, ext := range strings.Split(value, ";") {
		if ext != "" {
			exts = append(exts, ext)
		}
	}
	return exts
}
