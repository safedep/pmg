package alias

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

type bashShell struct{}

var _ Shell = &bashShell{}

// bashLoginFiles are the login startup files in the order bash reads them.
var bashLoginFiles = []string{".bash_profile", ".bash_login", ".profile"}

func NewBashShell() (*bashShell, error) {
	return &bashShell{}, nil
}

func (b bashShell) Source(rcPath string) string {
	return defaultShellSource(rcPath)
}

func (b bashShell) PathExport(binDir string) string {
	return defaultPathExport(binDir)
}

func (b bashShell) Name() string {
	return "bash"
}

func (b bashShell) CandidateRcFiles(homeDir string) []string {
	files := []string{filepath.Join(homeDir, ".bashrc")}
	for _, name := range bashLoginFiles {
		files = append(files, filepath.Join(homeDir, name))
	}

	return files
}

func (b bashShell) InstallRcFiles(homeDir string, create bool) ([]string, error) {
	return bashInstallRcFiles(homeDir, create, runtime.GOOS)
}

// bashInstallRcFiles resolves where bash should load PMG. bash reads .bashrc for
// interactive non-login shells and a login file (.bash_profile, .bash_login, or
// .profile) for login shells such as macOS Terminal, so the lines may need to
// land in both. goos is a parameter for testability.
func bashInstallRcFiles(homeDir string, create bool, goos string) ([]string, error) {
	bashrc := filepath.Join(homeDir, ".bashrc")
	bashrcExists := fileExists(bashrc)
	login := firstExistingFile(homeDir, bashLoginFiles)

	var files []string
	if bashrcExists {
		files = append(files, bashrc)
	}

	// macOS Terminal starts bash as a login shell, which does not read .bashrc.
	// Create .bash_profile so the lines reach login shells too.
	if login == "" && create && goos == "darwin" {
		login = filepath.Join(homeDir, ".bash_profile")
		if err := ensureFile(login); err != nil {
			return nil, err
		}
	}

	// Skip the login file when it already sources .bashrc, to avoid loading the
	// lines twice.
	if login != "" && (!bashrcExists || !referencesBashrc(login)) {
		files = append(files, login)
	}

	if len(files) > 0 {
		return files, nil
	}

	if !create {
		return nil, nil
	}

	// Nothing exists yet: create the canonical file for this OS.
	target := bashrc
	if goos == "darwin" {
		target = filepath.Join(homeDir, ".bash_profile")
	}

	if err := ensureFile(target); err != nil {
		return nil, err
	}

	return []string{target}, nil
}

// bashrcSourceRe matches a real sourcing of a bashrc file: a `source` or `.`
// command whose argument ends in `.bashrc` (for example `source ~/.bashrc` or
// `. "$HOME/.bashrc"`). Requiring the command keyword avoids matching mere
// mentions in comments or unrelated commands.
var bashrcSourceRe = regexp.MustCompile(`(^|[\s;&|()])(source|\.)\s+\S*\.bashrc($|[\s;'"&|)])`)

// referencesBashrc reports whether the file at path actually sources a bashrc
// file. It skips comment lines and inline comments so a commented mention does
// not wrongly suppress wiring the login file.
func referencesBashrc(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}

		if bashrcSourceRe.MatchString(line) {
			return true
		}
	}

	return false
}
