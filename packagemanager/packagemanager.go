package packagemanager

import (
	"io"
	"os"
	"slices"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
)

type Command struct {
	Exe  string
	Args []string
}

type PackageInstallTarget struct {
	PackageVersion *packagev1.PackageVersion

	// IsExplicitVersion indicates the user provided an explicit version constraint
	// (e.g. ==1.2.3) as opposed to the version being auto-resolved by the resolver.
	IsExplicitVersion bool
}

func (pit *PackageInstallTarget) HasVersion() bool {
	return pit.PackageVersion != nil && pit.PackageVersion.GetVersion() != ""
}

type ParsedCommand struct {
	// Original command
	Command Command

	// Parsed install target if this is an install command
	InstallTargets []*PackageInstallTarget

	// IsManifestInstall indicates if this is a manifest-based installation
	// (e.g., npm install, pip install -r requirements.txt)
	IsManifestInstall bool

	// IsKnownNonDownloadCommand is true for commands that are known to not download packages
	// (e.g., npm ls, pip list, yarn why). Used by the proxy to decide whether to skip
	// interception when proxy.install_only is enabled. Unknown commands default to false so
	// the proxy runs — fail safe when a new subcommand is added to a package manager.
	IsKnownNonDownloadCommand bool
}

// IsInstallationCommand returns true if command installs packages (explicit targets or from manifest).
func (pc *ParsedCommand) IsInstallationCommand() bool {
	return pc.HasInstallTarget() || pc.HasManifestInstall()
}

// MayDownloadPackages returns true if the command may download packages from a registry.
// Returns false only for commands explicitly known to be non-download (e.g., npm ls, pip list).
// Unknown commands return true by default — fail safe when new package manager subcommands appear.
func (pc *ParsedCommand) MayDownloadPackages() bool {
	return !pc.IsKnownNonDownloadCommand
}

func (pc *ParsedCommand) HasInstallTarget() bool {
	return len(pc.InstallTargets) > 0
}

func (pc *ParsedCommand) HasManifestInstall() bool {
	return pc.IsManifestInstall
}

// IsFirstNonFlagArgInList checks if the first non-flag argument in args is in the given list.
// Only the first non-flag arg (the subcommand) is checked to avoid false positives when package
// names or script arguments happen to match a known command.
func IsFirstNonFlagArgInList(args []string, nonDownloadCmds []string) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return slices.Contains(nonDownloadCmds, arg)
	}
	return false
}

// FirstNonFlagArg returns the first argument that is not a flag, plus the
// arguments after it. Flags in valueFlags consume the following argument
// (their value) when it is not attached with '=', so the value is never
// mistaken for the subcommand.
func FirstNonFlagArg(args []string, valueFlags map[string]bool) (string, []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			if flag, _, hasValue := strings.Cut(arg, "="); valueFlags[flag] && !hasValue {
				i++
			}
			continue
		}
		return arg, args[i+1:]
	}
	return "", nil
}

// PackageManager is the contract for implementing a package manager
type PackageManager interface {
	// Name of the package manager implementation
	Name() string

	// ParseCommand parses the command and returns a parsed command
	// specific to the package manager implementation
	ParseCommand(args []string) (*ParsedCommand, error)

	// Ecosystem of the package manager
	Ecosystem() packagev1.Ecosystem
}

// PackageManagerInteraction carries the confirmation prompt callback and input
// routing used by proxy-mode malware confirmations.
type PackageManagerInteraction struct {
	// GetConfirmationOnMalware is called to get the confirmation of the user on the malware packages
	GetConfirmationOnMalware func(malwarePackages []*analyzer.PackageVersionAnalysisResult) (bool, error)

	// inputReader is the reader to use for user input during confirmations.
	// If nil, os.Stdin is used. This is set via SetInput to allow PTY input routing.
	inputReader io.Reader
}

// SetInput sets the input reader for user confirmations.
// This allows the PTY switchboard to route input to the prompt during confirmations.
func (i *PackageManagerInteraction) SetInput(r io.Reader) {
	i.inputReader = r
}

// Reader returns the configured input reader, or os.Stdin if none is set.
func (i *PackageManagerInteraction) Reader() io.Reader {
	if i.inputReader != nil {
		return i.inputReader
	}
	return os.Stdin
}
