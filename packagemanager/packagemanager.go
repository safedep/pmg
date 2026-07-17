package packagemanager

import (
	"io"
	"os"
	"slices"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/internal/ui"
)

type Command struct {
	Exe  string
	Args []string
}

type PackageInstallTarget struct {
	PackageVersion *packagev1.PackageVersion

	// Extras specifies additional features to be installed with a Python package
	// Example: "django[mysql,redis]" has Extras as ["mysql", "redis"]
	// Currently only specific to Python packages
	Extras []string

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

	// ManifestFiles contains the list of manifest files to install from
	// (e.g., ["requirements.txt"] for pip install -r requirements.txt)
	ManifestFiles []string

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

func (pc *ParsedCommand) ShouldExtractFromManifest() bool {
	return pc.IsManifestInstall && !pc.HasInstallTarget()
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

// PackageManagerInteraction defines the user interaction callbacks used
// by the proxy flow and confirmation handlers to surface status, warnings and
// malware confirmation prompts.
type PackageManagerInteraction struct {
	// SetStatus is called to set the status of the guard in the UI
	SetStatus func(status string)

	// ClearStatus is called to clear the status of the guard in the UI
	ClearStatus func()

	// ShowWarning is called to show a warning message to the user
	ShowWarning func(message string)

	// GetConfirmationOnMalware is called to get the confirmation of the user on the malware packages
	GetConfirmationOnMalware func(malwarePackages []*analyzer.PackageVersionAnalysisResult) (bool, error)

	// Block is called to block the installation of the malware packages. One or more malicious
	// packages are passed as arguments. These are the packages that were detected as malicious.
	// Client code must perform the necessary error handling and termination of the process.
	Block func(config *ui.BlockConfig) error

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
