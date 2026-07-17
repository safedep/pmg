package guard

import (
	"io"
	"os"

	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/internal/ui"
)

// PackageManagerGuardInteraction defines the user interaction callbacks used
// by the proxy flow and confirmation handlers to surface status, warnings and
// malware confirmation prompts.
type PackageManagerGuardInteraction struct {
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
func (i *PackageManagerGuardInteraction) SetInput(r io.Reader) {
	i.inputReader = r
}

// Reader returns the configured input reader, or os.Stdin if none is set.
func (i *PackageManagerGuardInteraction) Reader() io.Reader {
	if i.inputReader != nil {
		return i.inputReader
	}
	return os.Stdin
}
