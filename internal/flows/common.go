package flows

import (
	"fmt"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/packagemanager"
)

func applySandboxPolicy(pc *packagemanager.ParsedCommand) error {
	if pc == nil {
		return fmt.Errorf("error while executing sandbox hook: got nil parsed command")
	}

	config.ConfigureSandbox(pc.IsInstallationCommand())
	return nil
}
