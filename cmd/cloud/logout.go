package cloud

import (
	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/usefulerror"
	"github.com/spf13/cobra"
)

func newLogoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Clear stored SafeDep Cloud credentials",
		RunE:  runLogout,
	}
}

func runLogout(cmd *cobra.Command, args []string) error {
	store, err := cloud.NewKeychainCredentialStore()
	if err != nil {
		ui.ErrorExit(usefulerror.Useful().
			Wrap(err).
			WithCode(usefulerror.ErrCodeLifecycle).
			WithHumanError("Failed to initialize credential store").
			WithHelp("Your system may not support secure credential storage"))
	}
	defer func() {
		if err := store.Close(); err != nil {
			log.Warnf("failed to close credential store: %v", err)
		}
	}()

	if err := store.Clear(); err != nil {
		ui.ErrorExit(usefulerror.Useful().
			Wrap(err).
			WithCode(usefulerror.ErrCodeLifecycle).
			WithHumanError("Failed to clear credentials"))
	}

	ui.Successf("Credentials cleared from keychain")
	return nil
}
