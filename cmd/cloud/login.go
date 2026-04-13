package cloud

import (
	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/usefulerror"
	"github.com/spf13/cobra"
)

func newLoginCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Store SafeDep Cloud credentials securely",
		RunE:  runLogin,
	}
}

func runLogin(cmd *cobra.Command, args []string) error {
	tenantID, err := ui.PromptInput("Tenant ID: ")
	if err != nil {
		ui.ErrorExit(usefulerror.Useful().
			Wrap(err).
			WithCode(usefulerror.ErrCodeLifecycle).
			WithHumanError("Failed to read Tenant ID"))
	}

	if tenantID == "" {
		ui.ErrorExit(usefulerror.Useful().
			WithCode(usefulerror.ErrCodeInvalidArgument).
			WithHumanError("Tenant ID cannot be empty"))
	}

	apiKey, err := ui.PromptSecret("API Key: ")
	if err != nil {
		ui.ErrorExit(usefulerror.Useful().
			Wrap(err).
			WithCode(usefulerror.ErrCodeLifecycle).
			WithHumanError("Failed to read API Key"))
	}

	if apiKey == "" {
		ui.ErrorExit(usefulerror.Useful().
			WithCode(usefulerror.ErrCodeInvalidArgument).
			WithHumanError("API Key cannot be empty"))
	}

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

	if err := store.SaveAPIKeyCredential(apiKey, tenantID); err != nil {
		ui.ErrorExit(usefulerror.Useful().
			Wrap(err).
			WithCode(usefulerror.ErrCodeLifecycle).
			WithHumanError("Failed to save credentials").
			WithHelp("Your system may not support secure credential storage"))
	}

	ui.Successf("Credentials saved securely")
	return nil
}
