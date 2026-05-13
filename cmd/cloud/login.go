package cloud

import (
	"os"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/usefulerror"
	"github.com/spf13/cobra"
)

var loginFromEnv bool

func newLoginCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Store SafeDep Cloud credentials securely",
		RunE:  runLogin,
	}

	cmd.Flags().BoolVar(&loginFromEnv, "from-env", false,
		"Read credentials from SAFEDEP_API_KEY and SAFEDEP_TENANT_ID environment variables")

	return cmd
}

func runLogin(cmd *cobra.Command, args []string) error {
	var tenantID, apiKey string

	if loginFromEnv {
		apiKey = os.Getenv("SAFEDEP_API_KEY")
		tenantID = os.Getenv("SAFEDEP_TENANT_ID")

		if apiKey == "" {
			ui.ErrorExit(usefulerror.Useful().
				WithCode(usefulerror.ErrCodeInvalidArgument).
				WithHumanError("SAFEDEP_API_KEY environment variable is not set"))
		}

		if tenantID == "" {
			ui.ErrorExit(usefulerror.Useful().
				WithCode(usefulerror.ErrCodeInvalidArgument).
				WithHumanError("SAFEDEP_TENANT_ID environment variable is not set"))
		}
	} else {
		var err error
		tenantID, err = ui.PromptInput("Tenant ID: ")
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

		apiKey, err = ui.PromptSecret("API Key: ")
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
