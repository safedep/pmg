package cloud

import (
	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/log"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/ui"
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
		resolver, err := cloud.NewEnvCredentialResolver()
		if err != nil {
			ui.ErrorExit(usefulerror.NewUsefulError().
				Wrap(err).
				WithCode(errcodes.Lifecycle).
				WithHumanError("Failed to create environment credential resolver"))
		}

		creds, err := resolver.Resolve()
		if err != nil {
			ui.ErrorExit(usefulerror.NewUsefulError().
				Wrap(err).
				WithCode(errcodes.InvalidArgument).
				WithHumanError("Failed to resolve credentials from environment").
				WithHelp("Set SAFEDEP_API_KEY and SAFEDEP_TENANT_ID environment variables"))
		}

		apiKey, err = creds.GetAPIKey()
		if err != nil || apiKey == "" {
			ui.ErrorExit(usefulerror.NewUsefulError().
				WithCode(errcodes.InvalidArgument).
				WithHumanError("SAFEDEP_API_KEY environment variable is not set"))
		}

		tenantID, err = creds.GetTenantDomain()
		if err != nil || tenantID == "" {
			ui.ErrorExit(usefulerror.NewUsefulError().
				WithCode(errcodes.InvalidArgument).
				WithHumanError("SAFEDEP_TENANT_ID environment variable is not set"))
		}
	} else {
		var err error
		tenantID, err = ui.PromptInput("Tenant ID: ")
		if err != nil {
			ui.ErrorExit(usefulerror.NewUsefulError().
				Wrap(err).
				WithCode(errcodes.Lifecycle).
				WithHumanError("Failed to read Tenant ID"))
		}

		if tenantID == "" {
			ui.ErrorExit(usefulerror.NewUsefulError().
				WithCode(errcodes.InvalidArgument).
				WithHumanError("Tenant ID cannot be empty"))
		}

		apiKey, err = ui.PromptSecret("API Key: ")
		if err != nil {
			ui.ErrorExit(usefulerror.NewUsefulError().
				Wrap(err).
				WithCode(errcodes.Lifecycle).
				WithHumanError("Failed to read API Key"))
		}

		if apiKey == "" {
			ui.ErrorExit(usefulerror.NewUsefulError().
				WithCode(errcodes.InvalidArgument).
				WithHumanError("API Key cannot be empty"))
		}
	}

	store, err := cloud.NewKeychainCredentialStore()
	if err != nil {
		ui.ErrorExit(usefulerror.NewUsefulError().
			Wrap(err).
			WithCode(errcodes.Lifecycle).
			WithHumanError("Failed to initialize credential store").
			WithHelp("Your system may not support secure credential storage"))
	}
	defer func() {
		if err := store.Close(); err != nil {
			log.Warnf("failed to close credential store: %v", err)
		}
	}()

	if err := store.SaveAPIKeyCredential(apiKey, tenantID); err != nil {
		ui.ErrorExit(usefulerror.NewUsefulError().
			Wrap(err).
			WithCode(errcodes.Lifecycle).
			WithHumanError("Failed to save credentials").
			WithHelp("Your system may not support secure credential storage"))
	}

	ui.Successf("Credentials saved securely")
	return nil
}
