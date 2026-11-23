package cloud

import (
	"errors"
	"fmt"
	"time"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/cloudauth"
	"github.com/safedep/pmg/internal/ui"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
)

func newWorkloadCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workload",
		Short: "Get and revoke SafeDep Cloud credentials with the workload identity of a CI job",
	}

	cmd.AddCommand(newWorkloadExchangeCommand())
	cmd.AddCommand(newWorkloadRevokeCommand())

	return cmd
}

func newWorkloadExchangeCommand() *cobra.Command {
	var tenantID, output string

	cmd := &cobra.Command{
		Use:   "exchange",
		Short: "Exchange the workload identity token of the CI job for a SafeDep Cloud credential",
		Long: "Exchange the workload identity token of the CI job, such as a GitHub Actions OIDC ID token, " +
			"for a short-lived SafeDep Cloud credential. pmg asks for the longest life that the trust rule " +
			"allows and writes the credential to a new file that only the current user can read. " +
			"Revoke the credential with 'pmg cloud workload revoke' at the end of the job.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// A detached sync child would inherit the ID token request token.
			audit.SuppressBackgroundSync()
			if tenantID == "" || output == "" {
				ui.ErrorExit(usefulerror.NewUsefulError().
					WithCode(errcodes.InvalidArgument).
					WithHumanError("Set --tenant-id and --output"))
			}

			cred, err := cloudauth.ExchangeToFile(cmd.Context(), tenantID, output)
			if err != nil {
				ui.ErrorExit(exchangeError(err))
			}

			ui.Successf("SafeDep Cloud issued the workload credential %s. It expires at %s",
				cred.CredentialID, cred.ExpiresAt.Format(time.RFC3339))
			return nil
		},
	}

	cmd.Flags().StringVar(&tenantID, "tenant-id", "", "SafeDep Cloud tenant domain that the credential is for")
	cmd.Flags().StringVar(&output, "output", "", "Path of the new credential file")

	return cmd
}

func exchangeError(err error) error {
	switch {
	case errors.Is(err, cloudauth.ErrCredentialFileWrite):
		return usefulerror.NewUsefulError().
			Wrap(err).
			WithCode(errcodes.Lifecycle).
			WithHumanError("Cannot write the workload credential file").
			WithHelp("pmg revoked the credential. Check the --output path")
	case errors.Is(err, cloud.ErrNoWorkloadIdentity):
		return usefulerror.NewUsefulError().
			Wrap(err).
			WithCode(errcodes.WorkloadIdentityNotFound).
			WithHumanError("The job has no workload identity token for SafeDep Cloud").
			WithHelp("Give the job 'permissions: id-token: write', or set an API key")
	case errors.Is(err, cloudauth.ErrExchangeRefused):
		return usefulerror.NewUsefulError().
			Wrap(err).
			WithCode(errcodes.WorkloadExchangeRefused).
			WithHumanError(fmt.Sprintf("SafeDep Cloud refused the workload identity exchange (%s)", statusMessage(err))).
			WithHelp("A tenant admin can see the reason with 'safedep workload exchange list --denied'")
	default:
		return usefulerror.NewUsefulError().
			Wrap(err).
			WithCode(errcodes.Network).
			WithHumanError("Cannot exchange the workload identity token with SafeDep Cloud")
	}
}

// statusMessage returns the message of the gRPC status that err wraps. The
// message names the reason of a refusal without the error chain.
func statusMessage(err error) string {
	var se interface{ GRPCStatus() *status.Status }
	if errors.As(err, &se) {
		return se.GRPCStatus().Message()
	}
	return err.Error()
}

func newWorkloadRevokeCommand() *cobra.Command {
	var credential string

	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a SafeDep Cloud credential that 'pmg cloud workload exchange' wrote",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			audit.SuppressBackgroundSync()
			if credential == "" {
				ui.ErrorExit(usefulerror.NewUsefulError().
					WithCode(errcodes.InvalidArgument).
					WithHumanError("Set --credential"))
			}

			cred, err := cloudauth.ReadCredentialFile(credential)
			if err != nil {
				ui.ErrorExit(usefulerror.NewUsefulError().
					Wrap(err).
					WithCode(errcodes.InvalidArgument).
					WithHumanError("Cannot read the workload credential file"))
			}

			if err := cloudauth.RevokeWorkloadCredential(cmd.Context(), cred); err != nil {
				ui.ErrorExit(usefulerror.NewUsefulError().
					Wrap(err).
					WithCode(errcodes.Network).
					WithHumanError("Cannot revoke the workload credential").
					WithHelp("The credential stays valid until it expires"))
			}

			ui.Successf("Revoked the workload credential %s", cred.CredentialID)
			return nil
		},
	}

	cmd.Flags().StringVar(&credential, "credential", "", "Path of the credential file")

	return cmd
}
