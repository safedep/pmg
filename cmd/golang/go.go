// Package golang implements the experimental `pmg go` command. The package is
// named golang (not go) to avoid shadowing the toolchain name as a package
// path; the user-facing command is still `pmg go`.
package golang

import (
	"context"
	"fmt"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/safedep/pmg/truststore"
	"github.com/spf13/cobra"
)

func NewGoCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "go [action] [module]",
		Short:              "Guard go module downloads (experimental)",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeGoFlow(cmd.Context(), args)
			if err != nil {
				ui.ExitFromCommandError(err)
			}

			return nil
		},
	}
}

func executeGoFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandGo()

	packageManager, err := packagemanager.NewGoPackageManager(packagemanager.DefaultGoPackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create go package manager: %w", err)
	}

	// Reject a removed proxy opt-out before the CA trust check: the old code
	// reported the mode error first, and a config problem must not steer the
	// user into an unnecessary OS trust store change.
	if err := config.RejectRemovedProxyOptOut(); err != nil {
		return err
	}

	if err := requireTrustedCA(); err != nil {
		return err
	}

	return flows.RunProxy(ctx, packageManager, args)
}

// requireTrustedCA fails fast when Go cannot trust PMG's MITM CA, so a module
// download does not fail mid-build with an opaque x509 error.
func requireTrustedCA() error {
	if err := truststore.GoTrustsCA(config.Get().ConfigDir()); err != nil {
		return errGoCertNotTrusted(err)
	}
	return nil
}

func errGoCertNotTrusted(cause error) error {
	return usefulerror.NewUsefulError().
		WithCode(errcodes.CertTrustStore).
		WithHumanError(fmt.Sprintf("Go cannot trust the PMG proxy CA (%v).", cause)).
		WithHelp("Run `pmg setup cert install` to install and trust the PMG proxy CA, then retry.").
		WithMsg("pmg proxy CA is not trusted in the OS trust store").
		Wrap(cause)
}
