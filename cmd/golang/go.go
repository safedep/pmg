// Package golang implements the experimental `pmg go` command. The package is
// named golang (not go) to avoid shadowing the toolchain name as a package
// path; the user-facing command is still `pmg go`.
package golang

import (
	"context"
	"fmt"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/safedep/pmg/proxy/certmanager"
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

	parsedCommand, err := packageManager.ParseCommand(args)
	if err != nil {
		return fmt.Errorf("failed to parse command: %w", err)
	}

	if !config.Get().IsProxyModeEnabled() {
		return errGoRequiresProxyMode()
	}

	if err := requireTrustedCA(); err != nil {
		return err
	}

	return flows.ProxyFlow(packageManager, noopResolver{}).Run(ctx, args, parsedCommand)
}

// requireTrustedCA fails fast when Go cannot trust PMG's MITM CA. Go's
// crypto/x509 ignores SSL_CERT_FILE on macOS and Windows and verifies TLS
// against the OS trust store only, so without an OS-trusted persisted CA every
// module download would fail mid-build with an opaque x509 error. Linux honors
// the injected SSL_CERT_FILE bundle, so any CA (persisted or ephemeral) works.
func requireTrustedCA() error {
	if !truststore.UserScopeSupported() {
		return nil
	}

	if _, err := certmanager.LoadCA(config.Get().ConfigDir()); err != nil {
		return errGoCertNotTrusted(err)
	}

	user, system, err := truststore.Status(certmanager.CACommonName)
	if err != nil {
		return errGoCertNotTrusted(err)
	}

	if !user && !system {
		return errGoCertNotTrusted(nil)
	}

	return nil
}

func errGoRequiresProxyMode() error {
	return usefulerror.NewUsefulError().
		WithCode(errcodes.InvalidArgument).
		WithHumanError("Go support requires proxy mode, which is disabled in your configuration.").
		WithHelp("Enable proxy mode (proxy.enabled: true in the PMG config) and retry.").
		WithMsg("go requires proxy mode")
}

func errGoCertNotTrusted(cause error) error {
	err := usefulerror.NewUsefulError().
		WithCode(errcodes.CertTrustStore).
		WithHumanError("Go ignores PMG's injected CA bundle on this OS; the PMG proxy CA must be trusted in the OS trust store.").
		WithHelp("Run `pmg setup cert install` to install and trust the PMG proxy CA, then retry.").
		WithMsg("pmg proxy CA is not trusted in the OS trust store")

	if cause != nil {
		return err.Wrap(cause)
	}

	return err
}

// noopResolver satisfies the ProxyFlow signature. The proxy flow never
// resolves dependencies up front: Go fetches every needed module zip through
// the proxy, where it is analyzed.
type noopResolver struct{}

var _ packagemanager.PackageResolver = noopResolver{}

func (noopResolver) ResolveLatestVersion(context.Context, *packagev1.Package) (*packagev1.PackageVersion, error) {
	return nil, fmt.Errorf("dependency resolution is not supported for go")
}

func (noopResolver) ResolveDependencies(context.Context, *packagev1.PackageVersion) ([]*packagev1.PackageVersion, error) {
	return nil, fmt.Errorf("dependency resolution is not supported for go")
}
