package setup

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/safedep/pmg/truststore"
	"github.com/spf13/cobra"
)

// trustStore is the testability seam; defaultTrustStore delegates to the package.
type trustStore interface {
	Install(certPEM []byte, scope truststore.Scope) error
	Uninstall(commonName string, scope truststore.Scope) error
	Status(commonName string) (user, system bool, err error)
	UserScopeSupported() bool
}

type defaultTrustStore struct{}

func (defaultTrustStore) Install(p []byte, s truststore.Scope) error { return truststore.Install(p, s) }
func (defaultTrustStore) Uninstall(cn string, s truststore.Scope) error {
	return truststore.Uninstall(cn, s)
}
func (defaultTrustStore) Status(cn string) (bool, bool, error) { return truststore.Status(cn) }
func (defaultTrustStore) UserScopeSupported() bool             { return truststore.UserScopeSupported() }

type certCommandError struct{ usefulerror.UsefulError }

func (e *certCommandError) ExitCode() int { return 1 }

func newCertCommandError(code, msg, help string, cause error) *certCommandError {
	return &certCommandError{
		UsefulError: usefulerror.NewUsefulError().
			WithCode(code).
			WithHumanError(msg).
			WithHelp(help).
			Wrap(cause),
	}
}

// NewCertCommand returns the `pmg setup cert` command tree.
func NewCertCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Manage PMG's MITM CA certificate and OS trust",
		Long: "Generate, persist, and trust PMG's MITM CA so package managers and " +
			"native tools (including Go on macOS/Windows) trust HTTPS interception.",
		RunE: func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newCertInstallCommand())
	cmd.AddCommand(newCertUninstallCommand())
	cmd.AddCommand(newCertStatusCommand())
	return cmd
}

func scopeFromFlag(system bool) truststore.Scope {
	if system {
		return truststore.ScopeSystem
	}
	return truststore.ScopeUser
}

func newCertInstallCommand() *cobra.Command {
	var system, force bool
	cmd := &cobra.Command{
		Use:          "install",
		Short:        "Generate, persist, and trust PMG's MITM CA",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCertInstall(config.Get().ConfigDir(), scopeFromFlag(system), force, defaultTrustStore{}, os.Stdout)
		},
	}
	cmd.Flags().BoolVar(&system, "system", false, "Install into the system (all-users) trust store; requires sudo/admin")
	cmd.Flags().BoolVar(&force, "force", false, "Regenerate and re-trust the CA even if one already exists")
	return cmd
}

func newCertUninstallCommand() *cobra.Command {
	var system, purge bool
	cmd := &cobra.Command{
		Use:          "uninstall",
		Short:        "Remove PMG's MITM CA from the OS trust store",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCertUninstall(config.Get().ConfigDir(), scopeFromFlag(system), purge, defaultTrustStore{}, os.Stdout)
		},
	}
	cmd.Flags().BoolVar(&system, "system", false, "Remove from the system (all-users) trust store; requires sudo/admin")
	cmd.Flags().BoolVar(&purge, "purge", false, "Also delete the on-disk CA keypair")
	return cmd
}

func newCertStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "status",
		Short:        "Show PMG MITM CA presence, trust scope, and expiry",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCertStatus(config.Get().ConfigDir(), defaultTrustStore{}, os.Stdout)
		},
	}
}

func runCertInstall(dir string, scope truststore.Scope, force bool, store trustStore, out io.Writer) error {
	caCert, loadErr := certmanager.LoadCA(dir)
	exists := loadErr == nil
	expired := exists && caCert.IsExpired(time.Hour)
	rotate := force || expired

	if exists && !rotate {
		user, system, _ := store.Status(certmanager.CACommonName)
		if (scope == truststore.ScopeUser && user) || (scope == truststore.ScopeSystem && system) {
			fmt.Fprintf(out, "%s CA already installed and trusted (%s scope)\n", ui.Colors.Green("✓"), scope.String())
			return nil
		}
	}

	if !exists || rotate {
		// Rotation uninstalls first so no duplicate CNs remain in the OS store.
		if rotate && exists {
			fmt.Fprintf(out, "%s Rotating existing CA\n", ui.Colors.Dim("ℹ"))
			if err := store.Uninstall(certmanager.CACommonName, scope); err != nil && !errors.Is(err, truststore.ErrUserScopeUnsupported) {
				return newCertCommandError(errcodes.CertTrustStore, "failed to remove old CA before rotation", trustHelp(scope), err)
			}

			// Best-effort cleanup of the opposite scope so a scope change during
			// rotation leaves no stale same-CN cert behind. Non-fatal: the other
			// scope may need privileges we do not hold.
			if err := store.Uninstall(certmanager.CACommonName, otherScope(scope)); err != nil && !errors.Is(err, truststore.ErrUserScopeUnsupported) {
				log.Debugf("best-effort cleanup of %s-scope CA during rotation failed: %v", otherScope(scope), err)
			}
		}

		generated, err := certmanager.GenerateCA(certmanager.PersistentCACertManagerConfig())
		if err != nil {
			return newCertCommandError(errcodes.CertGeneration, "failed to generate CA certificate",
				"Check available entropy and try again", err)
		}
		if err := certmanager.SaveCA(dir, generated); err != nil {
			return newCertCommandError(errcodes.CertPersistence, "failed to persist CA keypair",
				fmt.Sprintf("Check write permissions for %s", dir), err)
		}
		caCert = generated
		fmt.Fprintf(out, "%s CA keypair written to %s\n", ui.Colors.Green("✓"), certmanager.CACertPath(dir))
	} else {
		fmt.Fprintf(out, "%s Reusing existing CA keypair at %s\n", ui.Colors.Dim("ℹ"), certmanager.CACertPath(dir))
	}

	fmt.Fprintf(out, "%s Installing a system-trusted MITM CA (%s scope). This lets PMG inspect HTTPS package traffic.\n",
		ui.Colors.Yellow("⚠"), scope.String())

	if err := store.Install(caCert.Certificate, scope); err != nil {
		if errors.Is(err, truststore.ErrUserScopeUnsupported) {
			// Linux has no per-user trust store; the persisted CA is still useful via
			// SSL_CERT_FILE injection. Treat as a friendly no-op rather than an error.
			fmt.Fprintf(out, "%s %s\n", ui.Colors.Dim("ℹ"),
				"This platform has no per-user trust store. The CA keypair is persisted and Go on Linux honors "+
					"SSL_CERT_FILE (injected by PMG). Re-run with --system for machine-wide trust (requires sudo).")
			return nil
		}
		return newCertCommandError(errcodes.CertTrustStore, "failed to install CA into trust store", trustHelp(scope), err)
	}

	fmt.Fprintf(out, "%s CA installed and trusted (%s scope)\n", ui.Colors.Green("✓"), scope.String())
	return nil
}

func runCertUninstall(dir string, scope truststore.Scope, purge bool, store trustStore, out io.Writer) error {
	if err := store.Uninstall(certmanager.CACommonName, scope); err != nil && !errors.Is(err, truststore.ErrUserScopeUnsupported) {
		return newCertCommandError(errcodes.CertTrustStore, "failed to remove CA from trust store", trustHelp(scope), err)
	}
	fmt.Fprintf(out, "%s CA removed from %s trust store\n", ui.Colors.Green("✓"), scope.String())

	if purge {
		removed := false
		for _, p := range []string{certmanager.CACertPath(dir), certmanager.CAKeyPath(dir)} {
			if err := os.Remove(p); err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return newCertCommandError(errcodes.CertPersistence, "failed to delete CA file",
					"Check filesystem permissions", err)
			}
			removed = true
		}
		if removed {
			fmt.Fprintf(out, "%s CA keypair deleted from disk\n", ui.Colors.Green("✓"))
		}
	}
	return nil
}

func runCertStatus(dir string, store trustStore, out io.Writer) error {
	st, err := certmanager.InspectCA(dir)
	if err != nil {
		return newCertCommandError(errcodes.CertPersistence, "failed to inspect CA",
			"The CA file may be corrupt; re-run `pmg setup cert install`", err)
	}

	user, system, _ := store.Status(certmanager.CACommonName)
	st.UserTrusted, st.SystemTrusted = user, system

	entries := map[string]string{
		"Key Present":      strconv.FormatBool(st.KeyPresent),
		"Cert Present":     strconv.FormatBool(st.CertPresent),
		"Trusted (user)":   strconv.FormatBool(st.UserTrusted),
		"Trusted (system)": strconv.FormatBool(st.SystemTrusted),
	}
	if st.CertPresent {
		entries["Expires"] = st.NotAfter.Format(time.RFC3339)
		entries["Fingerprint"] = st.Fingerprint
	}
	ui.PrintInfoSection("PMG CA Certificate", entries)

	drift, reason := st.Drift()
	switch {
	case drift:
		fmt.Fprintf(out, "\n%s %s\n", ui.Colors.Red("drift:"), reason)
	case st.ExpiringSoon:
		fmt.Fprintf(out, "\n%s CA expires within 30 days (%s). Run `pmg setup cert install --force` to rotate.\n",
			ui.Colors.Yellow("⚠"), st.NotAfter.Format("2006-01-02"))
	case st.KeyPresent && st.CertPresent && !st.Trusted():
		// "not trusted" is expected on Linux (Go honors SSL_CERT_FILE) but a
		// real problem where a per-user store exists (macOS/Windows).
		if store.UserScopeSupported() {
			fmt.Fprintf(out, "\n%s CA on disk but not trusted in the OS store. Run `pmg setup cert install`.\n", ui.Colors.Yellow("⚠"))
		} else {
			fmt.Fprintf(out, "\n%s CA on disk; not in OS store. Expected on Linux (Go honors SSL_CERT_FILE); use --system for store trust.\n", ui.Colors.Dim("ℹ"))
		}
	}
	return nil
}

func otherScope(s truststore.Scope) truststore.Scope {
	if s == truststore.ScopeSystem {
		return truststore.ScopeUser
	}
	return truststore.ScopeSystem
}

func trustHelp(scope truststore.Scope) string {
	if scope == truststore.ScopeSystem {
		return "System scope needs elevation: re-run with sudo (macOS/Linux) or an elevated prompt (Windows)"
	}
	return "Approve the keychain prompt if shown; on Linux use --system (no per-user store)"
}
