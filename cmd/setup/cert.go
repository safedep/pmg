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
			if err := errIfRunningUnderSudo(); err != nil {
				return err
			}
			return runCertInstall(config.Get().ConfigDir(), scopeFromFlag(system), force, defaultTrustStore{}, os.Stdout)
		},
	}
	cmd.Flags().BoolVar(&system, "system", false, "Install into the system (all-users) trust store (PMG prompts for elevation; on Windows run from an elevated prompt)")
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
			if err := errIfRunningUnderSudo(); err != nil {
				return err
			}
			return runCertUninstall(config.Get().ConfigDir(), scopeFromFlag(system), purge, defaultTrustStore{}, os.Stdout)
		},
	}
	cmd.Flags().BoolVar(&system, "system", false, "Remove from the system (all-users) trust store (PMG prompts for elevation; on Windows run from an elevated prompt)")
	cmd.Flags().BoolVar(&purge, "purge", false, "Also delete the on-disk CA keypair")
	return cmd
}

func newCertStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "status",
		Short:        "Show PMG MITM CA presence, trust scope, and expiry",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := errIfRunningUnderSudo(); err != nil {
				return err
			}
			return runCertStatus(config.Get().ConfigDir(), defaultTrustStore{}, os.Stdout)
		},
	}
}

func runCertInstall(dir string, scope truststore.Scope, force bool, store trustStore, out io.Writer) error {
	caCert, loadErr := certmanager.LoadCA(dir)
	exists := loadErr == nil
	// A failed load with files still on disk means a corrupt or partial CA (e.g.
	// the cert is present/trusted but ca-key.pem is missing or unparseable).
	// Treat it like a rotation so the old trusted root is cleaned up rather than
	// left behind alongside a freshly generated one. (A missing key surfaces as
	// os.ErrNotExist from LoadCA, so checking on-disk remnants is what tells a
	// partial state apart from a truly fresh install.)
	diskState, inspectErr := certmanager.InspectCA(dir)
	if inspectErr != nil {
		log.Debugf("inspecting on-disk CA during install: %v", inspectErr)
	}
	corrupted := loadErr != nil && (diskState.KeyPresent || diskState.CertPresent)
	expired := exists && caCert.IsExpired(time.Hour)
	rotate := force || expired || corrupted
	if corrupted {
		log.Debugf("replacing unreadable persisted CA: %v", loadErr)
	}

	if exists && !rotate {
		user, system, _ := store.Status(certmanager.CACommonName)
		if (scope == truststore.ScopeUser && user) || (scope == truststore.ScopeSystem && system) {
			if _, err := fmt.Fprintf(out, "%s CA already installed and trusted (%s scope)\n", ui.Colors.Green("✓"), scope.String()); err != nil {
				return err
			}
			return nil
		}
	}

	if !exists || rotate {
		if rotate && (exists || corrupted) {
			msg := "Rotating existing CA"
			if corrupted {
				msg = "Persisted CA is incomplete or unreadable; replacing it"
			}
			if _, err := fmt.Fprintf(out, "%s %s\n", ui.Colors.Dim("ℹ"), msg); err != nil {
				return err
			}
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
		if _, err := fmt.Fprintf(out, "%s CA keypair written to %s\n", ui.Colors.Green("✓"), certmanager.CACertPath(dir)); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(out, "%s Reusing existing CA keypair at %s\n", ui.Colors.Dim("ℹ"), certmanager.CACertPath(dir)); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(out, "%s Installing an OS-trusted MITM CA (%s scope). This lets PMG inspect HTTPS package traffic.\n",
		ui.Colors.Yellow("⚠"), scope.String()); err != nil {
		return err
	}

	if err := store.Install(caCert.Certificate, scope); err != nil {
		if errors.Is(err, truststore.ErrUserScopeUnsupported) {
			// Linux has no per-user trust store; treat as a friendly no-op.
			if _, err := fmt.Fprintf(out, "%s %s\n", ui.Colors.Dim("ℹ"),
				"This platform has no per-user trust store. The CA keypair is persisted. "+
					"Re-run with --system for machine-wide trust (PMG prompts for elevation)."); err != nil {
				return err
			}
			return nil
		}
		return newCertCommandError(errcodes.CertTrustStore, "failed to install CA into trust store", trustHelp(scope), err)
	}

	if _, err := fmt.Fprintf(out, "%s CA installed and trusted (%s scope)\n", ui.Colors.Green("✓"), scope.String()); err != nil {
		return err
	}
	return nil
}

func runCertUninstall(dir string, scope truststore.Scope, purge bool, store trustStore, out io.Writer) error {
	switch err := store.Uninstall(certmanager.CACommonName, scope); {
	case errors.Is(err, truststore.ErrUserScopeUnsupported):
		if _, e := fmt.Fprintf(out, "%s This platform has no per-user trust store; nothing to remove. Use --system for machine-wide.\n", ui.Colors.Dim("ℹ")); e != nil {
			return e
		}
	case err != nil:
		return newCertCommandError(errcodes.CertTrustStore, "failed to remove CA from trust store", trustHelp(scope), err)
	default:
		if _, e := fmt.Fprintf(out, "%s CA removed from %s trust store\n", ui.Colors.Green("✓"), scope.String()); e != nil {
			return e
		}
	}

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
			if _, err := fmt.Fprintf(out, "%s CA keypair deleted from disk\n", ui.Colors.Green("✓")); err != nil {
				return err
			}
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
		if _, err := fmt.Fprintf(out, "\n%s %s\n", ui.Colors.Red("drift:"), reason); err != nil {
			return err
		}
	case st.ExpiringSoon:
		if _, err := fmt.Fprintf(out, "\n%s CA expires within 30 days (%s). Run `pmg setup cert install --force` to rotate.\n",
			ui.Colors.Yellow("⚠"), st.NotAfter.Format("2006-01-02")); err != nil {
			return err
		}
	case st.KeyPresent && st.CertPresent && !st.Trusted():
		// "not trusted" is expected on Linux (Go honors SSL_CERT_FILE) but a
		// real problem where a per-user store exists (macOS/Windows).
		if store.UserScopeSupported() {
			if _, err := fmt.Fprintf(out, "\n%s CA on disk but not trusted in the OS store. Run `pmg setup cert install`.\n", ui.Colors.Yellow("⚠")); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintf(out, "\n%s CA on disk; not in OS store. Expected on Linux (Go honors SSL_CERT_FILE); use --system for store trust.\n", ui.Colors.Dim("ℹ")); err != nil {
				return err
			}
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

var geteuid = os.Geteuid

func errIfRunningUnderSudo() error {
	if geteuid() == 0 && os.Getenv("SUDO_USER") != "" {
		return newCertCommandError(errcodes.PermissionDenied,
			"run `pmg setup cert` as your normal user, not with sudo",
			"PMG generates a per-user CA keypair and elevates only the system trust step. Re-run without sudo (use --system for machine-wide trust).",
			errors.New("invoked under sudo"))
	}
	return nil
}

func trustHelp(scope truststore.Scope) string {
	if scope == truststore.ScopeSystem {
		return "Approve the elevation prompt when asked (macOS/Linux), or run from an elevated prompt (Windows)"
	}
	return "Approve the keychain prompt if shown; on Linux use --system (no per-user store)"
}
