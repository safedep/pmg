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
	"github.com/safedep/pmg/internal/platform"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/safedep/pmg/truststore"
	"github.com/spf13/cobra"
)

// trustStore is the testability seam; defaultTrustStore delegates to the package.
type trustStore interface {
	Install(certPEM []byte, scope platform.CAScope) error
	Uninstall(commonName string, scope platform.CAScope) error
	Status(dir string) (user, system bool, err error)
	UserScopeSupported() bool
}

type defaultTrustStore struct{}

func (defaultTrustStore) Install(p []byte, s platform.CAScope) error { return truststore.Install(p, s) }
func (defaultTrustStore) Uninstall(cn string, s platform.CAScope) error {
	return truststore.Uninstall(cn, s)
}
func (defaultTrustStore) Status(dir string) (bool, bool, error) { return truststore.Status(dir) }
func (defaultTrustStore) UserScopeSupported() bool              { return truststore.UserScopeSupported() }

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

func scopeFromFlag(system bool) platform.CAScope {
	if system {
		return platform.CAScopeSystem
	}
	return platform.CAScopeUser
}

func newCertInstallCommand() *cobra.Command {
	var system, force bool
	cmd := &cobra.Command{
		Use:          "install",
		Short:        "Generate, persist, and trust PMG's MITM CA",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			scope := scopeFromFlag(system)
			dir, err := newKeypairLayout(config.Get()).installDir(scope)
			if err != nil {
				return err
			}
			return runCertInstall(dir, scope, force, defaultTrustStore{}, os.Stdout)
		},
	}
	cmd.Flags().BoolVar(&system, "system", false, "Install into the system (all-users) trust store (PMG prompts for elevation. On Windows run from an elevated prompt). On Linux as root, the keypair goes to the system config directory for the enforcing proxy.")
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
			scope := scopeFromFlag(system)
			dirs, err := newKeypairLayout(config.Get()).purgeDirs(scope)
			if err != nil {
				return err
			}
			return runCertUninstall(dirs, scope, purge, defaultTrustStore{}, os.Stdout)
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
			dir, err := newKeypairLayout(config.Get()).statusDir()
			if err != nil {
				return err
			}
			return runCertStatus(dir, defaultTrustStore{}, os.Stdout)
		},
	}
}

func runCertInstall(dir string, scope platform.CAScope, force bool, store trustStore, out io.Writer) error {
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
		user, system, _ := store.Status(dir)
		if (scope == platform.CAScopeUser && user) || (scope == platform.CAScopeSystem && system) {
			if _, err := fmt.Fprintf(out, "%s CA already installed and trusted (%s scope)\n", ui.Colors.Green("✓"), scope.String()); err != nil {
				return err
			}
			return nil
		}
	}

	if rotate && (exists || corrupted) {
		msg := "Rotating existing CA"
		if corrupted {
			msg = "Persisted CA is incomplete or unreadable; replacing it"
		}
		if _, err := fmt.Fprintf(out, "%s %s\n", ui.Colors.Dim("ℹ"), msg); err != nil {
			return err
		}

		// Best-effort cleanup of the opposite scope so a scope change during
		// rotation leaves no stale same-CN cert behind. Non-fatal: the other
		// scope may need privileges we do not hold.
		if err := store.Uninstall(certmanager.CACommonName, otherScope(scope)); err != nil && !errors.Is(err, platform.ErrCAUserScopeUnsupported) {
			log.Debugf("best-effort cleanup of %s-scope CA during rotation failed: %v", otherScope(scope), err)
		}
	}

	// A certificate with the PMG name that is not this CA can stay trusted:
	// a rotated CA, a lost keypair, or the system keypair of an older
	// release. Its private key can still exist, so remove every one before
	// the store trusts this CA. The removal runs before a new keypair is
	// written, so a failure leaves the keypair and the trust as they were.
	if err := store.Uninstall(certmanager.CACommonName, scope); err != nil && !errors.Is(err, platform.ErrCAUserScopeUnsupported) {
		return newCertCommandError(errcodes.CertTrustStore, "failed to remove an old PMG CA from the trust store", trustHelp(scope), err)
	}

	if !exists || rotate {
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
		if errors.Is(err, platform.ErrCAUserScopeUnsupported) {
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

func runCertUninstall(dirs []string, scope platform.CAScope, purge bool, store trustStore, out io.Writer) error {
	switch err := store.Uninstall(certmanager.CACommonName, scope); {
	case errors.Is(err, platform.ErrCAUserScopeUnsupported):
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
		var paths []string
		for _, dir := range dirs {
			paths = append(paths, certmanager.CACertPath(dir), certmanager.CAKeyPath(dir))
		}
		for _, p := range paths {
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

	user, system, _ := store.Status(dir)
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

func otherScope(s platform.CAScope) platform.CAScope {
	if s == platform.CAScopeSystem {
		return platform.CAScopeUser
	}
	return platform.CAScopeSystem
}

// keypairLayout names the directories that can hold a CA keypair. The
// system directory holds the keypair of the enforcing proxy, a root daemon
// that must not depend on one user's home. A platform without that proxy has
// no reader for a system keypair, so there the system directory is legacy:
// older releases wrote a keypair to it that nothing reads.
type keypairLayout struct {
	user   string
	system string
	legacy string
}

func newKeypairLayout(cfg *config.RuntimeConfig) keypairLayout {
	l := keypairLayout{user: cfg.ConfigDir()}
	if platform.Supports(platform.EnforcingProxy) {
		l.system = config.SystemConfigDir()
	} else {
		l.legacy = config.SystemConfigDir()
	}
	return l
}

// installDir is where `pmg setup cert install` keeps the keypair. Only a
// privileged system-scope install on a platform with the enforcing proxy
// uses the system directory. A sudo caller is sent back to their own
// account.
func (l keypairLayout) installDir(scope platform.CAScope) (string, error) {
	if l.system != "" && scope == platform.CAScopeSystem && platform.IsPrivileged() {
		return l.system, nil
	}
	if err := l.refuseSudo(); err != nil {
		return "", err
	}
	return l.user, nil
}

// purgeDirs are the keypair directories that `pmg setup cert uninstall
// --purge` deletes. An administrator also deletes the legacy keypair.
func (l keypairLayout) purgeDirs(scope platform.CAScope) ([]string, error) {
	// macOS needs sudo to delete the root-owned legacy keypair. The user's own
	// keypair is not root's to delete, so sudo purges the legacy one only.
	if l.legacy != "" && scope == platform.CAScopeSystem && platform.IsSudo() {
		return []string{l.legacy}, nil
	}
	dir, err := l.installDir(scope)
	if err != nil {
		return nil, err
	}
	dirs := []string{dir}
	if l.legacy != "" && scope == platform.CAScopeSystem && platform.IsPrivileged() {
		dirs = append(dirs, l.legacy)
	}
	return dirs, nil
}

// inspectDir is the keypair that `pmg setup info` and `pmg setup doctor`
// report: the user's keypair when there is one, else the system keypair,
// which any user may read. The bool reports the system one.
func (l keypairLayout) inspectDir() (string, bool) {
	if !hasKeypair(l.user) && hasKeypair(l.system) {
		return l.system, true
	}
	return l.user, false
}

// statusDir is the keypair that `pmg setup cert status` reports. A
// privileged process reports the system keypair when one exists.
func (l keypairLayout) statusDir() (string, error) {
	if platform.IsPrivileged() && hasKeypair(l.system) {
		return l.system, nil
	}
	if err := l.refuseSudo(); err != nil {
		return "", err
	}
	return l.user, nil
}

// legacyKeypair returns the legacy directory when it holds a keypair, or "".
// Its certificate can still be trusted machine-wide, so it matters also when
// the user has a keypair of their own.
func (l keypairLayout) legacyKeypair() string {
	if hasKeypair(l.legacy) {
		return l.legacy
	}
	return ""
}

func (l keypairLayout) refuseSudo() error {
	if !platform.IsSudo() {
		return nil
	}
	help := "PMG generates a per-user CA keypair and elevates only the system trust step. Re-run without sudo."
	if l.system != "" {
		help += " To keep a root-owned keypair for an enforcing proxy, run `sudo pmg setup cert install --system`."
	}
	return newCertCommandError(errcodes.PermissionDenied,
		"run `pmg setup cert` as your normal user, not with sudo", help, errors.New("invoked under sudo"))
}

func hasKeypair(dir string) bool {
	if dir == "" {
		return false
	}
	st, err := certmanager.InspectCA(dir)
	return err == nil && (st.CertPresent || st.KeyPresent)
}

func trustHelp(scope platform.CAScope) string {
	if scope == platform.CAScopeSystem {
		return "Approve the elevation prompt when asked (macOS/Linux), or run from an elevated prompt (Windows)"
	}
	return "Approve the keychain prompt if shown; on Linux use --system (no per-user store)"
}
